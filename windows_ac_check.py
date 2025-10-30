"""
windows_ac_check.py

Windows access-control checks via PowerShell (best-effort).
Requires: Windows (PowerShell available). For some queries admin privileges may be needed.

Usage:
    import windows_ac_check as wac
    admins = wac.get_local_admins()
    users = wac.get_local_users()
    disabled = wac.get_disabled_guest_accounts()
    policy = wac.get_password_policy()
    wh_status = wac.check_windows_hello()
    idle = wac.get_idle_accounts(threshold_days=90)
"""

import subprocess
import json
import datetime
from typing import List, Dict, Any, Optional


def _run_powershell(ps_cmd: str) -> str:
    """Run a PowerShell command and return stdout (text)."""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        # return stderr for debugging but keep returning stdout too
        raise RuntimeError(f"PowerShell error: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def _ps_json(cmd_without_convert: str) -> Any:
    """
    Run PowerShell command that outputs objects, append ConvertTo-Json,
    parse and return python object.
    """
    # Use a safe depth so nested objects are serialized
    ps = f"{cmd_without_convert} | ConvertTo-Json -Depth 6"
    out = _run_powershell(ps)
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # If PowerShell returns multiple JSON objects (rare), try line-by-line
        try:
            return json.loads(out.splitlines()[-1])
        except Exception:
            raise


def get_local_admins() -> List[Dict[str, Any]]:
    """
    Returns list of members in the local Administrators group.
    Each item contains at least: Name, ObjectClass (User/Group / Sid if present)
    """
    ps_cmd = 'Get-LocalGroupMember -Group "Administrators" | Select-Object Name,ObjectClass,PrincipalSource,SID'
    data = _ps_json(ps_cmd)
    # Normalize single-object to list
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    return data


def get_local_users() -> List[Dict[str, Any]]:
    """
    Returns list of local users with fields:
      Name, Enabled (bool), LastLogon (datetime or empty), PasswordExpired, PasswordRequired, PasswordChangeableDate
    """
    ps_cmd = (
        "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordExpires,PasswordRequired,FullName,Description"
    )
    data = _ps_json(ps_cmd)
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    # Convert LastLogon strings to iso or None (PowerShell returns .NET DateTime)
    for item in data:
        if item.get("LastLogon") in (None, ""):
            item["LastLogonIso"] = None
        else:
            # PowerShell JSON gives ISO-like string; keep as-is but normalize
            item["LastLogonIso"] = item.get("LastLogon")
    return data


def get_disabled_guest_accounts() -> List[Dict[str, Any]]:
    """
    Returns list of accounts that are disabled and whether they look like a Guest account.
    Includes a small heuristic for built-in Guest account (name 'Guest' or description).
    """
    users = get_local_users()
    disabled = []
    for u in users:
        if not u.get("Enabled", True):
            is_guest_like = False
            uname = (u.get("Name") or "").lower()
            desc = (u.get("Description") or "").lower()
            if "guest" in uname or "guest" in desc:
                is_guest_like = True
            disabled.append({"Name": u.get("Name"), "Enabled": u.get("Enabled"), "IsGuestLike": is_guest_like, **u})
    return disabled


def get_password_policy() -> Dict[str, Optional[Any]]:
    """
    Attempts to extract local password/account policy using `net accounts` (works for local SAM).
    Returns fields like MinimumPasswordAgeDays, MaximumPasswordAgeDays, MinimumPasswordLength,
    LockoutThreshold, LockoutDurationMinutes, LockoutObservationWindowMinutes, PasswordComplexity (best-effort).
    For Group Policy-managed workstations or AD domains, this may not reflect effective policy.
    """
    out = _run_powershell("net accounts")
    # Example lines in 'net accounts' output:
    # Minimum password age (days): 0
    # Maximum password age (days): 42
    # Minimum password length: 7
    # Lockout threshold: 0
    # Lockout duration (minutes): 30
    # Lockout observation window (minutes): 30
    policy = {
        "MinimumPasswordAgeDays": None,
        "MaximumPasswordAgeDays": None,
        "MinimumPasswordLength": None,
        "LockoutThreshold": None,
        "LockoutDurationMinutes": None,
        "LockoutObservationWindowMinutes": None,
        "PasswordComplexity": None,  # best-effort - check local security policy
    }
    for line in out.splitlines():
        if ":" not in line:
            continue
        k, v = [s.strip() for s in line.split(":", 1)]
        lk = k.lower()
        try:
            if "minimum password age" in lk:
                policy["MinimumPasswordAgeDays"] = int(v.split()[0])
            elif "maximum password age" in lk:
                policy["MaximumPasswordAgeDays"] = int(v.split()[0])
            elif "minimum password length" in lk:
                policy["MinimumPasswordLength"] = int(v.split()[0])
            elif "lockout threshold" in lk:
                # can be '0' meaning disabled
                policy["LockoutThreshold"] = int(v.split()[0])
            elif "lockout duration" in lk:
                policy["LockoutDurationMinutes"] = int(v.split()[0])
            elif "lockout observation window" in lk:
                policy["LockoutObservationWindowMinutes"] = int(v.split()[0])
        except ValueError:
            continue

    # Try to check local security policy (PasswordComplexity) via secedit export (best-effort)
    try:
        sec = _run_powershell('secedit /export /cfg $env:temp\\secpol.cfg > $null ; Get-Content $env:temp\\secpol.cfg | ConvertTo-Json -Depth 1')
        # parse lines instead of JSON for reliability
        cfg = _run_powershell('secedit /export /cfg $env:temp\\secpol.cfg > $null ; Get-Content $env:temp\\secpol.cfg')
        for line in cfg.splitlines():
            if line.strip().startswith("PasswordComplexity"):
                _, val = line.split("=", 1)
                policy["PasswordComplexity"] = bool(int(val.strip()))
            if line.strip().startswith("MinimumPasswordLength"):
                try:
                    policy["MinimumPasswordLength"] = int(line.split("=", 1)[1].strip())
                except:
                    pass
    except Exception:
        # failing this is non-fatal; leave PasswordComplexity as None
        pass

    return policy


def check_windows_hello() -> Dict[str, Any]:
    """
    Best-effort check for Windows Hello / PIN presence on the machine.
    Returns a dictionary describing possible Windows Hello/NGC artifacts.
    NOTE: this is NOT a definitive check for MFA. True MFA (e.g., Azure AD MFA) requires
    querying Azure AD/Intune or domain controllers and cannot be fully determined locally.
    """
    result = {"NgcExists": False, "NgcPathAccessible": False, "WindowsHelloForBusinessPolicy": None, "Note": None}
    try:
        # Check for NGC folder existence (Windows Hello credential store)
        ps_check_ngc = 'Test-Path "$env:ProgramData\\Microsoft\\Ngc"'
        out = _run_powershell(ps_check_ngc)
        result["NgcExists"] = out.strip().lower() == "true"
        # Try listing Ngc folder (may require admin)
        if result["NgcExists"]:
            try:
                _ = _run_powershell('Get-ChildItem -Path "$env:ProgramData\\Microsoft\\Ngc" -ErrorAction Stop | Select-Object Name | ConvertTo-Json -Depth 2')
                result["NgcPathAccessible"] = True
            except Exception:
                result["NgcPathAccessible"] = False
        # Check for Hello for Business policy presence (local)
        try:
            pol = _run_powershell("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\PassportForWork' -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 2")
            if pol:
                result["WindowsHelloForBusinessPolicy"] = True
        except Exception:
            result["WindowsHelloForBusinessPolicy"] = None
        result["Note"] = "Presence of Ngc folder or PassportForWork keys suggests Windows Hello/PIN may be configured. This does not prove MFA."
    except Exception as e:
        result["Note"] = f"Error checking Windows Hello: {e}"
    return result


def get_idle_accounts(threshold_days: int = 90) -> List[Dict[str, Any]]:
    """
    Returns list of users with their last logon and computed idle days.
    threshold_days: only return accounts idle >= threshold_days (if <0 returns all).
    """
    users = get_local_users()
    res = []
    now = datetime.datetime.utcnow()
    for u in users:
        last_iso = u.get("LastLogonIso")
        if not last_iso:
            idle_days = None
            last_dt = None
        else:
            # PowerShell usually returns 'YYYY-MM-DDTHH:MM:SS' or similar; try parsing
            try:
                # attempt to parse a few formats
                last_dt = datetime.datetime.fromisoformat(last_iso)
                # convert to UTC if tz-aware
                if last_dt.tzinfo is not None:
                    last_dt = last_dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
                idle_days = (now - last_dt).days
            except Exception:
                last_dt = None
                idle_days = None
        entry = {
            "Name": u.get("Name"),
            "Enabled": u.get("Enabled"),
            "LastLogonIso": last_iso,
            "LastLogonParsed": last_dt.isoformat() if last_dt else None,
            "IdleDays": idle_days,
        }
        if threshold_days < 0 or (idle_days is not None and idle_days >= threshold_days) or (idle_days is None and threshold_days <= 0):
            res.append(entry)
    return res


if __name__ == "__main__":
    # quick CLI demo if run directly
    print("Local Administrators:")
    try:
        admins = get_local_admins()
        print(json.dumps(admins, indent=2, default=str))
    except Exception as e:
        print("Error:", e)

    print("\nDisabled/Guest-like accounts:")
    try:
        dis = get_disabled_guest_accounts()
        print(json.dumps(dis, indent=2, default=str))
    except Exception as e:
        print("Error:", e)

    print("\nPassword policy (net accounts / secedit):")
    try:
        pol = get_password_policy()
        print(json.dumps(pol, indent=2, default=str))
    except Exception as e:
        print("Error:", e)

    print("\nWindows Hello best-effort check:")
    try:
        wh = check_windows_hello()
        print(json.dumps(wh, indent=2, default=str))
    except Exception as e:
        print("Error:", e)

    print("\nIdle accounts (>=90 days):")
    try:
        idle = get_idle_accounts(90)
        print(json.dumps(idle, indent=2, default=str))
    except Exception as e:
        print("Error:", e)
