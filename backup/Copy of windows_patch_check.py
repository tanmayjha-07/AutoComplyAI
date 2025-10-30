"""
windows_patch_check.py

Windows patching & update compliance checks via PowerShell + Winget.
Requires: Windows (PowerShell available). Some checks may require admin privileges.
For application updates, Winget must be installed.

Usage:
    import windows_patch_check as wpc
    version = wpc.get_os_version()
    last_update = wpc.get_last_update_date()
    pending = wpc.get_pending_updates()
    apps = wpc.get_app_updates()
    support = wpc.check_os_support()
    all_status = wpc.get_patch_status()
"""

import subprocess
import json
import platform
from typing import Dict, Any, Union, List


def _run_powershell(ps_cmd: str) -> str:
    """Run a PowerShell command and return stdout (text)."""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"PowerShell error: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def _ps_json(cmd: str):
    """
    Run a PowerShell command and return JSON-decoded output.
    If the command already contains ConvertTo-Json, don't add another one.
    """
    ps = cmd if "ConvertTo-Json" in cmd else f"{cmd} | ConvertTo-Json -Depth 6"
    out = _run_powershell(ps)
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


# 1. OS version & build
def get_os_version() -> Dict[str, Any]:
    try:
        data = _ps_json(
            "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture"
        )
        return data
    except Exception:
        return {
            "ProductName": platform.system(),
            "Version": platform.version(),
            "Release": platform.release(),
        }


# 2. Last update installed date
def get_last_update_date() -> Dict[str, Any]:
    try:
        updates = _ps_json("Get-HotFix | Select-Object HotFixID,Description,InstalledOn")
        if isinstance(updates, dict):
            updates = [updates]
        if not updates:
            return {"LastUpdate": None}
        for u in updates:
            try:
                u["InstalledOn"] = str(u.get("InstalledOn"))
            except Exception:
                pass
        sorted_updates = sorted(
            updates,
            key=lambda x: x.get("InstalledOn") or "",
            reverse=True,
        )
        return {"LastUpdate": sorted_updates[0]}
    except Exception as e:
        return {"Error": str(e)}


# 3. Pending Windows Updates
def get_pending_updates() -> Dict[str, Any]:
    result = {}
    try:
        ps_cmd = r"""
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0 and Type='Software'")
        $updates = @()
        foreach ($u in $result.Updates) {
            $updates += [PSCustomObject]@{
                Title        = $u.Title
                KBArticleIDs = $u.KBArticleIDs -join ","
                IsInstalled  = $u.IsInstalled
                IsHidden     = $u.IsHidden
            }
        }
        if ($updates.Count -eq 0) {
            $updates = @()
        }
        $updates | ConvertTo-Json -Depth 6
        """
        data = _ps_json(ps_cmd)
        if data is None:
            result["PendingUpdates"] = []
        elif isinstance(data, dict):
            result["PendingUpdates"] = [data]
        else:
            result["PendingUpdates"] = data
    except Exception as e:
        result["Error"] = f"Failed to query updates: {e}"
    return result


# 4. Application updates via Winget
def get_app_updates() -> Union[List[Dict[str, Any]], Dict[str, str]]:
    try:
        result = subprocess.run(
            ["winget", "upgrade", "--accept-source-agreements", "--accept-package-agreements"],
            capture_output=True, text=True, encoding="utf-8"
        )
        if result.returncode != 0:
            return {"Error": f"Winget not available or failed: {result.stderr.strip()}"}

        lines = result.stdout.splitlines()
        updates = []
        parsing = False

        for line in lines:
            if line.strip().startswith("Name") and "Available" in line:
                parsing = True
                continue
            if parsing and line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    name = " ".join(parts[:-2])
                    current = parts[-2]
                    available = parts[-1]
                    updates.append({
                        "App": name,
                        "CurrentVersion": current,
                        "AvailableVersion": available
                    })
        return updates if updates else {"Message": "No application updates found."}
    except Exception as e:
        return {"Error": str(e)}


# 5. Unsupported versions blocked
def check_os_support() -> Dict[str, Any]:
    os_info = get_os_version()
    product = os_info.get("WindowsProductName") or os_info.get("ProductName", "")
    build = str(os_info.get("OsBuildNumber") or os_info.get("Release", ""))

    unsupported = False
    reason = None

    try:
        if "Windows 7" in product or "Windows 8" in product:
            unsupported = True
            reason = "Windows 7/8 are out of support."
        elif "Windows 10" in product:
            try:
                build_int = int(build)
                if build_int < 19045:
                    unsupported = True
                    reason = f"Windows 10 build {build} is out of support. Need 22H2 (19045+)."
            except Exception:
                pass
        elif "Windows 11" in product:
            try:
                build_int = int(build)
                if build_int < 22621:
                    unsupported = True
                    reason = f"Windows 11 build {build} is older than 22H2 (22621+)."
            except Exception:
                pass
    except Exception:
        pass

    return {"OS": product, "Build": build, "Unsupported": unsupported, "Reason": reason}


# 6. Combined status
def get_patch_status() -> Dict[str, Any]:
    return {
        "OSVersion": get_os_version(),
        "LastUpdate": get_last_update_date(),
        "WindowsUpdates": get_pending_updates(),
        "ApplicationUpdates": get_app_updates(),
        "SupportStatus": check_os_support()
    }


if __name__ == "__main__":
    print("Patch status:")
    print(json.dumps(get_patch_status(), indent=2))
