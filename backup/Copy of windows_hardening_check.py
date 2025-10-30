"""
windows_hardening_check.py

Windows system-hardening checks via PowerShell.
Requires: Windows (PowerShell available). Some checks require admin privileges.

Usage:
    import windows_hardening_check as whc
    fw = whc.check_firewall()
    rdp = whc.check_rdp_status()
    bitlocker = whc.check_bitlocker()
    sb = whc.check_secure_boot()
    insecure = whc.check_insecure_services()
"""

import subprocess
import json
from typing import Dict, Any, List


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


def _ps_json(cmd_without_convert: str):
    """Run PowerShell command, convert to JSON, return as Python object."""
    ps = f"{cmd_without_convert} | ConvertTo-Json -Depth 6"
    out = _run_powershell(ps)
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


# 1. Firewall enabled (all profiles)
def check_firewall() -> Dict[str, Any]:
    """
    Checks firewall state for all profiles.
    Returns dict with Domain, Private, Public profile states.
    """
    ps_cmd = "Get-NetFirewallProfile | Select-Object Name,Enabled"
    data = _ps_json(ps_cmd)
    if isinstance(data, dict):
        data = [data]
    profiles = {}
    if data:
        for p in data:
            profiles[p["Name"]] = bool(p["Enabled"])
    return {"FirewallProfiles": profiles}


# 2. RDP enabled/disabled
def check_rdp_status() -> Dict[str, Any]:
    """
    Checks if RDP (Remote Desktop) is enabled.
    Returns dict with RDP status and Network Level Authentication enforcement.
    """
    result = {"RDPEnabled": None, "NLARequired": None}
    try:
        rdp = _run_powershell('(Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server").fDenyTSConnections')
        result["RDPEnabled"] = (rdp.strip() == "0")  # 0 means RDP allowed
    except Exception:
        pass

    try:
        nla = _run_powershell('(Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp").UserAuthentication')
        result["NLARequired"] = (nla.strip() == "1")
    except Exception:
        pass

    return result


# 3. BitLocker status
def check_bitlocker() -> Dict[str, Any]:
    """
    Checks BitLocker status for all drives.
    Returns dict with Volume, ProtectionStatus, EncryptionPercentage, LockStatus.
    """
    ps_cmd = "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,LockStatus"
    try:
        data = _ps_json(ps_cmd)
    except Exception as e:
        return {"Error": str(e)}

    if isinstance(data, dict):
        data = [data]
    return {"BitLockerVolumes": data or []}


# 4. Secure Boot enabled
def check_secure_boot() -> Dict[str, Any]:
    """
    Checks if Secure Boot is enabled (UEFI only).
    Returns dict with SecureBootEnabled status.
    """
    try:
        sb = _run_powershell('Confirm-SecureBootUEFI')
        return {"SecureBootEnabled": sb.strip().lower() == "true"}
    except Exception as e:
        return {"SecureBootEnabled": None, "Error": str(e)}


# 5. Insecure services disabled (Telnet, SMBv1, etc.)
def check_insecure_services() -> Dict[str, Any]:
    """
    Check if insecure services (Telnet, SMBv1) are disabled/not present.
    """
    results = {}

    # Telnet
    try:
        telnet_status = _run_powershell(r"""
        if (Get-Service -Name Telnet -ErrorAction SilentlyContinue) {
            (Get-Service -Name Telnet).Status
        } else {
            "NotInstalled"
        }
        """)
        results["TelnetService"] = telnet_status
    except Exception as e:
        results["TelnetService"] = f"Error: {e}"

    # SMBv1
    try:
        smb_status = _run_powershell(r"""
        Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State
        """)
        results["SMBv1"] = "Disabled" if "Disabled" in smb_status else smb_status
    except Exception as e:
        results["SMBv1"] = f"Error: {e}"

    return results


if __name__ == "__main__":
    print("Firewall status:")
    print(json.dumps(check_firewall(), indent=2))

    print("\nRDP status:")
    print(json.dumps(check_rdp_status(), indent=2))

    print("\nBitLocker status:")
    print(json.dumps(check_bitlocker(), indent=2))

    print("\nSecure Boot:")
    print(json.dumps(check_secure_boot(), indent=2))

    print("\nInsecure services:")
    print(json.dumps(check_insecure_services(), indent=2))
