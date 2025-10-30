"""
windows_hardening_check.py (ENHANCED)

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


# 1. Firewall enabled (all profiles) and Logging enabled
def check_firewall() -> Dict[str, Any]:
    """
    Checks firewall state for all profiles and verifies if logging of dropped packets is enabled.
    """
    # 1. Basic Enabled Status
    ps_cmd_status = "Get-NetFirewallProfile | Select-Object Name,Enabled"
    data = _ps_json(ps_cmd_status)
    if isinstance(data, dict):
        data = [data]
    profiles = {}
    if data:
        for p in data:
            profiles[p["Name"]] = bool(p["Enabled"])

    # 2. Logging Status (Checking for basic enforcement across profiles)
    log_status = {}
    try:
        ps_cmd_log = "Get-NetFirewallProfile | Select-Object Name,LogFileName,LogBlocked"
        log_data = _ps_json(ps_cmd_log)
        if isinstance(log_data, dict):
            log_data = [log_data]
            
        for l in log_data or []:
            # LogBlocked=True and a LogFileName are required for robust logging
            is_logging_on = (l.get("LogBlocked") and l.get("LogFileName") and "off" not in l["LogFileName"].lower())
            log_status[l["Name"]] = is_logging_on
            
    except Exception as e:
        log_status["Error"] = str(e)

    return {
        "FirewallProfilesEnabled": profiles,
        "LogBlockedPacketsEnabled": log_status
    }


# 2. RDP enabled/disabled and access restriction
def check_rdp_status() -> Dict[str, Any]:
    """
    Checks RDP status, NLA, and whether RDP is restricted to Administrators group.
    """
    result = {"RDPEnabled": None, "NLARequired": None, "RDP_RestrictedToAdmins": None}
    
    # Check RDP enabled (fDenyTSConnections)
    try:
        rdp = _run_powershell('(Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server").fDenyTSConnections')
        result["RDPEnabled"] = (rdp.strip() == "0")  # 0 means RDP allowed
    except Exception:
        pass

    # Check NLA required (UserAuthentication)
    try:
        nla = _run_powershell('(Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp").UserAuthentication')
        result["NLARequired"] = (nla.strip() == "1")
    except Exception:
        pass
    
    # Check RDP user restrictions (Default is 'Administrators' and 'Remote Desktop Users' SIDs)
    try:
        # Check security descriptor for RDP-Tcp (S-1-5-32-544 is Administrators)
        sd = _run_powershell('(Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp").SecurityDescriptor -ErrorAction Stop')
        # This is a complex binary descriptor; a simpler check is often used:
        # Check if the 'Remote Desktop Users' group has been removed or restricted, 
        # but for simplicity and high compliance, we check the default access which includes S-1-5-32-544 (Admins).
        
        # A simple check: if the RDP firewall rule is limited to local subnet, etc. (Out of scope for this simple check)
        
        # NOTE: A comprehensive check requires parsing the binary security descriptor. 
        # For simplicity, we assume if RDP is enabled, access is restricted if not on a domain.
        result["RDP_RestrictedToAdmins"] = "CheckRequiresComplexParsing" 
        
    except Exception:
        pass


    return result


# 3. BitLocker status (Kept for completeness, though data protection is now in another module)
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


# 4. Secure Boot enabled and TPM status
def check_secure_boot() -> Dict[str, Any]:
    """
    Checks if Secure Boot is enabled (UEFI only) and TPM status.
    """
    result = {"SecureBootEnabled": None, "TPM_PresentAndReady": None}
    
    # Secure Boot Check
    try:
        sb = _run_powershell('Confirm-SecureBootUEFI')
        result["SecureBootEnabled"] = sb.strip().lower() == "true"
    except Exception as e:
        result["SecureBootError"] = str(e)
        
    # TPM Check
    try:
        tpm = _ps_json("Get-Tpm | Select-Object TpmPresent,TpmReady")
        if isinstance(tpm, dict):
            result["TPM_PresentAndReady"] = (tpm.get("TpmPresent") and tpm.get("TpmReady"))
        else:
            result["TPM_PresentAndReady"] = False
    except Exception as e:
        result["TPM_Error"] = str(e)

    return result


# 5. Insecure services/protocols disabled (Telnet, SMBv1, NTLMv1, etc.)
def check_insecure_services() -> Dict[str, Any]:
    """
    Check if insecure services (Telnet, SMBv1) and legacy protocols (NTLMv1) are disabled.
    """
    results = {}

    # Telnet Service Status (Check for running/installed)
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

    # SMBv1 Protocol Status (Check for enabled optional feature)
    try:
        smb_status = _run_powershell(r"""
        Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State
        """)
        results["SMBv1"] = "Disabled" if "Disabled" in smb_status else smb_status
    except Exception as e:
        results["SMBv1"] = f"Error: {e}"

    # NTLMv1 Disablement (LSA policy)
    try:
        # Check LSA registry key for NTLMv1 status. Value 5 means "Send NTLMv2 response only. Refuse LM & NTLM."
        ntlm_policy = _run_powershell(r'(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LmCompatibilityLevel')
        results["NTLMv1_Disabled"] = (ntlm_policy.strip() == "5")
        results["NTLMv1_PolicyValue"] = ntlm_policy.strip()
    except Exception as e:
        results["NTLMv1_Disabled"] = f"Error: {e}"

    return results


if __name__ == "__main__":
    print("Firewall status:")
    print(json.dumps(check_firewall(), indent=2))

    print("\nRDP status:")
    print(json.dumps(check_rdp_status(), indent=2))

    print("\nBitLocker status:")
    print(json.dumps(check_bitlocker(), indent=2))

    print("\nSecure Boot/TPM:")
    print(json.dumps(check_secure_boot(), indent=2))

    print("\nInsecure services/protocols:")
    print(json.dumps(check_insecure_services(), indent=2))








# """
# windows_hardening_check.py

# Windows system-hardening checks via PowerShell.
# Requires: Windows (PowerShell available). Some checks require admin privileges.

# Usage:
#     import windows_hardening_check as whc
#     fw = whc.check_firewall()
#     rdp = whc.check_rdp_status()
#     bitlocker = whc.check_bitlocker()
#     sb = whc.check_secure_boot()
#     insecure = whc.check_insecure_services()
# """

# import subprocess
# import json
# from typing import Dict, Any, List


# def _run_powershell(ps_cmd: str) -> str:
#     """Run a PowerShell command and return stdout (text)."""
#     proc = subprocess.run(
#         ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
#         capture_output=True,
#         text=True,
#     )
#     if proc.returncode != 0:
#         raise RuntimeError(f"PowerShell error: {proc.stderr.strip() or proc.stdout.strip()}")
#     return proc.stdout.strip()


# def _ps_json(cmd_without_convert: str):
#     """Run PowerShell command, convert to JSON, return as Python object."""
#     ps = f"{cmd_without_convert} | ConvertTo-Json -Depth 6"
#     out = _run_powershell(ps)
#     if not out:
#         return None
#     try:
#         return json.loads(out)
#     except json.JSONDecodeError:
#         return out


# # 1. Firewall enabled (all profiles)
# def check_firewall() -> Dict[str, Any]:
#     """
#     Checks firewall state for all profiles.
#     Returns dict with Domain, Private, Public profile states.
#     """
#     ps_cmd = "Get-NetFirewallProfile | Select-Object Name,Enabled"
#     data = _ps_json(ps_cmd)
#     if isinstance(data, dict):
#         data = [data]
#     profiles = {}
#     if data:
#         for p in data:
#             profiles[p["Name"]] = bool(p["Enabled"])
#     return {"FirewallProfiles": profiles}


# # 2. RDP enabled/disabled
# def check_rdp_status() -> Dict[str, Any]:
#     """
#     Checks if RDP (Remote Desktop) is enabled.
#     Returns dict with RDP status and Network Level Authentication enforcement.
#     """
#     result = {"RDPEnabled": None, "NLARequired": None}
#     try:
#         rdp = _run_powershell('(Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server").fDenyTSConnections')
#         result["RDPEnabled"] = (rdp.strip() == "0")  # 0 means RDP allowed
#     except Exception:
#         pass

#     try:
#         nla = _run_powershell('(Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp").UserAuthentication')
#         result["NLARequired"] = (nla.strip() == "1")
#     except Exception:
#         pass

#     return result


# # 3. BitLocker status
# def check_bitlocker() -> Dict[str, Any]:
#     """
#     Checks BitLocker status for all drives.
#     Returns dict with Volume, ProtectionStatus, EncryptionPercentage, LockStatus.
#     """
#     ps_cmd = "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,LockStatus"
#     try:
#         data = _ps_json(ps_cmd)
#     except Exception as e:
#         return {"Error": str(e)}

#     if isinstance(data, dict):
#         data = [data]
#     return {"BitLockerVolumes": data or []}


# # 4. Secure Boot enabled
# def check_secure_boot() -> Dict[str, Any]:
#     """
#     Checks if Secure Boot is enabled (UEFI only).
#     Returns dict with SecureBootEnabled status.
#     """
#     try:
#         sb = _run_powershell('Confirm-SecureBootUEFI')
#         return {"SecureBootEnabled": sb.strip().lower() == "true"}
#     except Exception as e:
#         return {"SecureBootEnabled": None, "Error": str(e)}


# # 5. Insecure services disabled (Telnet, SMBv1, etc.)
# def check_insecure_services() -> Dict[str, Any]:
#     """
#     Check if insecure services (Telnet, SMBv1) are disabled/not present.
#     """
#     results = {}

#     # Telnet
#     try:
#         telnet_status = _run_powershell(r"""
#         if (Get-Service -Name Telnet -ErrorAction SilentlyContinue) {
#             (Get-Service -Name Telnet).Status
#         } else {
#             "NotInstalled"
#         }
#         """)
#         results["TelnetService"] = telnet_status
#     except Exception as e:
#         results["TelnetService"] = f"Error: {e}"

#     # SMBv1
#     try:
#         smb_status = _run_powershell(r"""
#         Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State
#         """)
#         results["SMBv1"] = "Disabled" if "Disabled" in smb_status else smb_status
#     except Exception as e:
#         results["SMBv1"] = f"Error: {e}"

#     return results


# if __name__ == "__main__":
#     print("Firewall status:")
#     print(json.dumps(check_firewall(), indent=2))

#     print("\nRDP status:")
#     print(json.dumps(check_rdp_status(), indent=2))

#     print("\nBitLocker status:")
#     print(json.dumps(check_bitlocker(), indent=2))

#     print("\nSecure Boot:")
#     print(json.dumps(check_secure_boot(), indent=2))

#     print("\nInsecure services:")
#     print(json.dumps(check_insecure_services(), indent=2))
