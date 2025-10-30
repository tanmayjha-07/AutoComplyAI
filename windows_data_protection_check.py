"""
windows_data_protection_check.py

Windows data protection, encryption, and DLP checks via PowerShell.
Focuses on Cryptographic Controls (ISO 27001 A 8.24) and Data Leakage (A 8.23).
Requires: Windows (PowerShell available). Admin privileges are often required.

Usage:
    import windows_data_protection_check as wdpc
    data_protection = wdpc.get_data_protection_status()
"""

import subprocess
import json
from typing import Dict, Any


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
        # Note: If PowerShell returns a single object, json.loads returns a dict, 
        # not a list of one dict. This needs handling by the caller.
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def check_bitlocker_status() -> Dict[str, Any]:
    """
    Checks BitLocker status for all fixed data volumes.
    FIX: Corrected logic to check numeric ProtectionStatus codes.
    ProtectionStatus codes: 0=Off, 1=Locked, 2=On (Protected)
    """
    ps_cmd = "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage"
    try:
        data = _ps_json(ps_cmd)
        if isinstance(data, dict):
            # Convert single dictionary object to a list for consistent processing
            data = [data]
            
        non_compliant_volumes = []

        for v in (data or []):
            mount_point = v.get("MountPoint")
            protection_status = v.get("ProtectionStatus")
            
            # We ignore system/recovery partitions (which typically have no MountPoint)
            if not mount_point:
                continue
            
            # Check Compliance: ProtectionStatus MUST be 2 (Protection On)
            # VolumeStatus 4 (Fully Encrypted) is ideal, but ProtectionStatus 2 is the key
            # security state for enforcement.
            if protection_status != 2: 
                non_compliant_volumes.append(mount_point)

        return {
            "VolumeStatus": data or [],
            "OverallStatus": "Compliant" if not non_compliant_volumes else "Non-Compliant",
            "NonCompliantVolumes": non_compliant_volumes
        }
    except Exception as e:
        return {"Error": f"BitLocker check failed: {str(e)}"}


def check_credential_protection() -> Dict[str, Any]:
    """
    Checks the status of Credential Guard (LsaCfgFlags) and LSA protection (LsaProtection).
    FIX: Interprets missing or zero LsaProtection value as "Disabled".
    """
    results = {"CredentialGuardEnabled": False, "LsaProtectionMode": "Unknown"}
    
    # 1. Credential Guard Status (LsaCfgFlags)
    try:
        # Key: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
        # RunAsPPL (1=Enabled, 3=Enabled with UEFI Lock)
        lsa_cfg = _run_powershell(r'(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LsaCfgFlags')
        if lsa_cfg.strip() in ("1", "3"):
            results["CredentialGuardEnabled"] = True
    except Exception:
        pass

    # 2. LSA Protection (AuditMode for LSA process protection)
    try:
        # Key: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
        lsa_audit = _run_powershell(r'(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LsaProtection')
        
        lsa_status = lsa_audit.strip()
        
        if lsa_status == "1":
            results["LsaProtectionMode"] = "Enabled"
        # FIX: Treat 0 or empty/missing value as Disabled
        elif lsa_status == "0" or not lsa_status:
            results["LsaProtectionMode"] = "Disabled"
        else:
            results["LsaProtectionMode"] = "Unknown"
        
    except Exception:
        results["LsaProtectionMode"] = "Error"
        
    return results


def check_dlp_agent_presence() -> Dict[str, Any]:
    """
    Best-effort check for common DLP agent services/processes.
    This check is highly dependent on the DLP vendor used.
    """
    # Common process names or service names for generic DLP (e.g., Symantec, McAfee, Microsoft Purview)
    
    found_indicators = []
    
    # Check running services for DLP-related names
    try:
        # NOTE: Regex is escaped for PowerShell match operator
        service_cmd = r"""
        Get-Service | Where-Object { $_.Name -match 'dlp|data loss|symantecd|mcafeeagent|mdeclient|purview' } | 
        Select-Object Name,Status
        """
        services = _ps_json(service_cmd)
        if isinstance(services, dict):
             services = [services]
        
        for s in services or []:
            if s.get("Status") == "Running":
                found_indicators.append(f"Service: {s.get('Name')}")
    except Exception:
        pass
        
    # Check running processes (less reliable as processes can be renamed)
    try:
        process_cmd = r"""
        Get-Process | Where-Object { $_.ProcessName -match 'dlp|symantecd|mcafeeagent|mdeclient' } | 
        Select-Object ProcessName,Id
        """
        processes = _ps_json(process_cmd)
        if isinstance(processes, dict):
            processes = [processes]
            
        for p in processes or []:
            found_indicators.append(f"Process: {p.get('ProcessName')}")
    except Exception:
        pass
        
    status = "Present" if found_indicators else "Not Found"
    
    return {
        "DlpAgentStatus": status,
        "DlpIndicatorsFound": found_indicators,
        "Note": "This is a best-effort check and must be confirmed against organizational policy."
    }


def get_data_protection_status() -> Dict[str, Any]:
    """
    Combines all data protection checks.
    """
    return {
        "BitLocker_DiskEncryption": check_bitlocker_status(),
        "Credential_Protection": check_credential_protection(),
        "DLP_Agent_Presence": check_dlp_agent_presence(),
    }


if __name__ == "__main__":
    print("Windows Data Protection and DLP Status:")
    print(json.dumps(get_data_protection_status(), indent=2, sort_keys=False))