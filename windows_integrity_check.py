"""
windows_integrity_check.py

Windows system integrity and core security feature checks via PowerShell.
Focuses on Configuration Management (ISO 27001 A 8.22) and advanced integrity protection.
Requires: Windows (PowerShell available). Admin privileges are often required.

Usage:
    import windows_integrity_check as wic
    integrity = wic.get_system_integrity_status()
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
        # Return stderr for debugging
        raise RuntimeError(f"PowerShell error: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def get_uac_status() -> Dict[str, Any]:
    """
    Checks the status and security level of User Account Control (UAC).
    Key: HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System 
    """
    result = {"UAC_Status": "Error", "ConsentLevel": None}
    try:
        # EnableLUA (1=Enabled)
        lua = _run_powershell(r'(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA')
        result["UAC_Enabled"] = (lua.strip() == "1")

        # ConsentPromptBehaviorAdmin (2=Secure Desktop, 5=Secure Desktop + Prompt for Consent)
        # Recommended secure value is 5.
        consent = _run_powershell(r'(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").ConsentPromptBehaviorAdmin')
        result["ConsentLevel"] = int(consent.strip()) if consent.strip().isdigit() else consent.strip()
        result["ConsentLevel_Recommendation"] = "Level 5 (Prompt for consent on the secure desktop)"
    except Exception as e:
        result["UAC_Error"] = str(e)

    result["UAC_Status"] = "Enabled/Secure" if result.get("UAC_Enabled") and result.get("ConsentLevel") == 5 else "Needs Review"
    return result


def get_credential_guard_status() -> Dict[str, Any]:
    """
    Checks the status of Credential Guard (a VBS-based security feature).
    Key: HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa 
    
    FIX: The PowerShell command is structured to use Test-Path before property access
    to avoid the "-ErrorAction" unexpected token error on potentially missing properties/keys.
    """
    result = {"CredentialGuardEnabled": False, "VBS_Status": "Unknown"}
    try:
        # LSA key: RunAsPPL (1=Enabled, 3=Enabled with UEFI Lock)
        lsa_cmd = r"""
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        if (Test-Path $path) {
            # Safely get the property; if it doesn't exist, this returns nothing (empty string).
            (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).LsaCfgFlags
        } else {
            ""
        }
        """
        lsa = _run_powershell(lsa_cmd)
        if lsa.strip() in ("1", "3"):
            result["CredentialGuardEnabled"] = True

        # Check VBS status (required for Credential Guard)
        vbs = _run_powershell(r"""
        try {
            # Use Stop to ensure an error is thrown if the class is unavailable (older OS/no VBS support)
            $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
            # SecurityServicesRunning[1] = Credential Guard
            # SecurityServicesConfigured[1] = Credential Guard
            if ($vbs.SecurityServicesRunning -contains 1) {
                "Running"
            } elseif ($vbs.SecurityServicesConfigured -contains 1) {
                "Configured"
            } else {
                "Disabled"
            }
        } catch {
            "NotAvailable/Error"
        }
        """)
        result["VBS_Status"] = vbs.strip()
    except Exception as e:
        result["Error"] = str(e)

    return result


def get_device_guard_status() -> Dict[str, Any]:
    """
    Checks Device Guard/WDAC (Windows Defender Application Control) status.
    Uses registry keys related to Code Integrity.
    
    FIX: The PowerShell command is restructured to use Test-Path before property access
    to avoid the "-ErrorAction" unexpected token error on potentially missing properties/keys.
    """
    result = {"WDAC_Enabled": "Unknown", "HVCI_Enabled": "Unknown"}
    try:
        # Check Hypervisor-protected Code Integrity (HVCI)
        hvci_cmd = r"""
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        if (Test-Path $path) {
            # Safely get the property; if it doesn't exist, this returns nothing (empty string).
            # The .Enabled value of 1 means enabled.
            (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Enabled
        } else {
            ""
        }
        """
        hvci = _run_powershell(hvci_cmd)
        result["HVCI_Enabled"] = (hvci.strip() == "1")

        # Check for WDAC Policy (Presence of one policy is usually sufficient)
        wdac = _run_powershell(r"""
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Policies"
        if (Test-Path $path) {
            $policies = Get-ChildItem $path
            if ($policies.Count -gt 0) { "PolicyPresent" }
            else { "NoPolicy" }
        } else {
            "NotConfigured"
        }
        """)
        result["WDAC_Enabled"] = wdac.strip()
    except Exception as e:
        result["Error"] = str(e)

    return result


def get_system_integrity_status() -> Dict[str, Any]:
    """
    Combines all system integrity checks.
    """
    return {
        "UAC_Check": get_uac_status(),
        "CredentialGuard_Check": get_credential_guard_status(),
        "DeviceGuard_WDAC_Check": get_device_guard_status(),
    }


if __name__ == "__main__":
    print("Windows System Integrity and Configuration Status:")
    # Use sort_keys=False to keep the output order consistent
    print(json.dumps(get_system_integrity_status(), indent=2, sort_keys=False))