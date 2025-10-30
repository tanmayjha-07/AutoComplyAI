"""
windows_gdpr_check.py (COMPLETE MODULAR DESIGN)

Dedicated GDPR compliance module. Calls functions from ALL supportive security modules 
(data_protection, audit_config, user_rights) to build a holistic GDPR technical report.
"""

import subprocess
import json
from typing import Dict, Any

# =========================================================================================
# 💡 ACTION REQUIRED 1: ADD YOUR IMPORT STATEMENTS HERE
# In your actual environment, you must uncomment and use these lines:
import windows_data_protection_check as wdpc
import windows_audit_config_check as wacc
import windows_user_rights_check as wurc
# =========================================================================================

# --- HELPER FUNCTIONS (KEEP THESE) ---

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


# --- UNIQUE GDPR CHECK (Privacy by Design/Data Minimization - Art. 25) ---

def check_data_sharing_controls_gdpr() -> Dict[str, Any]:
    """
    Checks for configurations that permit easy, unnecessary local data sharing (Art. 25).
    (This logic must remain here as it is unique to GDPR/Privacy checks.)
    """
    results = {}
    
    # Check for Public Folder sharing enabled
    try:
        public_sharing = _run_powershell(r"""
        (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache").EnablePublicSharing
        """)
        results["PublicFolderSharingDisabled"] = (public_sharing.strip() == "0")
    except Exception:
        results["PublicFolderSharingDisabled"] = "Error/NotConfigured"
        
    # Check if remote access to local SAM/Registry is restricted
    try:
        remote_sam = _run_powershell(r"""
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").RestrictRemoteSam
        """)
        results["RestrictRemoteSamAccess"] = (remote_sam.strip() == "1")
    except Exception:
        results["RestrictRemoteSamAccess"] = "Error/NotConfigured"
        
    # Check for Anonymous/Guest access to shares
    try:
        anon_access = _run_powershell(r"""
        (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").RestrictNullSessionAccess
        """)
        results["RestrictNullSessionAccess"] = (anon_access.strip() == "1")
    except Exception:
        results["RestrictNullSessionAccess"] = "Error/NotConfigured"

    return results


# --- AGGREGATION FUNCTION (The Modular Controller) ---

def get_gdpr_technical_status_modular() -> Dict[str, Any]:
    """
    Aggregates all GDPR-relevant technical checks by calling functions from the 
    supportive security modules (the core of your library).
    """
    
    # --- 1. Article 32: Data Security (Confidentiality, Integrity) ---
    try:
        # 💡 ACTION REQUIRED 2: Replace the placeholder with the actual function call
        # data_protection_status = wdpc.get_data_protection_status() 
        data_protection_status = wdpc.get_data_protection_status() 
    except Exception as e:
        data_protection_status = {"Error": f"Could not call Data Protection Module: {e}"}

    try:
        # 💡 ACTION REQUIRED 2: Replace the placeholder with the actual function call
        # user_rights_status = wurc.get_critical_user_rights()
        user_rights_status = wurc.get_critical_user_rights()
    except Exception as e:
        user_rights_status = {"Error": f"Could not call User Rights Module: {e}"}

    # --- 2. Article 5 & 32: Accountability & Security ---
    try:
        # 💡 ACTION REQUIRED 2: Replace the placeholder with the actual function call
        # accountability_status = wacc.get_security_baseline_status()
        accountability_status = wacc.get_security_baseline_status()
    except Exception as e:
        accountability_status = {"Error": f"Could not call Audit Config Module: {e}"}
    
    # --- 3. Article 25: Privacy by Design (Unique GDPR check) ---
    privacy_by_design_unique = check_data_sharing_controls_gdpr()


    return {
        "GDPR_Technical_Summary": "Modular report based on core security and privacy controls.",
        "Article32_DataSecurity_Encryption_DLP": data_protection_status,
        "Article32_AccessControl_Authorization": user_rights_status,
        "Article05_Accountability_Logging": accountability_status,
        "Article25_PrivacyByDesign_Sharing": privacy_by_design_unique,
        "ComplianceNote": "GDPR requires legal and organizational controls not covered here."
    }


if __name__ == "__main__":
    print("Windows Technical GDPR Compliance Status (Complete Modular Design):")
    print(json.dumps(get_gdpr_technical_status_modular(), indent=2))