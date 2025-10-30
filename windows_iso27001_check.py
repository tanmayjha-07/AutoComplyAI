"""
windows_iso27001_check.py (THREADING ENABLED & CORRECTED MAPPING)

Aggregates technical compliance status for ISO 27001 using concurrent threads,
mapping results accurately to ISO 27001 Annex A control areas, and respecting 
the original function structure of windows_patch_check.py.
"""

import subprocess
import json
import concurrent.futures
from typing import Dict, Any, Callable

# =========================================================================================
# FINAL IMPORTS: Calling ALL necessary modules from your library.
import windows_ac_check as wac
import windows_patch_check as wpc # Original version used
import windows_hardening_check as whc
import windows_network_security_check as wnsc
import windows_malware_protection_check as wmpc
import windows_backup_recovery_check as wbrc
import windows_integrity_check as wic
import windows_user_rights_check as wurc
import windows_audit_config_check as wacc
import windows_Log_Check as wlcc 
import windows_data_protection_check as wdpc 
# =========================================================================================

# --- HELPER FUNCTIONS (Kept for environment compatibility) ---

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


# --- THREADING SAFE CALLER ---

def _safe_call(func: Callable) -> Dict[str, Any]:
    """Wraps a module function call to handle exceptions and ensure thread-safe return."""
    try:
        return func()
    except Exception as e:
        return {"Execution_Error": str(e), "Status": "NON-COMPLIANT (Check failed)"}

# --- AGGREGATION FUNCTION (The ISO Controller with Threading) ---

def get_iso27001_technical_status() -> Dict[str, Any]:
    """
    Aggregates technical compliance status concurrently using ThreadPoolExecutor.
    Maps results accurately to ISO 27001 Annex A control areas.
    """
    
    # Define a map of compliance checks: {KeyName: FunctionReference}
    check_map = {
        # A05 Access Control
        "Local_Admins": wac.get_local_admins,
        "Admin_Account_Hardening": wac.check_built_in_admin_status,
        "Idle_Accounts": wac.get_idle_accounts,
        "Disabled_Guest_Accounts": wac.get_disabled_guest_accounts,
        "Critical_User_Rights": wurc.get_critical_user_rights,
        "Password_Policy": wac.get_password_policy,
        "Windows_Hello_MFA_Check": wac.check_windows_hello,

        # A08 System Hardening & Vulnerability Management
        # NOTE: Using get_patch_status() to cover the entire WPC module output.
        "Patch_Status_Summary": wpc.get_patch_status, 
        
        "RDP_Hardening_Status": whc.check_rdp_status,
        "Insecure_Services_Protocols": whc.check_insecure_services,
        "Audit_Config_Baseline": wacc.get_security_baseline_status,
        "System_Integrity_Check": wic.get_system_integrity_status,
        
        # A08 Cryptography & Network Security
        "Disk_Encryption_DLP_Status": wdpc.get_data_protection_status,
        "Secure_Boot_TPM": whc.check_secure_boot,
        "Network_Security_Checks": wnsc.get_network_security,
        "Firewall_Status_Logging": whc.check_firewall,
        
        # A08 Operational Security & Logging
        "Malware_Protection_Status": wmpc.get_defender_status,
        "Backup_Recovery_Status": wbrc.get_backup_status,
        "Audit_Policy_Check": wlcc.check_security_auditing, 
        "Log_Retention_Check": wlcc.check_log_retention,
        "PowerShell_Logging": wlcc.check_powershell_logging,
    }

    # Use ThreadPoolExecutor to run all checks concurrently
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all functions to the executor, wrapped in _safe_call
        future_to_check = {
            executor.submit(_safe_call, func): key
            for key, func in check_map.items()
        }

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_check):
            key = future_to_check[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"Execution_Error_Thread": str(e), "Status": "NON-COMPLIANT (Critical failure)"}

    # Organize the flat results into the final hierarchical structure
    final_report = {
        "ISO_Technical_Summary": "Aggregated status for technical Annex A controls (concurrency enabled).",
        
        "A05_Access_Control": {
            "Local_Admins": results.pop("Local_Admins"),
            "Admin_Account_Hardening": results.pop("Admin_Account_Hardening"),
            "Idle_Accounts": results.pop("Idle_Accounts"),
            "Disabled_Guest_Accounts": results.pop("Disabled_Guest_Accounts"),
            "Critical_User_Rights": results.pop("Critical_User_Rights"),
            "Password_Policy": results.pop("Password_Policy"),
            "Windows_Hello_MFA_Check": results.pop("Windows_Hello_MFA_Check"),
        },
        
        "A08_System_Hardening": {
            "Patch_Status_Summary": results.pop("Patch_Status_Summary"),
            # Removed the separate Update_Enforcement key as it's now inside the Patch_Status_Summary output
            "RDP_Hardening_Status": results.pop("RDP_Hardening_Status"),
            "Insecure_Services_Protocols": results.pop("Insecure_Services_Protocols"),
            "Audit_Config_Baseline": results.pop("Audit_Config_Baseline"),
            "System_Integrity_Check": results.pop("System_Integrity_Check"),
        },

        "A08_Network_Cryptography": {
            "Secure_Boot_TPM": results.pop("Secure_Boot_TPM"),
            "Network_Security_Checks": results.pop("Network_Security_Checks"),
            "Firewall_Status_Logging": results.pop("Firewall_Status_Logging"),
            "Disk_Encryption_DLP_Status": results.pop("Disk_Encryption_DLP_Status"),
        },

        "A08_Operational_Security": {
            "Malware_Protection_Status": results.pop("Malware_Protection_Status"),
            "Backup_Recovery_Status": results.pop("Backup_Recovery_Status"),
            "Audit_Policy_Check": results.pop("Audit_Policy_Check"), 
            "Log_Retention_Check": results.pop("Log_Retention_Check"),
            "PowerShell_Logging": results.pop("PowerShell_Logging"),
        }
    }

    return final_report


if __name__ == "__main__":
    print("Windows Technical ISO 27001 (Annex A) Compliance Status (Concurrency Enabled):")
    print(json.dumps(get_iso27001_technical_status(), indent=2))