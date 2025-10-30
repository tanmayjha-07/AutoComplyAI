"""
windows_audit_config_check.py

Windows security baseline and audit configuration checks via PowerShell/CMD.
Focuses on Configuration Management (ISO 27001 A 8.22) and Logging (A 8.16).
Requires: Windows (PowerShell available). Admin privileges are often required.

Usage:
    import windows_audit_config_check as wacc
    config = wacc.get_security_baseline_status()
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
        error_msg = proc.stderr.strip() or proc.stdout.strip()
        # If the known auditpol error occurs, raise a specific error that the caller can handle 
        # by attempting to use the CMD utility method.
        raise RuntimeError(f"PowerShell error: {error_msg}")
        
    return proc.stdout.strip()

def _run_cmd_utility(cmd: str) -> str:
    """
    Run a raw command line utility (like auditpol) using cmd.exe shell.
    This resolves parameter issues that occur when running utilities via PowerShell.
    """
    proc = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"CMD error: {proc.stderr.strip() or proc.stdout.strip()}")
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


def check_security_options() -> Dict[str, Any]:
    """
    Checks specific security options (e.g., AutoRun, Guest Account status).
    Uses secedit export/parse for broader policy coverage.
    """
    results = {}
    
    # 1. Disable AutoRun/AutoPlay (recommended for high security)
    try:
        autorun = _run_powershell(
            r'(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun'
        )
        if autorun.strip() == "255" or autorun.strip() == "0xff":
            results["AutoRun_Disabled"] = True
        else:
            results["AutoRun_Disabled"] = False
            results["AutoRun_CurrentValue"] = autorun.strip() or "Default (0)"
    except Exception:
        results["AutoRun_Disabled"] = "NotConfigured/Error"

    # 2. Account Lockout Threshold 
    try:
        # Use secedit export to get policies
        cfg = _run_powershell('secedit /export /cfg $env:temp\\secpol_check.cfg > $null ; Get-Content $env:temp\\secpol_check.cfg')
        
        for line in cfg.splitlines():
            line = line.strip()
            if line.startswith("LockoutBadCount"):
                results["LockoutThreshold"] = int(line.split("=", 1)[1].strip())
            elif line.startswith("ClearTextPassword"):
                # Should be 0 (do not store)
                results["ClearTextPassword_Storage"] = int(line.split("=", 1)[1].strip()) == 0
            elif line.startswith("RequireLogonToChangePassword"):
                # Should be 0 (user can change their own password)
                results["RequireLogonToChangePassword"] = int(line.split("=", 1)[1].strip()) == 0

    except Exception:
        results["LockoutThreshold"] = "Error"
        results["ClearTextPassword_Storage"] = "Error"
        results["RequireLogonToChangePassword"] = "Error"
        
    return results


def check_firewall_advanced_settings() -> Dict[str, Any]:
    """
    Checks advanced firewall settings for enforcement.
    """
    results = {}
    try:
        # Check Inbound/Outbound default actions (should be Block/Allow)
        profiles = _ps_json(
            "Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction,DefaultOutboundAction"
        )
        
        # Get-NetFirewallProfile returns a single object if only one profile is active, or a list.
        for p in profiles if isinstance(profiles, list) else [profiles]:
            name = p.get("Name")
            # Inbound should be Block for a secure perimeter
            inbound = p.get("DefaultInboundAction") == "Block"
            # Outbound should be Allow to permit user/application access, relying on application rules
            outbound = p.get("DefaultOutboundAction") == "Allow" 
            results[name] = {
                "InboundDefaultBlock": inbound,
                "OutboundDefaultAllow": outbound
            }
    except Exception as e:
        results["Error"] = str(e)
        
    return results


def get_security_baseline_status() -> Dict[str, Any]:
    """
    Combines all audit and configuration checks.
    """
    return {
        "SecurityOptions": check_security_options(),
        "FirewallAdvancedSettings": check_firewall_advanced_settings(),
    }


if __name__ == "__main__":
    print("Windows Audit and Configuration Baseline Status:")
    print(json.dumps(get_security_baseline_status(), indent=2, sort_keys=False))