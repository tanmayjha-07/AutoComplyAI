"""
windows_logging_check.py

Windows logging & monitoring compliance checks via PowerShell.
Requires: Windows (PowerShell available). Some checks may require admin privileges.

Usage:
    import windows_logging_check as wlc
    auditing = wlc.check_security_auditing()
    logs = wlc.check_event_logs()
    retention = wlc.check_log_retention()
    ps_logging = wlc.check_powershell_logging()
    ntp = wlc.check_time_sync()
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
        return json.loads(out)
    except json.JSONDecodeError:
        return out


# 1. Security auditing enabled
def check_security_auditing() -> Dict[str, Any]:
    """
    Checks if auditing is enabled (basic test).
    Uses auditpol.exe to list categories.
    """
    try:
        output = _run_powershell("auditpol /get /category:*")
        enabled = {}
        for line in output.splitlines():
            if "Success" in line or "Failure" in line:
                parts = line.split()
                if len(parts) >= 2:
                    category = " ".join(parts[:-2])
                    success = "Success" in parts[-2]
                    failure = "Failure" in parts[-1] or "Failure" in parts[-2]
                    enabled[category] = {"Success": success, "Failure": failure}
        return {"AuditingEnabled": True, "Categories": enabled}
    except Exception as e:
        return {"AuditingEnabled": False, "Error": str(e)}


# 2. Event log categories enabled
def check_event_logs() -> Dict[str, Any]:
    """
    Checks common event logs are enabled and accessible.
    """
    try:
        logs = _ps_json(
            "Get-WinEvent -ListLog * | Select-Object LogName,IsEnabled,LogType,MaximumSizeInBytes,RecordCount"
        )
        if isinstance(logs, dict):
            logs = [logs]
        enabled_logs = [l for l in logs if l.get("IsEnabled")]
        return {
            "EventLogsEnabledCount": len(enabled_logs),
            "EventLogsEnabled": enabled_logs[:10],  # preview first 10
        }
    except Exception as e:
        return {"Error": str(e)}


# 3. Log retention days
def check_log_retention() -> Dict[str, Any]:
    """
    Checks maximum size, overwrite mode, and retention for key logs.
    """
    result = {}
    for log in ["Security", "System", "Application"]:
        try:
            cmd = f'Get-WinEvent -ListLog {log} | Select-Object LogName, MaximumSizeInBytes, LogMode, Retention'
            info = _ps_json(cmd)
            result[log] = info
        except Exception as e:
            result[log] = {"Error": str(e)}
    return result


# 4. PowerShell script logging enabled
def check_powershell_logging() -> Dict[str, Any]:
    """
    Checks if PowerShell script block and module logging are enabled.
    """
    result = {"ScriptBlockLogging": "Disabled", "ModuleLogging": "Disabled"}
    try:
        sbl = _run_powershell(
            'Get-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" '
            '-ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableScriptBlockLogging -ErrorAction SilentlyContinue'
        )
        if sbl.strip() == "1":
            result["ScriptBlockLogging"] = "Enabled"
    except Exception:
        pass

    try:
        ml = _run_powershell(
            'Get-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" '
            '-ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableModuleLogging -ErrorAction SilentlyContinue'
        )
        if ml.strip() == "1":
            result["ModuleLogging"] = "Enabled"
    except Exception:
        pass

    return result


# 5. Time sync active (NTP)
def check_time_sync() -> Dict[str, Any]:
    """
    Checks Windows Time service and current NTP source.
    """
    result = {}
    try:
        status = _ps_json('Get-Service -Name W32Time | Select-Object Status,StartType')
        result["Service"] = status
        if status and status.get("Status") != "Running":
            result["Note"] = (
                "W32Time service not running; system may sync via AD/VMware instead."
            )
            return result
    except Exception as e:
        result["Service"] = {"Error": str(e)}
        return result

    try:
        result["NTPStatus"] = _run_powershell("w32tm /query /status")
    except Exception as e:
        result["NTPStatus"] = f"Error: {e}"

    try:
        result["NTPPeers"] = _run_powershell("w32tm /query /peers")
    except Exception as e:
        result["NTPPeers"] = f"Error: {e}"

    return result


if __name__ == "__main__":
    print("Security auditing:")
    print(json.dumps(check_security_auditing(), indent=2))

    print("\nEvent logs:")
    print(json.dumps(check_event_logs(), indent=2))

    print("\nLog retention:")
    print(json.dumps(check_log_retention(), indent=2))

    print("\nPowerShell logging:")
    print(json.dumps(check_powershell_logging(), indent=2))

    print("\nTime sync (NTP):")
    print(json.dumps(check_time_sync(), indent=2))
