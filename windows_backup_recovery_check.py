"""
windows_backup_recovery_check.py

Windows backup & recovery compliance checks via PowerShell.
Requires: Windows (PowerShell available). Some checks may require admin privileges.
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
        raise RuntimeError(
            f"PowerShell error: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip()


def _ps_json(cmd: str):
    """
    Run PowerShell command and return JSON.
    Automatically avoids empty pipeline issue.
    """
    ps = f"""
    $data = {cmd}
    if ($data) {{
        $data | ConvertTo-Json -Depth 6
    }} else {{
        "[]"
    }}
    """
    out = _run_powershell(ps)
    if not out:
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def get_backup_status() -> Dict[str, Any]:
    """
    Checks:
    - Backup agent/service installed (File History, Windows Backup, VSS providers)
    - Last successful backup date
    - Backup encryption enabled
    - Restore test events
    """
    result: Dict[str, Any] = {}

    # 1. Backup agent/service check
    try:
        agent = _ps_json(r"""
        Get-Service | Where-Object { $_.Name -match "SDRSVC|wbengine|VSS" } |
        Select-Object Name,Status
        """)
        result["BackupServices"] = agent
    except Exception as e:
        result["BackupServicesError"] = str(e)

    # 2. Last successful backup
    try:
        last_backup = _run_powershell(r"""
        try {
            $job = Get-WBJob -Previous 1 -ErrorAction Stop
            $job.EndTime
        } catch {
            "NotAvailable"
        }
        """)
        result["LastBackup"] = last_backup
    except Exception as e:
        result["LastBackupError"] = str(e)

    # 3. Backup encryption
    try:
        enc_status = _run_powershell(r"""
        try {
            $bl = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" }
            if ($bl) { "Enabled" } else { "NotEnabled" }
        } catch {
            "NotAvailable"
        }
        """)
        result["BackupEncryption"] = enc_status
    except Exception as e:
        result["BackupEncryptionError"] = str(e)

    # 4. Restore tests
    try:
        restore_events = _ps_json(r"""
        try {
            if (Get-WinEvent -ListLog "Microsoft-Windows-FileHistory-Core/Operational" -ErrorAction SilentlyContinue) {
                Get-WinEvent -LogName "Microsoft-Windows-FileHistory-Core/Operational" -MaxEvents 50 |
                Where-Object { $_.Message -match "restore" -or $_.Message -match "test" } |
                Select-Object TimeCreated,Message
            } else {
                @()
            }
        } catch {
            @()
        }
        """)
        result["RestoreTests"] = restore_events
    except Exception as e:
        result["RestoreTestsError"] = str(e)

    return result


if __name__ == "__main__":
    print("Backup & Recovery status:")
    print(json.dumps(get_backup_status(), indent=2))
