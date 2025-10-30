"""
windows_patch_check.py (ENHANCED)

Windows patching & update compliance checks via PowerShell + Winget.
Enhancements focus on checking the enforcement mechanism for automatic updates (ISO 27001 A 8.8).
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
    Safely wraps the command to handle null or empty output before ConvertTo-Json.
    """
    ps = f"""
    $data = ({cmd})
    if ($data -ne $null) {{
        $data | ConvertTo-Json -Depth 6
    }} else {{
        "[]"
    }}
    """
    out = _run_powershell(ps)
    if not out or out.strip() == "[]":
        return []
    try:
        parsed_json = json.loads(out)
        if isinstance(parsed_json, dict) and parsed_json.keys() and 'PSObject' not in parsed_json:
            return [parsed_json]
        return parsed_json
    except json.JSONDecodeError:
        return out


# 1. OS version & build
def get_os_version() -> Dict[str, Any]:
    try:
        data = _ps_json(
            "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture"
        )
        return data[0] if isinstance(data, list) else data if data else {}
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
        
        if updates is None or not updates:
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
    """
    Queries pending Windows updates using a passive CIM/WMI method to avoid triggering downloads.
    FIX: Uses Get-CimInstance on the update client history for a purely informational check.
    """
    result = {}
    try:
        # Passive command: Query the WMI class that holds update information.
        # This checks the LAST scan result, not initiating a new scan.
        ps_cmd = r"""
        Get-CimInstance -ClassName MSFT_WindowsUpdate -Namespace root\Microsoft\Windows\WindowsUpdate |
        Where-Object {$_.DeploymentState -eq 0 -or $_.DeploymentState -eq 1} | 
        Select-Object DeploymentState, Title, UpdateId
        """
        data = _ps_json(ps_cmd)
        
        if isinstance(data, list):
            # Clean up the output to be user-friendly
            pending_list = []
            for item in data:
                # Filter out items without a title (often metadata)
                if item.get('Title'):
                    status_map = {0: "Pending", 1: "Staged"}
                    pending_list.append({
                        "Title": item['Title'],
                        "Status": status_map.get(item['DeploymentState'], "Unknown")
                    })
            result["PendingUpdates"] = pending_list
        else:
            result["PendingUpdates"] = []
            
    except RuntimeError as e:
        # Catch errors if the WMI class is unavailable
        result["Error"] = f"Failed to query passive updates: {e}"
    except Exception as e:
        result["Error"] = f"Failed to query updates: {e}"
        
    return result


# --- ENHANCEMENT: Update Enforcement Check ---
def check_update_enforcement() -> Dict[str, Any]:
    """
    Checks if the Windows Update service is running/automatic and if automatic installation is enabled.
    """
    results = {"ServiceStatus": None, "ServiceStartType": None, "AutomaticUpdatesEnabled": False}
    
    # 1. Check Windows Update Service (wuauserv) Status
    try:
        service = _ps_json("Get-Service -Name wuauserv | Select-Object Status,StartType")
        if isinstance(service, list) and service:
            service = service[0]
        if isinstance(service, dict):
            results["ServiceStatus"] = service.get("Status")
            results["ServiceStartType"] = service.get("StartType")
        else:
            results["ServiceStatus"] = "Error/Not Found"
    except Exception:
        results["ServiceStatus"] = "Error"
        
    # 2. Check Automatic Updates Registry Policy
    try:
        no_auto_update = _run_powershell(
            r'(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue).NoAutoUpdate'
        )
        if no_auto_update.strip() == "0":
            results["AutomaticUpdatesEnabled"] = True
        
        results["NoAutoUpdate_Value"] = no_auto_update.strip()
    except Exception:
        results["AutomaticUpdatesEnabled"] = "Error/Not Configured"
        
    return results


# 4. Application updates via Winget
def get_app_updates() -> Union[List[Dict[str, Any]], Dict[str, str]]:
    """
    Queries pending application updates using winget and parses text output (for older winget versions).
    """
    try:
        # Use standard winget upgrade command with text output.
        result = subprocess.run(
            ["winget", "upgrade", "--all", "--accept-source-agreements", "--accept-package-agreements"],
            capture_output=True, text=True, encoding="utf-8"
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            if not error_msg.strip():
                 return {"Error": "Winget failed without specific error message (possible environment issue)."}
            return {"Error": f"Winget failed: {error_msg}"}

        lines = result.stdout.splitlines()
        updates = []
        parsing = False

        for line in lines:
            if line.strip().startswith("Name") and "Available" in line and not parsing:
                parsing = True
                continue
            
            if parsing and (line.strip().startswith(('-', '+', '=')) or not line.strip()):
                break
                
            if parsing and line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    current = parts[-2]
                    available = parts[-1]
                    name = " ".join(parts[:-2]) 
                    
                    updates.append({
                        "App": name,
                        "CurrentVersion": current,
                        "AvailableVersion": available
                    })
                    
        return updates if updates else {"Message": "No application updates found."}
    except FileNotFoundError:
        return {"Error": "Winget (Windows Package Manager) not found. Ensure it is installed and in PATH."}
    except Exception as e:
        return {"Error": f"Winget output parsing failed: {e}"}


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
                    reason = f"Windows 10 build {build} is older than 22H2 (19045+)."
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
        "SupportStatus": check_os_support(),
        "UpdateEnforcement": check_update_enforcement(), 
    }


if __name__ == "__main__":
    print("Patch status (Enhanced):")
    print(json.dumps(get_patch_status(), indent=2, sort_keys=False)) 