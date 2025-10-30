"""
windows_user_rights_check.py

Windows User Rights Assignment (URA) compliance checks via PowerShell.
Focuses on granular Access Control (ISO 27001 A 5.15).
Checks which accounts hold high-privilege rights critical for system security.
Requires: Windows (PowerShell available). Admin privileges are often required.
"""

import subprocess
import json
from typing import Dict, Any, List

# Define the critical user rights constants (used in secedit output)
CRITICAL_RIGHTS = {
    "SeBackupPrivilege": "Back up files and directories",
    "SeRestorePrivilege": "Restore files and directories",
    "SeTakeOwnershipPrivilege": "Take ownership of files or other objects",
    "SeDebugPrivilege": "Debug programs",
    "SeServiceLogonRight": "Log on as a service",
    "SeLoadDriverPrivilege": "Load and unload device drivers",
}

# Define the known problematic SID and its correct name
BACKUP_OPERATORS_SID = "S-1-5-32-551"
BACKUP_OPERATORS_NAME = "BUILTIN\\Backup Operators"
ERROR_STRING = "ERROR_RESOLVING_SID"


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


def _get_secedit_user_rights_data() -> str:
    """Exports and returns the User Rights Assignment section from the security policy."""
    try:
        # Export the local security policy to a temporary file
        temp_file = "$env:temp\\secpol_rights.inf"
        _run_powershell(f'secedit /export /cfg {temp_file} /areas USER_RIGHTS > $null')
        
        # Read the content of the exported file
        cfg_content = _run_powershell(f'Get-Content {temp_file}')
        
        # Clean up the temporary file (best effort)
        try:
            _run_powershell(f'Remove-Item {temp_file} -ErrorAction SilentlyContinue')
        except Exception:
            pass
        
        return cfg_content
    except Exception as e:
        raise RuntimeError(f"Failed to export security policy via secedit: {e}")


def parse_user_rights(secedit_data: str) -> Dict[str, List[str]]:
    """
    Parses the secedit output string to extract User Rights Assignments.
    Strips the leading asterisk (*) from SIDs.
    """
    rights_map = {}
    rights_section = False
    
    for line in secedit_data.splitlines():
        line = line.strip()
        
        if line == "[Privilege Rights]":
            rights_section = True
            continue
        
        if line.startswith("["):
            rights_section = False
            
        if rights_section and "=" in line:
            right_name, sid_list_str = [s.strip() for s in line.split("=", 1)]
            
            if right_name in CRITICAL_RIGHTS:
                sids = []
                for sid in sid_list_str.split(','):
                    sid = sid.strip()
                    if sid:
                        # Strip the leading '*' character from the SID
                        if sid.startswith('*'):
                            sid = sid[1:] 
                        sids.append(sid)
                
                rights_map[right_name] = sids
                
    return rights_map


def resolve_sids_to_names(rights_map: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
    """
    Converts SIDs in the rights map to human-readable names using PowerShell, 
    with explicit error handling for the Backup Operators SID.
    """
    final_results = {}
    
    # Flatten all unique SIDs we need to look up
    all_sids = set()
    for sids in rights_map.values():
        all_sids.update(sids)
    
    if not all_sids:
        return final_results

    # Build a single PowerShell command to look up all SIDs
    sid_list = ",".join(f"'{sid}'" for sid in all_sids)
    
    # PowerShell command to translate SIDs
    ps_cmd = f"""
    $sids = {sid_list}
    $sidMap = @{{}}
    
    foreach ($sid in $sids) {{
        try {{
            $id = New-Object System.Security.Principal.SecurityIdentifier $sid
            $name = $id.Translate([System.Security.Principal.NTAccount]).Value
            $sidMap[$sid] = $name
        }} catch {{
            $sidMap[$sid] = "{ERROR_STRING}"
        }}
    }}
    $sidMap | ConvertTo-Json -Depth 6
    """
    
    try:
        sid_names = json.loads(_run_powershell(ps_cmd))
    except Exception as e:
        print(f"Error resolving SIDs: {e}")
        sid_names = {}

    # Map the resolved names back to the rights structure, applying the final fix
    for right_name, sids in rights_map.items():
        users_and_groups = []
        for sid in sids:
            resolved_name = sid_names.get(sid, sid)
            
            # FINAL FIX LOGIC: Override the error for the known Backup Operators SID
            if sid == BACKUP_OPERATORS_SID and resolved_name == ERROR_STRING:
                resolved_name = BACKUP_OPERATORS_NAME
            elif resolved_name == ERROR_STRING:
                # If it's a different SID that failed, retain the error string for investigation
                pass 
            
            users_and_groups.append(resolved_name)

        final_results[right_name] = {
            "Description": CRITICAL_RIGHTS[right_name],
            "AssignedTo": sorted(users_and_groups),
            "SID_List": sids,
        }
        
    return final_results


def get_critical_user_rights() -> Dict[str, Any]:
    """
    Main function to orchestrate the user rights check.
    """
    try:
        # 1. Export User Rights Data from the local security policy
        secedit_output = _get_secedit_user_rights_data()
        
        # 2. Parse the output to get a list of SIDs assigned to critical rights
        parsed_rights = parse_user_rights(secedit_output)
        
        # 3. Resolve the SIDs into human-readable user/group names
        resolved_rights = resolve_sids_to_names(parsed_rights)
        
        return resolved_rights
    
    except Exception as e:
        return {"Error": f"User Rights Check failed: {e}"}


if __name__ == "__main__":
    print("Critical User Rights Assignments (via secedit/PowerShell):")
    results = get_critical_user_rights()
    print(json.dumps(results, indent=2))