"""
windows_network_security_check.py (ENHANCED)

Windows network security compliance checks via PowerShell.
Focuses on Network Security (ISO 27001 A 8.20) and Cryptography (A 8.24).
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
        raise RuntimeError(
            f"PowerShell error: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip()


def _ps_json(cmd: str):
    """Run PowerShell command and return JSON (safe for empty results)."""
    # NOTE: The command string passed here must NOT contain 'ConvertTo-Json'.
    # The helper adds it to ensure a consistent, structured output format.
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
        # Check if the result is a single object (dict) or a list of objects
        parsed_json = json.loads(out)
        
        # Ensure single object results are wrapped in a list for consistent iteration
        if isinstance(parsed_json, dict):
            return [parsed_json]
        return parsed_json
    except json.JSONDecodeError:
        # If decoding fails, return the raw output for debugging
        return out


def check_legacy_protocols() -> Dict[str, Any]:
    """
    Checks if insecure legacy protocols like NetBIOS and LLMNR are disabled.
    FIX: Corrected the _ps_json call in NetBIOS check to remove redundant ConvertTo-Json.
    """
    results = {}
    
    # 1. LLMNR (Link-Local Multicast Name Resolution) Disablement
    # Value: EnableMulticast (0=Disabled is secure)
    try:
        llmnr = _run_powershell(r'(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue).EnableMulticast')
        results["LLMNR_Disabled"] = (llmnr.strip() == "0")
        results["LLMNR_Config"] = llmnr.strip()
    except Exception:
        results["LLMNR_Disabled"] = "NotConfigured/Error"

    # 2. NetBIOS over TCP/IP Disablement
    try:
        # FIX: Command passed to _ps_json must be clean.
        netbios_cmd = r"""
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | 
        Select-Object Name, NetBiosSetting
        """
        netbios_status = _ps_json(netbios_cmd)
        
        # If _ps_json fails completely and returns a string, or returns an empty list
        if not isinstance(netbios_status, list):
             raise TypeError("NetBIOS output was not correctly parsed into a list.")

        # Check if NetBiosSetting is "Disabled" (3) for active adapters
        # Note: NetBiosSetting 3 = Disabled
        is_disabled = all(
            (a.get("NetBiosSetting") == 3 or a.get("NetBiosSetting") == "Disabled")
            for a in netbios_status if a.get("NetBiosSetting") is not None
        )
        results["NetBIOS_DisabledOnAdapters"] = is_disabled
        results["NetBIOS_AdapterStatus"] = netbios_status
    except Exception as e:
        results["NetBIOS_DisabledOnAdapters"] = f"Error: {e}"
        
    return results


def check_schannel_cipher_suites() -> Dict[str, Any]:
    """
    Checks for the disablement of insecure cipher suites in SCHANNEL.
    Looks for the existence of disabled keys for weak algorithms (DES, 3DES, RC4).
    """
    insecure_ciphers = ["DES", "3DES", "RC4"]
    disabled_status = {}
    
    # The presence of a key with 'Enabled' = 0 and 'DisabledByDefault' = 1 suggests hardening.
    for cipher in insecure_ciphers:
        try:
            # Check for the key used to explicitly disable the cipher
            ps_cmd = fr"""
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\{cipher}"
            if (Test-Path $path) {{
                $enabled = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Enabled
                $disabled_by_default = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).DisabledByDefault
                
                # Check if 'Enabled' is explicitly set to 0
                if ($enabled -eq 0) {{ "ExplicitlyDisabled" }}
                else {{ "ConfiguredButNotDisabled" }}
            }} else {{
                "NotConfigured"
            }}
            """
            status = _run_powershell(ps_cmd).strip()
            disabled_status[cipher] = status
        except Exception:
            disabled_status[cipher] = "Error"

    return {"InsecureCiphersStatus": disabled_status}


def check_ipv6_status() -> Dict[str, Any]:
    """
    Checks if IPv6 is globally disabled (a common hardening measure if not used).
    """
    results = {"IPv6_Globally_Disabled": False}
    try:
        # Check if the registry key to disable IPv6 is set to 0xFF (255)
        # Value 0xFF means "Disable all IPv6 interfaces/components"
        ipv6_key = _run_powershell(r'(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ErrorAction SilentlyContinue).DisabledComponents')
        
        if ipv6_key.strip() == "255" or ipv6_key.strip().lower() == "0xff":
            results["IPv6_Globally_Disabled"] = True
        
        results["DisabledComponentsValue"] = ipv6_key.strip()
    except Exception as e:
        results["Error"] = str(e)
        
    return results


def get_network_security(whitelist_ports: List[int] = None) -> Dict[str, Any]:
    """
    Checks:
    - Open ports vs whitelist
    - VPN enforcement
    - DNS & Proxy settings
    - TLS version enforcement (weak cipher enhancement)
    - Legacy protocol hardening (LLMNR/NetBIOS)
    - IPv6 status
    """
    result: Dict[str, Any] = {}

    # 1. Open ports (Original Check)
    try:
        ports = _ps_json(r"""
        Get-NetTCPConnection -State Listen |
        Select-Object LocalPort,LocalAddress,OwningProcess
        """)
            
        result["OpenPorts"] = ports
        if whitelist_ports:
            non_whitelist = [p for p in ports if isinstance(p, dict) and p.get("LocalPort") not in whitelist_ports]
            result["NonWhitelistedPorts"] = non_whitelist
    except Exception as e:
        result["OpenPortsError"] = str(e)

    # 2. VPN enforcement (Original Check)
    try:
        vpn_status = _ps_json(r"""
        Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue |
        Select-Object Name,ConnectionStatus
        """)
        result["VPNConnections"] = vpn_status
    except Exception as e:
        result["VPNError"] = str(e)

    # 3. DNS and Proxy settings (Original Check)
    try:
        dns = _ps_json(r"""
        Get-DnsClientServerAddress |
        Select-Object InterfaceAlias,ServerAddresses
        """)
        proxy = _run_powershell(r"""
        netsh winhttp show proxy
        """)
        result["DNS"] = dns
        result["Proxy"] = proxy
    except Exception as e:
        result["DNSProxyError"] = str(e)

    # 4. TLS version enforcement (Original Check)
    try:
        tls_versions = {}
        for ver in ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
            key = ver.replace(" ", "")
            try:
                # Checks if protocol version is enabled/disabled via registry
                state = _run_powershell(fr"""
                try {{
                    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{ver}\Server"
                    if (Test-Path $path) {{
                        Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object -ExpandProperty Enabled
                    }} else {{
                        "NotConfigured"
                    }}
                }} catch {{
                    "Error"
                }}
                """)
            except Exception:
                state = "Error"
            tls_versions[key] = state
        result["TLSVersions"] = tls_versions
        
        # --- ENHANCEMENT: Weak Cipher Check ---
        result["WeakCipherSuites"] = check_schannel_cipher_suites()
        
    except Exception as e:
        result["TLSError"] = str(e)

    # 5. Legacy Protocol Hardening (ENHANCEMENT)
    result["LegacyProtocolHardening"] = check_legacy_protocols()
    
    # 6. IPv6 Status (ENHANCEMENT)
    result["IPv6Status"] = check_ipv6_status()


    return result


if __name__ == "__main__":
    whitelist = [80, 443, 3389]  # Example allowed ports
    print("Network Security status (Enhanced):")
    print(json.dumps(get_network_security(whitelist), indent=2, sort_keys=False))