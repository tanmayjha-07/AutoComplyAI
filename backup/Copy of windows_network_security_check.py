"""
windows_network_security_check.py

Windows network security compliance checks via PowerShell.
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


def get_network_security(whitelist_ports: List[int] = None) -> Dict[str, Any]:
    """
    Checks:
    - Open ports vs whitelist
    - VPN enforcement
    - DNS & Proxy settings
    - TLS version enforcement
    """
    result: Dict[str, Any] = {}

    # 1. Open ports
    try:
        ports = _ps_json(r"""
        Get-NetTCPConnection -State Listen |
        Select-Object LocalPort,LocalAddress,OwningProcess
        """)
        result["OpenPorts"] = ports
        if whitelist_ports:
            non_whitelist = [p for p in ports if p.get("LocalPort") not in whitelist_ports]
            result["NonWhitelistedPorts"] = non_whitelist
    except Exception as e:
        result["OpenPortsError"] = str(e)

    # 2. VPN enforcement
    try:
        vpn_status = _ps_json(r"""
        Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue |
        Select-Object Name,ConnectionStatus
        """)
        result["VPNConnections"] = vpn_status
    except Exception as e:
        result["VPNError"] = str(e)

    # 3. DNS and Proxy settings
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

    # 4. TLS version enforcement (registry check)
    try:
        tls_versions = {}
        for ver in ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
            key = ver.replace(" ", "")
            try:
                state = _run_powershell(fr"""
                try {{
                    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{ver}\Server" -ErrorAction Stop |
                    Select-Object -ExpandProperty Enabled
                }} catch {{
                    "NotConfigured"
                }}
                """)
            except Exception:
                state = "Error"
            tls_versions[key] = state
        result["TLSVersions"] = tls_versions
    except Exception as e:
        result["TLSError"] = str(e)

    return result


if __name__ == "__main__":
    whitelist = [80, 443, 3389]  # Example allowed ports
    print("Network Security status:")
    print(json.dumps(get_network_security(whitelist), indent=2))
