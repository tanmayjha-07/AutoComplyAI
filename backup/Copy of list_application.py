import os
import json
import subprocess
from typing import Dict, Any


def run_powershell(cmd: str) -> Any:
    """Run a PowerShell command and return JSON-decoded output or raw error."""
    try:
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout.strip()

        if not output:
            return {"Error": "No output"}

        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {"RawOutput": output}
    except subprocess.CalledProcessError as e:
        return {"Error": e.stderr.strip() or str(e)}


def get_os_info() -> Dict[str, Any]:
    """Collect OS, build, and kernel version info."""
    return run_powershell(
        "Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer | ConvertTo-Json -Depth 3"
    )


def get_installed_apps(limit: int = 300) -> Any:
    """Collect installed apps list (limited)."""
    ps = (
        "@("
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*;"
        "Get-ItemProperty HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*;"
        "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
        ") | Where-Object { $_.DisplayName } | "
        f"Select-Object -First {limit} DisplayName, DisplayVersion | ConvertTo-Json -Depth 3"
    )
    return run_powershell(ps)


def get_drivers(limit: int = 250) -> Any:
    """Collect installed drivers (limited)."""
    ps = f"Get-WmiObject Win32_PnPSignedDriver | Select-Object -First {limit} DeviceName, DriverVersion | ConvertTo-Json -Depth 3"
    return run_powershell(ps)


def check_inventory(
    include_apps: bool = True,
    include_drivers: bool = True,
    app_limit: int = 300,
    driver_limit: int = 250,
) -> Dict[str, Any]:
    """Check system inventory info."""
    inventory: Dict[str, Any] = {
        "OSInfo": get_os_info(),
        "UserInfo": {
            "UserName": os.environ.get("USERNAME") or os.environ.get("USER"),
            "UserHome": os.path.expanduser("~"),
            "UserDir": os.getcwd(),
        },
        "JavaRuntime": {
            "JavaVersion": os.environ.get("JAVA_VERSION"),
            "JavaHome": os.environ.get("JAVA_HOME"),
            "JavaVendor": os.environ.get("JAVA_VENDOR"),
        },
    }

    if include_apps:
        inventory["InstalledApps"] = get_installed_apps(limit=app_limit)
    if include_drivers:
        inventory["Drivers"] = get_drivers(limit=driver_limit)

    return inventory


if __name__ == "__main__":
    result = check_inventory()
    print("System Inventory:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
