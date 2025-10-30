import requests
import os
import platform
import time


SERVER_URL = input("Enter the server URL (e.g., http://localhost:5000): ").strip()


def get_os_details():
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"
    
    os_details = {
        "OS": platform.system(),
        "OS Version": platform.version(),
        "OS Release": platform.release(),
        "Architecture": platform.machine(),
        "Processor": platform.processor(),
        "Platform": platform.platform(),
        "Node Name": platform.node(),
        "User": user
    }
    
    return os_details


def agent_workflow():
    while True:
        try:
            response = requests.get(f"{SERVER_URL}/inforequest", timeout=10)
            response.raise_for_status()
            request_data = response.json()

            # The key must match what your Flask /inforequest route returns
            if request_data.get("request_full_system_info"):
                sys_info = get_os_details()
                response = requests.post(f"{SERVER_URL}/sendinfo", json=sys_info, timeout=10)
                print("Server response:", response.json())

            time.sleep(10)  # wait 10 seconds before checking again

        except requests.exceptions.RequestException as e:
            print(f"Connection error: {e}. Retrying in 10 seconds...")
            time.sleep(10)


if __name__ == '__main__':
    agent_workflow()
