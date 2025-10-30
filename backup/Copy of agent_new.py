# import requests
# import os
# import platform
# import time

# # Import all check modules
# import list_application as la
# import windows_malware_protection_check as wmp
# import windows_backup_recovery_check as wbr
# import windows_patch_check as wpc
# import windows_ac_check as wac
# import windows_Log_Check as wlc
# import windows_hardening_check as whc
# import windows_network_security_check as wnc

# SERVER_URL = input("Enter the server URL (e.g., http://localhost:5000): ").strip()

# def collect_compliance_status():
#     status = {}
#     try:
#         status["Inventory"] = la.check_inventory  # Apps, drivers, OS info
#     except Exception as e:
#         status["Inventory"] = {"Error": str(e)}
#     try:
#         status["Defender"] = wmp.get_defender_status()  # Malware protection status
#     except Exception as e:
#         status["Defender"] = {"Error": str(e)}
#     try:
#         status["BackupRecovery"] = wbr.get_backup_status()  # Backup and restore status
#     except Exception as e:
#         status["BackupRecovery"] = {"Error": str(e)}
#     try:
#         status["Patch"] = wpc.get_patch_status()  # Patch/update status
#     except Exception as e:
#         status["Patch"] = {"Error": str(e)}
#     try:
#         status["AccessControl"] = {
#             "LocalAdmins": wac.get_local_admins(),
#             "PasswordPolicy": wac.get_password_policy(),
#             "WindowsHello": wac.check_windows_hello()
#         }
#     except Exception as e:
#         status["AccessControl"] = {"Error": str(e)}
#     try:
#         status["Logging"] = {
#             "SecurityAuditing": wlc.check_security_auditing(),
#             "EventLogs": wlc.check_event_logs(),
#             "LogRetention": wlc.check_log_retention(),
#             "PSLogging": wlc.check_powershell_logging(),
#             "TimeSync": wlc.check_time_sync()
#         }
#     except Exception as e:
#         status["Logging"] = {"Error": str(e)}
#     try:
#         status["Hardening"] = {
#             "Firewall": whc.check_firewall(),
#             "RDP": whc.check_rdp_status(),
#             "BitLocker": whc.check_bitlocker(),
#             "SecureBoot": whc.check_secure_boot(),
#             "InsecureServices": whc.check_insecure_services()
#         }
#     except Exception as e:
#         status["Hardening"] = {"Error": str(e)}
#     try:
#         status["Network"] = wnc.get_network_security([80, 443, 3389])  # Commonly allowed ports
#     except Exception as e:
#         status["Network"] = {"Error": str(e)}
#     return status

# def agent_workflow():
#         try:
#             response = requests.get(f"{SERVER_URL}/inforequest")
#             response.raise_for_status()
#             request_data = response.json()
#             if request_data.get("request_full_system_info"):
#                 sysinfo = collect_compliance_status()
#                 response2 = requests.post(f"{SERVER_URL}/sendinfo", json=sysinfo)
#                 print("Server response:", response2.json())
#         except requests.exceptions.RequestException as e:
#             print("Retrying in 10 seconds...", str(e))
#             time.sleep(10)

# if __name__ == "__main__":
#     agent_workflow()


import requests
import os
import platform
import time
import threading 

# Import all check modules
import list_application as la
import windows_malware_protection_check as wmp
import windows_backup_recovery_check as wbr
import windows_patch_check as wpc
import windows_ac_check as wac
import windows_Log_Check as wlc
import windows_hardening_check as whc
import windows_network_security_check as wnc

SERVER_URL = input("Enter the server URL (e.g., http://localhost:5000): ").strip()

# Dictionary to hold the status collected by threads
THREAD_STATUS = {}
THREAD_LOCK = threading.Lock() 

def run_check_and_store(key, func, *args, **kwargs):
    """
    Runs a compliance check function and stores the result in the global THREAD_STATUS dictionary.
    """
    try:
        # Execute the check function with its arguments
        result = func(*args, **kwargs)
    except Exception as e:
        result = {"Error": str(e)}
        
    # Safely update the shared status dictionary
    with THREAD_LOCK:
        THREAD_STATUS[key] = result

def collect_compliance_status():
    """
    Collects compliance status by running each check concurrently using threads.
    """
    global THREAD_STATUS
    # Reset status for a fresh collection
    THREAD_STATUS = {} 
    threads = []

    # Define all the checks to be run
    checks = [
        ("Inventory", la.check_inventory),
        ("Defender", wmp.get_defender_status),
        ("BackupRecovery", wbr.get_backup_status),
        ("Patch", wpc.get_patch_status),
    ]

    # AccessControl check (Wrapped in a local function)
    def access_control_check():
        return {
            "LocalAdmins": wac.get_local_admins(),
            "PasswordPolicy": wac.get_password_policy(),
            "WindowsHello": wac.check_windows_hello()
        }
    checks.append(("AccessControl", access_control_check))
    
    # Logging check (Wrapped in a local function)
    def logging_check():
        return {
            "SecurityAuditing": wlc.check_security_auditing(),
            "EventLogs": wlc.check_event_logs(),
            "LogRetention": wlc.check_log_retention(),
            "PSLogging": wlc.check_powershell_logging(),
            "TimeSync": wlc.check_time_sync()
        }
    checks.append(("Logging", logging_check))

    # Hardening check (Wrapped in a local function)
    def hardening_check():
        return {
            "Firewall": whc.check_firewall(),
            "RDP": whc.check_rdp_status(),
            "BitLocker": whc.check_bitlocker(),
            "SecureBoot": whc.check_secure_boot(),
            "InsecureServices": whc.check_insecure_services()
        }
    checks.append(("Hardening", hardening_check))
    
    # Network check with arguments (Ports converted to tuple for threading)
    network_ports = [80, 443, 3389]
    def network_check(ports):
        return wnc.get_network_security(ports)
    checks.append(("Network", network_check, tuple(network_ports))) 

    # Create and start threads
    for check in checks:
        key = check[0]
        func = check[1]
        
        # Extract arguments and ensure they are in tuple format
        check_args = check[2] if len(check) > 2 else ()
        if isinstance(check_args, list):
            check_args = tuple(check_args)
            
        kwargs = check[3] if len(check) > 3 else {}
        
        thread_args = (key, func) + check_args

        thread = threading.Thread(
            target=run_check_and_store, 
            args=thread_args,
            kwargs=kwargs
        )
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()
        
    return THREAD_STATUS

def agent_workflow():
    """
    Periodically checks the server for a request and sends system info if requested.
    Uses a cooldown period after a successful submission.
    """
    # Define a longer wait time after successfully sending data (1 minute)
    SUCCESS_COOLDOWN = 60 
    # Regular wait time if no collection was done (10 seconds)
    REGULAR_CHECK_DELAY = 10 

    # Continuously run the agent workflow
    delay = REGULAR_CHECK_DELAY # Default delay is 10s

    try:
            print(f"Checking {SERVER_URL}/inforequest for new requests...")
            
            # 1. Check for request from server
            response = requests.get(f"{SERVER_URL}/inforequest")
            response.raise_for_status()
            request_data = response.json()
            
            # 2. Collect and send info only if requested
            if request_data.get("request_full_system_info"):
                print("Server requested full system information. Collecting status concurrently...")
                
                # The threaded collection function is called here
                sysinfo = collect_compliance_status() 
                print("Status collected. Sending to server...")
                
                # Send the collected data
                response2 = requests.post(f"{SERVER_URL}/sendinfo", json=sysinfo)
                response2.raise_for_status()
                print("Server response:", response2.json())
                
                # Set the longer delay after a successful submission
                delay = SUCCESS_COOLDOWN 
                print(f"Submission complete. Waiting {SUCCESS_COOLDOWN} seconds before next check to prevent immediate re-run.")
            else:
                print(f"No request for full system information. Checking again in {REGULAR_CHECK_DELAY} seconds.")

    except requests.exceptions.RequestException as e:
            # Handle connection errors, HTTP errors, etc.
            print(f"An error occurred: {e}. Retrying in {REGULAR_CHECK_DELAY} seconds.")
            delay = REGULAR_CHECK_DELAY
            
    finally:
            # Sleep based on the calculated delay
            time.sleep(delay)

if __name__ == "__main__":
    agent_workflow()