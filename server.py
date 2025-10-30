# from flask import Flask, request, jsonify

# app = Flask(__name__)

# @app.route("/inforequest", methods=["GET"])
# def inforequest():
#     # The agent uses this to check if full system info should be sent
#     return jsonify({"request_full_system_info": True})

# @app.route("/sendinfo", methods=["POST"])
# def sendinfo():
#     data = request.json
#     print("Received system info from agent:")
#     print(data)  # This will print nested/complex compliance results directly
#     return jsonify({"status": "info received"})

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000)




import time
import json
import socket
from datetime import datetime
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# GLOBAL STATE to control whether the agent should send info
# True = Server is waiting for data, False = Server is NOT waiting
REQUEST_FULL_SYSTEM_INFO = True 

def get_ip_address():
    """Tries to get the local IP address of the server."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def save_data_to_json(data):
    """Saves the received data to a JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Use the hostname or IP if available, otherwise use a generic name
    agent_id = data.get("Inventory", {}).get("OSInfo", {}).get("ComputerName", "unknown_agent")
    
    # Sanitize agent_id for filename
    agent_id = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in agent_id)

    filename = f"compliance_report_{agent_id}_{timestamp}.json"
    
    try:
        with open(filename, 'w') as f:
            # Use json.dump with indentation for a clean, readable file
            json.dump(data, f, indent=4)
        print(f"✅ Successfully saved data to {filename}")
        return filename
    except Exception as e:
        print(f"❌ Error saving JSON file: {e}")
        return None

# =================================================================
# SERVER ROUTES
# =================================================================

@app.route("/inforequest", methods=['GET'])
def inforequest():
    """
    Route for the agent to check if the server needs data.
    """
    global REQUEST_FULL_SYSTEM_INFO
    
    # Server decides whether to request full data
    request_status = {"request_full_system_info": REQUEST_FULL_SYSTEM_INFO}
    
    if REQUEST_FULL_SYSTEM_INFO:
        print(f"Server is requesting system info from agent...")
    
    return jsonify(request_status)

@app.route("/sendinfo", methods=['POST'])
def sendinfo():
    """
    Route where the agent sends the compliance data.
    """
    global REQUEST_FULL_SYSTEM_INFO
    
    try:
        # Get the data sent by the agent (it's JSON)
        agent_data = request.json
        
        # --- 1. Display Data in Proper Format ---
        print("\n" + "="*50)
        print(f"✅ Received System Info from Agent at {datetime.now().strftime('%H:%M:%S')}:")
        # Use json.dumps for pretty printing the JSON data to the console
        pretty_data = json.dumps(agent_data, indent=2)
        print(pretty_data)
        print("="*50 + "\n")
        
        # --- 2. Save Data to JSON File ---
        save_data_to_json(agent_data)
        
        # --- 3. Update Server State ---
        # Crucial: Reset the flag so the agent doesn't immediately send data again
        REQUEST_FULL_SYSTEM_INFO = False 
        
        # Respond to the agent
        return jsonify({"status": "Info received", "message": "Thank you. Flag reset for next request."}), 200

    except Exception as e:
        print(f"An error occurred while receiving data: {e}")
        return jsonify({"status": "Error", "message": str(e)}), 400

if __name__ == '__main__':
    # Start the server and show the IP/Port
    ip = get_ip_address()
    port = 5000
    print(f"\n🚀 Server running on: http://{ip}:{port}")
   # print(f"💡 You can trigger a new collection by setting REQUEST_FULL_SYSTEM_INFO = True in the code or via a separate admin route (not implemented here).")
    app.run(host='0.0.0.0', port=port, debug=False)