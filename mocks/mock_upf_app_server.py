import socket
import time
import json
import random
import pandas as pd
import pickle

# Orchestrator's address and port
ORCHESTRATOR_IP = "127.0.0.1"
ORCHESTRATOR_PORT = 8080

PREPROCESSOR_PATH = './preprocessor.pkl'

# --- LOAD PRE-TRAINED ML COMPONENTS ---
# These must be loaded once at the start for efficiency.
try:
    print("Loading preprocessors...")
    with open(PREPROCESSOR_PATH, "rb") as f:
        preprocessor = pickle.load(f)
    print("preprocessors loaded successfully.")
except FileNotFoundError:
    print(f"ERROR: preprocessor files not found. Make sure '{PREPROCESSOR_PATH}' is in the same directory.")
    exit(1)


def create_mock_flow_data():
    """Generates a sample JSON string for the UPF flow data."""
    data = {
        "sst": 1,
        "sd": 1,
        "protocol_type": "tcp",
        "service": "http",
        "dst_bytes": random.randint(200, 1400),
        "src_bytes": random.randint(200, 1400)
    }
    return json.dumps(data)

def main():
    print("[MOCK_UPF] Starting UPF client...")
    
    try:
        # Create a socket and connect to the orchestrator
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ORCHESTRATOR_IP, ORCHESTRATOR_PORT))
            print(f"[MOCK_UPF] Connected to orchestrator at {ORCHESTRATOR_IP}:{ORCHESTRATOR_PORT}")

            # Send 5 mock data packets, one every 3 seconds
            for _ in range(5):
                raw = create_mock_flow_data()

                print(f"[MOCK_UPF] Sending data: {raw}")

                s.sendall(f"{raw}\n".encode())
                time.sleep(3) # Wait before sending the next packet

            print("[MOCK_UPF] Finished sending data. Closing connection.")

    except socket.error as e:
        print(f"[MOCK_UPF] Connection error: {e}")
        print("[MOCK_UPF] Is the orchestrator (xapp_enc_kpi_patched.py) running?")
    except Exception as e:
        print(f"[MOCK_UPF] An error occurred: {e}")

if __name__ == "__main__":
    main()
