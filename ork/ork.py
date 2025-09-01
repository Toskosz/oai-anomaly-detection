import socket
import time
import pickle
import threading
import pandas as pd
import json
from concrete.ml.deployment import FHEModelClient

LISTENING_IP = "127.0.0.1"
LISTENING_PORT = 8585

ADS_IP = "127.0.0.1"
ADS_PORT = 9000

XAPP_IP = "127.0.0.1"
XAPP_PORT = 8080

# Slice details
SST = 1
SD = 1

# FHE model details
MODEL_PATH = "./fhe_model_2_estimators_2_depth/"
PREPROCESSOR_PATH = "./preprocessor.pkl"

# --- Global Variables ---
normal_count = 0
anomaly_count = 0
count_lock = threading.Lock()

def load_fhe_client_and_preprocessor():
    """Loads the FHE client and the preprocessor."""
    try:
        print("[INFO] Loading FHE client and preprocessor...")
        fhe_model_client = FHEModelClient(MODEL_PATH)
        with open(PREPROCESSOR_PATH, "rb") as f:
            preprocessor = pickle.load(f)
        print("[INFO] FHE client and preprocessor loaded successfully.")
        return preprocessor, fhe_model_client
    except Exception as e:
        print(f"[ERROR] Could not load FHE model or preprocessor: {e}")
        exit(1)

def recv_all(sock, n):
    """Helper function to receive n bytes from a socket."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def get_fhe_prediction(encrypted_input):
    """Sends encrypted data to the ADS server and returns the encrypted prediction."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ADS_IP, ADS_PORT))
            
            # Send encrypted input
            s.sendall(len(encrypted_input).to_bytes(8, 'big'))
            s.sendall(encrypted_input)

            # Receive the size of the encrypted output
            size_bytes = recv_all(s, 8)
            if not size_bytes:
                return None
            size = int.from_bytes(size_bytes, 'big')

            # Receive the encrypted output
            encrypted_output = recv_all(s, size)
            if encrypted_output is not None:
                return bytes(encrypted_output)
            return None

    except Exception as e:
        print(f"[ERROR] Could not communicate with ADS server: {e}")
        return None

def flow_processing(flow_data_json, preprocessor, fhe_client):
    """Processes a single flow: feature extraction, FHE encryption, prediction, and counting."""
    global normal_count, anomaly_count

    try:
        flow_data = json.loads(flow_data_json)
        df = pd.DataFrame([flow_data])

        X_processed = preprocessor.transform(df).toarray()
        encrypted_input = fhe_client.quantize_encrypt_serialize(X_processed)

        # Get prediction from ADS server
        encrypted_output = get_fhe_prediction(encrypted_input)

        if encrypted_output:
            result = fhe_client.deserialize_decrypt_dequantize(encrypted_output)
            prediction = 1 if result[0][1] > 0.5 else 0

            with count_lock:
                if prediction == 0:
                    normal_count += 1
                else:
                    anomaly_count += 1
    except json.JSONDecodeError:
        print(f"[ERROR] Received invalid JSON data: {flow_data_json}")
    except KeyError as e:
        print(f"[ERROR] Missing expected key in flow data: {e}")

def send_stats_to_xapp(sock):
    """Periodically sends anomaly statistics to the xApp."""
    global normal_count, anomaly_count
    while True:
        time.sleep(5)
        with count_lock:
            message = f"sst:{SST},sd:{SD},normal:{normal_count},anomaly:{anomaly_count}"
            try:
                sock.sendall(message.encode())
                print(f"[INFO] Sent to xApp: {message}")
            except Exception as e:
                print(f"[ERROR] Failed to send stats to xApp: {e}")
                return
            normal_count = 0
            anomaly_count = 0

def main():
    """Main function to set up connections and start listening for flows."""
    preprocessor, fhe_client = load_fhe_client_and_preprocessor()

    xapp_sock = None
    while True:
        try:
            print(f"[INFO] Connecting to xApp at {XAPP_IP}:{XAPP_PORT}...")
            xapp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            xapp_sock.connect((XAPP_IP, XAPP_PORT))
            print("[INFO] Connected to xApp.")
            break
        except socket.error as e:
            print(f"[ERROR] Socket error when connecting to xApp: {e}. Retrying in 5 seconds...")
            time.sleep(5)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((LISTENING_IP, LISTENING_PORT))
        server_socket.listen(1)
        print(f"[INFO] Orchestrator waiting for UPF connection on {LISTENING_IP}:{LISTENING_PORT}...")
        
        conn, addr = server_socket.accept()
        print(f"[INFO] UPF connected from {addr}")

        stats_thread = threading.Thread(target=send_stats_to_xapp, args=(xapp_sock,))
        stats_thread.daemon = True
        stats_thread.start()

        with conn:
            fileobj = conn.makefile('r')
            while True:
                line = fileobj.readline()
                if not line:
                    break
                flow_processing(line.strip(), preprocessor, fhe_client)

    print("[INFO] UPF disconnected. Shutting down.")
    xapp_sock.close()

if __name__ == "__main__":
    main()
