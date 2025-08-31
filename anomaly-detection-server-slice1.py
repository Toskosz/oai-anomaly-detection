import socket
import os
import base64
from concrete.ml.deployment import FHEModelServer

# --- Configuration ---
LISTENING_IP = "0.0.0.0"
LISTENING_PORT = 9000  # Must match ADS_PORT in ork.py
MODEL_PATH = "./kdcup-models/fhe_model_4_estimators_4_depth/"

def recv_all(sock, n):
    """Helper function to receive n bytes from a socket."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def handle_client(conn, addr, fhe_model_server, eval_keys):
    """Handles a single client connection."""
    print(f"[INFO] Connection from {addr}")
    try:
        # Receive encrypted input
        size_bytes = recv_all(conn, 8)
        if not size_bytes:
            print("[WARNING] Client disconnected before sending input size.")
            return
        input_size = int.from_bytes(size_bytes, 'big')
        encrypted_input = recv_all(conn, input_size)
        if not encrypted_input:
            print("[WARNING] Client disconnected before sending input.")
            return

        # Run FHE prediction using keys from environment
        print(f"[INFO] Running FHE prediction for {addr}...")
        encrypted_output = fhe_model_server.run(encrypted_input, eval_keys)
        print(f"[INFO] Prediction complete for {addr}.")

        # Send back encrypted output
        conn.sendall(len(encrypted_output).to_bytes(8, 'big'))
        conn.sendall(encrypted_output)
        print(f"[INFO] Sent prediction to {addr}")

    except Exception as e:
        print(f"[ERROR] An error occurred while handling client {addr}: {e}")
    finally:
        print(f"[INFO] Closing connection from {addr}")
        conn.close()

def main():
    """Main function to load the model and start the server."""
    print("[INFO] Loading FHE evaluation keys from environment variable...")
    encoded_keys = os.getenv("FHE_EVALUATION_KEYS")
    if not encoded_keys:
        print("[ERROR] FHE_EVALUATION_KEYS environment variable not set.")
        exit(1)
    
    try:
        eval_keys = base64.b64decode(encoded_keys)
        print("[INFO] FHE evaluation keys loaded and decoded successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to decode Base64 keys: {e}")
        exit(1)

    print("[INFO] Loading FHE model server...")
    try:
        fhe_model_server = FHEModelServer(MODEL_PATH)
        fhe_model_server.load()
        print("[INFO] FHE model server loaded successfully.")
    except Exception as e:
        print(f"[ERROR] Could not load FHE model server: {e}")
        exit(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((LISTENING_IP, LISTENING_PORT))
        server_socket.listen()
        print(f"[INFO] ADS server listening on {LISTENING_IP}:{LISTENING_PORT}...")

        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr, fhe_model_server, eval_keys)

if __name__ == "__main__":
    main()
