import socket
from typing import cast
from concrete.ml.deployment import FHEModelServer, FHEModelClient

# This mock server will pretend to be the Anomaly Detection System (ADS).

LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 9000
MODEL_PATH = "./fhe_model_2_estimators_2_depth/"

def recv_all(sock, n):
    """Helper function to receive n bytes from a socket."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def serialize_encrypted_prediction(encrypted_prediction):
    """Serializes the encrypted prediction to bytes."""
    if isinstance(encrypted_prediction, tuple):
        # Assuming a tuple of bytes-like objects, concatenate them.
        # This might need a more sophisticated serialization if the client expects it.
        return b"".join(bytes(item) for item in encrypted_prediction)
    if hasattr(encrypted_prediction, 'value'):
        # For multiprocessing.sharedctypes.Value
        return encrypted_prediction.value
    return bytes(encrypted_prediction)

def main():
    """Main function to run the mock ADS server."""
    fhe_model_client = FHEModelClient(MODEL_PATH)
    serialized_evaluation_keys = cast(bytes, fhe_model_client.get_serialized_evaluation_keys())
    print("[INFO] Loading FHE server ...")
    server = FHEModelServer(MODEL_PATH)
    server.load()
    print("[INFO] FHE server loaded.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_IP, LISTEN_PORT))
        s.listen(1)
        print(f"[INFO] Mock ADS waiting for connection on {LISTEN_IP}:{LISTEN_PORT}...")

        while True:
            conn, addr = s.accept()
            print(f"[INFO] Orchestrator connected from {addr}")

            with conn:
                # Receive the size of the encrypted input
                size_bytes = recv_all(conn, 8)
                if not size_bytes:
                    print("[INFO] Connection closed before receiving size.")
                    continue
                size = int.from_bytes(size_bytes, 'big')
                print(f"[INFO] Receiving {size} bytes from orchestrator...")

                # Receive the encrypted input
                encrypted_input = recv_all(conn, size)
                if not encrypted_input:
                    print("[INFO] Connection closed before receiving data.")
                    continue
                
                print(f"[INFO] Received {len(encrypted_input)} bytes. Running FHE inference...")

                # Process the encrypted input and get the encrypted output
                encrypted_output = server.run(bytes(encrypted_input), bytes(serialized_evaluation_keys ))
                serialized_encrypted_output = serialize_encrypted_prediction(encrypted_output)

                # Send back the encrypted output
                print(f"[INFO] Sending response of {len(serialized_encrypted_output)} bytes.")
                conn.sendall(len(serialized_encrypted_output).to_bytes(8, 'big'))
                conn.sendall(serialized_encrypted_output)
            print("[INFO] Mock ADS finished handling a connection.")

if __name__ == "__main__":
    main()
