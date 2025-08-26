
import socket
import pickle
import threading
from concrete.ml.deployment import FHEModelServer

# -- Load FHE model server --
server = FHEModelServer("notebooks/server.zip")

# -- Network configuration --
ADS_IP = '0.0.0.0'
ADS_PORT = 8082

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            
            encrypted_features = pickle.loads(data)
            
            # FHE inference
            encrypted_prediction = server.run(encrypted_features)
            
            conn.sendall(pickle.dumps(encrypted_prediction))

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ads_sock:
        ads_sock.bind((ADS_IP, ADS_PORT))
        ads_sock.listen()
        print(f"ADS server listening on {ADS_IP}:{ADS_PORT}")
        while True:
            conn, addr = ads_sock.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()

if __name__ == "__main__":
    main()
