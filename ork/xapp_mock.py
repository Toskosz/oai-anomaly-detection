import socket
import time

# This mock server will pretend to be the xApp.
# Note: You may need to change the XAPP_IP in ork.py to "127.0.0.1" to connect to this mock server.

LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 8080

def main():
    """Main function to run the mock xApp server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_IP, LISTEN_PORT))
        s.listen(1)
        print(f"[INFO] Mock xApp waiting for connection on {LISTEN_IP}:{LISTEN_PORT}...")
        
        conn, addr = s.accept()
        print(f"[INFO] Orchestrator connected from {addr}")

        with conn:
            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        print("[INFO] Connection closed by orchestrator.")
                        break
                    print(f"[INFO] Received from orchestrator: {data.decode()}")
                except ConnectionResetError:
                    print("[INFO] Connection reset by orchestrator.")
                    break

if __name__ == "__main__":
    main()
