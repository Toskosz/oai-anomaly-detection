
import socket
import time
import threading
import pandas as pd
import json
from concrete.ml.deployment import FHEModelClient
import sys

# Listen on all available interfaces for the UPF connection
LISTENING_IP = "0.0.0.0"
LISTENING_PORT = 8080

# xApp/App server details
XAPP_IP = "192.168.70.1"
XAPP_PORT = 8081

# FHE ADS Server details (PLACEHOLDER - Configure as needed)
ADS_IP = "127.0.0.1"
ADS_PORT = 9000

# FHE model details
MODEL_PATH = "./fhe_model_2_estimators_2_depth/"


def load_fhe_client():
    """Loads the FHE client."""
    try:
        print("[INFO] Loading FHE client ...")
        fhe_model_client = FHEModelClient(MODEL_PATH)
        return fhe_model_client
    except Exception as e:
        print(f"[ERROR] Could not load FHE model: {e}")
        sys.exit(1)


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
        # Use a new socket for each prediction request
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ADS_IP, ADS_PORT))
            
            # Send encrypted input
            s.sendall(len(encrypted_input).to_bytes(8, 'big'))
            s.sendall(encrypted_input)

            # Receive the size of the encrypted output
            size_bytes = recv_all(s, 8)
            if not size_bytes:
                print("[ERROR] Did not receive size from ADS server.")
                return None
            size = int.from_bytes(size_bytes, 'big')

            # Receive the encrypted output
            encrypted_output = recv_all(s, size)
            if encrypted_output is not None:
                return bytes(encrypted_output)
            
            print("[ERROR] Did not receive encrypted output from ADS server.")
            return None

    except socket.error as e:
        print(f"[ERROR] Socket error communicating with ADS server: {e}")
        return None
    except Exception as e:
        print(f"[ERROR] Could not communicate with ADS server: {e}")
        return None

def send_decipher_model_response(encrypted_data, xapp_sock, fhe_client):
    """
    Handles encrypted messages received from the xApp (Function X).
    Receives encrypted data, decrypts it, and sends the result back.
    """
    print(f"[XAPP_RECV] Received {len(encrypted_data)} encrypted bytes from xApp.")
    
    # --- Start of Function X logic ---
    response_bytes = b''
    try:
        # Decrypt the data received from the xApp
        result = fhe_client.deserialize_decrypt_dequantize(encrypted_data)
        
        # Convert numpy array to list for JSON serialization
        result_list = result.tolist()
        response_json = json.dumps(result_list)
        response_bytes = response_json.encode('utf-8')
        print(f"[INFO] Decrypted message from xApp. Result: {response_json}")

    except Exception as e:
        print(f"[ERROR] Failed to decrypt message from xApp: {e}")
        response_json = json.dumps({"error": f"Failed to decrypt: {e}"})
        response_bytes = response_json.encode('utf-8')
    # --- End of Function X logic ---
    
    try:
        print(f"[XAPP_SEND] Sending decrypted response ({len(response_bytes)} bytes) to xApp.")
        # Send the response back with a length prefix
        xapp_sock.sendall(len(response_bytes).to_bytes(8, 'big'))
        xapp_sock.sendall(response_bytes)
    except Exception as e:
        print(f"[ERROR] Failed to send response to xApp: {e}")

def function_Y(flow_data_json, fhe_client, xapp_sock):
    """
    Processes a message from the UPF (Function Y).
    This involves FHE encryption, getting a prediction,
    and sending the *encrypted prediction* to the xApp.
    """
    print(f"[UPF_RECV] Received from UPF: {flow_data_json[:70]}...") # Log truncated message
    
    # --- Start of Function Y logic ---
    try:
        pre_processed_flow_data = json.loads(flow_data_json)
        df = pd.DataFrame([pre_processed_flow_data])
        df_for_model = df.drop(columns=['sst', 'sd'])

        # Encrypt the input flow data
        encrypted_input = fhe_client.quantize_encrypt_serialize(df_for_model)

        # Get encrypted prediction from ADS server
        encrypted_output = get_fhe_prediction(encrypted_input)

        if encrypted_output:

            result = fhe_client.deserialize_decrypt_dequantize(encrypted_output)
            prediction = 1 if result[0][1] > 0.5 else 0

            message = f"sst:{df['sst']},sd:{df['sd']},anomaly:{prediction}"

            try:
                print(f"[XAPP_SEND] Sending prediction ({len(message)} bytes) to xApp.")
                # Send with length prefix
                xapp_sock.sendall(message.encode())
            except Exception as e:
                print(f"[ERROR] Failed to send encrypted prediction to xApp: {e}")
        else:
            print("[WARN] No encrypted output received from ADS. Nothing sent to xApp.")

    except json.JSONDecodeError:
        print(f"[ERROR] Received invalid JSON data from UPF: {flow_data_json}")
        return
    except KeyError as e:
        print(f"[ERROR] Missing expected key in UPF flow data: {e}")
        return
    except Exception as e:
        print(f"[ERROR] Error in FHE processing (function_Y): {e}")
        return

def listen_to_upf(upf_conn, fhe_client, xapp_sock):
    """Worker thread to listen for messages from UPF."""
    print("[INFO] UPF listener thread started.")
    try:
        # Use makefile for convenient readline()
        with upf_conn, upf_conn.makefile('r') as fileobj:
            while True:
                line = fileobj.readline()
                if not line:
                    print("[INFO] UPF disconnected.")
                    break
                # Call Function Y
                function_Y(line.strip(), fhe_client, xapp_sock)
    except (IOError, socket.error) as e:
        print(f"[INFO] UPF connection error: {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled error in UPF listener: {e}")
    finally:
        print("[INFO] UPF listener thread stopped.")

def listen_to_xapp(xapp_sock, fhe_client):
    """Worker thread to listen for messages from xApp."""
    print("[INFO] xApp listener thread started.")
    try:
        while True:
            # Receive the size of the encrypted input
            size_bytes = recv_all(xapp_sock, 8)
            if not size_bytes:
                print("[INFO] xApp disconnected (no size bytes).")
                break
            size = int.from_bytes(size_bytes, 'big')

            # Receive the encrypted input
            encrypted_data = recv_all(xapp_sock, size)
            if not encrypted_data:
                print("[INFO] xApp disconnected (no data).")
                break
            
            # Call Function X
            send_decipher_model_response(bytes(encrypted_data), xapp_sock, fhe_client)

    except (IOError, socket.error) as e:
        print(f"[INFO] xApp connection error: {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled error in xApp listener: {e}")
    finally:
        print("[INFO] xApp listener thread stopped.")


def main():
    """Main function to set up connections and start listener threads."""

    fhe_client = load_fhe_client()

    xapp_sock = None
    upf_conn = None
    server_socket = None
    
    upf_thread = None
    xapp_thread = None

    try:
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
            except KeyboardInterrupt:
                print("\n[INFO] Shutdown requested during xApp connection.")
                sys.exit(0)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((LISTENING_IP, LISTENING_PORT))
        server_socket.listen(1)
        print(f"[INFO] Orchestrator waiting for UPF connection on {LISTENING_IP}:{LISTENING_PORT}...")
        
        upf_conn, addr = server_socket.accept()
        print(f"[INFO] UPF connected from {addr}")

        # 3. Start listener threads for both connections
        upf_thread = threading.Thread(target=listen_to_upf, args=(upf_conn, fhe_client, xapp_sock))
        xapp_thread = threading.Thread(target=listen_to_xapp, args=(xapp_sock, fhe_client))
        
        upf_thread.daemon = True
        xapp_thread.daemon = True

        upf_thread.start()
        xapp_thread.start()

        # Keep main thread alive to monitor listener threads
        while upf_thread.is_alive() and xapp_thread.is_alive():
            time.sleep(1)
        
        print("[INFO] A listener thread has stopped. Shutting down.")

    except KeyboardInterrupt:
        print("\n[INFO] Shutdown requested by user.")
    except Exception as e:
        print(f"[ERROR] Main thread encountered an error: {e}")
    finally:
        print("[INFO] Cleaning up and shutting down.")
        if xapp_sock:
            xapp_sock.close()
        if upf_conn:
            upf_conn.close()
        if server_socket:
            server_socket.close()
        
        # Wait for threads to finish
        if upf_thread and upf_thread.is_alive():
            upf_thread.join(1)
        if xapp_thread and xapp_thread.is_alive():
            xapp_thread.join(1)
            
        print("[INFO] Shutdown complete.")

if __name__ == "__main__":
    main()

