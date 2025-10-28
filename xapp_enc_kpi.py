import pickle
import socket
import time
import threading
import pandas as pd
import json
from concrete.ml.deployment import FHEModelClient
import sys
import sqlite3

# Listen on all available interfaces for the UPF connection
LISTENING_IP = "0.0.0.0"
LISTENING_PORT = 8080

# FHE model details
MODEL_PATH = "./fhe_model_2_estimators_2_depth/"
PREPROCESSOR_PATH = './preprocessor.pkl'

# --- Database constants ---
DB_NAME = "messages.db"
POLLING_INTERVAL = 1  # Seconds to wait between polling 

def setup_database(db_name):
    """Creates the necessary SQLite tables if they don't exist."""
    print(f"[INFO] Setting up database: {db_name}")
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            
            # Table for messages FROM orchestrator TO xApp (Function Y)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sst INTEGER NOT NULL,
                sd INTEGER NOT NULL,
                encrypted_input BLOB,
                encrypted_prediction_result BLOB,
                anomaly_percentage REAL,
                status INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """)

            conn.commit()
            print("[INFO] Database table 'messages' is ready.")
    except sqlite3.Error as e:
        print(f"[ERROR] Failed to set up database: {e}")
        sys.exit(1)

def load_fhe_client():
    """Loads the FHE client."""
    try:
        print("[INFO] Loading FHE client ...")
        fhe_model_client = FHEModelClient(MODEL_PATH)
        return fhe_model_client
    except Exception as e:
        print(f"[ERROR] Could not load FHE model: {e}")
        sys.exit(1)

def decipher_model_response(encrypted_data, conn, row_id, fhe_client):
    print(f"[DB_RECV] Processing job {row_id} with {len(encrypted_data)} encrypted bytes from DB.")
    try:
        result = fhe_client.deserialize_decrypt_dequantize(encrypted_data)

        try:
            conn.execute("""
                UPDATE messages
                SET anomaly_percentage = ?,
                    status = 2
                WHERE id = ?
            """, (result[0][1], row_id))
            conn.commit()
        except Exception as e:
            print(f"[ERROR] Failed to write prediction result for job {row_id}: {e}")
    except Exception as e:
        print(f"[ERROR] Failed to decrypt message from xApp: {e}")
        raise

def send_cipher_to_xapp(flow_data_json, fhe_client, conn, preprocessor):
    print(f"[UPF_RECV] Received from UPF: {flow_data_json[:70]}...") # Log truncated message
    
    try:
        flow_data = json.loads(flow_data_json)

        df = pd.DataFrame([flow_data])
        sst = int(df["sst"].iloc[0])
        sd = int(df["sd"].iloc[0])
        df_for_model = df.drop(columns=['sst', 'sd'])

        model_input = preprocessor.transform(df_for_model).toarray()
        encrypted_input = fhe_client.quantize_encrypt_serialize(model_input)

        try:
            print(f"[DB_WRITE_TO_XAPP] Writing upf data to database.")
            conn.execute("""
                INSERT INTO messages (sst, sd, encrypted_input, status) 
                VALUES (?, ?, ?, 0)
            """, (sst, sd, encrypted_input))
            conn.commit()
        except Exception as e:
            print(f"[ERROR] Failed to write message to database for xApp: {e}")

    except json.JSONDecodeError:
        print(f"[ERROR] Received invalid JSON data from UPF: {flow_data_json}")
        return
    except KeyError as e:
        print(f"[ERROR] Missing expected key in UPF flow data: {e}")
        return
    except Exception as e:
        print(f"[ERROR] Error in FHE processing (function_Y): {e}")
        return

def listen_to_upf(upf_conn, fhe_client, preprocessor):
    print("[INFO] UPF listener thread started.")
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        with upf_conn, upf_conn.makefile('r') as fileobj:
            while True:
                line = fileobj.readline()
                if not line:
                    print("[INFO] UPF disconnected.")
                    break
                send_cipher_to_xapp(line.strip(), fhe_client, conn, preprocessor)

    except (IOError, socket.error) as e:
        print(f"[INFO] UPF connection error: {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled error in UPF listener: {e}")
    finally:
        if conn:
            conn.close()
        print("[INFO] UPF listener thread stopped.")

def listen_to_xapp(fhe_client):
    """Worker thread to listen for messages from xApp."""
    print("[INFO] xApp listener thread started.")
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row

        while True:
            row_to_process = None
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT id,
                            sst,
                            sd,
                            encrypted_prediction_result
                        FROM messages
                        WHERE status = 1
                        ORDER BY timestamp
                        LIMIT 1
                    """)
                    row_to_process = cursor.fetchone()
            except sqlite3.Error as e:
                print(f"[ERROR] DB transaction error in KPI xApp: {e}")

            if row_to_process:
                print(f"[DB_RECV_FROM_XAPP] Found job id {row_to_process['id']}. Setting to 'pending'.")
                try:
                    decipher_model_response(
                        bytes(row_to_process['encrypted_prediction_result']), 
                        conn,
                        row_to_process['id'], 
                        fhe_client
                    )
                except Exception as e:
                    print(f"[ERROR] Failed during job processing for {row_to_process['id']}: {e}")
                    raise
            else:
                time.sleep(POLLING_INTERVAL)

    except sqlite3.Error as e:
        print(f"[INFO] xApp listener DB error: {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled error in xApp listener: {e}")
    finally:
        if conn:
            conn.close()
        print("[INFO] xApp listener thread stopped.")

def load_preprocessor():
    try:
        print("Loading preprocessors...")
        with open(PREPROCESSOR_PATH, "rb") as f:
            preprocessor = pickle.load(f)
            return preprocessor
        print("preprocessors loaded successfully.")
    except FileNotFoundError:
        print(f"ERROR: preprocessor files not found. Make sure '{PREPROCESSOR_PATH}' is in the same directory.")
        exit(1)

def main():
    """Main function to set up connections and start listener threads."""

    preprocessor = load_preprocessor()
    fhe_client = load_fhe_client()
    setup_database(DB_NAME)

    upf_conn = None
    server_socket = None
    
    upf_thread = None
    xapp_thread = None

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((LISTENING_IP, LISTENING_PORT))
        server_socket.listen(1)
        print(f"[INFO] Orchestrator waiting for UPF connection on {LISTENING_IP}:{LISTENING_PORT}...")
        
        upf_conn, addr = server_socket.accept()
        print(f"[INFO] UPF connected from {addr}")

        # 3. Start listener threads for both connections
        upf_thread = threading.Thread(target=listen_to_upf, args=(upf_conn, fhe_client, preprocessor))
        xapp_thread = threading.Thread(target=listen_to_xapp, args=(fhe_client, ))
        
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
        if upf_conn:
            upf_conn.close()
        if server_socket:
            server_socket.close()
        if upf_thread and upf_thread.is_alive():
            upf_thread.join(1)
        if xapp_thread and xapp_thread.is_alive():
            xapp_thread.join(1)

        print("[INFO] Shutdown complete.")

if __name__ == "__main__":
    main()

