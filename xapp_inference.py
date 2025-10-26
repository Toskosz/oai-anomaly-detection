from typing import cast
import time
from concrete.ml.deployment import FHEModelServer, FHEModelClient
import sqlite3

MODEL_PATH = "./fhe_model_2_estimators_2_depth/"
DB_NAME = "xapp_comm.db"
POLLING_INTERVAL = 1

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

def predict(fhe_server, keys, row_id, encrypted_input):
    # Process the encrypted input and get the encrypted output
    encrypted_output = fhe_server.run(bytes(encrypted_input), bytes(keys))
    serialized_encrypted_output = serialize_encrypted_prediction(encrypted_output)

    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("""
                UPDATE messages
                SET data = ?,
                    status = 1
                WHERE id = ?
            """, (serialized_encrypted_output, row_id))
            conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to write to 'predictions' table for job {row_id}: {e}")

def main():
    # the server should get the keys some other way
    fhe_client = FHEModelClient(MODEL_PATH)
    serialized_evaluation_keys = cast(bytes, fhe_client.get_serialized_evaluation_keys())

    fhe_server = FHEModelServer(MODEL_PATH)
    fhe_server.load()

    print("[INFO] FHE server loaded.")

    try:
        while True:
            row_to_process = None
            try:
                with sqlite3.connect(DB_NAME) as conn:
                    conn.row_factory = sqlite3.Row
                    with conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT id,
                                data
                            FROM messages
                            WHERE status = 0
                            ORDER BY timestamp
                            LIMIT 1
                        """)
                        row_to_process = cursor.fetchone()
                        if row_to_process:
                            print(f"[DB_RECV_FROM_XAPP] Found job id {row_to_process['id']}.")
            except sqlite3.Error as e:
                print(f"[ERROR] DB transaction error in Inference xApp: {e}")

            if row_to_process:
                try:
                    predict(fhe_server, serialized_evaluation_keys, row_to_process["id"], row_to_process["data"])
                except Exception as e:
                    print(f"[ERROR] Failed during job processing for {row_to_process['id']}: {e}")
            else:
                time.sleep(POLLING_INTERVAL)

    except sqlite3.Error as e:
        print(f"[INFO] Inference xApp DB error: {e}")
    except Exception as e:
        print(f"[ERROR] Unhandled error in Inference xApp: {e}")

