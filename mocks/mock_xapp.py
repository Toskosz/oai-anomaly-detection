from typing import cast
import sqlite3
import time
from concrete.ml.deployment import FHEModelServer, FHEModelClient

MODEL_PATH = "fhe_model_2_estimators_2_depth/"

DB_NAME = "xapp_comm.db"
POLLING_INTERVAL = 1 # Poll every 2 seconds

def process_jobs(fhe_server, keys):
    """
    Simulates the external xApp.
    - Polls the DB for jobs with status 0.
    - "Processes" them (copies input to output).
    - Updates their status to 1.
    """
    print("[MOCK_XAPP] xApp worker started. Polling database...")
    
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        conn.row_factory = sqlite3.Row

        while True:
            row_to_process = None
            try:
                # 1. Find a job with status 0
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT id, encrypted_input
                        FROM messages
                        WHERE status = 0
                        ORDER BY timestamp
                        LIMIT 1
                    """)
                    row_to_process = cursor.fetchone()

            except sqlite3.Error as e:
                print(f"[MOCK_XAPP] DB read error: {e}")
                time.sleep(POLLING_INTERVAL)
                continue # Skip this loop iteration

            if row_to_process:
                job_id = row_to_process['id']
                print(f"[MOCK_XAPP] Found job {job_id} with status 0. Processing...")
                
                # 2. "Process" the data.
                # In a real app, FHE operations would happen here.
                # We will just copy the 'encrypted_input' to 'encrypted_prediction_result'
                # to simulate that a result has been generated.
                # mock_result_data = row_to_process['encrypted_input']
                enc_output = fhe_server.run(bytes(row_to_process['encrypted_input']), bytes(keys))
                
                try:
                    # 3. Update the row with the result and set status to 1
                    with conn:
                        conn.execute("""
                            UPDATE messages
                            SET encrypted_prediction_result = ?,
                                status = 1
                            WHERE id = ?
                        """, (enc_output, job_id))
                        conn.commit()
                    print(f"[MOCK_XAPP] Finished processing job {job_id}. Set status to 1.")
                
                except sqlite3.Error as e:
                    print(f"[MOCK_XAPP] DB write error for job {job_id}: {e}")
            
            else:
                # No jobs found, wait
                print("[MOCK_XAPP] No jobs with status 0 found. Waiting...")
                time.sleep(POLLING_INTERVAL)

    except sqlite3.Error as e:
        print(f"[MOCK_XAPP] Database connection error: {e}")
    except KeyboardInterrupt:
        print("\n[MOCK_XAPP] Shutting down worker.")
    finally:
        if conn:
            conn.close()
        print("[MOCK_XAPP] Worker stopped.")

if __name__ == "__main__":
    # the server should get the keys some other way
    fhe_client = FHEModelClient(MODEL_PATH)
    serialized_evaluation_keys = cast(bytes, fhe_client.get_serialized_evaluation_keys())

    fhe_server = FHEModelServer(MODEL_PATH)
    fhe_server.load()

    process_jobs(fhe_server, serialized_evaluation_keys)
