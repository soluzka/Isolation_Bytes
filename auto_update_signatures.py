import threading
import time
import logging
from update_signatures import update_signatures

UPDATE_INTERVAL_HOURS = 24  # Set to 24 for daily updates, or adjust as needed


def auto_update_loop():
    while True:
        try:
            logging.info("[AUTO-UPDATE] Starting automatic signature update...")
            update_signatures()
            logging.info("[AUTO-UPDATE] Signature update completed successfully.")
        except Exception as e:
            logging.error(f"[AUTO-UPDATE] Signature update failed: {e}")
        time.sleep(UPDATE_INTERVAL_HOURS * 3600)


def start_auto_update_thread():
    t = threading.Thread(target=auto_update_loop, daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    start_auto_update_thread()
    while True:
        time.sleep(3600)  # Keep main thread alive
