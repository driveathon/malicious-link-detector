import os
import time
import logging
import threading
from datetime import datetime, timedelta

def run_evidence_janitor(screenshot_dir, max_age_hours=24):
    """
    Background worker to cleanup old screenshots.
    Ensures disk integrity for persistent security nodes.
    """
    logging.info(f"Evidence Janitor initialized. Retention: {max_age_hours}h")
    
    while True:
        try:
            now = time.time()
            cutoff = now - (max_age_hours * 3600)
            
            if not os.path.exists(screenshot_dir):
                time.sleep(3600)
                continue

            for filename in os.listdir(screenshot_dir):
                file_path = os.path.join(screenshot_dir, filename)
                if os.path.isfile(file_path):
                    if os.path.getmtime(file_path) < cutoff:
                        os.remove(file_path)
                        logging.info(f"Janitor: Purged stale asset {filename}")
        except Exception as e:
            logging.error(f"Janitor Error: {e}")
        
        # Run every hour
        time.sleep(3600)

def start_janitor_thread(screenshot_dir):
    thread = threading.Thread(target=run_evidence_janitor, args=(screenshot_dir,), daemon=True)
    thread.start()
    return thread
