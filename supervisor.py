import subprocess
import time
import os
from datetime import datetime

# ----------------------------
# Configuration
# ----------------------------
CAP_DIR = os.environ.get("CAP_DIR", "/captures")
DURATION = 60     # seconds per capture chunk
OVERLAP = 5       # seconds overlap

# Ensure capture directory exists
os.makedirs(CAP_DIR, exist_ok=True)

# ----------------------------
# Helper Functions
# ----------------------------
def current_daily_file():
    """Return filename for current day (YYYYMMDD.pcap)."""
    today = datetime.now().strftime('%Y%m%d')
    return os.path.join(CAP_DIR, f"cap_{today}.pcap")

def start_capture(temp_file):
    """Start tshark process to capture into temp_file."""
    print(f"[INFO] Starting capture: {temp_file}")
    return subprocess.Popen([
        "tshark",
        "-i", "any",
        "-a", f"duration:{DURATION}",
        "-w", temp_file
    ])

def append_to_daily(chunk_file):
    """Append chunk file to daily pcap file safely."""
    daily_file = current_daily_file()
    if os.path.exists(daily_file):
        temp_merge = daily_file + "_tmp.pcap"
        subprocess.run(["mergecap", "-w", temp_merge, daily_file, chunk_file])
        os.replace(temp_merge, daily_file)  # atomically replace
        os.remove(chunk_file)
    else:
        # first chunk of the day
        os.rename(chunk_file, daily_file)
    print(f"[INFO] Appended chunk to daily file: {daily_file}")

# ----------------------------
# Main Supervisor Loop (Two-Slot Overlap)
# ----------------------------
slot = 0
proc_slots = [None, None]  # two slots for overlapping TShark
i = 0
last_day = datetime.now().day

while True:
    temp_fname = os.path.join(CAP_DIR, f"cap_chunk_{i}.pcap")
    # Start capture in current slot
    proc_slots[slot] = (start_capture(temp_fname), temp_fname)
    print(f"[INFO] Slot {slot} capturing chunk #{i}")

    # Wait until next chunk should start
    start_time = time.time()
    while True:
        elapsed = time.time() - start_time
        current_day = datetime.now().day
        if elapsed >= DURATION - OVERLAP or current_day != last_day:
            break
        time.sleep(0.5)

    # Check finished captures and append
    for s in [0, 1]:
        p_tuple = proc_slots[s]
        if p_tuple:
            p, f = p_tuple
            if p.poll() is not None:  # finished
                print(f"[INFO] Slot {s} finished chunk: {f}")
                append_to_daily(f)
                proc_slots[s] = None

    # Switch slot for next chunk
    slot = 1 - slot
    i += 1
    last_day = datetime.now().day
