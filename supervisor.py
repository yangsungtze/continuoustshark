import os
import time
import subprocess
from datetime import datetime
from multiprocessing import Process, Event
import shutil

# ---------------- Configuration ----------------
OUTPUT_DIR = "/captures"
TEMP_DIR = "/captures/tmp"
CAP_DURATION = 60       # TShark capture duration in seconds
WAIT_AFTER_FINISH = 2   # seconds
MERGE_RETRIES = 5
MERGE_DELAY = 2
stop_event = Event()

# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# ---------------- TShark Process ----------------
def run_tshark(stop_event):
    """Continuously run TShark every CAP_DURATION seconds."""
    while not stop_event.is_set():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_file = os.path.join(TEMP_DIR, f"cap_temp_{timestamp}.pcapng")
        cmd = ["tshark", "-i", "any", "-a", f"duration:{CAP_DURATION}", "-w", temp_file]
        proc = subprocess.Popen(cmd)
        while proc.poll() is None and not stop_event.is_set():
            time.sleep(1)
        if proc.poll() is None:
            proc.terminate()
            proc.wait()
        print(f"[TShark] Finished {temp_file}")

# ---------------- Supervisor Utilities ----------------
def get_first_last_time(pcap_file):
    """Return first and last frame timestamps as datetime objects."""
    frames = subprocess.check_output(
        ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.time_epoch"],
        text=True
    ).strip().splitlines()
    if not frames:
        return None, None
    first_time = datetime.fromtimestamp(float(frames[0]))
    last_time = datetime.fromtimestamp(float(frames[-1]))
    return first_time, last_time

def safe_merge(hour_file, temp_file, retries=MERGE_RETRIES, delay=MERGE_DELAY):
    """Merge temp_file into hour_file with retry mechanism."""
    for attempt in range(retries):
        try:
            subprocess.run(["mergecap", "-w", hour_file, hour_file, temp_file], check=True)
            print(f"[Supervisor] Merged {temp_file} → {hour_file}")
            os.remove(temp_file)
            return True
        except subprocess.CalledProcessError:
            print(f"[WARN] Merge failed for {temp_file}, retrying in {delay}s ({attempt+1}/{retries})")
            time.sleep(delay)
    print(f"[ERROR] Could not merge {temp_file} after {retries} attempts.")
    return False

def merge_temp_file(temp_file):
    """Merge a finished temp file into hourly files, splitting across hours if needed."""
    time.sleep(WAIT_AFTER_FINISH)
    first_time, last_time = get_first_last_time(temp_file)
    if first_time is None:
        os.remove(temp_file)
        return

    # Check if temp file spans multiple hours
    if first_time.hour != last_time.hour or first_time.date() != last_time.date():
        # Split by hour using editcap -i 3600
        split_dir = os.path.join(TEMP_DIR, "split")
        os.makedirs(split_dir, exist_ok=True)
        subprocess.run([
            "editcap", "-F", "pcapng", "-i", "3600", temp_file,
            os.path.join(split_dir, "split.pcapng")
        ], check=True)
        os.remove(temp_file)
        # Merge each split piece recursively
        for f in sorted(os.listdir(split_dir)):
            split_file = os.path.join(split_dir, f)
            merge_temp_file(split_file)
        shutil.rmtree(split_dir)
        return

    # Merge into correct hour file
    hour_key = first_time.strftime("%Y%m%d_%H")
    hour_file = os.path.join(OUTPUT_DIR, f"cap_{hour_key}.pcapng")
    if os.path.exists(hour_file):
        safe_merge(hour_file, temp_file)
    else:
        os.rename(temp_file, hour_file)
        print(f"[Supervisor] Created new hour file {hour_file}")

# ---------------- Supervisor Loop ----------------
def supervisor_loop(stop_event):
    """Continuously monitor TEMP_DIR and merge completed temp files."""
    processed = set()
    while not stop_event.is_set():
        files = sorted(f for f in os.listdir(TEMP_DIR) if f.endswith(".pcapng"))
        if len(files) < 2:
            time.sleep(1)
            continue
        # Only merge previous files; skip last file (possibly still writing)
        for f in files[:-1]:
            temp_file = os.path.join(TEMP_DIR, f)
            if temp_file not in processed:
                merge_temp_file(temp_file)
                processed.add(temp_file)
        time.sleep(1)

# ---------------- Main ----------------
def main():
    tshark_proc = Process(target=run_tshark, args=(stop_event,))
    sup_proc = Process(target=supervisor_loop, args=(stop_event,))

    tshark_proc.start()
    sup_proc.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()

    print("[Main] Stopping processes...")
    tshark_proc.terminate()
    sup_proc.terminate()
    tshark_proc.join()
    sup_proc.join()
    print("[Main] Exited gracefully.")

if __name__ == "__main__":
    main()
