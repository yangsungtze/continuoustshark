import os
import time
import subprocess
from datetime import datetime
from multiprocessing import Process, Event, Manager
import shutil

# ---------------- Configuration ----------------
OUTPUT_DIR = "/captures"
TEMP_DIR = "/captures/tmp"
CAP_DURATION = 60       # TShark capture duration in seconds
WAIT_AFTER_FINISH = 2   # seconds before merging
MERGE_RETRIES = 5
MERGE_DELAY = 2
stop_event = Event()

# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# ---------------- TShark Process ----------------
def run_tshark(stop_event, last_temp_holder):
    """Continuously run TShark every CAP_DURATION seconds."""
    while not stop_event.is_set():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_file = os.path.join(TEMP_DIR, f"cap_temp_{timestamp}.pcapng")
        last_temp_holder['file'] = temp_file  # Store last temp file
        cmd = ["tshark", "-i", "any", "-a", f"duration:{CAP_DURATION}", "-w", temp_file]
        proc = subprocess.Popen(cmd)
        while proc.poll() is None and not stop_event.is_set():
            time.sleep(0.1)
        if proc.poll() is None:
            proc.terminate()
            proc.wait()
        print(f"[TShark] Finished {temp_file}")

# ---------------- Supervisor Utilities ----------------
def get_first_last_time(pcap_file):
    """Return first and last frame timestamps as datetime objects."""
    try:
        frames = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.time_epoch"],
            text=True
        ).strip().splitlines()
        if not frames:
            return None, None
        first_time = datetime.fromtimestamp(float(frames[0]))
        last_time = datetime.fromtimestamp(float(frames[-1]))
        return first_time, last_time
    except Exception as e:
        print(f"[WARN] Failed to get frame times: {e}")
        return None, None

def safe_merge(hour_file, temp_file, retries=MERGE_RETRIES, delay=MERGE_DELAY, initial_wait=WAIT_AFTER_FINISH):
    """Merge temp_file into hour_file with retry mechanism and initial wait."""
    time.sleep(initial_wait)  # initial wait only once
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
    first_time, last_time = get_first_last_time(temp_file)
    if first_time is None:
        os.remove(temp_file)
        return

    # Check if temp file spans multiple hours
    if first_time.hour != last_time.hour or first_time.date() != last_time.date():
        split_dir = os.path.join(TEMP_DIR, "split")
        os.makedirs(split_dir, exist_ok=True)
        subprocess.run([
            "editcap", "-F", "pcapng", "-i", "3600", temp_file,
            os.path.join(split_dir, "split.pcapng")
        ], check=True)
        os.remove(temp_file)
        for f in sorted(os.listdir(split_dir)):
            merge_temp_file(os.path.join(split_dir, f))
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
def supervisor_loop(stop_event, last_temp_holder, tshark_proc):
    """Monitor TEMP_DIR and merge completed temp files safely."""
    processed = set()
    while True:
        files = sorted(f for f in os.listdir(TEMP_DIR) if f.endswith(".pcapng"))

        # Merge all but the last file
        if len(files) >= 2:
            time.sleep(WAIT_AFTER_FINISH)
            for f in files[:-1]:
                temp_file = os.path.join(TEMP_DIR, f)
                if temp_file not in processed:
                    merge_temp_file(temp_file)
                    processed.add(temp_file)

        # Exit condition: stop_event set AND TShark finished
        if stop_event.is_set() and (tshark_proc is None or not tshark_proc.is_alive()):
            # Merge remaining files
            for f in files:
                temp_file = os.path.join(TEMP_DIR, f)
                if temp_file not in processed:
                    merge_temp_file(temp_file)
                    processed.add(temp_file)
            break

        if len(files) < 2:
            time.sleep(10)
        else:
            time.sleep(0.1)

# ---------------- Main ----------------
def main():
    with Manager() as manager:
        last_temp_holder = manager.dict()  # track last temp file

        tshark_proc = Process(target=run_tshark, args=(stop_event, last_temp_holder))
        sup_proc = Process(target=supervisor_loop, args=(stop_event, last_temp_holder, tshark_proc))

        tshark_proc.start()
        sup_proc.start()

        try:
            while True:
                cmd = input("Type STOP to terminate: ").strip().upper()
                if cmd == "STOP":
                    print("[Main] STOP received")
                    stop_event.set()
                    break
        except KeyboardInterrupt:
            stop_event.set()

        print("[Main] Waiting for TShark to finish current capture...")
        tshark_proc.join()
        print("[Main] TShark exited. Waiting for supervisor to merge last file...")
        sup_proc.join()

        print("[Main] Exited gracefully.")

if __name__ == "__main__":
    main()
