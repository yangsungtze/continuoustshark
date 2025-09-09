import socket
import time

# ----------------------------
# Configuration
# ----------------------------
TARGET_IP = "192.168.1.183"  # replace with receiver IP
TARGET_PORT = 12345           # replace with receiver port
INTERVAL = 0.05               # 50 ms

# ----------------------------
# Setup UDP socket
# ----------------------------
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
target = (TARGET_IP, TARGET_PORT)

# ----------------------------
# Send packets continuously
# ----------------------------
while True:
    # You can put a payload; here just simple bytes
    payload = b"heartbeat"
    sock.sendto(payload, target)
    time.sleep(INTERVAL)
