import random
import time
from datetime import datetime

# === Configuration ===
LOG_FILE = "alert.log"
SLEEP_INTERVAL = 10  # seconds

# Sample Snort alert messages (realistic examples)
ALERTS = [
    "[**] [1:1000001:1] SQL Injection Attempt [**]",
    "[**] [1:1000002:2] FTP Brute Force Attempt [**]",
    "[**] [1:1000003:3] XSS Attack Detected [**]",
    "[**] [1:1000004:4] Port Scan Detected [**]",
    "[**] [1:1000005:5] Malware Download Attempt [**]",
    "[**] [1:1000006:6] DoS Attack Detected [**]",
    "[**] [1:1000007:7] Suspicious ICMP Traffic [**]",
]

# Generate random IP address
def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

# Generate random port
def random_port():
    return random.randint(1024, 65535)

# Create a Snort-like log entry
def generate_log_entry():
    timestamp = datetime.now().strftime("%m/%d-%H:%M:%S.%f")[:-3]
    alert = random.choice(ALERTS)
    proto = random.choice(["TCP", "UDP", "ICMP"])
    src_ip = random_ip()
    dst_ip = random_ip()
    src_port = random_port()
    dst_port = random_port()

    log_entry = (
        f"{timestamp} {alert}\n"
        f"{proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n\n"
    )
    return log_entry

# Continuously append dummy Snort alerts
def append_logs():
    print(f"[+] Generating Snort-style alerts in {LOG_FILE} every {SLEEP_INTERVAL}s...")
    while True:
        entry = generate_log_entry()
        with open(LOG_FILE, "a") as f:
            f.write(entry)
        print(f"[+] Added: {entry.strip().splitlines()[1]}")
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    append_logs()
