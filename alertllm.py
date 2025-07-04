import time
import requests
import os
from datetime import datetime

# === CONFIGURATION ===
SNORT_LOG_FILE = "alert.log"  # Should be in the same directory
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_API_KEY = "PLACE_GROK_API"  # Replace with your Groq API key
MODEL = "llama3-70b-8192"

headers = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

# === AI Summary Function ===
def get_ai_summary(log_entry):
    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an AI SOC analyst. Focus on analyzing Honeypot alerts. "
                    "Extract only relevant attacker activity from the Snort alert. "
                    "Map the detected activity to the MITRE ATT&CK framework if possible. "
                    "Do not add any recommendations or remediation steps. "
                    "Output format: \n"
                   # "Timestamp: <timestamp>\n"
                    "Summary: <brief summary>\n"
                    "MITRE Technique: <technique name and ID if identified>"
                )
            },
            {
                "role": "user",
                "content": f"Analyze this Snort alert:\n{log_entry}"
            }
        ],
        "temperature": 0.1
    }
    try:
        r = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        return r.json()['choices'][0]['message']['content'].strip()
    except requests.exceptions.RequestException as e:
        return f"[ERROR] Groq API failed: {e}"

# === Real-time file tailing ===
def tail_f(f):
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line.strip()

# === Main Monitor ===
print("Groq-powered Honeypot Monitor started...")
alert_counter = 0  # Initialize alert counter

try:
    with open(SNORT_LOG_FILE, "r") as logfile:
        for line in tail_f(logfile):
            if line:
                alert_counter += 1  # Increment counter for each alert
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print("\n" + "="*60)
                print(f"              Honeypot Alert #{alert_counter}")
                print("="*60)
                print(f"Detection Timestamp: {timestamp}")
                print(f"Snort Alert: {line}")
                print("-"*60)
                summary = get_ai_summary(line)
                print(summary)
                print("="*60)
except FileNotFoundError:
    print(f"[ERROR] Could not find {SNORT_LOG_FILE}")
except KeyboardInterrupt:
    print("\n[INFO] Stopped.")
