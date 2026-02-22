
import time
import requests
import json
import os
import re
from datetime import datetime

# CONFIGURATION
# In a real deployment, these would be env vars or args
API_URL = "http://<YOUR_VM_IP>:8000/api/v1/logs" 
LOG_FILE_PATH = "/var/log/auth.log" # Example: SSH logs
# For Cowrie honeypot, it might be: /home/cowrie/cowrie/var/log/cowrie/cowrie.json

def follow(thefile):
    """Yield each line from a file as it's written."""
    thefile.seek(0, os.SEEK_END)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def parse_ssh_log(line):
    """
    Parses a standard AUTH.LOG line for SSH attempts.
    Example: "Feb 10 12:34:56 server sshd[123]: Failed password for root from 192.168.1.5 port 22 ssh2"
    """
    try:
        # Simple extraction logic (can be enhanced)
        if "Failed password" in line or "Invalid user" in line:
            # Extract IP
            ip_match = re.search(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            ip = ip_match.group(1) if ip_match else "unknown"
            
            return {
                "source_ip": ip,
                "payload": line.strip(),
                "protocol": "SSH",
                "port": 22,
                "timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        print(f"Error parsing line: {e}")
    return None

def main():
    print(f"Starting Log Collector... Watching {LOG_FILE_PATH}")
    
    try:
        with open(LOG_FILE_PATH, "r") as logfile:
            loglines = follow(logfile)
            for line in loglines:
                # 1. Parse Log
                parsed_data = parse_ssh_log(line)
                
                if parsed_data:
                    # 2. Send to Backend
                    try:
                        response = requests.post(API_URL, json=parsed_data)
                        if response.status_code == 200:
                            print(f"[+] Sent log from {parsed_data['source_ip']}")
                        else:
                            print(f"[-] API Error: {response.status_code} - {response.text}")
                    except Exception as req_err:
                        print(f"[-] Connection Error: {req_err}")

    except FileNotFoundError:
        print(f"[!] Log file not found: {LOG_FILE_PATH}")
    except KeyboardInterrupt:
        print("\nStopping Log Collector.")

if __name__ == "__main__":
    main()
