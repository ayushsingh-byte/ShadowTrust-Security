
import requests
import json
import time

API_URL = "http://localhost:8000/api/v1/nodes/launch"

nodes = [
    {"name": "EDU-01 (Ubuntu)", "type": "honeypot", "sector": "Education"},
    {"name": "DEF-09 (Kali)", "type": "honeypot", "sector": "Government"},
    {"name": "MED-04 (WinServ)", "type": "honeypot", "sector": "Healthcare"},
    {"name": "COM-02 (CentOS)", "type": "server", "sector": "Commercial"},
    {"name": "FIN-05 (RHEL)", "type": "server", "sector": "Financial"},
    {"name": "GOV-06 (Debian)", "type": "server", "sector": "Government"}
]

def seed():
    print(f"Seeding {len(nodes)} nodes to {API_URL}...")
    for node in nodes:
        try:
            # Backend expects query params, not JSON body for this specific endpoint
            response = requests.post(API_URL, params=node)
            if response.status_code == 200:
                print(f"[SUCCESS] Deployed {node['name']}")
            else:
                print(f"[FAILED] {node['name']} - {response.status_code} - {response.text}")
        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
        time.sleep(0.5)

if __name__ == "__main__":
    seed()
