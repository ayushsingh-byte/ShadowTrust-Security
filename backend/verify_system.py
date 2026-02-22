import requests
import json
import time

BASE_URL = "http://localhost:8000/api/v1"

def test_endpoints():
    print("Waiting for server to start...")
    time.sleep(5) 
    
    print("\n[TEST] 1. Checking Nodes API...")
    try:
        res = requests.get(f"{BASE_URL}/nodes/")
        if res.status_code == 200:
            print(f"✅ Nodes List: OK ({len(res.json())} nodes found)")
        else:
            print(f"❌ Nodes List Failed: {res.status_code} {res.text}")
    except Exception as e:
        print(f"❌ Nodes List Error: {e}")

    print("\n[TEST] 2. Checking Nodes Stats (psutil)...")
    try:
        res = requests.get(f"{BASE_URL}/nodes/stats")
        if res.status_code == 200:
            data = res.json()
            print(f"✅ System Stats: OK (CPU: {data.get('cpu_percent')}%)")
        else:
            print(f"❌ Stats Failed: {res.status_code}")
    except Exception as e:
        print(f"❌ Stats Error: {e}")

    print("\n[TEST] 3. Checking Admin Backup...")
    try:
        res = requests.get(f"{BASE_URL}/admin/backup")
        if res.status_code == 200:
            print("✅ Admin Backup: OK (JSON reçieved)")
        else:
            print(f"❌ Backup Failed: {res.status_code}")
    except Exception as e:
        print(f"❌ Backup Error: {e}")
        
    print("\n[TEST] 4. Launching Simulated Node...")
    try:
        payload = {"name": "TEST-NODE", "type": "honeypot", "sector": "TEST"}
        res = requests.post(f"{BASE_URL}/nodes/launch", params=payload)
        if res.status_code == 200:
            print("✅ Launch Node: OK")
        else:
            print(f"❌ Launch Failed: {res.status_code} {res.text}")
    except Exception as e:
        print(f"❌ Launch Error: {e}")

if __name__ == "__main__":
    test_endpoints()
