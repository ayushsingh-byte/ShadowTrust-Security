
import sys
import os
import time

# Add backend to path to import AIEngine
sys.path.append(os.path.join(os.path.dirname(__file__), '../backend'))

from ai_engine.classifier import AIEngine

def test_detection():
    ai = AIEngine()
    
    print("--- Test 1: Normal Traffic ---")
    res = ai.analyze_log("GET /index.html", "192.168.1.5", 80)
    print(f"Result: {res['type']}")
    assert res['type'] == "NORMAL"

    print("\n--- Test 2: Nmap Scan (Port Scan) ---")
    ip = "192.168.1.100"
    # Simulate 6 distinct ports
    for port in range(80, 86):
        res = ai.analyze_log("GET /", ip, port)
    
    print(f"Final Result: {res['type']}")
    if res['type'] == "NMAP_SCAN":
        print("PASS: Nmap Scan Detected")
    else:
        print(f"FAIL: Expected NMAP_SCAN, got {res['type']}")

    print("\n--- Test 3: DDoS Attack ---")
    ip = "192.168.1.101"
    # Threshold is 20, let's send 25
    for i in range(25):
        res = ai.analyze_log(f"GET /flooding_{i}", ip, 443)
        
    print(f"Final Result: {res['type']}")
    if res['type'] == "DDOS":
        print("PASS: DDoS Detected")
    else:
        print(f"FAIL: Expected DDOS, got {res['type']}")

    print("\n--- Test 4: Brute Force ---")
    ip = "192.168.1.102"
    # Threshold is 5, send 6
    for i in range(6):
        res = ai.analyze_log("Failed password for root", ip, 22)
        
    print(f"Final Result: {res['type']}")
    if res['type'] == "BRUTE_FORCE":
        print("PASS: Brute Force Detected")
    else:
        print(f"FAIL: Expected BRUTE_FORCE, got {res['type']}")

if __name__ == "__main__":
    test_detection()
