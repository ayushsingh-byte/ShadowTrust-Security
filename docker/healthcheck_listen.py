#!/usr/bin/env python3
"""
Container healthcheck: exit 0 iff a TCP port is in the LISTEN state.

Reads /proc/net/tcp{,6} directly — it never opens a socket, so the honeypot
service it is checking (cowrie, dionaea) does not log the probe as an attacker
connection. Bind-mounted into the sensor containers by docker-compose.yml.

Usage:  healthcheck_listen.py <port>
"""
import sys

LISTEN = "0A"  # TCP state code for LISTEN in /proc/net/tcp


def main() -> int:
    try:
        port_hex = format(int(sys.argv[1]), "04X")
    except (IndexError, ValueError):
        return 2

    rows = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as fh:
                rows.extend(fh.read().splitlines()[1:])
        except OSError:
            pass

    for line in rows:
        cols = line.split()
        if len(cols) < 4:
            continue
        local_port = cols[1].rsplit(":", 1)[-1]
        state = cols[3]
        if local_port == port_hex and state == LISTEN:
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
