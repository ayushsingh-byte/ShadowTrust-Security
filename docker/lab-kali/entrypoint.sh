#!/bin/bash
# Starts the lab's remote-access services.
#
# Containers have no systemd, so xrdp, xrdp-sesman and sshd are started
# directly. xrdp runs in the foreground as PID 1's child so the container's
# lifetime tracks the desktop service.

set -euo pipefail

LAB_USER="${LAB_USER:-kali}"
LAB_PASSWORD="${LAB_PASSWORD:-kali}"

# ── Fix 2: set the lab user's password at runtime ────────────────────────────
# Done here rather than in the image so no credential is baked into a layer.
echo "${LAB_USER}:${LAB_PASSWORD}" | chpasswd

# ── DBus ─────────────────────────────────────────────────────────────────────
# XFCE needs a system bus. Without this the session dies immediately after the
# RDP handshake — the same failure the EC2 startwm.sh patch worked around.
mkdir -p /run/dbus
rm -f /run/dbus/pid
dbus-uuidgen --ensure=/etc/machine-id 2>/dev/null || true
dbus-uuidgen --ensure 2>/dev/null || true
# Non-fatal: a broken system bus degrades the desktop but must not kill PID 1
# before xrdp is even listening.
dbus-daemon --system --fork || echo "[lab] warning: system dbus failed to start"

# ── SSH ──────────────────────────────────────────────────────────────────────
mkdir -p /run/sshd
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
fi
/usr/sbin/sshd

# ── XRDP ─────────────────────────────────────────────────────────────────────
# sesman must be up before xrdp accepts a session request.
rm -f /var/run/xrdp/xrdp-sesman.pid /var/run/xrdp/xrdp.pid 2>/dev/null || true
/usr/sbin/xrdp-sesman

echo "[lab] Kali lab ready — RDP on 3389, SSH on 22, user '${LAB_USER}'."

# Foreground: keeps the container alive and forwards signals for clean shutdown.
exec /usr/sbin/xrdp --nodaemon
