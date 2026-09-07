# ShadowTrust local lab environment — Kali Linux + XFCE + XRDP
#
# This reproduces what the EC2 Kali AMI provided, not more. The EC2 user_data
# bootstrap (aws_orchestrator.py) installed nothing — it assumed the AMI already
# had XFCE, xrdp and sshd, and only applied four fixes:
#
#   1. force SSH password authentication
#   2. set the 'kali' user password
#   3. write ~/.xsession = xfce4-session  (fixes the XRDP black screen on XFCE)
#   4. unset DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR in startwm.sh
#      (prevents DBus session crashes under xrdp)
#
# So this image supplies the desktop stack the AMI had, then applies the same
# four fixes. Tooling beyond that is opt-in via the LAB_TOOLS build arg rather
# than pulling the multi-gigabyte kali-linux-large metapackage.

FROM kalilinux/kali-rolling:latest

LABEL org.opencontainers.image.title="ShadowTrust Kali Lab" \
      org.opencontainers.image.description="Kali Linux XFCE desktop reachable over RDP/SSH via Guacamole" \
      shadowtrust.image.role="lab"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LAB_USER=kali

# Extra Kali tooling. Override at build time, e.g.:
#   docker build --build-arg LAB_TOOLS="nmap metasploit-framework" -t shadowtrust/lab-kali .
ARG LAB_TOOLS="nmap netcat-traditional tcpdump curl wget git python3 vim"

# ── Desktop + remote access stack ────────────────────────────────────────────
# xfce4 / xrdp / openssh-server are what the AMI shipped with.
# dbus-x11 and xorgxrdp are required for an XFCE session under xrdp.
# netcat-openbsd backs the provider's readiness probe (nc -z 127.0.0.1 3389).
RUN apt-get update && apt-get install -y --no-install-recommends \
        xfce4 \
        xfce4-terminal \
        xorgxrdp \
        xrdp \
        dbus \
        dbus-x11 \
        dbus-system-bus-common \
        dbus-session-bus-common \
        openssh-server \
        netcat-openbsd \
        sudo \
        procps \
        ca-certificates \
    && apt-get install -y --no-install-recommends ${LAB_TOOLS} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Lab user ─────────────────────────────────────────────────────────────────
# Password is set at runtime from LAB_PASSWORD so image layers carry no credential.
RUN useradd -m -s /bin/bash ${LAB_USER} \
    && usermod -aG sudo ${LAB_USER}

# ── Fix 1: force SSH password authentication ─────────────────────────────────
RUN mkdir -p /etc/ssh/sshd_config.d /run/sshd \
    && echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/99-force-password.conf \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config

# ── Fix 3: XFCE session for xrdp (prevents the black screen) ─────────────────
RUN echo "xfce4-session" > /home/${LAB_USER}/.xsession \
    && chown ${LAB_USER}:${LAB_USER} /home/${LAB_USER}/.xsession \
    && chmod +x /home/${LAB_USER}/.xsession

# ── Fix 4: unset DBus/runtime vars so xrdp sessions do not crash ─────────────
RUN sed -i '1s|^|unset DBUS_SESSION_BUS_ADDRESS\nunset XDG_RUNTIME_DIR\n|' /etc/xrdp/startwm.sh \
    && chmod +x /etc/xrdp/startwm.sh

# xrdp listens on 3389; its session manager binds loopback only.
RUN sed -i 's/^port=3389/port=3389/' /etc/xrdp/xrdp.ini || true

# Fix 5: xrdp drops privileges to the 'xrdp' user, which by default cannot read
# /etc/xrdp/key.pem (root:root 0600) — TLS then fails and Guacamole reports
# "RDP server closed/refused connection: Upstream error". The key is a
# throwaway self-signed cert for a disposable local lab, so make it readable.
RUN chmod 0644 /etc/xrdp/key.pem /etc/xrdp/cert.pem 2>/dev/null || true \
    && adduser xrdp ssl-cert 2>/dev/null || true

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 3389 22

# Guacamole connects to 3389; the provider's readiness probe checks the same port.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
    CMD nc -z 127.0.0.1 3389 || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
