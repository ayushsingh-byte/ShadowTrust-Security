"""
Sensor telemetry normalization.

Every honeypot speaks its own dialect. Cowrie emits rich SSH session JSON,
Dionaea emits connection records with nested endpoints, Honeytrap emits
hyphenated field names. The dashboard should not know or care about any of
that, so this module is the single place where sensor-specific shapes are
turned into one common event model.

Before this module existed the same parsing logic lived inline in two places
(``aws_telemetry_service.run_pipeline`` and ``endpoints/aws.py::
_s3_fetch_and_parse``) and had already drifted apart. Both now delegate here.

Design notes:

* Pure stdlib and pure functions — no I/O, no DB, no config. That keeps the
  parsers trivially testable and safe to call from a thread.
* Unknown sensors fall through to a generic parser rather than being dropped,
  so a new sensor still produces usable events before anyone writes a parser.
* ``event_id`` is a deterministic hash of the raw event. Replaying the same
  log line always yields the same id, which is what makes ingestion idempotent
  even if a file is re-read after a crash.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Source IPs that mean "the machine itself", never a real remote attacker in
# this deployment. Sensor healthchecks and local curls land here.
_LOOPBACK_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::", "localhost"}

# ── Severity levels, ordered ────────────────────────────────────────────────
SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER = (
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

# Authentication outcomes.
AUTH_SUCCESS = "SUCCESS"
AUTH_FAILURE = "FAILURE"
AUTH_NONE = None

# Canonical sensor names.
SENSOR_COWRIE = "cowrie"
SENSOR_DIONAEA = "dionaea"
SENSOR_HONEYTRAP = "honeytrap"
SENSOR_UNKNOWN = "unknown"

KNOWN_SENSORS = (SENSOR_COWRIE, SENSOR_DIONAEA, SENSOR_HONEYTRAP)

# Ports we can attribute to a sensor when the event itself does not say.
# Matches the port map in docker-compose.honeypots.yml.
DEFAULT_SENSOR_PORTS = {
    SENSOR_COWRIE: 2222,
    SENSOR_DIONAEA: 445,
    SENSOR_HONEYTRAP: 8022,
}

# Port -> protocol label, used when the sensor omits the protocol.
PORT_PROTOCOL = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    135: "msrpc",
    139: "netbios",
    443: "https",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgres",
    8022: "ssh",
    8023: "telnet",
    8080: "http",
    2222: "ssh",
    2223: "ssh",
}

# Placeholder addresses that carry no information.
_EMPTY_IPS = {"", "0.0.0.0", "::", "None", "null"}

# Dionaea sometimes embeds the endpoints in a bracketed connection string,
# e.g. "connection [127.0.0.1:445->10.0.0.5:51823]".
_DIONAEA_CONN_RE = re.compile(r"\[([0-9.]+):(\d+)->([0-9.]+):(\d+)\]")


@dataclass
class NormalizedEvent:
    """
    One honeypot observation, sensor-agnostic.

    Field names are deliberately boring and match the storage model in
    ``all_models.NormalizedEventModel`` one-for-one, so persisting is a plain
    field copy with no translation layer in between.
    """

    event_id: str
    timestamp: datetime
    sensor: str
    sensor_event_type: str
    source_ip: str
    protocol: str
    severity: str
    raw_event: str

    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    authentication_result: Optional[str] = None
    command: Optional[str] = None
    payload: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe dict, for the API and the SSE stream."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


# ── Helpers ────────────────────────────────────────────────────────────────


def _clean_ip(value: Any) -> Optional[str]:
    """Return a usable IP string, or None for placeholders and junk."""
    if value is None:
        return None
    text = str(value).strip()
    if text in _EMPTY_IPS:
        return None
    return text


def _clean_port(value: Any) -> Optional[int]:
    """Coerce a port to int, tolerating strings and rejecting out-of-range."""
    if value is None or value == "":
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _first(event: Dict[str, Any], *keys: str) -> Any:
    """First present, non-empty value among ``keys``."""
    for key in keys:
        if key in event:
            value = event[key]
            if value not in (None, "", []):
                return value
    return None


def _nested(event: Dict[str, Any], parent_keys, child_keys):
    """
    Look up ``parent.child`` for several possible spellings of each.

    Dionaea and Honeytrap both nest endpoints, but disagree on whether the
    parent is "source"/"src"/"remote" and the child "host"/"ip"/"address".
    """
    for parent in parent_keys:
        nested = event.get(parent)
        if not isinstance(nested, dict):
            continue
        for child in child_keys:
            value = nested.get(child)
            if value not in (None, "", []):
                return value
    return None


def parse_timestamp(value: Any) -> datetime:
    """
    Parse a sensor timestamp into naive UTC.

    The storage layer keeps naive UTC throughout (see RawEventModel), so
    everything tz-aware is converted rather than stored mixed — comparing the
    two raises TypeError, which is what previously made dedup silently
    re-process files.

    Unparseable input falls back to "now" so one malformed line cannot drop an
    otherwise valid event.
    """
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if not text:
            return datetime.utcnow()
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                return datetime.utcnow()

    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def compute_event_id(raw_event: Dict[str, Any]) -> str:
    """
    Deterministic id derived from the raw event's content.

    Using a content hash rather than a random UUID means re-reading the same
    log line produces the same id, so a duplicate insert collides on the
    primary key instead of creating a second copy of the event. This replaces
    the old ``ip:port:timestamp`` signature, which collapsed distinct events
    that happened in the same second from the same host.
    """
    canonical = json.dumps(raw_event, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def detect_sensor(event: Dict[str, Any]) -> str:
    """
    Identify which honeypot produced an event.

    Checks explicit sensor fields first, then falls back to fingerprinting the
    event id, since Cowrie prefixes every eventid with "cowrie.".
    """
    declared = str(
        _first(event, "sensor", "system", "sensor_name", "honeypot") or ""
    ).lower()
    for name in KNOWN_SENSORS:
        if name in declared:
            return name

    event_id = str(_first(event, "eventid", "event", "type") or "").lower()
    for name in KNOWN_SENSORS:
        if name in event_id:
            return name

    if event_id.startswith("cowrie."):
        return SENSOR_COWRIE
    # Honeytrap-go marks events with a hyphenated source-ip field.
    if "source-ip" in event or "destination-ip" in event:
        return SENSOR_HONEYTRAP
    # Dionaea nests its endpoints under "connection".
    if isinstance(event.get("connection"), dict):
        return SENSOR_DIONAEA

    return SENSOR_UNKNOWN


def derive_protocol(port: Optional[int], declared: Any = None) -> str:
    """Protocol label, preferring what the sensor said over the port guess."""
    if declared:
        text = str(declared).strip().lower()
        # "tcp"/"udp" are transports, not application protocols — only useful
        # as a last resort, so let a known port win over them.
        if text not in ("tcp", "udp", "", "unknown"):
            return text
        if port and port in PORT_PROTOCOL:
            return PORT_PROTOCOL[port]
        return text or "tcp"
    if port and port in PORT_PROTOCOL:
        return PORT_PROTOCOL[port]
    return "tcp"


def derive_severity(
    sensor_event_type: str,
    auth_result: Optional[str],
    command: Optional[str],
) -> str:
    """
    Map an event to a severity band.

    Deliberately simple and explainable — a student project is better served
    by rules a reader can audit than by an opaque score. Ordered most-severe
    first so the first match wins.
    """
    event_type = (sensor_event_type or "").lower()

    # Code execution and file transfer on a honeypot is always the top signal.
    if any(k in event_type for k in ("file_download", "file_upload", "download")):
        return SEVERITY_CRITICAL
    if command:
        return SEVERITY_HIGH
    if auth_result == AUTH_SUCCESS:
        return SEVERITY_HIGH
    if auth_result == AUTH_FAILURE:
        return SEVERITY_MEDIUM
    if any(k in event_type for k in ("login", "auth", "credential")):
        return SEVERITY_MEDIUM
    if any(k in event_type for k in ("connect", "session", "connection")):
        return SEVERITY_LOW
    return SEVERITY_INFO


# ── Per-sensor parsers ──────────────────────────────────────────────────────


def parse_cowrie(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cowrie SSH/Telnet honeypot.

    Cowrie's JSON is the richest of the three: it carries the session id,
    credentials, and every command the attacker typed. Field names are already
    flat and stable, so this is mostly a rename.
    """
    event_type = str(_first(event, "eventid", "event") or "cowrie.session.connect")

    auth_result = AUTH_NONE
    if "login.success" in event_type:
        auth_result = AUTH_SUCCESS
    elif "login.failed" in event_type:
        auth_result = AUTH_FAILURE

    # Cowrie names the typed command "input" on command.input events.
    command = _first(event, "input", "command")

    return {
        "sensor_event_type": event_type,
        "source_ip": _clean_ip(_first(event, "src_ip", "peerIP", "srcIP")),
        "source_port": _clean_port(_first(event, "src_port", "peerPort")),
        "destination_ip": _clean_ip(_first(event, "dst_ip", "hostIP")),
        "destination_port": _clean_port(_first(event, "dst_port", "hostPort")),
        "username": _first(event, "username", "user"),
        "password": _first(event, "password"),
        "authentication_result": auth_result,
        "command": str(command) if command else None,
        "session_id": _first(event, "session", "session_id"),
        "protocol_hint": _first(event, "protocol"),
        "metadata": {
            key: event[key]
            for key in ("message", "duration", "version", "shasum", "url", "outfile", "ttylog")
            if key in event and event[key] not in (None, "")
        },
    }


def parse_dionaea(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dionaea malware-capture honeypot.

    Dionaea's output varies by handler version: newer builds nest endpoints
    under "connection", older ones use flat peerIP/hostPort, and some emit a
    bracketed "[local:port->remote:port]" string. All three are handled.

    The image's own built-in log_json ihandler (dionaea/log_json.py — the one
    actually wired up in sensors/dionaea/log_json.yaml) submits one object per
    connection, shaped like:
        {"connection": {"protocol": "smbd", "transport": "tcp", "type": "accept"},
         "src_ip": ..., "src_port": ..., "dst_ip": ..., "dst_port": ...,
         "credentials": [{"username": ..., "password": ...}]}   # only if a
                                                                  # login happened
    "type" (listen/connect/accept/reject) lives under "connection", not at the
    top level, and credentials are a list under "credentials", not flat
    "username"/"password" keys — both are handled below alongside the older
    flat shape emitted by other Dionaea forks/versions.
    """
    connection = event.get("connection") if isinstance(event.get("connection"), dict) else {}

    event_type = _first(event, "eventid", "event", "connection_type")
    if not event_type and connection.get("type"):
        # e.g. "dionaea.connection.accept" — matches the "sensor.category"
        # convention every other sensor_event_type in this file follows.
        event_type = f"dionaea.connection.{connection['type']}"
    event_type = str(event_type or "dionaea.connection")

    source_ip = _clean_ip(
        _first(event, "src_ip", "peerIP", "remote_host", "remote_ip")
        or _nested(connection, ("remote",), ("host", "ip", "address"))
        or _nested(event, ("remote", "source", "src"), ("host", "ip", "address"))
    )
    source_port = _clean_port(
        _first(event, "src_port", "peerPort", "remote_port")
        or _nested(connection, ("remote",), ("port",))
        or _nested(event, ("remote", "source", "src"), ("port",))
    )
    destination_ip = _clean_ip(
        _first(event, "dst_ip", "hostIP", "local_host")
        or _nested(connection, ("local",), ("host", "ip", "address"))
        or _nested(event, ("local", "destination", "dst"), ("host", "ip", "address"))
    )
    destination_port = _clean_port(
        _first(event, "dst_port", "hostPort", "local_port")
        or _nested(connection, ("local",), ("port",))
        or _nested(event, ("local", "destination", "dst"), ("port",))
    )

    # Last resort: pull endpoints out of the bracketed connection string.
    if source_ip is None or destination_port is None:
        match = _DIONAEA_CONN_RE.search(event_type)
        if match:
            destination_ip = destination_ip or _clean_ip(match.group(1))
            destination_port = destination_port or _clean_port(match.group(2))
            source_ip = source_ip or _clean_ip(match.group(3))
            source_port = source_port or _clean_port(match.group(4))

    protocol_hint = (
        _first(event, "connection_protocol", "protocol")
        or connection.get("protocol")
        or connection.get("transport")
    )

    # log_json.py's _append_credentials() collects every login attempt on a
    # connection into a "credentials" list rather than flat username/password
    # keys. A connection can carry more than one (e.g. several FTP login
    # attempts before the session closes); the first is what lands in the
    # normalized columns, and the full list is kept in metadata so nothing is
    # lost for a connection with several attempts.
    credentials = event.get("credentials")
    first_credential = (
        credentials[0] if isinstance(credentials, list) and credentials
        and isinstance(credentials[0], dict) else {}
    )

    return {
        "sensor_event_type": event_type,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "username": _first(event, "username", "user", "login") or first_credential.get("username"),
        "password": _first(event, "password", "pass") or first_credential.get("password"),
        "authentication_result": AUTH_NONE,
        "command": None,
        "session_id": _first(event, "connection_id", "id", "session"),
        "protocol_hint": protocol_hint,
        "metadata": {
            key: event[key]
            for key in ("md5_hash", "sha512_hash", "url", "daddr", "saddr", "filename")
            if key in event and event[key] not in (None, "")
        } | ({"credentials": credentials} if isinstance(credentials, list) and len(credentials) > 1 else {}),
    }


def parse_honeytrap(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Honeytrap multi-port honeypot.

    Honeytrap-go uses hyphenated field names ("source-ip"); older builds nest
    under "source"/"destination". Both spellings are accepted.
    """
    # A real event carries both "category" (protocol family: http, ssh-alt,
    # ...) and "type" (request/response/connect/...) - combined they read
    # like every other sensor_event_type here ("honeytrap.http.request"
    # rather than the bare "request" a "type"-only lookup would produce, which
    # is indistinguishable across every emulated service).
    category = event.get("category")
    kind = event.get("type")
    if category and kind:
        event_type = f"honeytrap.{category}.{kind}"
    else:
        event_type = str(
            _first(event, "type", "eventid", "category", "event") or "honeytrap.connection"
        )

    source_ip = _clean_ip(
        _first(event, "source-ip", "source_ip", "src_ip")
        or _nested(event, ("source", "src", "origin", "peer"), ("host", "ip", "address"))
    )
    source_port = _clean_port(
        _first(event, "source-port", "source_port", "src_port")
        or _nested(event, ("source", "src", "origin", "peer"), ("port",))
    )
    destination_ip = _clean_ip(
        _first(event, "destination-ip", "destination_ip", "dst_ip")
        or _nested(event, ("destination", "dst", "local"), ("host", "ip", "address"))
    )
    destination_port = _clean_port(
        _first(event, "destination-port", "destination_port", "dst_port")
        or _nested(event, ("destination", "dst", "local"), ("port",))
    )

    return {
        "sensor_event_type": event_type,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "username": _first(event, "username", "user"),
        "password": _first(event, "password"),
        "authentication_result": AUTH_NONE,
        "command": _first(event, "command", "payload-command"),
        "session_id": _first(event, "session", "token", "id"),
        "protocol_hint": _first(event, "protocol", "transport", "category"),
        "metadata": {
            key: event[key]
            for key in (
                "agent", "token", "payload-hex", "content-type",
                # The attack-scenarios.sh http-probe demo is only legible on
                # the dashboard if the actual request is visible - which
                # path was hit and how, not just "an http event happened".
                "http.method", "http.url", "http.host",
            )
            if key in event and event[key] not in (None, "")
        },
    }


def parse_generic(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fallback for sensors with no dedicated parser.

    Tries every field spelling the other parsers know about. A new sensor
    therefore produces usable events immediately, just without sensor-specific
    enrichment.
    """
    return {
        "sensor_event_type": str(_first(event, "eventid", "event", "type") or "event"),
        "source_ip": _clean_ip(
            _first(event, "src_ip", "source_ip", "source-ip", "peerIP",
                   "remote_host", "remote_ip", "attacker", "client_ip", "ip")
            or _nested(event, ("source", "src", "origin", "peer", "remote"),
                       ("host", "ip", "addr", "address"))
        ),
        "source_port": _clean_port(
            _first(event, "src_port", "source_port", "source-port", "peerPort")
            or _nested(event, ("source", "src", "remote"), ("port",))
        ),
        "destination_ip": _clean_ip(
            _first(event, "dst_ip", "destination_ip", "destination-ip", "hostIP")
            or _nested(event, ("destination", "dst", "local"), ("host", "ip", "address"))
        ),
        "destination_port": _clean_port(
            _first(event, "dst_port", "destination_port", "destination-port",
                   "hostPort", "port")
            or _nested(event, ("destination", "dst", "local"), ("port",))
        ),
        "username": _first(event, "username", "user"),
        "password": _first(event, "password"),
        "authentication_result": AUTH_NONE,
        "command": _first(event, "command", "input"),
        "session_id": _first(event, "session", "session_id", "id"),
        "protocol_hint": _first(event, "protocol", "transport"),
        "metadata": {},
    }


PARSERS = {
    SENSOR_COWRIE: parse_cowrie,
    SENSOR_DIONAEA: parse_dionaea,
    SENSOR_HONEYTRAP: parse_honeytrap,
}


# ── Entry point ────────────────────────────────────────────────────────────


def normalize(raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
    """
    Convert one raw sensor event into a NormalizedEvent.

    Returns None when the event should not be stored — either it is not a dict,
    it is a heartbeat, or it carries no usable source address. Returning None
    rather than raising keeps one bad line from killing an ingest cycle.
    """
    if not isinstance(raw_event, dict):
        return None

    sensor = detect_sensor(raw_event)
    parser = PARSERS.get(sensor, parse_generic)

    try:
        parsed = parser(raw_event)
    except Exception:
        # A malformed event must never take down the pipeline; fall back to
        # the generic parser, and drop the event if even that fails.
        try:
            parsed = parse_generic(raw_event)
        except Exception:
            return None

    event_type = parsed.get("sensor_event_type") or "event"

    # Heartbeats are liveness pings, not attacker activity. Storing them would
    # swamp the event feed with noise.
    if "heartbeat" in event_type.lower():
        return None

    source_ip = parsed.get("source_ip")
    if not source_ip:
        # No attacker address means the event cannot be attributed. Keeping it
        # would produce dashboard rows nobody can act on.
        return None

    # The sensor healthchecks used to open a real connection every 30s, which
    # cowrie/dionaea logged as an "attack" from 127.0.0.1 — hundreds of fake
    # events per hour. That is fixed at the healthcheck level (it now checks
    # the listen socket via /proc without connecting). If you still want to
    # exclude loopback — e.g. you run other local probes you don't care about —
    # set TELEMETRY_DROP_LOOPBACK=1. Off by default so `attack_scenarios.sh
    # localhost` and the /health page's copy-paste commands still generate
    # events.
    if (
        source_ip in _LOOPBACK_IPS
        and os.getenv("TELEMETRY_DROP_LOOPBACK", "") in ("1", "true", "yes")
    ):
        return None

    destination_port = parsed.get("destination_port")
    if destination_port is None:
        destination_port = DEFAULT_SENSOR_PORTS.get(sensor)

    protocol = derive_protocol(destination_port, parsed.get("protocol_hint"))

    command = parsed.get("command")
    auth_result = parsed.get("authentication_result")
    severity = derive_severity(event_type, auth_result, command)

    metadata = parsed.get("metadata") or {}
    metadata.setdefault("detected_sensor", sensor)

    return NormalizedEvent(
        event_id=compute_event_id(raw_event),
        timestamp=parse_timestamp(_first(raw_event, "timestamp", "time", "date", "@timestamp")),
        sensor=sensor,
        sensor_event_type=event_type,
        source_ip=source_ip,
        source_port=parsed.get("source_port"),
        destination_ip=parsed.get("destination_ip"),
        destination_port=destination_port,
        protocol=protocol,
        username=parsed.get("username"),
        password=parsed.get("password"),
        authentication_result=auth_result,
        command=command,
        payload=parsed.get("payload"),
        session_id=parsed.get("session_id"),
        severity=severity,
        raw_event=json.dumps(raw_event, default=str),
        metadata=metadata,
    )
