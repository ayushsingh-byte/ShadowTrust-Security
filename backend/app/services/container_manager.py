"""
Container Manager — the single chokepoint for Docker socket access.

Task-10 hardening. Before this module, five call sites each did their own
``docker.from_env()``: the lab provider, the sensor-status reader, the health
page, the logs feed, and (indirectly) MobSF. Any of them — or a future endpoint
— could issue an arbitrary Docker API call.

Now **this module is the only code that calls ``docker.from_env()``**. It
exposes a deliberately small, allow-listed surface:

  * ``get_client()``            — the one cached client (ping-checked)
  * ``validate_lab_run(...)``   — raises ContainerPolicyError unless a lab
                                  container spec is safe (image/network/mounts/
                                  privileges/resources/labels)
  * ``assert_managed(c)``       — raises unless a container carries
                                  ``shadowtrust.managed=true``; lifecycle ops
                                  (stop/remove/inspect) must call this first
  * ``list_managed()``          — managed lab containers only
  * ``read_stack_status(names)``— read-only state for a fixed set of stack
                                  container names
  * ``read_container_logs(name)``— ``docker logs`` for a fixed platform
                                  allow-list only

There is **no** "run arbitrary container" / "exec arbitrary command" /
"raw Docker API" method here, and no HTTP endpoint exposes one. The honeypot
containers (honeynet_edge) are never created or mutated through this module —
only read for status.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional

MANAGED_LABEL = "shadowtrust.managed"
LAB_ID_LABEL = "shadowtrust.lab_id"
KIND_LABEL = "shadowtrust.kind"
SESSION_LABEL = "shadowtrust.session"
OWNER_LABEL = "shadowtrust.owner"

# ── Allow-lists ─────────────────────────────────────────────────────────────
# Lab images an operator can launch. Pinned by env so a deployment can add its
# own build without editing code, but never a free-form image string.
ALLOWED_LAB_IMAGES = {
    os.getenv("LAB_IMAGE_KALI", "shadowtrust/lab-kali:latest"),
    os.getenv("LAB_IMAGE_WINDOWS", "dockurr/windows"),
}
_extra = os.getenv("LAB_IMAGE_ALLOWLIST", "").strip()
if _extra:
    ALLOWED_LAB_IMAGES |= {i.strip() for i in _extra.split(",") if i.strip()}

# The lab network. Nothing may be launched onto honeynet_edge / honeynet_app.
DEFAULT_LAB_NETWORK = os.getenv("LAB_DOCKER_NETWORK", "shadowtrust_labnet")

# Resource ceilings for any managed container.
MAX_MEM_GB = int(os.getenv("CONTAINER_MAX_MEM_GB", "16"))
MAX_CPU = float(os.getenv("CONTAINER_MAX_CPU", "8"))

# Only the Windows-in-KVM lab image may add these — nothing else.
_KVM_CAPS = {"NET_ADMIN"}
_KVM_DEVICES = {"/dev/kvm"}
_KVM_IMAGES = {os.getenv("LAB_IMAGE_WINDOWS", "dockurr/windows")}

# ── Analysis Lab sandboxes (analysis_lab.html) ─────────────────────────────
ALLOWED_ANALYSIS_IMAGES = {os.getenv("ANALYSIS_IMAGE", "shadowtrust/analysis-shell:latest")}
ANALYSIS_NETWORK = os.getenv("ANALYSIS_DOCKER_NETWORK", "shadowtrust_analysis")
_ANALYSIS_MAX_MEM = "512m"
_ANALYSIS_MAX_NANO_CPUS = 1_000_000_000
_ANALYSIS_PIDS_LIMIT = 128

# Stack containers whose *status* the dashboard / health page may read.
STACK_CONTAINERS = (
    "honeynet_backend", "honeynet_frontend", "honeynet_db", "honeynet_phpmyadmin",
    "honeynet_mobsf", "honeynet_clamav", "honeynet_cowrie", "honeynet_dionaea",
    "honeynet_honeytrap", "guacamole", "guacd", "guacamole_db", "splunk",
)
# Containers whose *logs* the unified Logs feed may tail (a subset — never the
# honeypots' stdout, which could echo attacker payloads out of the edge zone).
PLATFORM_CONTAINERS = (
    "honeynet_backend", "honeynet_frontend", "honeynet_db", "honeynet_phpmyadmin",
    "honeynet_mobsf", "honeynet_clamav", "guacamole", "guacd", "guacamole_db",
)

_MAX_LOG_TAIL = 200


class ContainerPolicyError(Exception):
    """A requested container operation violates the manager's allow-list."""


class ContainerManagerUnavailable(Exception):
    """The Docker socket is not reachable from this process."""


# ── The one client ─────────────────────────────────────────────────────────
_client_cache: Dict[str, Any] = {"client": None}


def get_client():
    """
    Return the process-wide Docker client. The ONLY ``docker.from_env()`` in
    the codebase. Raises ContainerManagerUnavailable if the socket is missing.
    """
    if _client_cache["client"] is not None:
        return _client_cache["client"]
    try:
        import docker  # type: ignore
    except ImportError as exc:  # pragma: no cover - dep is in requirements
        raise ContainerManagerUnavailable(
            "the 'docker' package is not installed"
        ) from exc
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001
        raise ContainerManagerUnavailable(f"Docker daemon unreachable: {exc}") from exc
    _client_cache["client"] = client
    return client


def available() -> bool:
    try:
        get_client()
        return True
    except ContainerManagerUnavailable:
        return False


def reset_client() -> None:
    """Test hook — drop the cached client."""
    _client_cache["client"] = None


# ── Policy checks ──────────────────────────────────────────────────────────
def _labels_of(container) -> Dict[str, str]:
    return getattr(container, "labels", None) or {}


def is_managed(container) -> bool:
    return _labels_of(container).get(MANAGED_LABEL) == "true"


def assert_managed(container) -> None:
    """
    Guard for every lifecycle op. Refuses to touch anything that is not a
    Shadow-Trust-managed lab container — in particular the honeypots and the
    stack's own services.
    """
    if not is_managed(container):
        raise ContainerPolicyError(
            f"refusing to operate on unmanaged container "
            f"'{getattr(container, 'name', '?')}' (no {MANAGED_LABEL}=true label)"
        )


_FORBIDDEN_RUN_KEYS = {
    "privileged", "pid_mode", "ipc_mode", "userns_mode", "network_mode",
    "volumes", "mounts", "binds", "volumes_from", "tmpfs",
    "cgroup_parent", "security_opt", "sysctls", "pids_limit",
}


def validate_lab_run(
    image: str,
    run_kwargs: Dict[str, Any],
    *,
    allowed_network: Optional[str] = None,
) -> None:
    """
    Raise ContainerPolicyError unless ``docker.containers.run(image, **run_kwargs)``
    is a safe managed-lab launch. The lab provider MUST call this immediately
    before ``run``.
    """
    net = allowed_network or DEFAULT_LAB_NETWORK

    if image not in ALLOWED_LAB_IMAGES:
        raise ContainerPolicyError(
            f"image '{image}' is not in the lab allow-list {sorted(ALLOWED_LAB_IMAGES)}"
        )

    requested_net = run_kwargs.get("network") or run_kwargs.get("network_mode")
    if requested_net not in (net, None):
        raise ContainerPolicyError(
            f"lab containers may only join '{net}', not '{requested_net}'"
        )

    for key in _FORBIDDEN_RUN_KEYS:
        val = run_kwargs.get(key)
        if val:
            raise ContainerPolicyError(f"run option '{key}' is not permitted for labs")

    labels = run_kwargs.get("labels") or {}
    if labels.get(MANAGED_LABEL) != "true":
        raise ContainerPolicyError(f"lab containers must carry {MANAGED_LABEL}=true")
    if not labels.get(LAB_ID_LABEL):
        raise ContainerPolicyError(f"lab containers must carry {LAB_ID_LABEL}")

    name = run_kwargs.get("name") or ""
    if not name.startswith("shadowtrust-"):
        raise ContainerPolicyError("lab container name must start with 'shadowtrust-'")

    # Resource ceilings.
    nano = run_kwargs.get("nano_cpus")
    if nano and nano > MAX_CPU * 1_000_000_000:
        raise ContainerPolicyError(f"nano_cpus exceeds the {MAX_CPU}-vCPU ceiling")
    mem = str(run_kwargs.get("mem_limit") or "")
    if mem.endswith("g") and mem[:-1].isdigit() and int(mem[:-1]) > MAX_MEM_GB:
        raise ContainerPolicyError(f"mem_limit exceeds the {MAX_MEM_GB}g ceiling")

    # cap_add / devices — only the fixed KVM pair, and only for the Windows image.
    caps = set(run_kwargs.get("cap_add") or [])
    devices = set(run_kwargs.get("devices") or [])
    if caps or devices:
        if image not in _KVM_IMAGES:
            raise ContainerPolicyError(
                f"cap_add/devices are only allowed for {sorted(_KVM_IMAGES)}"
            )
        if not caps <= _KVM_CAPS:
            raise ContainerPolicyError(f"cap_add limited to {sorted(_KVM_CAPS)}")
        if not devices <= _KVM_DEVICES:
            raise ContainerPolicyError(f"devices limited to {sorted(_KVM_DEVICES)}")


def run_lab_container(
    image: str,
    run_kwargs: Dict[str, Any],
    *,
    allowed_network: Optional[str] = None,
    client: Any = None,
):
    """Validate then launch. The only sanctioned ``containers.run`` in the app."""
    validate_lab_run(image, run_kwargs, allowed_network=allowed_network)
    return (client or get_client()).containers.run(image, **run_kwargs)


def find_lab_container(lab_id: str, client: Any = None):
    """Return the managed container for a lab_id, or None. Never returns an
    unmanaged container."""
    try:
        client = client or get_client()
    except ContainerManagerUnavailable:
        return None
    matches = client.containers.list(all=True, filters={"label": f"{LAB_ID_LABEL}={lab_id}"})
    for c in matches:
        if is_managed(c):
            return c
    return None


def list_managed(running_only: bool = False, kind: Optional[str] = None, client: Any = None) -> List[Any]:
    try:
        client = client or get_client()
    except ContainerManagerUnavailable:
        return []
    labels = [f"{MANAGED_LABEL}=true"]
    if kind:
        labels.append(f"{KIND_LABEL}={kind}")
    # docker-py accepts a str or list; keep the single-label case a plain str so
    # simple filter shims (and the provider tests) keep working.
    filters: Dict[str, Any] = {"label": labels[0] if len(labels) == 1 else labels}
    if running_only:
        filters["status"] = "running"
    return client.containers.list(all=not running_only, filters=filters)


# ── Lifecycle helpers (managed containers only) ────────────────────────────
def exec_in_managed(container, cmd, **kwargs):
    """``exec_run`` inside a Shadow-Trust-managed container. Refuses anything else."""
    assert_managed(container)
    return container.exec_run(cmd, **kwargs)


def attach_shell(container, shell: str = "/bin/bash"):
    """Interactive PTY into a managed container — returns the raw duplex socket."""
    assert_managed(container)
    return container.exec_run(
        [shell], stdin=True, tty=True, socket=True, demux=False,
        environment={"TERM": "xterm-256color"},
    )


def stop_and_remove_managed(container) -> None:
    assert_managed(container)
    try:
        container.stop(timeout=3)
    except Exception:
        pass
    try:
        container.remove(force=True)
    except Exception:
        pass


# ── Analysis Lab sandboxes ────────────────────────────────────────────────
def validate_analysis_run(image: str, run_kwargs: Dict[str, Any]) -> None:
    """
    Raise ContainerPolicyError unless this is a safe disposable analysis shell:
    allow-listed image, the internal `shadowtrust_analysis` network, no mounts,
    cap_drop ALL + no-new-privileges, non-root, tight resource caps.
    """
    if image not in ALLOWED_ANALYSIS_IMAGES:
        raise ContainerPolicyError(
            f"image '{image}' is not an allowed analysis-shell image"
        )
    if run_kwargs.get("network") != ANALYSIS_NETWORK:
        raise ContainerPolicyError(
            f"analysis shells must run on '{ANALYSIS_NETWORK}' (internal, no egress)"
        )
    for key in ("volumes", "mounts", "binds", "volumes_from", "tmpfs", "devices",
                "privileged", "pid_mode", "ipc_mode", "network_mode"):
        if run_kwargs.get(key):
            raise ContainerPolicyError(f"analysis shells may not set '{key}'")
    if run_kwargs.get("cap_add"):
        raise ContainerPolicyError("analysis shells may not add capabilities")
    if list(run_kwargs.get("cap_drop") or []) != ["ALL"]:
        raise ContainerPolicyError("analysis shells must set cap_drop=['ALL']")
    if "no-new-privileges:true" not in list(run_kwargs.get("security_opt") or []):
        raise ContainerPolicyError("analysis shells must set no-new-privileges")
    if str(run_kwargs.get("user") or "").strip() in ("", "0", "root"):
        raise ContainerPolicyError("analysis shells must run as a non-root user")
    if str(run_kwargs.get("mem_limit") or "") != _ANALYSIS_MAX_MEM:
        raise ContainerPolicyError(f"analysis shell mem_limit must be {_ANALYSIS_MAX_MEM}")
    if int(run_kwargs.get("nano_cpus") or 0) > _ANALYSIS_MAX_NANO_CPUS:
        raise ContainerPolicyError("analysis shell nano_cpus over the ceiling")
    if not run_kwargs.get("pids_limit"):
        raise ContainerPolicyError("analysis shells must set pids_limit")
    name = run_kwargs.get("name") or ""
    if not name.startswith("shadowtrust-shell-"):
        raise ContainerPolicyError("analysis shell name must start with 'shadowtrust-shell-'")
    labels = run_kwargs.get("labels") or {}
    if labels.get(MANAGED_LABEL) != "true" or labels.get(KIND_LABEL) != "analysis-shell":
        raise ContainerPolicyError("analysis shells must carry managed + kind=analysis-shell labels")
    if not labels.get(SESSION_LABEL) or not labels.get(OWNER_LABEL):
        raise ContainerPolicyError("analysis shells must carry session + owner labels")


def run_analysis_container(session_id: str, owner: str, client: Any = None):
    """Validate then launch a hardened disposable analysis shell."""
    image = sorted(ALLOWED_ANALYSIS_IMAGES)[0]
    run_kwargs: Dict[str, Any] = {
        "name": f"shadowtrust-shell-{session_id[:12]}",
        "hostname": "web-prod-01",
        "command": ["sleep", "infinity"],
        "detach": True,
        "tty": True,
        "stdin_open": True,
        "network": ANALYSIS_NETWORK,
        "user": "analyst",
        "mem_limit": _ANALYSIS_MAX_MEM,
        "nano_cpus": _ANALYSIS_MAX_NANO_CPUS,
        "pids_limit": _ANALYSIS_PIDS_LIMIT,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "read_only": False,
        "auto_remove": False,
        "restart_policy": {"Name": "no"},
        "labels": {
            MANAGED_LABEL: "true",
            KIND_LABEL: "analysis-shell",
            SESSION_LABEL: session_id,
            OWNER_LABEL: owner,
        },
    }
    validate_analysis_run(image, run_kwargs)
    client = client or get_client()
    _ensure_internal_network(ANALYSIS_NETWORK, client)
    return client.containers.run(image, **run_kwargs)


def _ensure_internal_network(name: str, client: Any) -> None:
    try:
        client.networks.get(name)
    except Exception:
        try:
            client.networks.create(name, driver="bridge", internal=True)
        except Exception:
            pass


def find_session_container(session_id: str, client: Any = None):
    try:
        client = client or get_client()
    except ContainerManagerUnavailable:
        return None
    for c in client.containers.list(all=True, filters={"label": f"{SESSION_LABEL}={session_id}"}):
        if is_managed(c) and (c.labels or {}).get(KIND_LABEL) == "analysis-shell":
            return c
    return None


def ensure_lab_network(name: Optional[str] = None, client: Any = None) -> None:
    net = name or DEFAULT_LAB_NETWORK
    try:
        client = client or get_client()
    except ContainerManagerUnavailable:
        return
    try:
        client.networks.get(net)
    except Exception:
        try:
            client.networks.create(net, driver="bridge")
        except Exception:
            pass


# ── Read-only surfaces for the dashboard / health / logs ────────────────────
def read_stack_status(names: Iterable[str]) -> Dict[str, dict]:
    """
    ``{name: {status, health, running, started_at, kind}}`` for the requested
    names — restricted to STACK_CONTAINERS plus managed lab containers. Any name
    outside that set is silently ignored.
    """
    wanted = set(names) & set(STACK_CONTAINERS)
    out: Dict[str, dict] = {}
    try:
        client = get_client()
    except ContainerManagerUnavailable:
        return {}
    for c in client.containers.list(all=True):
        labels = c.labels or {}
        managed = labels.get(MANAGED_LABEL) == "true"
        if c.name not in wanted and not managed:
            continue
        state = c.attrs.get("State", {}) or {}
        out[c.name] = {
            "status": c.status,
            "running": bool(state.get("Running")),
            "health": (state.get("Health", {}) or {}).get("Status"),
            "started_at": state.get("StartedAt"),
            "kind": "lab" if managed else "stack",
            "env": labels.get("shadowtrust.environment") if managed else None,
        }
    return out


def read_container_logs(name: str, tail: int = 100) -> str:
    """``docker logs`` for a container on the PLATFORM_CONTAINERS allow-list."""
    if name not in PLATFORM_CONTAINERS:
        raise ContainerPolicyError(f"logs for '{name}' are not exposed")
    tail = max(1, min(int(tail), _MAX_LOG_TAIL))
    client = get_client()
    container = client.containers.get(name)
    return container.logs(tail=tail, timestamps=True).decode("utf-8", "replace")
