"""
Local lab provider backed by Docker.

Labs are ordinary containers on a shared bridge network that guacd also joins,
so the existing GuacamoleService can route to them by container name with no
changes to the Guacamole layer.

The Docker SDK is imported lazily inside _client() so that importing this
module (or the provider factory) costs nothing when INFRA_PROVIDER=aws.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from app.services import container_manager
from app.services.providers.base import (
    ClusterMetrics,
    LabConfig,
    LabConnection,
    LabInfo,
    LabProvider,
    LabStatus,
    ProviderUnavailableError,
    UnsupportedEnvironmentError,
    resolve_profile,
)

logger = logging.getLogger(__name__)

# Docker labels used to identify labs Shadow Trust manages. Mirrors the
# 'ManagedBy=ShadowTrust' EC2 tag filter used by the AWS provider.
LABEL_MANAGED = "shadowtrust.managed"
LABEL_LAB_ID = "shadowtrust.lab_id"
LABEL_ENVIRONMENT = "shadowtrust.environment"
LABEL_PROFILE = "shadowtrust.profile"
LABEL_PROTOCOL = "shadowtrust.protocol"
LABEL_OWNER = "shadowtrust.owner"

# Environment -> container image. Overridable so operators can pin their own builds.
DEFAULT_IMAGES = {
    "kali": os.getenv("LAB_IMAGE_KALI", "shadowtrust/lab-kali:latest"),
    # Windows-in-a-container (KVM). Only usable on a Linux host with /dev/kvm;
    # gated behind LAB_WINDOWS_ENABLED so it never appears as an option on macOS.
    "windows": os.getenv("LAB_IMAGE_WINDOWS", "dockurr/windows"),
}

# Default in-container credentials. Match docker/lab-kali/Dockerfile and the
# dockurr/windows defaults.
DEFAULT_CREDENTIALS = {
    "kali": (os.getenv("LAB_KALI_USER", "kali"), os.getenv("LAB_KALI_PASSWORD", "kali")),
    "windows": (os.getenv("LAB_WINDOWS_USER", "Docker"), os.getenv("LAB_WINDOWS_PASSWORD", "admin")),
}


def _windows_enabled() -> bool:
    return os.getenv("LAB_WINDOWS_ENABLED", "false").strip().lower() in ("1", "true", "yes")


PROTOCOL_PORTS = {"rdp": 3389, "ssh": 22}

# Docker container state -> normalised LabStatus.
_STATE_MAP = {
    "created": LabStatus.PROVISIONING,
    "restarting": LabStatus.PROVISIONING,
    "running": LabStatus.RUNNING,
    "paused": LabStatus.STOPPING,
    "removing": LabStatus.STOPPING,
    "exited": LabStatus.TERMINATED,
    "dead": LabStatus.ERROR,
}


class DockerLabProvider(LabProvider):
    """Runs labs as local Docker containers. Requires no cloud account."""

    name = "local"

    def __init__(
        self,
        network: Optional[str] = None,
        images: Optional[Dict[str, str]] = None,
        auto_remove: Optional[bool] = None,
    ):
        # kali is always available; windows only when explicitly enabled (needs
        # a Linux host with KVM — it is never runnable on macOS).
        envs = {"kali", "kali_base", "linux"}
        if _windows_enabled():
            envs |= {"windows"}
        self.supported_environments = frozenset(envs)
        # Network guacd + the backend + every lab container share. docker-compose.yml
        # declares it with an explicit name so this default matches without
        # depending on the compose project name.
        self.network = network or os.getenv("LAB_DOCKER_NETWORK", "shadowtrust_labnet")
        self.images = {**DEFAULT_IMAGES, **(images or {})}
        self.auto_remove = (
            auto_remove
            if auto_remove is not None
            else os.getenv("LAB_AUTO_REMOVE", "true").lower() == "true"
        )
        self._docker = None

    # ── Docker plumbing ──────────────────────────────────────────────────────

    def _client(self):
        """
        The Docker client. Obtained from the central container_manager — the
        one module allowed to open the socket. A test may inject ``self._docker``
        directly to bypass it.
        """
        if self._docker is not None:
            return self._docker
        try:
            self._docker = container_manager.get_client()
        except container_manager.ContainerManagerUnavailable as exc:
            raise ProviderUnavailableError(
                f"Cannot reach the Docker daemon: {exc}. Is Docker Desktop running?"
            ) from exc
        return self._docker

    def _ensure_network(self, client) -> None:
        """Create the shared lab network if Guacamole has not already made it."""
        container_manager.ensure_lab_network(self.network, client=client)

    def _normalise_env(self, environment: str) -> str:
        """Collapse legacy profile names ('kali_base') onto canonical environments."""
        env = str(environment or "").lower()
        if "kali" in env or env == "linux":
            return "kali"
        return env

    def _find_container(self, lab_id: str):
        return container_manager.find_lab_container(lab_id, client=self._client())

    def _container_host(self, container) -> Optional[str]:
        """
        Hostname guacd should dial.

        Container name is preferred: it is stable across restarts and resolves
        over the shared bridge network via Docker's embedded DNS. Falls back to
        the container's IP on that network.
        """
        try:
            container.reload()
            name = container.name
            if name:
                return name
            nets = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            entry = nets.get(self.network) or next(iter(nets.values()), {})
            return entry.get("IPAddress") or None
        except Exception:
            return None

    def _connection_for(self, container, environment: str, protocol: str) -> Optional[LabConnection]:
        host = self._container_host(container)
        if not host:
            return None
        env = self._normalise_env(environment)
        username, password = DEFAULT_CREDENTIALS.get(env, ("", ""))
        return LabConnection(
            host=host,
            port=PROTOCOL_PORTS.get(protocol, 3389),
            protocol=protocol,
            username=username,
            password=password,
        )

    def _info_from_container(self, container) -> LabInfo:
        labels = container.labels or {}
        environment = labels.get(LABEL_ENVIRONMENT, "kali")
        profile = labels.get(LABEL_PROFILE, "standard")
        protocol = labels.get(LABEL_PROTOCOL, "rdp")
        status = _STATE_MAP.get(container.status, LabStatus.UNKNOWN)

        connection = None
        host = None
        if status in (LabStatus.RUNNING, LabStatus.READY):
            connection = self._connection_for(container, environment, protocol)
            host = connection.host if connection else None

        return LabInfo(
            lab_id=labels.get(LABEL_LAB_ID, container.id[:12]),
            status=status,
            environment=environment,
            profile=profile,
            host=host,
            connection=connection,
            resources=resolve_profile(profile),
        )

    # ── LabProvider contract ─────────────────────────────────────────────────

    def launch_lab(self, config: LabConfig) -> LabInfo:
        env = self._normalise_env(config.environment)

        if env == "windows" and not _windows_enabled():
            raise UnsupportedEnvironmentError(
                "Windows labs are disabled. Set LAB_WINDOWS_ENABLED=true — and note "
                "they only run on a Linux host with KVM (/dev/kvm). macOS cannot "
                "run a Windows VM in a container at all."
            )
        if env not in self.supported_environments:
            raise UnsupportedEnvironmentError(
                f"The local Docker provider cannot run '{config.environment}'. "
                f"Supported locally: {', '.join(sorted(self.supported_environments))}. "
                f"Use INFRA_PROVIDER=aws for anything else."
            )

        image = self.images.get(env)
        if not image:
            raise UnsupportedEnvironmentError(f"No image configured for environment '{env}'.")

        client = self._client()
        self._ensure_network(client)

        lab_id = str(uuid.uuid4())
        resources = config.resources

        run_kwargs: Dict[str, Any] = dict(
            detach=True,
            name=f"shadowtrust-lab-{lab_id[:8]}",
            hostname=f"lab-{lab_id[:8]}",
            network=self.network,
            nano_cpus=int(resources.cpu * 1_000_000_000),
            mem_limit=f"{resources.memory_gb}g",
            shm_size="512m",
            labels={
                LABEL_MANAGED: "true",
                LABEL_LAB_ID: lab_id,
                LABEL_ENVIRONMENT: env,
                LABEL_PROFILE: resources.id,
                LABEL_PROTOCOL: config.protocol,
                LABEL_OWNER: config.owner_id or "",
                **(config.labels or {}),
            },
            auto_remove=False,
            restart_policy={"Name": "no"},
        )

        if env == "kali":
            username, password = DEFAULT_CREDENTIALS["kali"]
            run_kwargs["environment"] = {"LAB_USER": username, "LAB_PASSWORD": password}
        elif env == "windows":
            # dockurr/windows runs Windows in QEMU/KVM. Needs the KVM device and
            # NET_ADMIN for its internal TAP networking; give it real RAM.
            username, password = DEFAULT_CREDENTIALS["windows"]
            run_kwargs["environment"] = {
                "VERSION": os.getenv("LAB_WINDOWS_VERSION", "11"),
                "USERNAME": username,
                "PASSWORD": password,
                "RAM_SIZE": f"{max(resources.memory_gb, 4)}G",
                "CPU_CORES": str(resources.cpu),
            }
            run_kwargs["devices"] = ["/dev/kvm"]
            run_kwargs["cap_add"] = ["NET_ADMIN"]
            run_kwargs["mem_limit"] = f"{max(resources.memory_gb, 6)}g"

        try:
            container = container_manager.run_lab_container(
                image, run_kwargs, allowed_network=self.network, client=client
            )
        except container_manager.ContainerPolicyError as exc:
            raise ProviderUnavailableError(f"Lab launch blocked by policy: {exc}") from exc
        except Exception as exc:
            msg = str(exc).lower()
            if "no such image" in msg or "not found" in msg:
                hint = (
                    "make lab-image" if env == "kali"
                    else f"docker pull {image}"
                )
                raise ProviderUnavailableError(
                    f"Lab image '{image}' is not available. Run: {hint}"
                ) from exc
            if "/dev/kvm" in msg or "kvm" in msg or "no such file or directory" in msg:
                raise UnsupportedEnvironmentError(
                    "Windows labs need a Linux host with hardware virtualization "
                    "(/dev/kvm). This is not available on macOS."
                ) from exc
            raise ProviderUnavailableError(f"Failed to start lab container: {exc}") from exc

        logger.info(f"Launched local lab {lab_id} ({env}/{resources.id}) as {container.name}")

        return LabInfo(
            lab_id=lab_id,
            status=LabStatus.PROVISIONING,
            environment=env,
            profile=resources.id,
            host=None,
            resources=resources,
            message="Lab container starting.",
        )

    def terminate_lab(self, lab_id: str) -> bool:
        try:
            container = self._find_container(lab_id)
        except ProviderUnavailableError:
            raise
        except Exception as exc:
            logger.error(f"Lookup failed while terminating lab {lab_id}: {exc}")
            return False

        if container is None:
            # Already gone — termination is idempotent.
            logger.info(f"Lab {lab_id} not found; treating as already terminated.")
            return True

        # Defence in depth: _find_container only returns managed containers, but
        # never stop/remove anything without re-checking the label.
        container_manager.assert_managed(container)

        try:
            container.stop(timeout=10)
        except Exception as exc:
            logger.warning(f"Stop failed for lab {lab_id}: {exc}")
        try:
            container.remove(force=True)
        except Exception as exc:
            logger.error(f"Remove failed for lab {lab_id}: {exc}")
            return False

        logger.info(f"Terminated local lab {lab_id}")
        return True

    def get_lab_status(self, lab_id: str) -> LabInfo:
        container = self._find_container(lab_id)
        if container is None:
            return LabInfo(
                lab_id=lab_id,
                status=LabStatus.TERMINATED,
                environment="unknown",
                profile="standard",
                message="No container found for this lab.",
            )
        return self._info_from_container(container)

    def get_metrics(self) -> ClusterMetrics:
        try:
            containers = container_manager.list_managed(
                running_only=True, client=self._client()
            )
        except ProviderUnavailableError as exc:
            return ClusterMetrics(status="success", message=str(exc))
        except Exception as exc:
            logger.warning(f"Failed to collect Docker lab metrics: {exc}")
            return ClusterMetrics(status="success", message=str(exc))

        total_cpu = 0
        total_ram = 0
        labs: List[Dict[str, Any]] = []

        for container in containers:
            info = self._info_from_container(container)
            res = info.resources
            if res:
                total_cpu += res.cpu
                total_ram += res.memory_gb
            entry = info.to_dict()
            entry["host"] = info.host
            labs.append(entry)

        return ClusterMetrics(
            vcpu=total_cpu,
            ram=total_ram,
            active_count=len(containers),
            labs=labs,
        )

    def wait_until_ready(self, lab_id: str, timeout: Optional[int] = None) -> LabInfo:
        """
        Poll until the container is running and its remote-access port accepts
        connections.

        Kali boots in seconds. A Windows lab (dockurr/windows) downloads a
        multi-GB ISO and runs an unattended install on first launch, so its
        window is far larger — LAB_WINDOWS_READY_TIMEOUT (default 1800s).
        """
        container = self._find_container(lab_id)
        env = (container.labels or {}).get(LABEL_ENVIRONMENT, "kali") if container else "kali"

        if timeout is None:
            if env == "windows":
                timeout = int(os.getenv("LAB_WINDOWS_READY_TIMEOUT", "1800"))
            else:
                timeout = int(os.getenv("LAB_READY_TIMEOUT", "300"))

        deadline = time.time() + timeout
        poll_interval = 5 if env == "windows" else 3
        last: Optional[LabInfo] = None

        while time.time() < deadline:
            last = self.get_lab_status(lab_id)

            if last.status in (LabStatus.TERMINATED, LabStatus.ERROR):
                return last

            if last.status == LabStatus.RUNNING and last.connection:
                if self._port_open(lab_id, last.connection.port):
                    last.status = LabStatus.READY
                    return last

            time.sleep(poll_interval)

        if last is None:
            last = self.get_lab_status(lab_id)
        last.status = LabStatus.ERROR
        last.message = f"Lab did not become ready within {timeout}s."
        return last

    def _port_open(self, lab_id: str, port: int) -> bool:
        """
        Check the service is listening, from inside the container's own netns.

        Done via exec rather than from the backend host because the backend may
        not share a network with the lab — guacd is the component that needs the
        route, and it lives on the lab network.
        """
        container = self._find_container(lab_id)
        if container is None:
            return False
        try:
            exit_code, _ = container.exec_run(
                ["sh", "-c", f"command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 {port}"],
            )
            return exit_code == 0
        except Exception:
            return False

    def get_connection(self, lab_id: str, protocol: str = "rdp") -> Optional[LabConnection]:
        container = self._find_container(lab_id)
        if container is None:
            return None
        labels = container.labels or {}
        environment = labels.get(LABEL_ENVIRONMENT, "kali")
        return self._connection_for(container, environment, protocol)
