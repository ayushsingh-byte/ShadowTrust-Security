"""
Provider-agnostic lab infrastructure contract.

The application layer talks only to the types defined here. Nothing in this
module imports boto3, the Docker SDK, or any other provider dependency, so it
is safe to import from any context regardless of which provider is configured.

Concepts used across Shadow Trust:

    lab_id      opaque handle for a running lab, issued by the provider
    profile     resource tier ('light' | 'standard' | 'heavy')
    environment logical machine image ('kali', 'windows', ...)
    status      normalised lifecycle state (see LabStatus)
    resources   vCPU / RAM reported back for metrics

Provider-specific identifiers (EC2 instance IDs, Docker container IDs, AMIs,
instance types) never leave the provider implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class LabStatus:
    """Normalised lab lifecycle states shared by every provider."""

    PROVISIONING = "PROVISIONING"
    READY = "READY"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    TERMINATED = "TERMINATED"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

    ACTIVE = {PROVISIONING, READY, RUNNING}
    TERMINAL = {TERMINATED, ERROR}


@dataclass(frozen=True)
class ResourceProfile:
    """A provider-independent resource tier."""

    id: str
    label: str
    cpu: int          # vCPU count
    memory_gb: int    # RAM in GiB


# The canonical profile catalogue. Providers map these to their own sizing.
PROFILES: Dict[str, ResourceProfile] = {
    "light": ResourceProfile(id="light", label="Light", cpu=2, memory_gb=2),
    "standard": ResourceProfile(id="standard", label="Standard", cpu=4, memory_gb=4),
    "heavy": ResourceProfile(id="heavy", label="Heavy", cpu=6, memory_gb=8),
}

DEFAULT_PROFILE = "standard"


def resolve_profile(profile_id: Optional[str]) -> ResourceProfile:
    """Look up a resource profile, falling back to the default tier."""
    if not profile_id:
        return PROFILES[DEFAULT_PROFILE]
    key = str(profile_id).strip().lower()
    return PROFILES.get(key, PROFILES[DEFAULT_PROFILE])


class UnsupportedEnvironmentError(Exception):
    """Raised when a provider cannot serve the requested environment."""


class ProviderUnavailableError(Exception):
    """Raised when the provider's backing infrastructure is unreachable."""


@dataclass
class LabConfig:
    """Everything a provider needs to launch a lab, in generic terms."""

    environment: str                     # 'kali', 'windows', ...
    profile: str = DEFAULT_PROFILE       # 'light' | 'standard' | 'heavy'
    protocol: str = "rdp"                # 'rdp' | 'ssh'
    owner_id: Optional[str] = None       # user this lab belongs to
    labels: Dict[str, str] = field(default_factory=dict)

    @property
    def resources(self) -> ResourceProfile:
        return resolve_profile(self.profile)


@dataclass
class LabConnection:
    """
    Connection details handed to Guacamole.

    Mirrors GuacamoleService.create_connection()'s parameters exactly so the
    existing Guacamole layer needs no changes.
    """

    host: str
    port: int
    protocol: str
    username: str = ""
    password: str = ""


@dataclass
class LabInfo:
    """Normalised description of a lab, whatever the provider."""

    lab_id: str
    status: str
    environment: str
    profile: str
    host: Optional[str] = None
    connection: Optional[LabConnection] = None
    resources: Optional[ResourceProfile] = None
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res = self.resources
        return {
            "lab_id": self.lab_id,
            "status": self.status,
            "environment": self.environment,
            "profile": self.profile,
            "host": self.host,
            "resources": (
                {"cpu": res.cpu, "memory_gb": res.memory_gb, "label": res.label}
                if res else None
            ),
            "message": self.message,
        }


@dataclass
class ClusterMetrics:
    """Aggregate view of every lab this provider currently manages."""

    vcpu: int = 0
    ram: int = 0
    active_count: int = 0
    labs: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "success"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "vcpu": self.vcpu,
            "ram": self.ram,
            "active_count": self.active_count,
            "labs": self.labs,
            # Retained so existing dashboard code that reads `instances` keeps
            # working; it is the same payload under a provider-neutral name.
            "instances": self.labs,
            "message": self.message,
        }


class LabProvider(ABC):
    """Contract every infrastructure backend implements."""

    #: Short provider name, surfaced to the UI ('local' / 'aws').
    name: str = "base"

    #: Environments this provider can actually serve.
    supported_environments: frozenset = frozenset()

    @abstractmethod
    def launch_lab(self, config: LabConfig) -> LabInfo:
        """Start a lab and return it in PROVISIONING (or READY) state."""

    @abstractmethod
    def terminate_lab(self, lab_id: str) -> bool:
        """Destroy a lab. Returns True when the lab is gone."""

    @abstractmethod
    def get_lab_status(self, lab_id: str) -> LabInfo:
        """Return the lab's current normalised state."""

    @abstractmethod
    def get_metrics(self) -> ClusterMetrics:
        """Aggregate resource usage across every managed lab."""

    def wait_until_ready(self, lab_id: str, timeout: int = 600) -> LabInfo:
        """
        Block until the lab is usable, or until `timeout` seconds elapse.

        Providers with a meaningful boot delay override this. The default
        implementation simply reports current status.
        """
        return self.get_lab_status(lab_id)

    def get_connection(self, lab_id: str, protocol: str = "rdp") -> Optional[LabConnection]:
        """Connection details for Guacamole, or None if the lab is not routable."""
        info = self.get_lab_status(lab_id)
        return info.connection

    def get_console_url(self, lab_id: str) -> Optional[str]:
        """
        Out-of-band management console for a lab, if the provider offers one
        (the AWS provider returns an SSM Session Manager link). Providers
        without a separate console return None and callers fall back to the
        Guacamole browser session.
        """
        return None

    def supports(self, environment: str) -> bool:
        return str(environment or "").lower() in self.supported_environments

    def describe_profiles(self) -> List[Dict[str, Any]]:
        """Profile catalogue for the UI — provider-independent by construction."""
        return [
            {"id": p.id, "label": p.label, "cpu": p.cpu, "memory_gb": p.memory_gb}
            for p in PROFILES.values()
        ]
