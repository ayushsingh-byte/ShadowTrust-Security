"""
DockerLabProvider lifecycle tests.

The Docker SDK is stubbed so these run without a Docker daemon. Live
verification against a real daemon lives in scripts/verify_local_lab.py.
"""

import pytest

from app.services.providers.base import (
    LabConfig,
    LabStatus,
    UnsupportedEnvironmentError,
    resolve_profile,
)
from app.services.providers.docker_provider import (
    LABEL_ENVIRONMENT,
    LABEL_LAB_ID,
    LABEL_MANAGED,
    LABEL_PROFILE,
    LABEL_PROTOCOL,
    DockerLabProvider,
)


class FakeContainer:
    def __init__(self, name, labels, status="running", ip="172.20.0.5"):
        self.name = name
        self.labels = labels
        self.status = status
        self.id = "c" * 64
        self.attrs = {
            "NetworkSettings": {"Networks": {"guacamole_guacnet": {"IPAddress": ip}}}
        }
        self.stopped = False
        self.removed = False
        self.exec_exit_code = 0

    def reload(self):
        pass

    def stop(self, timeout=10):
        self.stopped = True

    def remove(self, force=False):
        self.removed = True

    def exec_run(self, cmd):
        return self.exec_exit_code, b""


class FakeContainerCollection:
    def __init__(self):
        self.store = []
        self.run_kwargs = None
        self.run_error = None

    def run(self, image, **kwargs):
        if self.run_error:
            raise self.run_error
        self.run_kwargs = {"image": image, **kwargs}
        container = FakeContainer(kwargs.get("name", "lab"), kwargs.get("labels", {}))
        self.store.append(container)
        return container

    def list(self, all=False, filters=None):
        filters = filters or {}
        label_filter = filters.get("label")
        status_filter = filters.get("status")
        results = []
        for c in self.store:
            if label_filter:
                key, _, value = label_filter.partition("=")
                if c.labels.get(key) != value:
                    continue
            if status_filter and c.status != status_filter:
                continue
            if not all and c.status != "running":
                continue
            results.append(c)
        return results


class FakeNetworkCollection:
    def __init__(self):
        self.created = []

    def get(self, name):
        return object()

    def create(self, name, driver="bridge"):
        self.created.append(name)


class FakeDockerClient:
    def __init__(self):
        self.containers = FakeContainerCollection()
        self.networks = FakeNetworkCollection()

    def ping(self):
        return True


@pytest.fixture
def provider():
    p = DockerLabProvider(network="guacamole_guacnet")
    p._docker = FakeDockerClient()
    return p


class TestLaunch:
    def test_launch_returns_provisioning_lab(self, provider):
        info = provider.launch_lab(LabConfig(environment="kali", profile="light"))

        assert info.status == LabStatus.PROVISIONING
        assert info.environment == "kali"
        assert info.profile == "light"
        assert info.lab_id

    def test_profile_maps_to_container_resource_limits(self, provider):
        provider.launch_lab(LabConfig(environment="kali", profile="heavy"))
        kwargs = provider._docker.containers.run_kwargs

        heavy = resolve_profile("heavy")
        assert kwargs["nano_cpus"] == heavy.cpu * 1_000_000_000
        assert kwargs["mem_limit"] == f"{heavy.memory_gb}g"

    def test_managed_labels_are_applied(self, provider):
        info = provider.launch_lab(
            LabConfig(environment="kali", profile="standard", protocol="ssh")
        )
        labels = provider._docker.containers.run_kwargs["labels"]

        assert labels[LABEL_MANAGED] == "true"
        assert labels[LABEL_LAB_ID] == info.lab_id
        assert labels[LABEL_ENVIRONMENT] == "kali"
        assert labels[LABEL_PROFILE] == "standard"
        assert labels[LABEL_PROTOCOL] == "ssh"

    def test_container_joins_the_guacamole_network(self, provider):
        provider.launch_lab(LabConfig(environment="kali"))
        assert provider._docker.containers.run_kwargs["network"] == "guacamole_guacnet"

    def test_legacy_environment_name_is_normalised(self, provider):
        info = provider.launch_lab(LabConfig(environment="kali_base"))
        assert info.environment == "kali"

    def test_windows_is_rejected_when_disabled(self, provider, monkeypatch):
        """Windows labs are off by default; the provider must say why, not fake it."""
        monkeypatch.delenv("LAB_WINDOWS_ENABLED", raising=False)
        with pytest.raises(UnsupportedEnvironmentError) as exc:
            provider.launch_lab(LabConfig(environment="windows"))
        msg = str(exc.value).lower()
        assert "windows" in msg
        assert "lab_windows_enabled" in msg or "kvm" in msg

    def test_windows_launches_with_kvm_device_when_enabled(self, monkeypatch):
        """With LAB_WINDOWS_ENABLED=true the container requests /dev/kvm."""
        monkeypatch.setenv("LAB_WINDOWS_ENABLED", "true")
        p = DockerLabProvider(network="guacamole_guacnet")
        p._docker = FakeDockerClient()
        info = p.launch_lab(LabConfig(environment="windows", profile="standard"))
        kwargs = p._docker.containers.run_kwargs
        assert info.environment == "windows"
        assert "/dev/kvm" in kwargs["devices"]
        assert "NET_ADMIN" in kwargs["cap_add"]

    def test_unknown_profile_falls_back_to_standard(self, provider):
        info = provider.launch_lab(LabConfig(environment="kali", profile="gigantic"))
        assert info.profile == "standard"


class TestTerminate:
    def test_terminate_stops_and_removes(self, provider):
        info = provider.launch_lab(LabConfig(environment="kali"))
        container = provider._docker.containers.store[0]

        assert provider.terminate_lab(info.lab_id) is True
        assert container.stopped is True
        assert container.removed is True

    def test_terminate_is_idempotent_for_missing_lab(self, provider):
        assert provider.terminate_lab("no-such-lab") is True


class TestStatus:
    def test_running_container_reports_running_and_a_connection(self, provider):
        info = provider.launch_lab(LabConfig(environment="kali", protocol="rdp"))
        status = provider.get_lab_status(info.lab_id)

        assert status.status == LabStatus.RUNNING
        assert status.connection is not None
        assert status.connection.port == 3389
        assert status.connection.username == "kali"

    def test_ssh_protocol_maps_to_port_22(self, provider):
        info = provider.launch_lab(LabConfig(environment="kali", protocol="ssh"))
        status = provider.get_lab_status(info.lab_id)
        assert status.connection.port == 22

    def test_missing_container_reports_terminated(self, provider):
        status = provider.get_lab_status("ghost")
        assert status.status == LabStatus.TERMINATED

    def test_exited_container_maps_to_terminated(self, provider):
        info = provider.launch_lab(LabConfig(environment="kali"))
        provider._docker.containers.store[0].status = "exited"
        assert provider.get_lab_status(info.lab_id).status == LabStatus.TERMINATED


class TestMetrics:
    def test_metrics_sum_declared_profile_resources(self, provider):
        provider.launch_lab(LabConfig(environment="kali", profile="light"))
        provider.launch_lab(LabConfig(environment="kali", profile="heavy"))

        metrics = provider.get_metrics()
        light, heavy = resolve_profile("light"), resolve_profile("heavy")

        assert metrics.active_count == 2
        assert metrics.vcpu == light.cpu + heavy.cpu
        assert metrics.ram == light.memory_gb + heavy.memory_gb

    def test_metrics_are_empty_with_no_labs(self, provider):
        metrics = provider.get_metrics()
        assert metrics.active_count == 0
        assert metrics.vcpu == 0

    def test_metrics_payload_exposes_both_keys(self, provider):
        provider.launch_lab(LabConfig(environment="kali"))
        payload = provider.get_metrics().to_dict()
        # 'labs' is canonical; 'instances' kept for the existing dashboard code.
        assert payload["labs"] == payload["instances"]


class TestConnection:
    def test_connection_targets_container_name(self, provider):
        """
        Guacamole reaches labs by container name over the shared network, which
        survives container IP changes.
        """
        info = provider.launch_lab(LabConfig(environment="kali"))
        conn = provider.get_connection(info.lab_id, "rdp")
        assert conn.host == provider._docker.containers.store[0].name
        assert conn.host.startswith("shadowtrust-lab-")

    def test_no_connection_for_unknown_lab(self, provider):
        assert provider.get_connection("ghost", "rdp") is None
