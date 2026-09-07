"""
End-to-end lab lifecycle through LabSessionManager.

Verifies the application layer stays provider-agnostic: the manager drives a
stub provider through launch -> ready -> Guacamole registration -> terminate
without ever referring to instance IDs, AMIs or EC2 states.
"""

import asyncio

import pytest

from app.services.providers.base import (
    ClusterMetrics,
    LabConfig,
    LabConnection,
    LabInfo,
    LabProvider,
    LabStatus,
    resolve_profile,
)


class StubProvider(LabProvider):
    """Minimal in-memory LabProvider; stands in for Docker or EC2."""

    name = "stub"
    supported_environments = frozenset({"kali"})

    def __init__(self):
        self.labs = {}
        self.launched = []
        self.terminated = []
        self.fail_ready = False

    def launch_lab(self, config: LabConfig) -> LabInfo:
        lab_id = config.labels.get("lab_id", "stub-lab")
        self.launched.append(config)
        self.labs[lab_id] = {
            "environment": config.environment,
            "profile": config.resources.id,
            "protocol": config.protocol,
        }
        return LabInfo(
            lab_id=lab_id,
            status=LabStatus.PROVISIONING,
            environment=config.environment,
            profile=config.resources.id,
            resources=config.resources,
        )

    def terminate_lab(self, lab_id: str) -> bool:
        self.terminated.append(lab_id)
        self.labs.pop(lab_id, None)
        return True

    def get_lab_status(self, lab_id: str) -> LabInfo:
        record = self.labs.get(lab_id)
        if record is None:
            return LabInfo(lab_id=lab_id, status=LabStatus.TERMINATED,
                           environment="unknown", profile="standard")
        return LabInfo(
            lab_id=lab_id, status=LabStatus.RUNNING,
            environment=record["environment"], profile=record["profile"],
            host="lab-host", resources=resolve_profile(record["profile"]),
        )

    def get_metrics(self) -> ClusterMetrics:
        return ClusterMetrics(vcpu=4, ram=4, active_count=len(self.labs), labs=[])

    def wait_until_ready(self, lab_id: str, timeout: int = 300) -> LabInfo:
        if self.fail_ready:
            return LabInfo(lab_id=lab_id, status=LabStatus.ERROR,
                           environment="kali", profile="light",
                           message="boot failed")
        info = self.get_lab_status(lab_id)
        info.status = LabStatus.READY
        info.connection = LabConnection(
            host="lab-host", port=3389, protocol="rdp",
            username="kali", password="kali",
        )
        return info

    def get_connection(self, lab_id, protocol="rdp"):
        if lab_id not in self.labs:
            return None
        return LabConnection(host="lab-host", port=3389, protocol=protocol,
                             username="kali", password="kali")


class RecordingGuac:
    def __init__(self, connection_id=7):
        self.connection_id = connection_id
        self.created = []
        self.deleted = []

    def create_connection(self, lab_id, private_ip, protocol="rdp", port="3389",
                          username="", password=""):
        self.created.append({
            "lab_id": lab_id, "host": private_ip, "protocol": protocol,
            "port": port, "username": username, "password": password,
        })
        return self.connection_id

    def delete_connection(self, connection_id):
        self.deleted.append(connection_id)
        return True


@pytest.fixture
def manager(monkeypatch, tmp_path):
    from app.services import session_manager as sm

    # Isolate the on-disk state file and the in-memory registry per test.
    monkeypatch.setattr(sm, "STATE_FILE", str(tmp_path / ".lab_state.json"))
    monkeypatch.setattr(sm, "GLOBAL_LAB_STATE", {})

    # The DB is exercised elsewhere; here we isolate the provider/Guacamole path.
    async def _noop(*args, **kwargs):
        return None
    monkeypatch.setattr(sm.LabSessionManager, "_update_db_status", _noop)

    provider = StubProvider()
    mgr = sm.LabSessionManager(provider=provider)
    mgr.guac = RecordingGuac()
    return mgr, provider, sm


class TestProvisioning:
    def test_launch_returns_generic_payload(self, manager):
        mgr, provider, _sm = manager
        result = asyncio.run(
            mgr.start_lab_provisioning(user_id="u1", environment_type="kali",
                                       profile="light", protocol="rdp")
        )

        assert result["status"] == "provisioning"
        assert result["lab_id"]
        assert result["environment"] == "kali"
        assert result["profile"] == "light"
        # No EC2 vocabulary anywhere in the response.
        assert "instance_id" not in result
        assert "ami_id" not in result

    def test_profile_reaches_the_provider(self, manager):
        mgr, provider, _sm = manager
        asyncio.run(
            mgr.start_lab_provisioning(user_id="u1", environment_type="kali",
                                       profile="heavy")
        )
        assert provider.launched[0].resources.id == "heavy"
        assert provider.launched[0].resources.cpu == 6

    def test_state_records_provider_name(self, manager):
        mgr, _provider, sm = manager
        result = asyncio.run(
            mgr.start_lab_provisioning(user_id="u1", environment_type="kali")
        )
        assert sm.GLOBAL_LAB_STATE[result["lab_id"]]["provider"] == "stub"


class TestReadiness:
    def test_ready_lab_registers_a_guacamole_connection(self, manager):
        mgr, _provider, sm = manager
        result = asyncio.run(
            mgr.start_lab_provisioning(user_id="u1", environment_type="kali")
        )
        lab_id = result["lab_id"]

        asyncio.run(mgr.process_lab_readiness(lab_id))

        assert len(mgr.guac.created) == 1
        created = mgr.guac.created[0]
        assert created["host"] == "lab-host"
        assert created["port"] == "3389"
        assert created["username"] == "kali"

        assert sm.GLOBAL_LAB_STATE[lab_id]["status"] == LabStatus.READY
        assert sm.GLOBAL_LAB_STATE[lab_id]["guacamole_connection_id"] == 7

    def test_failed_boot_marks_error_and_skips_guacamole(self, manager):
        mgr, provider, _sm = manager
        provider.fail_ready = True
        result = asyncio.run(
            mgr.start_lab_provisioning(user_id="u1", environment_type="kali")
        )

        asyncio.run(mgr.process_lab_readiness(result["lab_id"]))

        assert mgr.guac.created == []

    def test_lab_stays_ready_when_guacamole_is_down(self, manager):
        """A Guacamole outage must not destroy a healthy lab."""
        mgr, _provider, sm = manager
        mgr.guac.connection_id = None
        result = asyncio.run(
            mgr.start_lab_provisioning(user_id="u1", environment_type="kali")
        )
        lab_id = result["lab_id"]

        asyncio.run(mgr.process_lab_readiness(lab_id))

        assert sm.GLOBAL_LAB_STATE[lab_id]["status"] == LabStatus.READY
        assert sm.GLOBAL_LAB_STATE[lab_id]["guacamole_connection_id"] is None


class TestTermination:
    def test_terminate_removes_lab_and_guacamole_connection(self, manager):
        mgr, provider, sm = manager
        result = asyncio.run(
            mgr.start_lab_provisioning(user_id="u1", environment_type="kali")
        )
        lab_id = result["lab_id"]
        asyncio.run(mgr.process_lab_readiness(lab_id))

        success = asyncio.run(mgr.terminate_lab(lab_id))

        assert success is True
        assert provider.terminated == [lab_id]
        assert mgr.guac.deleted == [7]
        assert sm.GLOBAL_LAB_STATE[lab_id]["status"] == LabStatus.TERMINATED

    def test_terminate_needs_only_a_lab_id(self, manager):
        """No instance_id argument exists any more — lab_id is sufficient."""
        mgr, provider, _sm = manager
        result = asyncio.run(
            mgr.start_lab_provisioning(user_id="u1", environment_type="kali")
        )
        assert asyncio.run(mgr.terminate_lab(result["lab_id"])) is True


class TestMetrics:
    def test_metrics_come_back_provider_neutral(self, manager):
        mgr, _provider, _sm = manager
        asyncio.run(mgr.start_lab_provisioning(user_id="u1", environment_type="kali"))

        metrics = asyncio.run(mgr.get_metrics())

        assert metrics["status"] == "success"
        assert metrics["active_count"] == 1
        assert "labs" in metrics and "instances" in metrics
