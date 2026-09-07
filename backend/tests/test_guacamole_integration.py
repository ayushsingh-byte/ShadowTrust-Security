"""
Guacamole connection generation from provider-supplied details.

The point of these tests is the seam: GuacamoleService takes a host, port,
protocol and credentials, and does not care which provider produced them. A
Docker container and an EC2 instance must both be able to feed it.
"""

import pytest

from app.services.guacamole_service import GuacamoleService
from app.services.providers.base import LabConfig, LabConnection
from app.services.providers.docker_provider import DockerLabProvider

from tests.test_docker_provider import FakeDockerClient


class FakeCursor:
    def __init__(self, recorder):
        self.recorder = recorder

    def execute(self, sql, params=None):
        self.recorder["statements"].append((sql.strip(), params))

    def executemany(self, sql, seq):
        self.recorder["params"].extend(seq)

    def fetchone(self):
        return (42,)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConnection:
    def __init__(self, recorder):
        self.recorder = recorder

    def cursor(self):
        return FakeCursor(self.recorder)

    def commit(self):
        self.recorder["committed"] = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture
def guac(monkeypatch):
    recorder = {"statements": [], "params": [], "committed": False}
    service = GuacamoleService()
    monkeypatch.setattr(service, "_get_connection", lambda: FakeConnection(recorder))
    service.recorder = recorder
    return service


@pytest.fixture
def provider():
    p = DockerLabProvider(network="guacamole_guacnet")
    p._docker = FakeDockerClient()
    return p


class TestConnectionFromDockerLab:
    def test_docker_connection_details_register_with_guacamole(self, provider, guac):
        info = provider.launch_lab(LabConfig(environment="kali", protocol="rdp"))
        connection = provider.get_connection(info.lab_id, "rdp")

        connection_id = guac.create_connection(
            lab_id=info.lab_id,
            private_ip=connection.host,
            protocol=connection.protocol,
            port=str(connection.port),
            username=connection.username,
            password=connection.password,
        )

        assert connection_id == 42
        assert guac.recorder["committed"] is True

    def test_hostname_parameter_is_the_container_name(self, provider, guac):
        info = provider.launch_lab(LabConfig(environment="kali"))
        connection = provider.get_connection(info.lab_id, "rdp")

        guac.create_connection(
            lab_id=info.lab_id,
            private_ip=connection.host,
            protocol=connection.protocol,
            port=str(connection.port),
            username=connection.username,
            password=connection.password,
        )

        params = dict((name, value) for _cid, name, value in guac.recorder["params"])
        assert params["hostname"] == connection.host
        assert params["hostname"].startswith("shadowtrust-lab-")
        assert params["port"] == "3389"

    def test_credentials_are_passed_through(self, provider, guac):
        info = provider.launch_lab(LabConfig(environment="kali"))
        connection = provider.get_connection(info.lab_id, "rdp")

        guac.create_connection(
            lab_id=info.lab_id,
            private_ip=connection.host,
            protocol=connection.protocol,
            port=str(connection.port),
            username=connection.username,
            password=connection.password,
        )

        params = dict((name, value) for _cid, name, value in guac.recorder["params"])
        assert params["username"] == "kali"
        assert params["password"] == "kali"

    def test_ssh_lab_registers_on_port_22(self, provider, guac):
        info = provider.launch_lab(LabConfig(environment="kali", protocol="ssh"))
        connection = provider.get_connection(info.lab_id, "ssh")

        guac.create_connection(
            lab_id=info.lab_id,
            private_ip=connection.host,
            protocol=connection.protocol,
            port=str(connection.port),
            username=connection.username,
            password=connection.password,
        )

        params = dict((name, value) for _cid, name, value in guac.recorder["params"])
        assert params["port"] == "22"


class TestSeamIsProviderAgnostic:
    def test_guacamole_accepts_any_labconnection(self, guac):
        """
        A hand-built LabConnection (standing in for the AWS provider's output)
        registers exactly the same way a Docker one does.
        """
        aws_style = LabConnection(
            host="13.234.55.10", port=3389, protocol="rdp",
            username="Administrator", password="secret",
        )

        connection_id = guac.create_connection(
            lab_id="lab-from-aws",
            private_ip=aws_style.host,
            protocol=aws_style.protocol,
            port=str(aws_style.port),
            username=aws_style.username,
            password=aws_style.password,
        )

        params = dict((name, value) for _cid, name, value in guac.recorder["params"])
        assert connection_id == 42
        assert params["hostname"] == "13.234.55.10"

    def test_delete_connection_revokes_access(self, guac):
        assert guac.delete_connection(42) is True
        statements = " ".join(s for s, _p in guac.recorder["statements"])
        assert "DELETE FROM guacamole_connection" in statements
