"""Container manager policy allow-list (task 10) — pure unit tests."""

import pytest

from app.services import container_manager as cm
from app.services.container_manager import ContainerPolicyError


def _ok_kwargs(**over):
    base = dict(
        name="shadowtrust-lab-abc123",
        network="shadowtrust_labnet",
        nano_cpus=2_000_000_000,
        mem_limit="4g",
        labels={cm.MANAGED_LABEL: "true", cm.LAB_ID_LABEL: "lab-1"},
    )
    base.update(over)
    return base


IMG = sorted(cm.ALLOWED_LAB_IMAGES)[0]


def test_valid_lab_run_passes():
    cm.validate_lab_run(IMG, _ok_kwargs(), allowed_network="shadowtrust_labnet")


def test_rejects_unknown_image():
    with pytest.raises(ContainerPolicyError):
        cm.validate_lab_run("evil/image:latest", _ok_kwargs())


def test_rejects_wrong_network():
    with pytest.raises(ContainerPolicyError):
        cm.validate_lab_run(IMG, _ok_kwargs(network="honeynet_edge"),
                            allowed_network="shadowtrust_labnet")


def test_rejects_bind_mounts():
    with pytest.raises(ContainerPolicyError):
        cm.validate_lab_run(IMG, _ok_kwargs(volumes={"/etc": {"bind": "/host_etc"}}),
                            allowed_network="shadowtrust_labnet")


def test_rejects_privileged():
    with pytest.raises(ContainerPolicyError):
        cm.validate_lab_run(IMG, _ok_kwargs(privileged=True),
                            allowed_network="shadowtrust_labnet")


def test_rejects_missing_managed_label():
    with pytest.raises(ContainerPolicyError):
        cm.validate_lab_run(IMG, _ok_kwargs(labels={cm.LAB_ID_LABEL: "x"}),
                            allowed_network="shadowtrust_labnet")


def test_rejects_bad_name_prefix():
    with pytest.raises(ContainerPolicyError):
        cm.validate_lab_run(IMG, _ok_kwargs(name="pwned"),
                            allowed_network="shadowtrust_labnet")


def test_rejects_oversized_resources():
    with pytest.raises(ContainerPolicyError):
        cm.validate_lab_run(IMG, _ok_kwargs(mem_limit="999g"),
                            allowed_network="shadowtrust_labnet")


def test_caps_and_devices_only_for_windows_image():
    win = cm.os.getenv("LAB_IMAGE_WINDOWS", "dockurr/windows")
    # allowed for the windows image
    cm.validate_lab_run(win, _ok_kwargs(cap_add=["NET_ADMIN"], devices=["/dev/kvm"]),
                        allowed_network="shadowtrust_labnet")
    # not for kali
    with pytest.raises(ContainerPolicyError):
        cm.validate_lab_run(IMG, _ok_kwargs(cap_add=["SYS_ADMIN"]),
                            allowed_network="shadowtrust_labnet")


class _C:
    def __init__(self, name, managed):
        self.name = name
        self.labels = {cm.MANAGED_LABEL: "true"} if managed else {}


def test_assert_managed_guards_lifecycle():
    cm.assert_managed(_C("shadowtrust-lab-1", True))
    with pytest.raises(ContainerPolicyError):
        cm.assert_managed(_C("honeynet_cowrie", False))


def test_read_container_logs_is_name_allowlisted():
    with pytest.raises(ContainerPolicyError):
        cm.read_container_logs("honeynet_cowrie", 50)  # honeypot stdout not exposed
