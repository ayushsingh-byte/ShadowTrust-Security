"""
Provider factory selection.

The most important assertion here is the last one: selecting the local provider
must not import boto3 or construct any AWS client.
"""

import sys

import pytest

from app.services.providers import get_lab_provider, get_provider_name
from app.services.providers.docker_provider import DockerLabProvider


class TestProviderSelection:
    def test_defaults_to_local_when_unset(self):
        assert get_provider_name() == "local"
        assert isinstance(get_lab_provider(), DockerLabProvider)

    def test_local_provider_selected_explicitly(self, monkeypatch):
        monkeypatch.setenv("INFRA_PROVIDER", "local")
        provider = get_lab_provider()
        assert isinstance(provider, DockerLabProvider)
        assert provider.name == "local"

    def test_aws_provider_selected(self, monkeypatch):
        monkeypatch.setenv("INFRA_PROVIDER", "aws")
        from app.services.providers.aws_provider import AWSLabProvider

        provider = get_lab_provider()
        assert isinstance(provider, AWSLabProvider)
        assert provider.name == "aws"

    def test_provider_name_is_case_and_space_insensitive(self, monkeypatch):
        monkeypatch.setenv("INFRA_PROVIDER", "  AWS  ")
        assert get_provider_name() == "aws"

    def test_invalid_provider_raises(self, monkeypatch):
        monkeypatch.setenv("INFRA_PROVIDER", "azure")
        with pytest.raises(ValueError) as exc:
            get_lab_provider()
        assert "azure" in str(exc.value)
        assert "local" in str(exc.value)

    def test_explicit_argument_overrides_environment(self, monkeypatch):
        monkeypatch.setenv("INFRA_PROVIDER", "aws")
        provider = get_lab_provider(provider="local")
        assert isinstance(provider, DockerLabProvider)


class TestNoAWSInLocalMode:
    """INFRA_PROVIDER=local must never touch AWS libraries."""

    def test_local_selection_does_not_construct_aws_clients(self, monkeypatch):
        monkeypatch.setenv("INFRA_PROVIDER", "local")

        import boto3

        def _explode(*args, **kwargs):
            raise AssertionError("boto3 client was constructed in local mode")

        monkeypatch.setattr(boto3, "client", _explode)
        monkeypatch.setattr(boto3, "Session", _explode)
        monkeypatch.setattr(boto3, "resource", _explode, raising=False)

        provider = get_lab_provider()
        # Constructing and inspecting the provider must stay AWS-free.
        assert provider.name == "local"
        assert provider.describe_profiles()
        assert provider.supports("kali")

    def test_aws_provider_defers_client_construction(self, monkeypatch):
        """
        Instantiating AWSLabProvider must not build a client either — clients
        appear only when a lab operation actually runs.
        """
        monkeypatch.setenv("INFRA_PROVIDER", "aws")

        import boto3

        monkeypatch.setattr(
            boto3, "client",
            lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("client built during construction")
            ),
        )

        provider = get_lab_provider()
        assert provider._orchestrator is None

    def test_telemetry_module_imports_without_boto3(self, monkeypatch):
        """
        The telemetry service must stay importable with boto3 absent, so a
        local-only deployment need not install AWS libraries at all.
        """
        monkeypatch.setitem(sys.modules, "boto3", None)
        import importlib

        import app.services.aws_telemetry_service as svc

        importlib.reload(svc)
        assert hasattr(svc, "UnifiedTelemetryService")
