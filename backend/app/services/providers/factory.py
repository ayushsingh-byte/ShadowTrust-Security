"""
Single entry point for obtaining the configured lab provider.

Selection is driven by INFRA_PROVIDER, defaulting to 'local' so a fresh
checkout runs with no cloud account and no AWS credentials.

Provider modules are imported inside the branches, so selecting 'local' never
imports boto3 and selecting 'aws' never imports the Docker SDK.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from app.services.providers.base import LabProvider

VALID_PROVIDERS = ("local", "aws")

DEFAULT_PROVIDER = "local"


def get_provider_name() -> str:
    """The provider this process is configured to use."""
    return os.getenv("INFRA_PROVIDER", DEFAULT_PROVIDER).strip().lower()


def get_lab_provider(
    provider: Optional[str] = None,
    aws_credentials: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> LabProvider:
    """
    Build the configured LabProvider.

    Args:
        provider: overrides INFRA_PROVIDER (mainly for tests).
        aws_credentials: optional dict with aws_access_key / aws_secret_key /
            aws_region, used only when the AWS provider is selected. Callers
            that hold per-request credentials (the AWS Connection page saves
            them in SystemConfig) pass them through here.
        **kwargs: forwarded to the provider constructor.

    Raises:
        ValueError: when INFRA_PROVIDER names an unknown provider.
    """
    name = (provider or get_provider_name()).strip().lower()

    if name == "local":
        from app.services.providers.docker_provider import DockerLabProvider
        return DockerLabProvider(**kwargs)

    if name == "aws":
        from app.services.providers.aws_provider import AWSLabProvider
        creds = aws_credentials or {}
        return AWSLabProvider(
            region_name=creds.get("aws_region"),
            aws_access_key=creds.get("aws_access_key"),
            aws_secret_key=creds.get("aws_secret_key"),
            ami_map=creds.get("ami_map"),
            subnet_id=creds.get("subnet_id"),
            security_group_id=creds.get("security_group_id"),
            iam_profile_name=creds.get("iam_profile_name"),
            **kwargs,
        )

    raise ValueError(
        f"Unknown INFRA_PROVIDER '{name}'. Valid values: {', '.join(VALID_PROVIDERS)}."
    )
