"""
Telemetry source selection.

Follows the same INFRA_PROVIDER switch as the lab providers, so a single
environment variable puts the whole platform in local or AWS mode.
TELEMETRY_SOURCE can override it independently when someone wants, say, local
labs but cloud telemetry.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from app.services.telemetry.base import TelemetrySource

VALID_SOURCES = ("local", "s3")


def get_source_name() -> str:
    """Resolve the telemetry source name from configuration."""
    explicit = os.getenv("TELEMETRY_SOURCE", "").strip().lower()
    if explicit:
        return explicit

    # Fall back to the platform-wide provider switch.
    provider = os.getenv("INFRA_PROVIDER", "local").strip().lower()
    return "s3" if provider == "aws" else "local"


def get_telemetry_source(source: Optional[str] = None, **kwargs: Any) -> TelemetrySource:
    """
    Build the configured TelemetrySource.

    Raises:
        ValueError: when the configured source name is unknown.
    """
    name = (source or get_source_name()).strip().lower()

    if name == "local":
        from app.services.telemetry.local_source import LocalDirectorySource
        return LocalDirectorySource(**kwargs)

    if name == "s3":
        from app.services.telemetry.s3_source import S3Source
        return S3Source(**kwargs)

    raise ValueError(
        f"Unknown TELEMETRY_SOURCE '{name}'. Valid values: {', '.join(VALID_SOURCES)}."
    )
