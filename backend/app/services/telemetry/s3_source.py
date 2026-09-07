"""
S3 telemetry source — the original AWS ingestion path, behind TelemetrySource.

Delegates to _pipeline_s3_fetch in aws_telemetry_service, which is unchanged,
so AWS ingestion behaviour is byte-for-byte what it was before the refactor.

boto3 is only touched inside fetch(), so constructing this class costs nothing
and importing the module does not pull in AWS libraries.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from app.services.telemetry.base import TelemetrySource

logger = logging.getLogger(__name__)


class S3Source(TelemetrySource):
    """Reads honeypot events from an S3 bucket. Requires AWS credentials."""

    name = "s3"

    def __init__(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        region: Optional[str] = None,
        bucket: Optional[str] = None,
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region or "ap-south-1"
        self.bucket = bucket

    def configure(
        self,
        access_key: Optional[str],
        secret_key: Optional[str],
        region: Optional[str],
        bucket: Optional[str],
    ) -> None:
        """Refresh credentials from SystemConfig between polling cycles."""
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region or "ap-south-1"
        self.bucket = bucket

    def is_configured(self) -> bool:
        return bool(self.access_key and self.secret_key and self.bucket)

    def describe(self) -> str:
        return f"s3://{self.bucket}" if self.bucket else "s3 (unconfigured)"

    def fetch(
        self, processed_state_by_key: Dict[str, datetime]
    ) -> Tuple[List[dict], Set[str]]:
        if not self.is_configured():
            return [], set()

        # Imported here so INFRA_PROVIDER=local never loads boto3.
        from app.services.aws_telemetry_service import _pipeline_s3_fetch

        return _pipeline_s3_fetch(
            self.access_key,
            self.secret_key,
            self.region,
            self.bucket,
            processed_state_by_key,
        )
