"""
AWS lab provider — the original EC2 implementation, preserved behind the
LabProvider contract.

This module wraps AWSOrchestrator without modifying it, so existing AWS
behaviour is unchanged when INFRA_PROVIDER=aws. All EC2 vocabulary
(instance IDs, instance types, AMIs, subnets, EC2 states) is confined to this
file; the application layer only ever sees lab_id / profile / status.

lab_id -> instance mapping is resolved through the 'SessionID' EC2 tag that
AWSOrchestrator.launch_analysis_vm already writes, so no orchestrator change
is required.

boto3 and AWSOrchestrator are imported lazily so that INFRA_PROVIDER=local
never constructs an AWS client.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

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

# Generic resource tier -> EC2 instance type.
PROFILE_INSTANCE_TYPES = {
    "light": os.getenv("AWS_INSTANCE_TYPE_LIGHT", "t3.small"),
    "standard": os.getenv("AWS_INSTANCE_TYPE_STANDARD", "t3.medium"),
    "heavy": os.getenv("AWS_INSTANCE_TYPE_HEAVY", "t3.xlarge"),
}

# EC2 lifecycle state -> normalised LabStatus.
_STATE_MAP = {
    "pending": LabStatus.PROVISIONING,
    "running": LabStatus.RUNNING,
    "shutting-down": LabStatus.STOPPING,
    "stopping": LabStatus.STOPPING,
    "stopped": LabStatus.TERMINATED,
    "terminated": LabStatus.TERMINATED,
}

PROTOCOL_PORTS = {"rdp": 3389, "ssh": 22}

# Per-environment lab credentials, matching the EC2 user_data bootstrap.
_ENV_CREDENTIALS = {
    "kali": (
        os.getenv("LAB_KALI_USER", "kali"),
        os.getenv("LAB_KALI_PASSWORD", "kali"),
    ),
    "windows": (
        os.getenv("LAB_WINDOWS_USER", "Administrator"),
        os.getenv("LAB_WINDOWS_PASSWORD", ""),
    ),
    "windows_malware": (
        os.getenv("LAB_WINDOWS_USER", "Administrator"),
        os.getenv("LAB_WINDOWS_MALWARE_PASSWORD", ""),
    ),
}


class AWSLabProvider(LabProvider):
    """EC2-backed labs. Requires AWS credentials; selected via INFRA_PROVIDER=aws."""

    name = "aws"
    supported_environments = frozenset(
        {"kali", "kali_base", "linux", "windows", "win_base", "windows_malware", "win_malware"}
    )

    def __init__(
        self,
        region_name: Optional[str] = None,
        aws_access_key: Optional[str] = None,
        aws_secret_key: Optional[str] = None,
        ami_map: Optional[Dict[str, str]] = None,
        subnet_id: Optional[str] = None,
        security_group_id: Optional[str] = None,
        iam_profile_name: Optional[str] = None,
    ):
        self.region_name = region_name or os.getenv("AWS_REGION", "ap-south-1")
        self.aws_access_key = aws_access_key or os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = aws_secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.subnet_id = subnet_id or os.getenv("AWS_SUBNET_ID", "")
        self.security_group_id = security_group_id or os.getenv("AWS_SECURITY_GROUP_ID", "")
        self.iam_profile_name = (
            iam_profile_name if iam_profile_name is not None
            else os.getenv("AWS_IAM_PROFILE", "")
        )
        self.ami_map = ami_map or {
            "kali": os.getenv("AWS_AMI_KALI", ""),
            "windows": os.getenv("AWS_AMI_WINDOWS", ""),
            "windows_malware": os.getenv("AWS_AMI_WINDOWS_MALWARE", ""),
        }
        self._orchestrator = None

    # ── AWS plumbing ─────────────────────────────────────────────────────────

    @property
    def orchestrator(self):
        """Lazily construct AWSOrchestrator so importing this module is boto3-free."""
        if self._orchestrator is None:
            try:
                from app.services.aws_orchestrator import AWSOrchestrator
            except ImportError as exc:
                raise ProviderUnavailableError(
                    "boto3 is required for INFRA_PROVIDER=aws. Install it with: pip install boto3"
                ) from exc
            self._orchestrator = AWSOrchestrator(
                region_name=self.region_name,
                aws_access_key=self.aws_access_key,
                aws_secret_key=self.aws_secret_key,
            )
        return self._orchestrator

    def _normalise_env(self, environment: str) -> str:
        env = str(environment or "").lower()
        if "malware" in env:
            return "windows_malware"
        if "kali" in env or env == "linux":
            return "kali"
        if "win" in env:
            return "windows"
        return env

    def _resolve_instance_id(self, lab_id: str) -> Optional[str]:
        """Map an opaque lab_id back to its EC2 instance via the SessionID tag."""
        try:
            response = self.orchestrator.ec2.describe_instances(
                Filters=[
                    {"Name": "tag:SessionID", "Values": [lab_id]},
                    {"Name": "tag:ManagedBy", "Values": ["ShadowTrust"]},
                ]
            )
            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    return instance.get("InstanceId")
        except Exception as exc:
            logger.warning(f"Could not resolve lab {lab_id} to an EC2 instance: {exc}")
        return None

    def _describe(self, lab_id: str) -> Optional[Dict[str, Any]]:
        try:
            response = self.orchestrator.ec2.describe_instances(
                Filters=[
                    {"Name": "tag:SessionID", "Values": [lab_id]},
                    {"Name": "tag:ManagedBy", "Values": ["ShadowTrust"]},
                ]
            )
            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    return instance
        except Exception as exc:
            logger.warning(f"describe_instances failed for lab {lab_id}: {exc}")
        return None

    def _credentials_for(self, environment: str):
        return _ENV_CREDENTIALS.get(self._normalise_env(environment), ("", ""))

    def _info_from_instance(self, lab_id: str, instance: Dict[str, Any]) -> LabInfo:
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        environment = tags.get("Environment", "kali")
        profile = tags.get("Profile", "standard")
        protocol = tags.get("Protocol", "rdp")

        ec2_state = instance.get("State", {}).get("Name", "")
        status = _STATE_MAP.get(ec2_state, LabStatus.UNKNOWN)

        host = instance.get("PublicIpAddress") or instance.get("PrivateIpAddress")
        connection = None
        if status == LabStatus.RUNNING and host:
            username, password = self._credentials_for(environment)
            connection = LabConnection(
                host=host,
                port=PROTOCOL_PORTS.get(protocol, 3389),
                protocol=protocol,
                username=username,
                password=password,
            )

        return LabInfo(
            lab_id=lab_id,
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
        if env not in {"kali", "windows", "windows_malware"}:
            raise UnsupportedEnvironmentError(
                f"AWS provider does not know environment '{config.environment}'."
            )

        ami_id = self.ami_map.get(env)
        if not ami_id:
            raise ProviderUnavailableError(
                f"No AMI configured for environment '{env}'. "
                f"Set AWS_AMI_{env.upper()} or save it on the AWS Connection page."
            )

        resources = config.resources
        instance_type = PROFILE_INSTANCE_TYPES.get(resources.id, "t3.medium")

        # The lab_id is minted here and written to the instance's SessionID tag,
        # which is how every later lookup maps lab_id back to an instance.
        lab_id = str(config.labels.get("lab_id") or uuid.uuid4())

        result = self.orchestrator.launch_analysis_vm(
            ami_id=ami_id,
            instance_type=instance_type,
            session_id=lab_id,
            subnet_id=self.subnet_id,
            iam_profile_name=self.iam_profile_name,
            profile_id=env,
            security_group_id=self.security_group_id,
        )

        if result.get("status") == "error":
            raise ProviderUnavailableError(result.get("message", "EC2 launch failed."))

        # Record generic attributes as tags so status lookups stay provider-agnostic.
        try:
            self.orchestrator.ec2.create_tags(
                Resources=[result["instance_id"]],
                Tags=[
                    {"Key": "Environment", "Value": env},
                    {"Key": "Profile", "Value": resources.id},
                    {"Key": "Protocol", "Value": config.protocol},
                ],
            )
        except Exception as exc:
            logger.warning(f"Could not tag instance for lab {lab_id}: {exc}")

        return LabInfo(
            lab_id=lab_id,
            status=LabStatus.PROVISIONING,
            environment=env,
            profile=resources.id,
            resources=resources,
            message="EC2 instance launching.",
        )

    def terminate_lab(self, lab_id: str) -> bool:
        instance_id = self._resolve_instance_id(lab_id)
        if instance_id is None:
            # Fall back to treating lab_id as an instance ID (legacy records).
            instance_id = lab_id if lab_id.startswith("i-") else None
        if instance_id is None:
            logger.info(f"Lab {lab_id} has no live EC2 instance; treating as terminated.")
            return True
        return self.orchestrator.terminate_vm(instance_id)

    def get_lab_status(self, lab_id: str) -> LabInfo:
        instance = self._describe(lab_id)
        if instance is None:
            return LabInfo(
                lab_id=lab_id,
                status=LabStatus.TERMINATED,
                environment="unknown",
                profile="standard",
                message="No EC2 instance found for this lab.",
            )
        return self._info_from_instance(lab_id, instance)

    def get_metrics(self) -> ClusterMetrics:
        raw = self.orchestrator.get_cluster_metrics()
        if raw.get("status") != "success":
            return ClusterMetrics(status="success", message=raw.get("message"))

        labs: List[Dict[str, Any]] = []
        for inst in raw.get("instances", []):
            labs.append(
                {
                    "lab_id": inst.get("instance_id"),
                    "status": str(inst.get("status", "")).upper(),
                    "environment": inst.get("profile_id", "unknown"),
                    "profile": "standard",
                    "host": inst.get("public_ip") or inst.get("private_ip"),
                    "resources": None,
                }
            )

        return ClusterMetrics(
            vcpu=raw.get("vcpu", 0),
            ram=raw.get("ram", 0),
            active_count=raw.get("active_count", 0),
            labs=labs,
        )

    def get_console_url(self, lab_id: str) -> Optional[str]:
        """AWS Systems Manager Session Manager link for the lab's instance."""
        instance_id = self._resolve_instance_id(lab_id)
        if instance_id is None:
            return None
        return self.orchestrator.generate_ssm_session_url(instance_id)

    def wait_until_ready(self, lab_id: str, timeout: int = 900) -> LabInfo:
        """
        Two-stage EC2 readiness wait, moved out of LabSessionManager:
          1. instance reaches 'running' and reports an IP
          2. both EC2 status checks report 'ok' (the OS has actually booted)
        """
        instance_id = self._resolve_instance_id(lab_id)
        if instance_id is None:
            return LabInfo(
                lab_id=lab_id,
                status=LabStatus.ERROR,
                environment="unknown",
                profile="standard",
                message="Instance for lab not found.",
            )

        deadline = time.time() + timeout
        poll = 10
        host = None

        # Stage 1 — running with an IP.
        while time.time() < deadline:
            instance = self._describe(lab_id)
            if instance is None:
                break
            state = instance.get("State", {}).get("Name", "")
            if state in ("terminated", "shutting-down"):
                return LabInfo(
                    lab_id=lab_id, status=LabStatus.ERROR, environment="unknown",
                    profile="standard", message="Instance terminated during provisioning.",
                )
            if state == "running":
                host = instance.get("PublicIpAddress") or instance.get("PrivateIpAddress")
                if host:
                    break
            time.sleep(poll)

        if not host:
            return LabInfo(
                lab_id=lab_id, status=LabStatus.ERROR, environment="unknown",
                profile="standard", message="Timed out waiting for an instance IP.",
            )

        # Stage 2 — status checks 2/2.
        while time.time() < deadline:
            try:
                resp = self.orchestrator.ec2.describe_instance_status(
                    InstanceIds=[instance_id], IncludeAllInstances=True
                )
                statuses = resp.get("InstanceStatuses", [])
                if statuses:
                    entry = statuses[0]
                    sys_ok = entry.get("SystemStatus", {}).get("Status") == "ok"
                    inst_ok = entry.get("InstanceStatus", {}).get("Status") == "ok"
                    inst_state = entry.get("InstanceState", {}).get("Name", "")
                    if inst_state in ("terminated", "shutting-down"):
                        return LabInfo(
                            lab_id=lab_id, status=LabStatus.ERROR, environment="unknown",
                            profile="standard", message="Instance terminated during boot.",
                        )
                    if sys_ok and inst_ok:
                        info = self.get_lab_status(lab_id)
                        info.status = LabStatus.READY
                        return info
            except Exception as exc:
                logger.warning(f"Status check failed for lab {lab_id}: {exc}")
            time.sleep(poll)

        info = self.get_lab_status(lab_id)
        info.status = LabStatus.ERROR
        info.message = f"Instance did not pass status checks within {timeout}s."
        return info
