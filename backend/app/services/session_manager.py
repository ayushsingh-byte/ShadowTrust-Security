import logging
import uuid
import json
import os
import asyncio
from typing import Dict, Any, Optional

from app.services.aws_orchestrator import AWSOrchestrator
from app.services.guacamole_service import GuacamoleService
from app.db.sqlite_db import AsyncSessionLocal
from app.models.all_models import VMInstance
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

STATE_FILE = os.path.join(os.path.dirname(__file__), "..", "..", ".lab_state.json")

def load_local_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
            # Any PROVISIONING entries left over from a previous process run are stuck —
            # the background task that was polling AWS died with that process.
            # Mark them ERROR so the frontend can reset cleanly instead of polling forever.
            changed = False
            for lab_id, record in state.items():
                if record.get("status") == "PROVISIONING":
                    record["status"] = "ERROR"
                    changed = True
            if changed:
                try:
                    with open(STATE_FILE, "w") as f:
                        json.dump(state, f)
                except Exception:
                    pass
            return state
        except:
            pass
    return {}

def save_local_state(state):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        logger.warning(f"Failed to save local state: {e}")

GLOBAL_LAB_STATE = load_local_state()

class LabSessionManager:
    """
    Coordinates the entire Lab lifecycle: AWS EC2 Provisioning -> IP Extraction -> Guacamole Connection Registration -> Database tracking.
    """
    def __init__(self, aws_region="ap-south-1", aws_access_key=None, aws_secret_key=None):
        self.aws = AWSOrchestrator(
            region_name=aws_region,
            aws_access_key=aws_access_key,
            aws_secret_key=aws_secret_key
        )
        self.guac = GuacamoleService()

    async def start_lab_provisioning(self, user_id: str, environment_type: str, ami_id: str, instance_type: str, subnet_id: str, security_group_id: str = None, protocol: str = "rdp") -> Dict[str, Any]:
        """
        Initiates the EC2 launch sequence immediately and creates a provisioning database record.
        Returns the lab_id to the frontend.
        """
        lab_id = str(uuid.uuid4())

        # 1. Start EC2 Instance
        launch_res = self.aws.launch_analysis_vm(
            ami_id=ami_id,
            instance_type=instance_type,
            session_id=lab_id,
            subnet_id=subnet_id,
            iam_profile_name=None, # Guacamole connects natively, no IAM profile needed
            profile_id=environment_type,
            security_group_id=security_group_id
        )

        if launch_res["status"] == "error":
            logger.error(f"Failed to launch EC2 for lab {lab_id}: {launch_res['message']}")
            raise Exception(f"Infrastructure launch failed: {launch_res['message']}")

        instance_id = launch_res["instance_id"]

        # 2. Record initial 'provisioning' state in memory and SQLite DB
        GLOBAL_LAB_STATE[lab_id] = {
            "id": lab_id,
            "instance_id": instance_id,
            "status": "PROVISIONING",
            "session_id": user_id,
            "protocol": protocol,
            "profile_id": environment_type
        }
        save_local_state(GLOBAL_LAB_STATE)

        try:
            async with AsyncSessionLocal() as session:
                new_vm = VMInstance(
                    id=lab_id,
                    instance_id=instance_id,
                    status="PROVISIONING",
                    session_id=user_id
                )
                session.add(new_vm)
                await session.commit()
        except Exception as e:
            logger.warning(f"Failed to insert DB record for lab {lab_id}, but EC2 is live: {e}")

        return {
            "status": "provisioning",
            "lab_id": lab_id,
            "instance_id": instance_id,
            "message": "Provisioning started in background."
        }

    async def process_lab_readiness(self, lab_id: str, instance_id: str):
        """
        Background Worker Function.
        Polls AWS until the instance passes 2/2 status checks (OS fully booted),
        extracts the IP, generates the Guacamole connection, and marks the lab READY.

        Uses asyncio.sleep() instead of time.sleep() so the event loop is never blocked.
        Uses AWS EC2 status checks instead of a TCP port probe — reliable regardless of
        whether the backend server has network access to the instance.
        """
        logger.info(f"Background Worker started for lab {lab_id} (Instance: {instance_id})")

        # ── Stage 1: Wait for EC2 to enter RUNNING state and obtain an IP ──────────
        max_ip_retries = 30   # 30 × 10 s = 5 minutes
        ip_poll_delay  = 10   # seconds between polls
        instance_ip    = None

        for attempt in range(max_ip_retries):
            try:
                response = self.aws.ec2.describe_instances(InstanceIds=[instance_id])
                instance = response['Reservations'][0]['Instances'][0]
                state    = instance['State']['Name']

                if state == 'terminated' or state == 'shutting-down':
                    logger.error(f"Lab {lab_id}: Instance {instance_id} was terminated externally.")
                    await self._update_db_status(lab_id, "ERROR")
                    return

                if state == 'running':
                    # Prefer public IP for Guacamole routing; fall back to private IP
                    instance_ip = (
                        instance.get('PublicIpAddress') or
                        instance.get('PrivateIpAddress')
                    )
                    if instance_ip:
                        logger.info(f"Lab {lab_id}: Instance running, IP = {instance_ip}")
                        break

            except Exception as e:
                logger.warning(f"Lab {lab_id}: EC2 describe error on attempt {attempt + 1}: {e}")

            await asyncio.sleep(ip_poll_delay)

        if not instance_ip:
            logger.error(f"Lab {lab_id}: Timed out waiting for instance to start (no IP after {max_ip_retries * ip_poll_delay}s).")
            await self._update_db_status(lab_id, "ERROR")
            # Do NOT terminate — the instance may simply be in a private subnet.
            # The user can investigate from the AWS console.
            return

        # ── Stage 2: Wait for AWS instance status checks (2/2 OK) ────────────────
        # This is the authoritative signal that the OS has fully booted.
        # It does NOT require any network path from the backend server to the EC2 instance.
        # Windows Server can take 8-12 minutes to pass status checks after first boot.
        max_status_retries = 72   # 72 × 10 s = 12 minutes (covers Windows cold-boot)
        status_poll_delay  = 10   # seconds
        instance_ready     = False

        logger.info(f"Lab {lab_id}: Waiting for EC2 status checks to pass (2/2)...")

        for attempt in range(max_status_retries):
            try:
                status_response = self.aws.ec2.describe_instance_status(
                    InstanceIds=[instance_id],
                    IncludeAllInstances=True
                )
                statuses = status_response.get('InstanceStatuses', [])
                if statuses:
                    entry    = statuses[0]
                    sys_ok   = entry.get('SystemStatus',   {}).get('Status') == 'ok'
                    inst_ok  = entry.get('InstanceStatus', {}).get('Status') == 'ok'
                    inst_state = entry.get('InstanceState', {}).get('Name', '')

                    if inst_state in ('terminated', 'shutting-down'):
                        logger.error(f"Lab {lab_id}: Instance terminated while waiting for status checks.")
                        await self._update_db_status(lab_id, "ERROR")
                        return

                    if sys_ok and inst_ok:
                        logger.info(f"Lab {lab_id}: Status checks passed (2/2) after {(attempt + 1) * status_poll_delay}s.")
                        instance_ready = True
                        break

            except Exception as e:
                logger.warning(f"Lab {lab_id}: Status check error on attempt {attempt + 1}: {e}")

            await asyncio.sleep(status_poll_delay)

        if not instance_ready:
            logger.error(f"Lab {lab_id}: Instance did not pass status checks within {max_status_retries * status_poll_delay}s.")
            await self._update_db_status(lab_id, "ERROR")
            # Terminate to avoid paying for a non-functional instance
            self.aws.terminate_vm(instance_id)
            return

        # ── Stage 3: Create Guacamole connection ─────────────────────────────────
        state_data = GLOBAL_LAB_STATE.get(lab_id, {})
        protocol   = state_data.get("protocol", "rdp")
        profile_id = state_data.get("profile_id", "")
        target_port = "22" if protocol == "ssh" else "3389"

        # Map credentials based on target environment
        if "kali" in profile_id:
            username = "kali"
            password = "kali"
        elif "malware" in profile_id:
            username = "Administrator"
            password = "N1oHa9gwwPqU8b?0E(K4Mv2&Y&iu&u85"
        else:
            username = "Administrator"
            password = "2aA.XlugId5KDkwu!pc5!@UygmmVkvov"

        guac_id = self.guac.create_connection(
            lab_id=lab_id,
            private_ip=instance_ip,
            protocol=protocol,
            port=target_port,
            username=username,
            password=password
        )

        if not guac_id:
            # Guacamole is not running or its DB is misconfigured.
            # The EC2 instance is healthy — do NOT terminate it.
            # Mark as READY so the user can still see and manage the instance.
            logger.warning(
                f"Lab {lab_id}: Guacamole connection could not be created (is Guacamole running?). "
                f"Marking lab READY without browser session. Instance IP: {instance_ip}"
            )
            if lab_id in GLOBAL_LAB_STATE:
                GLOBAL_LAB_STATE[lab_id].update({
                    "status": "READY",
                    "private_ip": instance_ip,
                    "guacamole_connection_id": None
                })
                save_local_state(GLOBAL_LAB_STATE)
            await self._update_db_status(lab_id, "READY")
            return

        # ── Stage 4: Transition to READY ─────────────────────────────────────────
        if lab_id in GLOBAL_LAB_STATE:
            GLOBAL_LAB_STATE[lab_id].update({
                "status": "READY",
                "private_ip": instance_ip,
                "guacamole_connection_id": guac_id
            })
            save_local_state(GLOBAL_LAB_STATE)

        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(VMInstance).where(VMInstance.id == lab_id))
                vm = result.scalars().first()
                if vm:
                    vm.status = "READY"
                    vm.private_ip = instance_ip
                    await session.commit()

            logger.info(f"Lab {lab_id} fully provisioned. Guacamole connection #{guac_id} at {instance_ip}.")
        except Exception as e:
            logger.error(f"Failed to update DB for lab {lab_id}: {e}")

    async def terminate_lab(self, lab_id: str, instance_id: str, guac_connection_id: Optional[int] = None):
        """
        Shuts down the entire lab: AWS EC2 termination + Guacamole cleanup.
        """
        await self._update_db_status(lab_id, "STOPPING")

        # 1. Clean up Guacamole
        if guac_connection_id:
            self.guac.delete_connection(guac_connection_id)

        # Also look up guac ID from state if not provided
        if not guac_connection_id and lab_id in GLOBAL_LAB_STATE:
            stored_guac_id = GLOBAL_LAB_STATE[lab_id].get("guacamole_connection_id")
            if stored_guac_id:
                self.guac.delete_connection(stored_guac_id)

        # 2. Terminate EC2
        success = self.aws.terminate_vm(instance_id)
        if success:
            if lab_id in GLOBAL_LAB_STATE:
                GLOBAL_LAB_STATE[lab_id]["status"] = "TERMINATED"
                save_local_state(GLOBAL_LAB_STATE)
            await self._update_db_status(lab_id, "TERMINATED")
        else:
            await self._update_db_status(lab_id, "ERROR")

        return success

    async def _update_db_status(self, lab_id: str, status: str):
        if lab_id in GLOBAL_LAB_STATE:
            GLOBAL_LAB_STATE[lab_id]["status"] = status
            save_local_state(GLOBAL_LAB_STATE)
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(VMInstance).where(VMInstance.id == lab_id))
                vm = result.scalars().first()
                if vm:
                    vm.status = status
                    await session.commit()
        except:
            pass
