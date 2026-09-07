import logging
import uuid
import json
import os
import asyncio
from typing import Dict, Any, Optional

from app.services.guacamole_service import GuacamoleService
from app.services.providers import (
    LabConfig,
    LabStatus,
    ProviderUnavailableError,
    UnsupportedEnvironmentError,
    get_lab_provider,
    get_provider_name,
)
from app.db.database import AsyncSessionLocal
from app.models.all_models import VMInstance
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

STATE_FILE = os.path.join(os.path.dirname(__file__), "..", "..", ".lab_state.json")

def load_local_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
            # Any PROVISIONING/READY/RUNNING entries left over from a previous process run
            # are unverifiable — the background workers that were tracking them are dead
            # and we cannot confirm the labs are still alive without a provider call.
            # Mark them TERMINATED so the frontend resets cleanly instead of showing stale
            # "CONNECT TERMINAL" buttons for labs that may no longer exist.
            changed = False
            for lab_id, record in state.items():
                if record.get("status") in ("PROVISIONING", "READY", "RUNNING"):
                    record["status"] = "TERMINATED"
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
    Coordinates the lab lifecycle: provider provisioning -> connection details ->
    Guacamole connection registration -> database tracking.

    The manager is provider-agnostic: it never sees instance IDs, AMIs, instance
    types or EC2 states. Whether a lab is a Docker container or an EC2 instance
    is entirely the LabProvider's business.
    """
    def __init__(self, provider=None, aws_credentials: Optional[Dict[str, Any]] = None):
        self.provider = provider or get_lab_provider(aws_credentials=aws_credentials)
        self.guac = GuacamoleService()

    @property
    def provider_name(self) -> str:
        return getattr(self.provider, "name", get_provider_name())

    async def start_lab_provisioning(
        self,
        user_id: str,
        environment_type: str,
        profile: str = "standard",
        protocol: str = "rdp",
    ) -> Dict[str, Any]:
        """
        Launches a lab through the configured provider and records it as
        PROVISIONING. Returns the lab_id immediately; readiness is handled by
        process_lab_readiness() in the background.
        """
        lab_id = str(uuid.uuid4())

        config = LabConfig(
            environment=environment_type,
            profile=profile,
            protocol=protocol,
            owner_id=user_id,
            labels={"lab_id": lab_id},
        )

        # 1. Launch through the provider (blocking SDK call -> worker thread).
        try:
            info = await asyncio.to_thread(self.provider.launch_lab, config)
        except (UnsupportedEnvironmentError, ProviderUnavailableError) as exc:
            logger.error(f"Failed to launch lab {lab_id}: {exc}")
            raise Exception(str(exc))

        # Providers may mint their own lab_id (AWS tags the instance with it).
        lab_id = info.lab_id

        # 2. Record initial 'provisioning' state in memory and database
        GLOBAL_LAB_STATE[lab_id] = {
            "id": lab_id,
            "lab_id": lab_id,
            "status": info.status,
            "session_id": user_id,
            "protocol": protocol,
            "environment": info.environment,
            "profile": info.profile,
            "provider": self.provider_name,
        }
        save_local_state(GLOBAL_LAB_STATE)

        try:
            async with AsyncSessionLocal() as session:
                new_vm = VMInstance(
                    id=lab_id,
                    # instance_id is the generic provider handle; for Docker it is
                    # the lab_id itself, for AWS it resolves via the SessionID tag.
                    instance_id=lab_id,
                    status=LabStatus.PROVISIONING,
                    session_id=user_id,
                )
                session.add(new_vm)
                await session.commit()
        except Exception as e:
            logger.warning(f"Failed to insert DB record for lab {lab_id}, but the lab is live: {e}")

        return {
            "status": "provisioning",
            "lab_id": lab_id,
            "provider": self.provider_name,
            "environment": info.environment,
            "profile": info.profile,
            "message": "Provisioning started in background.",
        }

    async def process_lab_readiness(self, lab_id: str):
        """
        Background worker.

        Waits for the provider to report the lab ready, then registers a
        Guacamole connection from the provider-supplied connection details and
        marks the lab READY.
        """
        logger.info(f"Background worker started for lab {lab_id} (provider: {self.provider_name})")

        state_data = GLOBAL_LAB_STATE.get(lab_id, {})
        protocol = state_data.get("protocol", "rdp")

        # ── Stage 1: provider-specific readiness wait ────────────────────────
        try:
            info = await asyncio.to_thread(self.provider.wait_until_ready, lab_id)
        except Exception as exc:
            logger.error(f"Lab {lab_id}: readiness wait failed: {exc}")
            await self._update_db_status(lab_id, LabStatus.ERROR)
            return

        if info.status in (LabStatus.ERROR, LabStatus.TERMINATED):
            logger.error(f"Lab {lab_id}: not ready ({info.status}) — {info.message}")
            await self._update_db_status(lab_id, LabStatus.ERROR)
            return

        # ── Stage 2: resolve connection details ──────────────────────────────
        connection = info.connection
        if connection is None:
            try:
                connection = await asyncio.to_thread(
                    self.provider.get_connection, lab_id, protocol
                )
            except Exception as exc:
                logger.warning(f"Lab {lab_id}: could not resolve connection details: {exc}")

        if connection is None:
            logger.error(f"Lab {lab_id}: lab is up but has no reachable address.")
            await self._update_db_status(lab_id, LabStatus.ERROR)
            return

        host = connection.host

        # ── Stage 3: Create Guacamole connection ─────────────────────────────
        guac_id = self.guac.create_connection(
            lab_id=lab_id,
            private_ip=host,
            protocol=connection.protocol,
            port=str(connection.port),
            username=connection.username,
            password=connection.password,
        )

        if not guac_id:
            # Guacamole is not running or its DB is misconfigured.
            # The lab itself is healthy — do NOT terminate it.
            # Mark as READY so the user can still see and manage it.
            logger.warning(
                f"Lab {lab_id}: Guacamole connection could not be created (is Guacamole running?). "
                f"Marking lab READY without browser session. Lab host: {host}"
            )
            if lab_id in GLOBAL_LAB_STATE:
                GLOBAL_LAB_STATE[lab_id].update({
                    "status": LabStatus.READY,
                    "private_ip": host,
                    "host": host,
                    "guacamole_connection_id": None
                })
                save_local_state(GLOBAL_LAB_STATE)
            await self._update_db_status(lab_id, LabStatus.READY)
            return

        # ── Stage 4: Transition to READY ─────────────────────────────────────
        if lab_id in GLOBAL_LAB_STATE:
            GLOBAL_LAB_STATE[lab_id].update({
                "status": LabStatus.READY,
                "private_ip": host,
                "host": host,
                "guacamole_connection_id": guac_id
            })
            save_local_state(GLOBAL_LAB_STATE)

        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(VMInstance).where(VMInstance.id == lab_id))
                vm = result.scalars().first()
                if vm:
                    vm.status = LabStatus.READY
                    vm.private_ip = host
                    await session.commit()

            logger.info(f"Lab {lab_id} fully provisioned. Guacamole connection #{guac_id} at {host}.")
        except Exception as e:
            logger.error(f"Failed to update DB for lab {lab_id}: {e}")

    async def terminate_lab(self, lab_id: str, guac_connection_id: Optional[int] = None) -> bool:
        """
        Shuts down the entire lab: provider teardown + Guacamole cleanup.
        """
        await self._update_db_status(lab_id, LabStatus.STOPPING)

        # 1. Clean up Guacamole
        if guac_connection_id:
            self.guac.delete_connection(guac_connection_id)
        elif lab_id in GLOBAL_LAB_STATE:
            stored_guac_id = GLOBAL_LAB_STATE[lab_id].get("guacamole_connection_id")
            if stored_guac_id:
                self.guac.delete_connection(stored_guac_id)

        # 2. Tear down the lab through the provider
        try:
            success = await asyncio.to_thread(self.provider.terminate_lab, lab_id)
        except Exception as exc:
            logger.error(f"Provider failed to terminate lab {lab_id}: {exc}")
            success = False

        if success:
            if lab_id in GLOBAL_LAB_STATE:
                GLOBAL_LAB_STATE[lab_id]["status"] = LabStatus.TERMINATED
                save_local_state(GLOBAL_LAB_STATE)
            await self._update_db_status(lab_id, LabStatus.TERMINATED)
        else:
            await self._update_db_status(lab_id, LabStatus.ERROR)

        return success

    async def get_metrics(self) -> Dict[str, Any]:
        """Aggregate resource usage across every lab this provider manages."""
        try:
            metrics = await asyncio.to_thread(self.provider.get_metrics)
            return metrics.to_dict()
        except Exception as exc:
            logger.warning(f"Metrics fetch failed ({self.provider_name}): {exc}")
            return {
                "status": "success", "vcpu": 0, "ram": 0,
                "active_count": 0, "labs": [], "instances": [],
            }

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
