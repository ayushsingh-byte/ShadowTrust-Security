import logging
import uuid
import time
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
                return json.load(f)
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
            iam_profile_name=None, # Guacamole doesn't need IAM profiles, it connects natively
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
        Polls AWS until the instance is fully booted, extracts the private IP,
        generates the Guacamole connection, and marks the lab as READY.
        """
        logger.info(f"Background Worker started for lab {lab_id} (Instance: {instance_id})")
        
        max_retries = 30
        retry_delay = 5 # seconds
        public_ip = None
        
        # 1. Wait for EC2 to assign a Public IP and enter RUNNING state
        for _ in range(max_retries):
            try:
                response = self.aws.ec2.describe_instances(InstanceIds=[instance_id])
                instance = response['Reservations'][0]['Instances'][0]
                state = instance['State']['Name']
                
                if state == 'running' and 'PublicIpAddress' in instance:
                    public_ip = instance['PublicIpAddress']
                    break
            except Exception as e:
                logger.warning(f"Polling EC2 {instance_id} threw an error: {e}")
                
            time.sleep(retry_delay)
            
        if not public_ip:
            logger.error(f"Lab {lab_id} failed to provision: Timeout waiting for Public IP.")
            await self._update_db_status(lab_id, "ERROR")
            return
            
        logger.info(f"Lab {lab_id} assigned Public IP: {public_ip}. Waiting for services to initialize...")
        
        # Retrieve intended protocol from state mapping
        state_data = GLOBAL_LAB_STATE.get(lab_id, {})
        protocol = state_data.get("protocol", "rdp")
        profile_id = state_data.get("profile_id", "")
        target_port = 22 if protocol == "ssh" else 3389

        # 2. Wait for the actual SSH/RDP port to open
        import socket
        port_open = False
        for _ in range(40): # Wait up to ~200 seconds for boot
            try:
                with socket.create_connection((public_ip, target_port), timeout=3):
                    port_open = True
                    break
            except (ConnectionRefusedError, TimeoutError, OSError):
                time.sleep(5)
                
        if not port_open:
            logger.error(f"Lab {lab_id} failed to provision: Timeout waiting for port {target_port} to open on {public_ip}.")
            await self._update_db_status(lab_id, "ERROR")
            return
            
        logger.info(f"Port {target_port} on {public_ip} is open. Creating Guacamole Connection...")
        
        # Map user-provided credentials based on target environment
        if "kali" in profile_id:
            username = "kali"
            password = "kali"
        elif "malware" in profile_id:
            username = "Administrator"
            password = "N1oHa9gwwPqU8b?0E(K4Mv2&Y&iu&u85"
        else:
            # Baseline or fallback
            username = "Administrator"
            password = "2aA.XlugId5KDkwu!pc5!@UygmmVkvov"
        
        guac_id = self.guac.create_connection(
            lab_id=lab_id,
            private_ip=public_ip,
            protocol=protocol, 
            port=str(target_port),
            username=username,
            password=password
        )
        
        if not guac_id:
            logger.error(f"Lab {lab_id} failed to provision: Guacamole DB error.")
            await self._update_db_status(lab_id, "ERROR")
            return
            
        # 3. Transition to READY
        if lab_id in GLOBAL_LAB_STATE:
            GLOBAL_LAB_STATE[lab_id].update({
                "status": "READY",
                "private_ip": public_ip,
                "guacamole_connection_id": guac_id
            })
            save_local_state(GLOBAL_LAB_STATE)
            
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(VMInstance).where(VMInstance.id == lab_id))
                vm = result.scalars().first()
                if vm:
                    vm.status = "READY"
                    vm.private_ip = public_ip
                    await session.commit()
            
            logger.info(f"Lab {lab_id} completely provisioned. Ready for Guacamole connection #{guac_id}.")
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
            
        # 2. Terminate EC2
        success = self.aws.terminate_vm(instance_id)
        if success:
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
