import logging
import uuid
import time
from typing import Dict, Any, Optional

from app.services.aws_orchestrator import AWSOrchestrator
from app.services.guacamole_service import GuacamoleService
from app.db.supabase_client import get_supabase

logger = logging.getLogger(__name__)

GLOBAL_LAB_STATE = {}

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
        self.db = get_supabase()

    def start_lab_provisioning(self, user_id: str, environment_type: str, ami_id: str, instance_type: str, subnet_id: str, security_group_id: str = None, protocol: str = "rdp") -> Dict[str, Any]:
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
        
        # 2. Record initial 'provisioning' state in memory and Supabase DB
        GLOBAL_LAB_STATE[lab_id] = {
            "id": lab_id,
            "instance_id": instance_id,
            "status": "PROVISIONING",
            "session_id": user_id,
            "protocol": protocol
        }
        
        try:
            self.db.table("vm_instances").insert({
                "id": lab_id,
                "instance_id": instance_id,
                "status": "PROVISIONING",
                "session_id": user_id # Map user
            }).execute()
        except Exception as e:
            logger.warning(f"Failed to insert DB record for lab {lab_id}, but EC2 is live: {e}")
            
        return {
            "status": "provisioning",
            "lab_id": lab_id,
            "instance_id": instance_id,
            "message": "Provisioning started in background."
        }

    def process_lab_readiness(self, lab_id: str, instance_id: str):
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
            self._update_db_status(lab_id, "ERROR")
            return
            
        logger.info(f"Lab {lab_id} assigned Public IP: {public_ip}. Creating Guacamole Connection...")
        
        # Retrieve intended protocol from state mapping
        protocol = GLOBAL_LAB_STATE.get(lab_id, {}).get("protocol", "rdp")
        
        guac_id = self.guac.create_connection(
            lab_id=lab_id,
            private_ip=public_ip,
            protocol=protocol, 
            username="Administrator" if protocol == "rdp" else "root"
        )
        
        if not guac_id:
            logger.error(f"Lab {lab_id} failed to provision: Guacamole DB error.")
            self._update_db_status(lab_id, "ERROR")
            return
            
        # 3. Transition to READY
        if lab_id in GLOBAL_LAB_STATE:
            GLOBAL_LAB_STATE[lab_id].update({
                "status": "READY",
                "private_ip": public_ip,
                "guacamole_connection_id": guac_id
            })
            
        try:
            self.db.table("vm_instances").update({
                "status": "READY",
                "private_ip": public_ip,
                # In a real schema we'd store guac_connection_id as well
            }).eq("id", lab_id).execute()
            
            logger.info(f"Lab {lab_id} completely provisioned. Ready for Guacamole connection #{guac_id}.")
        except Exception as e:
            logger.error(f"Failed to update DB for lab {lab_id}: {e}")

    def terminate_lab(self, lab_id: str, instance_id: str, guac_connection_id: Optional[int] = None):
        """
        Shuts down the entire lab: AWS EC2 termination + Guacamole cleanup.
        """
        self._update_db_status(lab_id, "STOPPING")
        
        # 1. Clean up Guacamole
        if guac_connection_id:
            self.guac.delete_connection(guac_connection_id)
            
        # 2. Terminate EC2
        success = self.aws.terminate_vm(instance_id)
        if success:
            self._update_db_status(lab_id, "TERMINATED")
        else:
            self._update_db_status(lab_id, "ERROR")
            
        return success

    def _update_db_status(self, lab_id: str, status: str):
        if lab_id in GLOBAL_LAB_STATE:
            GLOBAL_LAB_STATE[lab_id]["status"] = status
        try:
            self.db.table("vm_instances").update({"status": status}).eq("id", lab_id).execute()
        except:
            pass
