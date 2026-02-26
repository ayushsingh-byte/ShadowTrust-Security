import boto3
from botocore.exceptions import ClientError
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AWSOrchestrator:
    def __init__(self, region_name='ap-south-1', aws_access_key=None, aws_secret_key=None):
        self.region_name = region_name
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        
        client_kwargs = {'region_name': region_name}
        if aws_access_key and aws_secret_key:
            client_kwargs['aws_access_key_id'] = aws_access_key
            client_kwargs['aws_secret_access_key'] = aws_secret_key

        self.ec2 = boto3.client('ec2', **client_kwargs)
        self.ssm = boto3.client('ssm', **client_kwargs)

    def launch_analysis_vm(self, ami_id: str, instance_type: str, session_id: str, subnet_id: str, iam_profile_name: str) -> Dict[str, Any]:
        """Launches an EC2 instance from an AMI configured with the SSM IAM role."""
        try:
            response = self.ec2.run_instances(
                ImageId=ami_id,
                InstanceType=instance_type,
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={'Name': iam_profile_name},
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'Name', 'Value': f'Analysis-VM-{session_id}'},
                            {'Key': 'SessionID', 'Value': session_id},
                            {'Key': 'ManagedBy', 'Value': 'ShadowTrust'}
                        ]
                    }
                ]
            )
            instance_id = response['Instances'][0]['InstanceId']
            logger.info(f"Launched VM: {instance_id} for session: {session_id}")
            return {"status": "success", "instance_id": instance_id}
            
        except ClientError as e:
            logger.error(f"Failed to launch VM: {e}")
            return {"status": "error", "message": str(e)}

    def terminate_vm(self, instance_id: str) -> bool:
        """Terminates an EC2 instance by its Instance ID."""
        try:
            self.ec2.terminate_instances(InstanceIds=[instance_id])
            logger.info(f"Terminated VM: {instance_id}")
            return True
        except ClientError as e:
            logger.error(f"Failed to terminate VM {instance_id}: {e}")
            return False

    def get_instance_status(self, instance_id: str) -> Optional[str]:
        """Fetches the current status state of the specified instance."""
        try:
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            state = response['Reservations'][0]['Instances'][0]['State']['Name']
            return state
        except ClientError as e:
            logger.error(f"Failed to get status for {instance_id}: {e}")
            return None

    def generate_ssm_session_url(self, instance_id: str) -> str:
        """
        Generates a direct AWS Console link to the Systems Manager Session for the instance.
        In a production scenario, you would use StartSession API and wrap it in a custom terminal UI.
        """
        # Note: AWS Systems Manager requires the target instance to be fully booted with the SSM agent running.
        region = self.ec2.meta.region_name
        return f"https://{region}.console.aws.amazon.com/systems-manager/session-manager/{instance_id}"
