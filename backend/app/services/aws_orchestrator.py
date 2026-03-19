import boto3
from botocore.exceptions import ClientError, BotoCoreError
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

    def launch_analysis_vm(self, ami_id: str, instance_type: str, session_id: str, subnet_id: str, iam_profile_name: str, profile_id: str = "custom_vm", security_group_id: str = None) -> Dict[str, Any]:
        """Launches an EC2 instance from an AMI configured with the SSM IAM role."""
        try:
            kwargs = {
                'ImageId': ami_id,
                'InstanceType': instance_type,
                'MinCount': 1,
                'MaxCount': 1,
                'SubnetId': subnet_id,
                'TagSpecifications': [
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'Name', 'Value': f'ShadowTrust-{profile_id}-{session_id[:5]}'},
                            {'Key': 'SessionID', 'Value': session_id},
                            {'Key': 'ManagedBy', 'Value': 'ShadowTrust'}
                        ]
                    }
                ]
            }
            
            # Provide initialization scripts
            if "linux" in profile_id or "kali" in profile_id:
                user_data = '''#!/bin/bash
# Force password authentication
echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/99-force-password.conf
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
systemctl restart sshd || service ssh restart

# Force the kali user password so Guacamole (or the user) can log in
echo "kali:kali" | chpasswd

# Fix the prominent XRDP Black Screen issue for Kali XFCE
echo "xfce4-session" > /home/kali/.xsession
chown kali:kali /home/kali/.xsession
chmod +x /home/kali/.xsession

# Prevent DBus session crashes in xrdp
if [ -f /etc/xrdp/startwm.sh ]; then
    sed -i '1s/^/unset DBUS_SESSION_BUS_ADDRESS\\nunset XDG_RUNTIME_DIR\\n/' /etc/xrdp/startwm.sh
    systemctl restart xrdp
fi
'''
                import base64
                encoded_user_data = base64.b64encode(user_data.encode('utf-8')).decode('utf-8')
                kwargs['UserData'] = encoded_user_data
            
            # Optional: Allow VMs to boot without an attached IAM profile
            if iam_profile_name and iam_profile_name.strip():
                kwargs['IamInstanceProfile'] = {'Name': iam_profile_name.strip()}
                
            if security_group_id and security_group_id.strip():
                kwargs['SecurityGroupIds'] = [security_group_id.strip()]

            response = self.ec2.run_instances(**kwargs)
            
            instance_id = response['Instances'][0]['InstanceId']
            logger.info(f"Launched VM: {instance_id} for session: {session_id}")
            return {"status": "success", "instance_id": instance_id}
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_msg = e.response.get('Error', {}).get('Message', '')
            
            # If the user hasn't created the IAM role yet, fallback and launch the VM without it.
            if error_code == 'InvalidParameterValue' and 'iamInstanceProfile.name' in error_msg and iam_profile_name is not None:
                logger.warning(f"IAM Profile '{iam_profile_name}' not found. Falling back to launching without an IAM role attached.")
                return self.launch_analysis_vm(ami_id, instance_type, session_id, subnet_id, iam_profile_name=None, profile_id=profile_id, security_group_id=security_group_id)
                
            logger.error(f"Failed to launch VM: {e}")
            return {"status": "error", "message": f"{error_code}: {error_msg}"}
        except BotoCoreError as e:
            logger.error(f"Boto3 Core Error: {e}")
            return {"status": "error", "message": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error launching VM: {e}")
            return {"status": "error", "message": "An unexpected infrastructure error occurred."}

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

    def get_cluster_metrics(self) -> Dict[str, Any]:
        """Fetches total vCPU, RAM, and returning instance details for the cluster."""
        try:
            # Filter all running/pending instances managed by ShadowTrust
            response = self.ec2.describe_instances(
                Filters=[
                    {'Name': 'tag:ManagedBy', 'Values': ['ShadowTrust']},
                    {'Name': 'instance-state-name', 'Values': ['running', 'pending']}
                ]
            )
            
            total_vcpu = 0
            total_ram = 0
            active_instances = 0
            instances_data = []

            # Hardware specs for AWS instances used
            hw_map = {
                't2.micro':   {'vcpu': 1, 'ram': 1},
                't3.micro':   {'vcpu': 2, 'ram': 1},
                't3.small':   {'vcpu': 2, 'ram': 2},
                't3.medium':  {'vcpu': 2, 'ram': 4},
                't3.large':   {'vcpu': 2, 'ram': 8},
                't3.xlarge':  {'vcpu': 4, 'ram': 16},
                't3.2xlarge': {'vcpu': 8, 'ram': 32},
            }

            for r in response.get('Reservations', []):
                for i in r.get('Instances', []):
                    active_instances += 1
                    itype = i.get('InstanceType', 't3.micro')
                    specs = hw_map.get(itype, {'vcpu': 2, 'ram': 1})
                    
                    total_vcpu += specs['vcpu']
                    total_ram += specs['ram']
                    
                    # Extract tags for profile matching
                    profile_id = "unknown"
                    for tag in i.get('Tags', []):
                        if tag['Key'] == 'Name':
                            name_val = tag['Value']
                            if 'win_base' in name_val: profile_id = 'win_base'
                            elif 'kali_base' in name_val: profile_id = 'kali_base'
                            elif 'win_malware' in name_val: profile_id = 'win_malware'
                    
                    instances_data.append({
                        "instance_id": i.get('InstanceId'),
                        "profile_id": profile_id,
                        "private_ip": i.get('PrivateIpAddress', 'Unknown'),
                        "public_ip": i.get('PublicIpAddress', 'None'),
                        "architecture": i.get('Architecture', 'x86_64'),
                        "instance_type": itype,
                        "status": i.get('State', {}).get('Name', 'unknown').upper()
                    })

            return {
                "status": "success",
                "vcpu": total_vcpu,
                "ram": total_ram,
                "active_count": active_instances,
                "instances": instances_data
            }
        except Exception as e:
            logger.error(f"Failed to fetch cluster metrics: {e}")
            return {"status": "error", "message": str(e), "vcpu": 0, "ram": 0, "active_count": 0, "instances": []}
