import subprocess
import os
from typing import List, Dict, Optional

class VMService:
    # TODO: Move to config
    VM_REGISTRY = {
        "vm-8291f": {
            "name": "Kali-Attack-Box",
            "path": "/Users/ayuahkumarsingh/Documents/Virtual Machines.localized/Kali-Linux-2023.2-vmware-amd64.vmwarevm/Kali-Linux-2023.2-vmware-amd64.vmx",
            "ip": "10.0.1.50",
            "type": "linux"
        },
        "vm-1102a": {
            "name": "WinServer-AD",
            "path": "/Users/ayuahkumarsingh/Documents/Virtual Machines.localized/Windows Server 2019.vmwarevm/Windows Server 2019.vmx", 
            "ip": "10.0.1.20",
            "type": "windows"
        }
    }

    @staticmethod
    def _run_cmd(args: List[str]) -> str:
        try:
            # -T fusion is for VMware Fusion on Mac
            result = subprocess.run(
                ["vmrun", "-T", "fusion"] + args,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"VMRun Error: {e.stderr}")
            raise Exception(f"VM Operation Failed: {e.stderr}")
        except FileNotFoundError:
             # Fallback for dev/testing when vmrun isn't installed
            print("VMRun not found. Returning mock data.")
            return "MOCK_OK"

    @classmethod
    def list_running(cls) -> List[str]:
        try:
            output = cls._run_cmd(["list"])
            if output == "MOCK_OK":
                return []
            
            # Output format:
            # Total running VMs: 1
            # /path/to/vm.vmx
            lines = output.splitlines()
            if len(lines) > 1:
                return lines[1:]
            return []
        except Exception:
            return []

    @classmethod
    def get_vm_status(cls, vm_id: str) -> str:
        vm = cls.VM_REGISTRY.get(vm_id)
        if not vm:
            return "stopped" # Unknown VM
        
        running_vms = cls.list_running()
        # Check if our VM path is in the running list
        # We need to be careful about path matching (absolute vs relative)
        # For now, simple string inclusion
        for running_vm_path in running_vms:
            if vm["path"] in running_vm_path:
                return "running"
        
        return "stopped"

    @classmethod
    def start_vm(cls, vm_id: str):
        vm = cls.VM_REGISTRY.get(vm_id)
        if not vm:
            raise ValueError("VM ID not found")
        
        # nogui starts it in headless mode
        return cls._run_cmd(["start", vm["path"], "nogui"])

    @classmethod
    def stop_vm(cls, vm_id: str):
        vm = cls.VM_REGISTRY.get(vm_id)
        if not vm:
            raise ValueError("VM ID not found")
            
        return cls._run_cmd(["stop", vm["path"], "soft"])

    @classmethod
    def get_all_vms(cls) -> Dict:
        # returns static registry combined with dynamic status
        result = {}
        for vm_id, data in cls.VM_REGISTRY.items():
            status = cls.get_vm_status(vm_id)
            result[vm_id] = {**data, "status": status, "id": vm_id}
        return result
