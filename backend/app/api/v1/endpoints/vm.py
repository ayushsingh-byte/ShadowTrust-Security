from fastapi import APIRouter, HTTPException
from typing import Dict, List, Any
from app.services.vm_service import VMService

router = APIRouter()

@router.get("/list", response_model=Dict[str, Any])
async def list_vms():
    """
    Get all registered VMs and their current status.
    """
    return VMService.get_all_vms()

@router.post("/{vm_id}/start")
async def start_vm(vm_id: str):
    """
    Start a VM by ID.
    """
    
    try:
        VMService.start_vm(vm_id)
        return {"status": "success", "message": f"VM {vm_id} starting..."}
    except ValueError:
        raise HTTPException(status_code=404, detail="VM not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{vm_id}/stop")
async def stop_vm(vm_id: str):
    """
    Stop a VM by ID.
    """
    try:
        VMService.stop_vm(vm_id)
        return {"status": "success", "message": f"VM {vm_id} stopping..."}
    except ValueError:
        raise HTTPException(status_code=404, detail="VM not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{vm_id}/status")
async def get_vm_status(vm_id: str):
    """
    Get status of a specific VM.
    """
    status = VMService.get_vm_status(vm_id)
    return {"id": vm_id, "status": status}
