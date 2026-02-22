
from fastapi import APIRouter
from app.core.supabase import supabase

router = APIRouter()

@router.get("/")
def get_mitre_matrix():
    """
    Fetch all attack events with MITRE mapping and aggregate by tactic.
    """
    try:
        # Fetch all attacks with MITRE info
        # We limit to recent 100 or so for performance in this MVP
        response = supabase.table("attacks").select("*").order("timestamp", desc=True).limit(100).execute()
        attacks = response.data

        # Aggregate by Tactic
        matrix = {
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Privilege Escalation": [],
            "Defense Evasion": [],
            "Credential Access": [],
            "Discovery": [],
            "Lateral Movement": [],
            "Collection": [],
            "Command and Control": [],
            "Exfiltration": [],
            "Impact": []
        }

        # Populate matrix
        for attack in attacks:
            tactic = attack.get("mitre_tactic")
            if tactic and tactic in matrix:
                matrix[tactic].append({
                    "id": attack.get("mitre_id"),
                    "technique": attack.get("type"), # Using type as technique name proxy for now if needed, or fetch name
                    "severity": attack.get("severity"),
                    "timestamp": attack.get("timestamp")
                })
        
        return {"status": "success", "matrix": matrix}

    except Exception as e:
        return {"status": "error", "detail": str(e)}
