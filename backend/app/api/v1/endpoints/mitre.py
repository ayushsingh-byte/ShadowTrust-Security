from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.db.sqlite_db import get_db
from app.models.all_models import Attack
from app.api.v1.dependencies import get_current_active_user, User

router = APIRouter()

@router.get("/")
async def get_mitre_matrix(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Fetch all attack events with MITRE mapping and aggregate by tactic.
    """
    try:
        # Fetch all attacks with MITRE info
        # We limit to recent 100 or so for performance in this MVP
        result = await db.execute(select(Attack).order_by(Attack.timestamp.desc()).limit(100))
        attacks = result.scalars().all()

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
            tactic = attack.mitre_tactic
            if tactic and tactic in matrix:
                matrix[tactic].append({
                    "id": attack.mitre_id,
                    "technique": attack.type, # Using type as technique name proxy for now if needed, or fetch name
                    "severity": attack.severity,
                    "timestamp": str(attack.timestamp) if attack.timestamp else None
                })
        
        return {"status": "success", "matrix": matrix}

    except Exception as e:
        return {"status": "error", "detail": str(e)}
