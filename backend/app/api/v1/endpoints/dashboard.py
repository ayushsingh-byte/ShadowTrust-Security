
from fastapi import APIRouter
from app.core.supabase import supabase

router = APIRouter()

@router.get("/stats")
def get_dashboard_stats():
    # 1. Total Attacks (24H) - Mock query logic for demo
    # In real world: supabase.table("attacks").select("*", count="exact").execute()
    
    total_attacks_res = supabase.table("attacks").select("count", count="exact").execute()
    total_attacks = total_attacks_res.count if total_attacks_res.count else 0
    
    # 2. Attack Types Distribution
    # Group by logic is limited in Supabase Client, often easier to do raw SQL or process in python for MVP
    attacks_res = supabase.table("attacks").select("type").execute()
    type_counts = {}
    for row in attacks_res.data:
        t = row.get("type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
        
    # 3. Recent Attacks
    recent_res = supabase.table("attacks").select("*").order("processed_at", desc=True).limit(10).execute()
    
    return {
        "summary": {
            "total_attacks": total_attacks,
            "unique_attackers": 120, # Mock for now
        },
        "distribution": type_counts,
        "recent": recent_res.data
    }
