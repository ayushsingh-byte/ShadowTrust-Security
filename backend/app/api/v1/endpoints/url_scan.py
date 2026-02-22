from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.url_scan_service import URLScanService

router = APIRouter()

class URLRequest(BaseModel):
    url: str

@router.post("/scan")
async def scan_url(request: URLRequest):
    """
    Scan a URL for phishing and malware threats.
    """
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
        
    try:
        report = URLScanService.analyze_limit(request.url)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
