from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.security.cvss_engine import calculate_risk # Use your existing engine

router = APIRouter()

class URLScanRequest(BaseModel):
    url: str

@router.post("/url")
async def scan_url(request: URLScanRequest):
    # This is where your actual AIGIS logic lives
    # 1. Analyze the URL (mocked for this example)
    # 2. Use your CVSS engine to get a real score
    score = calculate_risk(request.url) 
    
    return {
        "url": request.url,
        "cvss_score": score,
        "summary": "The AI Engine detected insecure protocols and potential phishing signatures. Block recommended."
    }