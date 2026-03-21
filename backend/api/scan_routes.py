from fastapi import APIRouter, UploadFile, File, HTTPException
import os
import uuid
from backend.workers.tasks import run_scan_task

# Full path for endpoints: /api/v1/scan/...
router = APIRouter(prefix="/scan", tags=["Scanning Engine"])

UPLOAD_DIR = "/app/uploads"

@router.post("/file")
async def scan_file(file: UploadFile = File(...)):
    """Receives a file, saves it, and dispatches a sandbox analysis task."""
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    # Validation: Ensures the file is not empty (0.0B)
    content = await file.read()
    if not content or len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty. No content to analyze.")

    # Generate unique ID for the file to prevent collisions
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")

    # Save the file to the local sandbox directory
    with open(file_path, "wb") as buffer:
        buffer.write(content)

    # Dispatch to the Celery worker for actual analysis
    run_scan_task.delay(file_path)

    return {
        "risk_score": 0, 
        "filename": file.filename,
        "summary": "Sandbox initialized successfully.",
        "report": f"File queued for analysis at {file_path}"
    }

@router.post("/url")
async def scan_url(data: dict):
    return {"cvss_score": 0, "summary": "URL reputation analysis initiated."}

@router.post("/github")
async def scan_github(data: dict):
    return {"status": "Job Accepted", "code": 202}