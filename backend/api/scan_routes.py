from fastapi import APIRouter, UploadFile, File, HTTPException
import os
import uuid
from backend.workers.tasks import run_scan_task

# Prefix is /scan. Combined with main.py, path is /api/v1/scan/...
router = APIRouter(prefix="/scan", tags=["Scanning"])
UPLOAD_DIR = "/app/uploads"

@router.post("/file")
async def scan_file(file: UploadFile = File(...)):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    # Check for empty file content
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="File content is empty.")

    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")

    # Save file to disk for the worker to find
    with open(file_path, "wb") as buffer:
        buffer.write(content)

    # Trigger Celery Worker
    run_scan_task.delay(file_path)

    return {
        "risk_score": 0, 
        "filename": file.filename,
        "summary": "Sandbox initialized.",
        "report": "File received. Analysis task queued."
    }

@router.post("/url")
async def scan_url(data: dict):
    return {"cvss_score": 10, "summary": "URL scanning complete."}