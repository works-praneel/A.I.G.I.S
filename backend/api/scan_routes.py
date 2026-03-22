from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse 
from sqlalchemy.orm import Session
from celery.result import AsyncResult
from backend.workers.tasks import run_scan_task
from backend.workers.celery_app import celery as celery_app
from backend.database import models, database
import os
import uuid

# --- CONFIGURATION ---
router = APIRouter(prefix="/scan", tags=["Scanning Engine"])
get_db = database.get_db
UPLOAD_DIR = "/app/uploads"
# This path must match the shared Docker volume for reports
REPORT_DIR = "/app/backend/reporting/reports"

@router.post("/file")
async def scan_file(user_id: int, file: UploadFile = File(...)):
    """
    Receives a file from the user and dispatches it to the Celery worker.
    The user_id is passed so the history can be saved to the database.
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    content = await file.read()
    if not content or len(content) == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    # Generate a unique filename to prevent overwriting
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")

    with open(file_path, "wb") as buffer:
        buffer.write(content)

    # Dispatch the task to the worker
    task = run_scan_task.delay(file_path, user_id)

    return {
        "job_id": task.id, 
        "status": "queued",
        "filename": file.filename
    }

@router.get("/status/{job_id}")
async def get_scan_status(job_id: str):
    """
    Checks if the worker has finished the analysis.
    Returns the full result (risk_score, etc.) once ready.
    """
    result = AsyncResult(job_id, app=celery_app)
    
    if result.ready():
        # result.result contains the dict returned by run_scan_task
        return result.result 
    
    return {"status": result.state}

@router.get("/download/{job_id}")
async def download_report(job_id: str):
    """
    Fetches the generated PDF report from the shared volume.
    """
    report_path = os.path.join(REPORT_DIR, f"report_{job_id}.pdf")
    
    if os.path.exists(report_path):
        return FileResponse(
            path=report_path,
            filename=f"AIGIS_Security_Report_{job_id[:8]}.pdf",
            media_type='application/pdf'
        )
    
    raise HTTPException(
        status_code=404, 
        detail="Report file not found on server."
    )

@router.get("/history/me")
def get_my_history(user_id: int, db: Session = Depends(get_db)):
    """
    Fetches scan history for the logged-in user.
    """
    return db.query(models.ScanHistory)\
             .filter(models.ScanHistory.user_id == user_id)\
             .order_by(models.ScanHistory.timestamp.desc())\
             .all()

@router.get("/history/all")
def get_all_history(db: Session = Depends(get_db)):
    """
    ROOT ONLY: Fetches every scan in the system joined with the username.
    """
    return db.query(
        models.ScanHistory.filename,
        models.ScanHistory.risk_score,
        models.ScanHistory.timestamp,
        models.User.username.label("uploaded_by"),
        models.ScanHistory.job_id
    ).join(models.User).all()