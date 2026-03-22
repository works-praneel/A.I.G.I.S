from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
import os
import uuid

from backend.workers.tasks import run_scan_task
from backend.auth.dependencies import get_current_user

router = APIRouter(prefix="/scan", tags=["scan"])

UPLOAD_DIR = "/app/uploads"

limiter = Limiter(key_func=get_remote_address)


@router.post("/upload")
@limiter.limit("10/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    current_user=Depends(get_current_user)
):
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    job_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{job_id}_{file.filename}"

    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    run_scan_task.apply_async(
        args=[file_path],
        kwargs={"user_id": current_user.id},
        task_id=job_id
    )

    return {
        "filename": file.filename,
        "stored_path": file_path,
        "job_id": job_id,
        "status": "scan_started",
        "message": f"Poll /api/scan/status/{job_id} for results."
    }


@router.delete("/cancel/{job_id}")
async def cancel_scan(
    job_id: str,
    current_user=Depends(get_current_user)
):
    from celery.result import AsyncResult
    from backend.workers.celery_app import celery

    result = AsyncResult(job_id, app=celery)

    if result.state in ("SUCCESS", "FAILURE"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel a task that has already {result.state.lower()}."
        )

    result.revoke(terminate=True, signal="SIGTERM")

    return {
        "job_id": job_id,
        "status": "cancelled",
        "message": "Scan task has been cancelled."
    }