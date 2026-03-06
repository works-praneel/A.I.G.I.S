import os
import uuid
from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.orchestrator.job_manager import create_scan_job
from backend.workers.tasks import run_scan_task

router = APIRouter(prefix="/scan", tags=["scan"])

UPLOAD_DIR = "/app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    # generate unique filename
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")

    # save uploaded file
    with open(file_path, "wb") as f:
        contents = await file.read()
        f.write(contents)

    # create job in database
    job = create_scan_job(db, file.filename)

    # queue celery task
    run_scan_task.delay(job.id, file_path)

    return {
        "job_id": job.id,
        "status": "queued"
    }