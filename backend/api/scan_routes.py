from fastapi import APIRouter, UploadFile, File
import os
import uuid

from backend.workers.tasks import run_scan_task

router = APIRouter(prefix="/scan", tags=["scan"])

UPLOAD_DIR = "/app/uploads"


@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    run_scan_task.delay(file_path)

    return {
        "filename": file.filename,
        "stored_path": file_path,
        "status": "scan_started"
    }