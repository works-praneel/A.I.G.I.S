from fastapi import APIRouter, HTTPException
from backend.workers.tasks import run_scan_task

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/url")
async def scan_url(target: str):

    if not target.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL")

    run_scan_task.delay(target)

    return {
        "status": "scan_started",
        "target": target
    }