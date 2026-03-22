import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.workers.tasks import run_url_scan_task, run_repo_scan_task
from backend.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/scan", tags=["scan"])

limiter = Limiter(key_func=get_remote_address)


class URLScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^https?://", v):
            raise ValueError("URL must start with http:// or https://")
        without_scheme = re.sub(r"^https?://", "", v)
        if not without_scheme or without_scheme.startswith("/"):
            raise ValueError("URL must contain a valid host")
        private_patterns = [
            r"^https?://localhost",
            r"^https?://127\.",
            r"^https?://192\.168\.",
            r"^https?://10\.",
            r"^https?://172\.(1[6-9]|2[0-9]|3[0-1])\.",
        ]
        for pattern in private_patterns:
            if re.match(pattern, v):
                raise ValueError(
                    "Scanning private/loopback addresses is not permitted"
                )
        return v


class RepoScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        v = v.strip()
        if not re.match(
            r"^https://(github|gitlab|bitbucket)\.com/[\w\-\.]+/[\w\-\.]+",
            v
        ):
            raise ValueError(
                "Must be a valid GitHub, GitLab, or Bitbucket HTTPS URL."
            )
        if v.endswith(".git"):
            v = v[:-4]
        return v


@router.post("/url")
@limiter.limit("5/minute")
async def scan_url(
    request: Request,
    body: URLScanRequest,
    current_user=Depends(get_current_user)
):
    job_id = str(uuid.uuid4())
    run_url_scan_task.apply_async(
        args=[body.url],
        kwargs={"user_id": current_user.id},
        task_id=job_id
    )
    return {
        "status": "scan_started",
        "job_id": job_id,
        "target": body.url,
        "message": f"Poll /api/scan/status/{job_id} for results."
    }


@router.post("/repository")
@limiter.limit("3/minute")
async def scan_repository(
    request: Request,
    body: RepoScanRequest,
    current_user=Depends(get_current_user)
):
    job_id = str(uuid.uuid4())
    run_repo_scan_task.apply_async(
        args=[body.repo_url],
        kwargs={
            "branch": body.branch,
            "user_id": current_user.id
        },
        task_id=job_id
    )
    return {
        "status": "scan_started",
        "job_id": job_id,
        "target": body.repo_url,
        "branch": body.branch,
        "message": f"Poll /api/scan/status/{job_id} for results."
    }


@router.get("/status/{job_id}")
async def scan_status(
    job_id: str,
    current_user=Depends(get_current_user)
):
    from celery.result import AsyncResult
    from backend.workers.celery_app import celery

    result = AsyncResult(job_id, app=celery)

    if result.state == "PENDING":
        return {"job_id": job_id, "status": "pending"}
    if result.state == "STARTED":
        return {"job_id": job_id, "status": "running"}
    if result.state == "SUCCESS":
        return {
            "job_id": job_id,
            "status": "completed",
            "result": result.result
        }
    if result.state == "FAILURE":
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(result.result)
        }
    return {"job_id": job_id, "status": result.state.lower()}


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
            detail=f"Cannot cancel — task already {result.state.lower()}."
        )

    result.revoke(terminate=True, signal="SIGTERM")

    return {
        "job_id": job_id,
        "status": "cancelled",
        "message": "Scan task has been cancelled."
    }