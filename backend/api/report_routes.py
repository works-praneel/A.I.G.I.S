from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import os

from backend.database.database import get_db
from backend.database.models import Report
from backend.auth.dependencies import get_current_user

router = APIRouter(tags=["reports"])


@router.get("/")
def list_my_reports(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    reports = db.query(Report).filter(
        Report.user_id == current_user.id
    ).order_by(Report.created_at.desc()).all()

    return [
        {
            "job_id": r.job_id,
            "scan_type": r.scan_type,
            "target": r.target,
            "vulnerability_count": r.vulnerability_count or 0,
            "threat_score": r.threat_score or 0.0,
            "highest_severity": r.highest_severity or "none",
            "created_at": r.created_at,
            "download_url": f"/api/reports/{r.job_id}/download"
        }
        for r in reports
    ]


@router.get("/{job_id}/download")
def download_report(
    job_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    report = db.query(Report).filter(Report.job_id == job_id).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )

    is_admin = (
        current_user.role and
        current_user.role.name.lower() == "admin"
    )

    if not is_admin and report.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to download this report"
        )

    if not os.path.exists(report.path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found on disk"
        )

    return FileResponse(
        path=report.path,
        filename=f"{job_id}.pdf",
        media_type="application/pdf"
    )