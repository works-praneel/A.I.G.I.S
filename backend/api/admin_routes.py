from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import os

from backend.database.database import get_db
from backend.database.models import User, Report, ScanJob
from backend.auth.rbac import require_role

router = APIRouter(tags=["admin"])


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "role": u.role.name if u.role else "none",
            "created_at": u.created_at
        }
        for u in users
    ]


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own admin account"
        )
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    db.delete(user)
    db.commit()
    return {"message": f"User '{user.username}' deleted successfully"}


@router.get("/reports")
def list_all_reports(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    reports = db.query(Report).order_by(
        Report.created_at.desc()
    ).all()
    return [
        {
            "id": r.id,
            "job_id": r.job_id,
            "scan_type": r.scan_type,
            "target": r.target,
            "vulnerability_count": r.vulnerability_count or 0,
            "threat_score": r.threat_score or 0.0,
            "highest_severity": r.highest_severity or "none",
            "user_id": r.user_id,
            "path": r.path,
            "created_at": r.created_at
        }
        for r in reports
    ]


@router.get("/reports/{job_id}/download")
def admin_download_report(
    job_id: str,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    report = db.query(Report).filter(Report.job_id == job_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
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


@router.get("/scans")
def list_all_scans(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    scans = db.query(ScanJob).order_by(ScanJob.created_at.desc()).all()
    return [
        {
            "id": s.id,
            "input_name": s.input_name,
            "input_type": s.input_type,
            "status": s.status,
            "created_at": s.created_at
        }
        for s in scans
    ]