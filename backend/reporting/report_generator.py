from backend.reporting.pdf_exporter import export_pdf
from backend.database.database import SessionLocal
from backend.database.models import Report


def generate_report(job_id, vulnerabilities, remediation):

    path = export_pdf(
        job_id=job_id,
        vulnerabilities=vulnerabilities,
        remediation=remediation
    )

    db = SessionLocal()

    report = Report(
        job_id=job_id,
        path=path
    )

    db.add(report)
    db.commit()
    db.refresh(report)
    db.close()

    return path