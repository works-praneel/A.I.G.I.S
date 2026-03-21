from backend.reporting.pdf_exporter import export_pdf
from backend.database.database import SessionLocal
from backend.database.models import Report

def generate_report(job_id, vulnerabilities, remediation, risk_score=0):
    # Now perfectly synchronized with the pdf_exporter signature
    path = export_pdf(
        job_id=job_id,
        vulnerabilities=vulnerabilities,
        remediation=remediation,
        score=risk_score
    )

    db = SessionLocal()
    try:
        report = Report(job_id=job_id, path=path)
        db.add(report)
        db.commit()
    except Exception as e:
        print(f"Database logging failed: {e}")
    finally:
        db.close()

    return path