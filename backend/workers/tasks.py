import os
import time
from backend.workers.celery_app import celery
from backend.database.database import SessionLocal
from backend.database import models
from backend.orchestrator.dispatcher import dispatch
from backend.security.vulnerability_parser import parse_vulnerabilities
from backend.security.cvss_engine import score_vulnerabilities
from backend.ai.remediation_engine import generate_remediation
from backend.reporting.report_generator import generate_report
from backend.utils.logger import get_logger

logger = get_logger(__name__)

@celery.task(name="backend.workers.tasks.run_scan_task", bind=True)
def run_scan_task(self, file_path: str, user_id: int):
    """
    Full AIGIS Pipeline: Scan -> Score -> AI Fix -> PDF -> Database Save
    """
    # Create a fresh database session for this specific worker task
    db = SessionLocal()
    
    try:
        logger.info(f"[AIGIS] Task {self.request.id} started for User {user_id}")

        # 1. RUN SECURITY TOOLS (Bandit, Semgrep, etc.)
        raw_results = dispatch(file_path)
        
        # 2. PARSE & SCORE
        vulnerabilities = parse_vulnerabilities(raw_results)
        scored_vulnerabilities = score_vulnerabilities(vulnerabilities)

        # 3. CALCULATE THREAT LEVEL (0-100%)
        total_cvss = sum([float(v.get('cvss', 0)) for v in scored_vulnerabilities])
        final_score = min(float(total_cvss), 100.0)
        
        # 4. AI REMEDIATION (Llama3)
        remediation = generate_remediation(scored_vulnerabilities)

        # 5. GENERATE PDF REPORT
        report_path = generate_report(
            job_id=self.request.id,
            vulnerabilities=scored_vulnerabilities,
            remediation=remediation,
            risk_score=final_score
        )

        # 6. SAVE TO POSTGRESQL HISTORY
        new_history = models.ScanHistory(
            job_id=self.request.id,
            filename=os.path.basename(file_path),
            risk_score=final_score,
            vulnerabilities=len(scored_vulnerabilities),
            user_id=user_id,
            status="completed"
        )
        db.add(new_history)
        db.commit()
        logger.info(f"[AIGIS] History saved for {os.path.basename(file_path)}")

        # 7. RETURN RESULT TO FRONTEND
        return {
            "status": "completed",
            "risk_score": final_score,
            "report": report_path,
            "vulnerabilities": len(scored_vulnerabilities),
            "vulnerabilities_list": scored_vulnerabilities, 
            "job_id": self.request.id
        }

    except Exception as e:
        if db:
            db.rollback()
        logger.error(f"[AIGIS] Critical Task Failure: {str(e)}")
        return {"status": "failed", "error": str(e)}
    
    finally:
        if db:
            db.close()