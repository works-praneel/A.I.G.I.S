import os
from backend.workers.celery_app import celery
from backend.orchestrator.dispatcher import dispatch
from backend.security.vulnerability_parser import parse_vulnerabilities
from backend.security.cvss_engine import score_vulnerabilities
from backend.ai.remediation_engine import generate_remediation
from backend.reporting.report_generator import generate_report
from backend.utils.logger import get_logger

logger = get_logger(__name__)

@celery.task(name="backend.workers.tasks.run_scan_task", bind=True)
def run_scan_task(self, file_path: str):
    # ... (Keep existing tool execution and parsing logic)
    
    try:
        # 1. Dispatch and Parse (Already working in your logs)
        raw_results = dispatch(file_path)
        vulnerabilities = parse_vulnerabilities(raw_results)
        scored_vulnerabilities = score_vulnerabilities(vulnerabilities)

        # 2. Calculate Final Score for the Dashboard
        # Logic: Sum CVSS scores and cap at 100%
        final_score = sum([v.get('cvss', 0) for v in scored_vulnerabilities])
        final_score = min(float(final_score), 100.0)

        # 3. AI Remediation (Already working in your logs)
        remediation = generate_remediation(scored_vulnerabilities)

        # 4. Generate Report (This was where it crashed)
        report_path = generate_report(
            job_id=self.request.id,
            vulnerabilities=scored_vulnerabilities,
            remediation=remediation,
            risk_score=final_score # Pass the calculated score
        )

        return {
            "status": "completed",
            "risk_score": final_score,
            "report": report_path,
            "vulnerabilities": len(scored_vulnerabilities)
        }
    except Exception as e:
        logger.exception("[AIGIS] Scan failed")
        return {"status": "failed", "error": str(e)}