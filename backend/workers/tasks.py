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

    logger.info(f"[AIGIS] Starting scan for: {file_path}")

    if not os.path.exists(file_path):
        logger.error(f"[AIGIS] File not found: {file_path}")
        return {
            "status": "error",
            "reason": "file not found"
        }

    try:
        logger.info("[AIGIS] Dispatching tools")
        raw_results = dispatch(file_path)
        logger.info(f"[AIGIS] Tools executed: {len(raw_results)}")

        logger.info("[AIGIS] Parsing vulnerabilities")
        vulnerabilities = parse_vulnerabilities(raw_results)
        logger.info(f"[AIGIS] Vulnerabilities detected: {len(vulnerabilities)}")

        logger.info("[AIGIS] Scoring vulnerabilities")
        scored_vulnerabilities = score_vulnerabilities(vulnerabilities)

        logger.info("[AIGIS] Generating AI remediation")
        remediation = generate_remediation(scored_vulnerabilities)

        logger.info("[AIGIS] Generating report")
        report_path = generate_report(
            job_id=self.request.id,
            vulnerabilities=scored_vulnerabilities,
            remediation=remediation
        )

        logger.info("[AIGIS] Scan completed successfully")

        return {
            "status": "completed",
            "file": file_path,
            "report": report_path,
            "vulnerabilities": len(scored_vulnerabilities)
        }

    except Exception as e:
        logger.exception("[AIGIS] Scan failed")

        return {
            "status": "failed",
            "error": str(e),
            "file": file_path
        }