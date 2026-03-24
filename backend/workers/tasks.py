import os
import re
import shutil
import tempfile
import subprocess

from backend.workers.celery_app import celery
from backend.orchestrator.dispatcher import dispatch
from backend.security.vulnerability_parser import parse_vulnerabilities
from backend.security.cvss_engine import score_vulnerabilities
from backend.ai.remediation_engine import generate_remediation
from backend.reporting.report_generator import generate_report
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def _write_scan_job(input_name, input_type, status, user_id=None):
    """Write a ScanJob record so the admin All Scans page populates."""
    try:
        from backend.database.database import SessionLocal
        from backend.database.models import ScanJob
        db = SessionLocal()
        job = ScanJob(
            input_name=input_name,
            input_type=input_type,
            status=status,
            user_id=user_id if hasattr(ScanJob, 'user_id') else None,
        )
        db.add(job)
        db.commit()
        db.close()
    except Exception as e:
        logger.warning(f"[AIGIS] Could not write ScanJob: {e}")


# ── File scan ──────────────────────────────────────────────────────────────────

@celery.task(name="backend.workers.tasks.run_scan_task", bind=True)
def run_scan_task(self, file_path: str, user_id: int = None):

    logger.info(f"[AIGIS] Starting file scan for: {file_path}")

    filename = os.path.basename(file_path)
    if len(filename) > 37 and filename[36] == "_":
        filename = filename[37:]

    if not os.path.exists(file_path):
        logger.error(f"[AIGIS] File not found: {file_path}")
        _write_scan_job(filename, "file", "failed", user_id)
        return {"status": "error", "reason": "file not found"}

    _write_scan_job(filename, "file", "running", user_id)

    try:
        logger.info("[AIGIS] Dispatching tools")
        raw_results = dispatch(file_path)
        logger.info(f"[AIGIS] Tools executed: {len(raw_results)}")

        logger.info("[AIGIS] Parsing vulnerabilities")
        vulnerabilities = parse_vulnerabilities(raw_results)
        logger.info(f"[AIGIS] Vulnerabilities detected: {len(vulnerabilities)}")

        logger.info("[AIGIS] Scoring vulnerabilities")
        scored = score_vulnerabilities(vulnerabilities)

        logger.info("[AIGIS] Generating AI remediation")
        remediated = generate_remediation(scored)

        logger.info("[AIGIS] Generating report")
        report_path = generate_report(
            job_id=self.request.id,
            vulnerabilities=remediated,
            scan_type="file",
            target=file_path,
            user_id=user_id
        )

        _write_scan_job(filename, "file", "completed", user_id)
        logger.info("[AIGIS] Scan completed successfully")
        return {
            "status": "completed",
            "file": file_path,
            "report": report_path,
            "vulnerabilities": len(remediated)
        }

    except Exception as e:
        _write_scan_job(filename, "file", "failed", user_id)
        logger.exception("[AIGIS] File scan failed")
        return {"status": "failed", "error": str(e), "file": file_path}


# ── URL scan ───────────────────────────────────────────────────────────────────

@celery.task(name="backend.workers.tasks.run_url_scan_task", bind=True)
def run_url_scan_task(self, url: str, user_id: int = None):

    logger.info(f"[AIGIS] Starting URL scan for: {url}")

    if not re.match(r"^https?://", url):
        return {"status": "error", "reason": "Invalid URL", "url": url}

    _write_scan_job(url, "url", "running", user_id)

    try:
        logger.info("[AIGIS] Dispatching web tools")
        raw_results = dispatch(url)
        logger.info(f"[AIGIS] Tools executed: {len(raw_results)}")

        logger.info("[AIGIS] Parsing vulnerabilities")
        vulnerabilities = parse_vulnerabilities(raw_results)
        logger.info(f"[AIGIS] Vulnerabilities detected: {len(vulnerabilities)}")

        logger.info("[AIGIS] Scoring vulnerabilities")
        scored = score_vulnerabilities(vulnerabilities)

        logger.info("[AIGIS] Generating AI remediation")
        remediated = generate_remediation(scored)

        logger.info("[AIGIS] Generating report")
        report_path = generate_report(
            job_id=self.request.id,
            vulnerabilities=remediated,
            scan_type="url",
            target=url,
            user_id=user_id
        )

        _write_scan_job(url, "url", "completed", user_id)
        logger.info("[AIGIS] URL scan completed successfully")
        return {
            "status": "completed",
            "url": url,
            "report": report_path,
            "vulnerabilities": len(remediated)
        }

    except Exception as e:
        _write_scan_job(url, "url", "failed", user_id)
        logger.exception("[AIGIS] URL scan failed")
        return {"status": "failed", "error": str(e), "url": url}


# ── Repository scan ────────────────────────────────────────────────────────────

@celery.task(name="backend.workers.tasks.run_repo_scan_task", bind=True)
def run_repo_scan_task(
    self, repo_url: str,
    branch: str = "main",
    user_id: int = None
):

    logger.info(f"[AIGIS] Starting repository scan for: {repo_url}")

    if not re.match(r"^https?://(github|gitlab|bitbucket)\.com/", repo_url):
        return {
            "status": "error",
            "reason": "Invalid repository URL.",
            "repo_url": repo_url
        }

    clone_dir = None
    _write_scan_job(repo_url, "repository", "running", user_id)

    try:
        clone_dir = tempfile.mkdtemp(prefix="aigis_repo_")
        logger.info(f"[AIGIS] Cloning {repo_url} into {clone_dir}")

        clone_result = subprocess.run(
            ["git", "clone", "--depth", "1",
             "--branch", branch, repo_url, clone_dir],
            capture_output=True, text=True, timeout=120
        )

        if clone_result.returncode != 0:
            logger.warning(
                f"[AIGIS] Branch '{branch}' failed, retrying without --branch"
            )
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, clone_dir],
                capture_output=True, text=True, timeout=120
            )

        if clone_result.returncode != 0:
            _write_scan_job(repo_url, "repository", "failed", user_id)
            return {
                "status": "error",
                "reason": f"Git clone failed: {clone_result.stderr.strip()}",
                "repo_url": repo_url
            }

        logger.info("[AIGIS] Repository cloned successfully")

        raw_results = dispatch(clone_dir)
        logger.info(f"[AIGIS] Tools executed: {len(raw_results)}")

        vulnerabilities = parse_vulnerabilities(raw_results)
        logger.info(f"[AIGIS] Vulnerabilities detected: {len(vulnerabilities)}")

        scored = score_vulnerabilities(vulnerabilities)
        remediated = generate_remediation(scored)

        report_path = generate_report(
            job_id=self.request.id,
            vulnerabilities=remediated,
            scan_type="repository",
            target=repo_url,
            user_id=user_id
        )

        _write_scan_job(repo_url, "repository", "completed", user_id)
        logger.info("[AIGIS] Repository scan completed successfully")
        return {
            "status": "completed",
            "repo_url": repo_url,
            "report": report_path,
            "vulnerabilities": len(remediated)
        }

    except subprocess.TimeoutExpired:
        _write_scan_job(repo_url, "repository", "failed", user_id)
        return {
            "status": "error",
            "reason": "Git clone timed out after 120s.",
            "repo_url": repo_url
        }

    except Exception as e:
        _write_scan_job(repo_url, "repository", "failed", user_id)
        logger.exception("[AIGIS] Repository scan failed")
        return {"status": "failed", "error": str(e), "repo_url": repo_url}

    finally:
        if clone_dir and os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)
            logger.info(f"[AIGIS] Cleaned up clone dir: {clone_dir}")