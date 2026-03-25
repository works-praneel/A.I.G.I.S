import os
from backend.reporting.pdf_exporter import export_pdf
from backend.database.database import SessionLocal
from backend.database.models import Report


def _clean_target(target: str, scan_type: str) -> str:
    """
    Clean target before storing in DB.
    For file/zip scans, strips internal path and UUID prefix.
    For URL/repo scans, returns as-is.
    """
    if scan_type in ("file", "zip"):
        if "/app/uploads/" in target:
            target = target.split("/app/uploads/")[-1]
        basename = os.path.basename(target)
        if len(basename) > 37 and basename[36] == "_":
            return basename[37:]
        return basename
    return target


def _sanitize_vulnerabilities(vulnerabilities: list, clean_target: str) -> list:
    """
    Cleans up missing locations and raw unparsed tool outputs 
    before they are written to the PDF.
    """
    for v in vulnerabilities:
        # 1. Fix missing or N/A locations by using the cleaned filename
        loc = str(v.get("location", "")).strip()
        if not loc or loc == "N/A":
            v["location"] = clean_target

        # 2. Fix ugly raw dictionary descriptions (like cppcheck XML dumps)
        desc = str(v.get("description", "")).strip()
        if desc.startswith("{") and "'tool':" in desc and "'result':" in desc:
            tool_name = str(v.get("tool", "The scanner")).upper()
            v["description"] = (
                f"{tool_name} flagged a potential issue, but returned raw diagnostic data "
                f"instead of a standard description. Please review the file manually."
            )
            
    return vulnerabilities


def generate_report(
    job_id,
    vulnerabilities,
    scan_type="file",
    target="",
    user_id=None
):
    clean_target = _clean_target(target, scan_type)
    
    # Clean up the vulnerabilities BEFORE they hit the PDF generator
    vulnerabilities = _sanitize_vulnerabilities(vulnerabilities, clean_target)

    path = export_pdf(
        job_id=job_id,
        vulnerabilities=vulnerabilities,
        scan_type=scan_type,
        target=target
    )

    vuln_count = len(vulnerabilities)
    threat_score = round(min(vuln_count * 10.0, 100.0), 1)

    severity_order = ["critical", "high", "medium", "low", "info", "none"]
    highest = "none"
    for sev in severity_order:
        if any(v.get("severity", "").lower() == sev for v in vulnerabilities):
            highest = sev
            break

    db = SessionLocal()
    report = Report(
        job_id=job_id,
        path=path,
        scan_type=scan_type,
        target=clean_target,
        user_id=user_id,
        vulnerability_count=vuln_count,
        threat_score=threat_score,
        highest_severity=highest,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    db.close()

    return path