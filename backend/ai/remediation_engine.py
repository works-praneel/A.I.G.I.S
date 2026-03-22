from backend.ai.ollama_client import query_llm
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Cap at 10 vulns for AI remediation within the 5-minute budget.
# At ~8s per call sequentially, 10 vulns = ~80s for AI.
# Total budget: ~60s scanning + ~80s AI + ~10s PDF = ~2.5 minutes.
MAX_REMEDIATION_VULNS = 10


def generate_remediation(vulnerabilities: list) -> list:
    """
    Call Ollama sequentially for each vulnerability.

    Why sequential instead of parallel:
    Ollama processes one request at a time internally. Parallel calls
    queue up and each one waits for the previous to finish before
    generation even starts. With a 45s timeout, queued calls time out
    before Ollama touches them. Sequential calls with a 90s timeout
    means every call gets its full generation time without queue penalty.
    """
    if not vulnerabilities:
        return vulnerabilities

    to_remediate = vulnerabilities[:MAX_REMEDIATION_VULNS]
    skipped = vulnerabilities[MAX_REMEDIATION_VULNS:]

    logger.info(
        f"[AIGIS] Remediating {len(to_remediate)} vulns sequentially. "
        f"{len(skipped)} skipped (cap reached)."
    )

    for i, vuln in enumerate(to_remediate):
        logger.info(
            f"[AIGIS] Remediating {i+1}/{len(to_remediate)}: "
            f"[{vuln.get('tool')}] {vuln.get('test_id', '')} "
            f"— {vuln.get('severity', '').upper()}"
        )
        try:
            vuln["remediation"] = _remediate_single(vuln)
        except Exception as e:
            logger.warning(f"[AIGIS] Remediation failed for vuln {i}: {e}")
            vuln["remediation"] = "Remediation unavailable — LLM error."

    for vuln in skipped:
        vuln["remediation"] = (
            "Remediation not generated — vulnerability cap reached. "
            "See full report for details."
        )

    return to_remediate + skipped


def _remediate_single(vuln: dict) -> str:
    """
    Short, focused prompt — fewer tokens = faster Ollama response.
    Previous prompt was too long, causing slow generation.
    """
    # Clean the location — strip internal container path
    location = vuln.get("location", "unknown")
    if "/app/uploads/" in location:
        # e.g. /app/uploads/uuid_filename.py:13 → filename.py:13
        parts = location.split("/app/uploads/")[-1]
        # Strip UUID prefix (36 chars + underscore)
        if len(parts) > 37 and parts[36] == "_":
            parts = parts[37:]
        location = parts

    prompt = (
        f"Security vulnerability found:\n"
        f"Tool: {vuln.get('tool', 'unknown')} | "
        f"Severity: {vuln.get('severity', '').upper()} | "
        f"CWE: {vuln.get('cwe', 'N/A')} | "
        f"Location: {location}\n"
        f"Issue: {vuln.get('description', 'No description')}\n\n"
        f"Respond in exactly this format:\n"
        f"EXPLANATION:\n<one sentence — what this is and why it matters>\n\n"
        f"FIX:\n<the exact code or config change needed>\n\n"
        f"EXAMPLE:\n<before/after snippet, 3-5 lines max>"
    )

    response = query_llm(prompt)
    return response.strip() if response else "No remediation available."