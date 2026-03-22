def calculate_cvss_base_score(vuln):
    """
    CVSS v3.1 simplified base score calculation.
    """

    severity_map = {
        "critical": 9.8,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.1,
        "info": 0.0
    }

    severity = vuln.get("severity", "low").lower()

    return severity_map.get(severity, 3.1)


def score_vulnerabilities(vulnerabilities):

    scored = []

    for vuln in vulnerabilities:

        score = calculate_cvss_base_score(vuln)

        vuln["cvss_score"] = round(score, 1)

        if score >= 9.0:
            vuln["cvss_rating"] = "Critical"
        elif score >= 7.0:
            vuln["cvss_rating"] = "High"
        elif score >= 4.0:
            vuln["cvss_rating"] = "Medium"
        elif score > 0:
            vuln["cvss_rating"] = "Low"
        else:
            vuln["cvss_rating"] = "None"

        # Ensure these fields always exist so report_generator
        # never hits a KeyError regardless of which tool produced the finding
        vuln.setdefault("location", "")
        vuln.setdefault("test_id", "")
        vuln.setdefault("description", "No description")

        scored.append(vuln)

    return scored