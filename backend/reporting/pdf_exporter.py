from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

REPORT_DIR = "/app/backend/reporting/reports"

def export_pdf(job_id, vulnerabilities, remediation, score=0): # Renamed 'results' to 'vulnerabilities'
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = f"{REPORT_DIR}/report_{job_id}.pdf"
    c = canvas.Canvas(path, pagesize=letter)
    y = 750

    c.drawString(50, y, "AIGIS Security Report")
    y -= 40
    c.drawString(50, y, f"Job ID: {job_id}")
    y -= 30
    c.drawString(50, y, f"Overall Risk Score: {score}%") # Display the score

    y -= 40
    c.drawString(50, y, "Detected Vulnerabilities:")
    y -= 20

    for v in vulnerabilities:
        # Use .get() to avoid KeyErrors if a tool returns unexpected formats
        severity = v.get('severity', 'UNKNOWN')
        issue = v.get('issue', v.get('message', 'No description'))
        tool = v.get('tool', 'Scanner')
        
        c.drawString(50, y, f"[{severity}] {issue} ({tool})")
        y -= 20
        if y < 50: # Handle page overflow
            c.showPage()
            y = 750

    y -= 30
    c.drawString(50, y, "AI Remediation Suggestions:")
    y -= 20
    for line in remediation.split("\n"):
        c.drawString(50, y, line[:95]) # Truncate long lines to fit page
        y -= 15
        if y < 50:
            c.showPage()
            y = 750

    c.save()
    return path