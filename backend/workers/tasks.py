from backend.workers.celery_app import celery
import subprocess


@celery.task(name="run_scan_task")
def run_scan_task(job_id, file_path):

    results = []

    tools = [
        ["bandit", "-r", file_path],
        ["semgrep", "--config=auto", file_path]
    ]

    for tool in tools:

        process = subprocess.run(
            tool,
            capture_output=True,
            text=True
        )

        results.append({
            "tool": tool[0],
            "stdout": process.stdout,
            "stderr": process.stderr
        })

    return {
        "job_id": job_id,
        "results": results
    }