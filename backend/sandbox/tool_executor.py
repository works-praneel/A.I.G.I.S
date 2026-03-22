import subprocess
import json
import shlex
import os
from urllib.parse import urlparse


def _run_command(cmd, timeout=60):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        try:
            return json.loads(stdout)
        except Exception:
            return {
                "stdout": stdout,
                "stderr": stderr,
                "returncode": result.returncode
            }
    except subprocess.TimeoutExpired:
        return {"error": f"Tool timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def _extract_host(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.hostname or parsed.netloc
    return target


def _get_dir(filepath: str) -> str:
    return (
        os.path.dirname(filepath)
        if os.path.isfile(filepath)
        else filepath
    )


def execute_tool(tool_name: str, target: str):

    host = _extract_host(target)

    commands = {

        # ── Python ────────────────────────────────────────────────────────────
        "bandit": ["bandit", "-f", "json", "-ll", target],

        # Local rulesets instead of --config auto
        # auto downloads rules from internet on every scan (+10-30s)
        "semgrep": [
            "semgrep", "--json",
            "--config", "p/python3",
            "--config", "p/security-audit",
            "--no-rewrite-rule-ids",
            "--timeout", "30",
            target
        ],
        "pylint": ["pylint", "--output-format=json", target],
        "safety": ["safety", "check", "--json", "-r", target],

        # ── JavaScript ────────────────────────────────────────────────────────
        "eslint": ["eslint", target, "-f", "json"],
        "npm-audit": [
            "npm", "audit", "--json", "--prefix", _get_dir(target)
        ],
        "retire": [
            "retire", "--path", target, "--outputformat", "json"
        ],

        # ── Java ──────────────────────────────────────────────────────────────
        "checkstyle": [
            "java", "-jar", "/opt/checkstyle.jar",
            "-c", "/google_checks.xml", target
        ],
        "spotbugs": [
            "/opt/spotbugs/bin/spotbugs", "-textui", "-xml", target
        ],
        "pmd": [
            "/opt/pmd/bin/run.sh", "pmd",
            "-d", target,
            "-R", "rulesets/java/quickstart.xml",
            "-f", "json"
        ],

        # ── C/C++ ─────────────────────────────────────────────────────────────
        "cppcheck": [
            "cppcheck", "--enable=all",
            "--output-file=/dev/stdout", "--xml", target
        ],
        "flawfinder": ["flawfinder", "--dataonly", "--html", target],
        "rats": ["rats", "--xml", target],

        # ── Ruby ──────────────────────────────────────────────────────────────
        "brakeman": ["brakeman", "-f", "json", "-q", target],
        "bundler-audit": ["bundler-audit", "check", "--verbose"],

        # ── Go ────────────────────────────────────────────────────────────────
        "gosec": ["gosec", "-fmt", "json", "./..."],
        "staticcheck": ["staticcheck", "-f", "json", "./..."],

        # ── PHP ───────────────────────────────────────────────────────────────
        "phpcs": [
            "phpcs", "--report=json", "--standard=Security", target
        ],
        "psalm": ["psalm", "--output-format=json", target],

        # ── Web ───────────────────────────────────────────────────────────────
        "nmap": ["nmap", "-sV", "-T4", "--open", "-oX", "-", host],
        "nikto": [
            "nikto", "-h", target, "-nointeractive", "-Display", "V"
        ],
        "whatweb": ["whatweb", "--log-json=-", target],
        "wafw00f": ["wafw00f", target, "-o", "-", "-f", "json"],

        # ── Repository ────────────────────────────────────────────────────────
        "gitleaks": [
            "gitleaks", "detect",
            "--source", target,
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-git"
        ],
        "trufflehog": [
            "trufflehog", "filesystem",
            "--directory", target,
            "--json",
            "--no-update"
        ],

        # ── Binary ────────────────────────────────────────────────────────────
        "binwalk": ["binwalk", "--extract", "--quiet", target],
        "strings": ["strings", "-n", "8", target],
        "radare2": [
            "radare2", "-q", "-c", "aaa;afl;pdf;iS;iz;q", target
        ],
        "yara": ["yara", "-r", "/opt/yara-rules/", target],
        "objdump": ["objdump", "-d", "-f", target],
        "checksec": ["checksec", "--file", target, "--output=json"],
        "clamav": ["clamscan", "--infected", "--no-summary", target],
    }

    if tool_name not in commands:
        return {
            "tool": tool_name,
            "error": f"Tool '{tool_name}' not implemented in executor"
        }

    command = commands[tool_name]

    print(f"[AIGIS] Running tool: {tool_name}")
    print(
        f"[AIGIS] Command: "
        f"{' '.join(shlex.quote(str(c)) for c in command)}"
    )

    # Tiered timeouts
    if tool_name in ("nmap", "nikto"):
        timeout = 180
    elif tool_name in ("wafw00f", "whatweb"):
        timeout = 60
    elif tool_name in ("radare2", "binwalk", "clamav"):
        timeout = 120
    elif tool_name in ("trufflehog", "gitleaks"):
        timeout = 180
    elif tool_name == "semgrep":
        timeout = 60
    else:
        timeout = 45

    result = _run_command(command, timeout=timeout)

    return {
        "tool": tool_name,
        "target": target,
        "result": result
    }