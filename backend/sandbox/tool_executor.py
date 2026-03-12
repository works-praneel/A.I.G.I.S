import subprocess
import json
import shlex


def _run_command(cmd):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
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

    except Exception as e:
        return {"error": str(e)}


def execute_tool(tool_name: str, target: str):

    commands = {

        # Python
        "bandit": ["bandit", "-f", "json", target],
        "semgrep": ["semgrep", "--json", target],

        # JavaScript
        "eslint": ["eslint", target, "-f", "json"],
        "npm-audit": ["npm", "audit", "--json"],

        # Java
        "checkstyle": ["java", "-jar", "/opt/checkstyle.jar", "-f", "json", target],
        "spotbugs": ["/opt/spotbugs/bin/spotbugs", "-textui", target],

        # C/C++
        "cppcheck": ["cppcheck", "--enable=all", "--xml", target],
        "flawfinder": ["flawfinder", target],

        # Ruby
        "brakeman": ["brakeman", "-f", "json", target],

        # Go
        "gosec": ["gosec", "-fmt", "json", target],

        # Binary tools
        "binwalk": ["binwalk", target],
        "strings": ["strings", target],
        "radare2": ["radare2", "-c", "aaa;afl;q", target],
        "yara": ["yara", target],

        # Web tools
        "nmap": ["nmap", "-sV", target],
        "nikto": ["/opt/nikto/program/nikto.pl", "-h", target]
    }

    if tool_name not in commands:
        return {
            "tool": tool_name,
            "error": "Tool not implemented in executor"
        }

    command = commands[tool_name]

    print(f"[AIGIS] Running tool: {tool_name}")
    print(f"[AIGIS] Command: {' '.join(shlex.quote(c) for c in command)}")

    result = _run_command(command)

    return {
        "tool": tool_name,
        "target": target,
        "result": result
    }