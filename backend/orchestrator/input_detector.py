import os
import re


def detect_input_type(target: str):
    """
    Detect the type of scan target.
    Returns one of:
    web | project | python | javascript | java | c_cpp | ruby | go | binary
    """

    # Detect URL targets
    if isinstance(target, str) and re.match(r"^https?://", target):
        return "web"

    # Detect directories (project scans)
    if os.path.isdir(target):
        return "project"

    # Detect file types
    ext = os.path.splitext(target)[1].lower()

    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "javascript",
        ".jsx": "javascript",
        ".java": "java",
        ".c": "c_cpp",
        ".cpp": "c_cpp",
        ".cc": "c_cpp",
        ".h": "c_cpp",
        ".hpp": "c_cpp",
        ".rb": "ruby",
        ".go": "go",
        ".php": "web",
        ".html": "web",
        ".htm": "web",
    }

    if ext in mapping:
        return mapping[ext]

    # Default fallback
    return "binary"