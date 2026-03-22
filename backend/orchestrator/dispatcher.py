from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.utils.yaml_loader import load_yaml
from backend.orchestrator.input_detector import detect_input_type
from backend.sandbox.tool_executor import execute_tool

import os

TOOLS_CONFIG = "/app/config/tools.yaml"


def dispatch(target):

    config = load_yaml(TOOLS_CONFIG)
    input_type = detect_input_type(target)
    tools = []

    if input_type in config.get("engines", {}):
        tools.extend([e["name"] for e in config["engines"][input_type]])

    if input_type == "binary":
        tools.extend(config.get("binary", []))

    if input_type == "project":
        project_tools = config.get("project", [])
        tools.extend([e["name"] for e in project_tools])

    if not tools:
        return [{"tool": "none", "output": {
            "error": f"No tools configured for input type: {input_type}"
        }}]

    results = []

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(execute_tool, tool, target): tool
            for tool in tools
        }
        for future in as_completed(futures):
            tool = futures[future]
            try:
                output = future.result()
                results.append({"tool": tool, "output": output})
            except Exception as e:
                results.append({"tool": tool, "output": {"error": str(e)}})

    return results