import yaml
from backend.utils.yaml_loader import load_yaml

TOOLS_CONFIG = "backend/config/tools.yaml"


def get_tools(language):

    config = load_yaml(TOOLS_CONFIG)

    engines = config.get("engines", {})

    return engines.get(language, [])