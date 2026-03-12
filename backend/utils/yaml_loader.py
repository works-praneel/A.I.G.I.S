import yaml
import os


def load_yaml(path):
    """
    Generic YAML loader used by dispatcher and other modules.
    """

    if not os.path.exists(path):
        raise FileNotFoundError(f"YAML file not found: {path}")

    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_tools_config():
    """
    Loads the AIGIS tool configuration.
    """

    config_path = "backend/config/tools.yaml"

    return load_yaml(config_path)