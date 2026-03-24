import requests
from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger(__name__)

OLLAMA_GENERATE_URL = f"{settings.OLLAMA_HOST}/api/generate"
OLLAMA_TAGS_URL     = f"{settings.OLLAMA_HOST}/api/tags"
OLLAMA_TIMEOUT      = 180

_MODEL_NAME = None


def _get_model_name() -> str:
    """
    Query /api/tags to discover which model is actually loaded.
    Result is cached after first successful call so we only pay
    the round-trip once per worker lifetime.
    """
    global _MODEL_NAME
    if _MODEL_NAME:
        return _MODEL_NAME

    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=10)
        r.raise_for_status()
        models = [m.get("name", "") for m in r.json().get("models", [])]
        logger.info(f"[AIGIS] Ollama models available: {models}")

        # Preference order — first match wins
        for candidate in ["llama3", "llama3:latest", "llama3:8b"]:
            if candidate in models:
                _MODEL_NAME = candidate
                logger.info(f"[AIGIS] Using Ollama model: {_MODEL_NAME}")
                return _MODEL_NAME

        # Fall back to whatever is loaded
        if models:
            _MODEL_NAME = models[0]
            logger.info(f"[AIGIS] Using first available model: {_MODEL_NAME}")
            return _MODEL_NAME

    except Exception as e:
        logger.warning(f"[AIGIS] Could not query Ollama tags: {e}")

    _MODEL_NAME = "llama3"
    return _MODEL_NAME


def _extract_text(data: dict) -> str:
    """Pull the generated text out of the /api/generate response."""
    if isinstance(data, dict) and "response" in data:
        return data["response"]
    if isinstance(data, dict) and "error" in data:
        return f"Ollama error: {data['error']}"
    return str(data)


def query_llm(prompt: str) -> str:
    """
    Call Ollama /api/generate.

    NOTE: We use /api/generate, NOT /api/chat.
    /api/chat returns 404 on older Ollama builds and on versions
    where the model was not pulled with chat support.
    /api/generate works on every Ollama version.
    """
    model = _get_model_name()

    payload = {
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 300,
            "temperature": 0.1,
        },
    }

    try:
        logger.debug(f"[AIGIS] Calling Ollama /api/generate: model={model}")
        r = requests.post(
            OLLAMA_GENERATE_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT,
        )

        # 404 almost always means a model-name mismatch.
        # Try the alternate spelling once before giving up.
        if r.status_code == 404:
            global _MODEL_NAME
            alt = "llama3:latest" if model == "llama3" else "llama3"
            logger.warning(
                f"[AIGIS] Model '{model}' not found (404), retrying as '{alt}'"
            )
            _MODEL_NAME    = alt
            payload["model"] = alt
            r = requests.post(
                OLLAMA_GENERATE_URL,
                json=payload,
                timeout=OLLAMA_TIMEOUT,
            )

        r.raise_for_status()
        result = _extract_text(r.json())
        logger.debug(f"[AIGIS] Ollama response: {len(result)} chars")
        return result

    except requests.exceptions.Timeout:
        logger.warning("[AIGIS] Ollama timed out")
        return ""   # empty → remediation_engine will use static fallback

    except requests.exceptions.ConnectionError:
        logger.error("[AIGIS] Cannot connect to Ollama")
        return ""   # empty → remediation_engine will use static fallback

    except Exception as e:
        logger.error(f"[AIGIS] Ollama error: {e}")
        return ""   # empty → remediation_engine will use static fallback