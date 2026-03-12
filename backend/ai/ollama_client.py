import requests
from backend.config import settings

OLLAMA_GENERATE_URL = f"{settings.OLLAMA_HOST}/api/generate"
OLLAMA_CHAT_URL = f"{settings.OLLAMA_HOST}/api/chat"

def _extract_text(data: dict) -> str:
    """Extract text from Ollama responses."""
    # /api/generate format
    if isinstance(data, dict) and "response" in data:
        return data["response"]

    # /api/chat format
    if isinstance(data, dict) and "message" in data:
        msg = data["message"]
        if isinstance(msg, dict) and "content" in msg:
            return msg["content"]

    # error returned by Ollama
    if isinstance(data, dict) and "error" in data:
        return f"Ollama error: {data['error']}"

    return str(data)

def query_llm(prompt: str) -> str:
    # Model name updated to match docker-compose pull command
    payload_generate = {
        "model": "llama3:latest",
        "prompt": prompt,
        "stream": False
    }

    try:
        r = requests.post(
            OLLAMA_GENERATE_URL,
            json=payload_generate,
            timeout=180
        )

        r.raise_for_status()
        data = r.json()

        return _extract_text(data)

    except Exception:
        # Fallback to chat API
        payload_chat = {
            "model": "llama3:latest",
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }

        try:
            r = requests.post(
                OLLAMA_CHAT_URL,
                json=payload_chat,
                timeout=180
            )

            r.raise_for_status()
            data = r.json()

            return _extract_text(data)

        except Exception as e:
            return f"LLM request failed: {str(e)}"