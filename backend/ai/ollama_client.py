import requests
from backend.config import settings

OLLAMA_GENERATE_URL = f"{settings.OLLAMA_HOST}/api/generate"
OLLAMA_CHAT_URL = f"{settings.OLLAMA_HOST}/api/chat"

# 90 seconds per call — enough for queue wait + generation
# Previously 45s was too short when calls were parallel and queuing
OLLAMA_TIMEOUT = 90


def _extract_text(data: dict) -> str:
    if isinstance(data, dict) and "response" in data:
        return data["response"]
    if isinstance(data, dict) and "message" in data:
        msg = data["message"]
        if isinstance(msg, dict) and "content" in msg:
            return msg["content"]
    if isinstance(data, dict) and "error" in data:
        return f"Ollama error: {data['error']}"
    return str(data)


def query_llm(prompt: str) -> str:
    payload = {
        "model": "llama3:latest",
        "prompt": prompt,
        "stream": False,
        "options": {
            # 300 tokens is enough for EXPLANATION + FIX + EXAMPLE
            # Fewer tokens = faster generation
            "num_predict": 300,
            "temperature": 0.1,
        }
    }

    try:
        r = requests.post(
            OLLAMA_GENERATE_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT
        )
        r.raise_for_status()
        return _extract_text(r.json())

    except requests.exceptions.Timeout:
        return "AI remediation timed out."

    except Exception:
        # Fallback to chat API
        try:
            r = requests.post(
                OLLAMA_CHAT_URL,
                json={
                    "model": "llama3:latest",
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {
                        "num_predict": 300,
                        "temperature": 0.1,
                    }
                },
                timeout=OLLAMA_TIMEOUT
            )
            r.raise_for_status()
            return _extract_text(r.json())
        except requests.exceptions.Timeout:
            return "AI remediation timed out."
        except Exception as e:
            return f"LLM request failed: {str(e)}"