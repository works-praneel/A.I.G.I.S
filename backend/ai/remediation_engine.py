from backend.ai.ollama_client import query_llm


def generate_remediation(results):
    prompt = f"""
Explain these security issues briefly and give fixes.

{results[:2]}
"""
    return query_llm(prompt)