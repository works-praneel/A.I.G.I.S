import os


class Settings:
    # --- Project Metadata ---
    PROJECT_NAME: str = "A.I.G.I.S"

    # --- Database (PostgreSQL) ---
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://aigis:aigis@postgres:5432/aigis"
    )

    # --- Redis (Task Broker) ---
    REDIS_URL: str = os.getenv(
        "REDIS_URL",
        "redis://redis:6379/0"
    )

    # --- Security (JWT) ---
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "aigis-secret"
    )

    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # --- Ollama Configuration ---
    # Use host.docker.internal so containers can reach Ollama running on the host machine
    OLLAMA_HOST: str = os.getenv(
        "OLLAMA_HOST",
        "http://host.docker.internal:11434"
    )

    # Model name available in Ollama
    OLLAMA_MODEL: str = os.getenv(
        "OLLAMA_MODEL",
        "llama3"
    )

    # --- Computed Properties ---
    @property
    def OLLAMA_GENERATE_URL(self) -> str:
        return f"{self.OLLAMA_HOST}/api/generate"

    @property
    def OLLAMA_CHAT_URL(self) -> str:
        return f"{self.OLLAMA_HOST}/api/chat"


settings = Settings()