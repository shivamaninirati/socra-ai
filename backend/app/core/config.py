from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    # =========================
    # Splunk
    # =========================

    SPLUNK_HOST: str

    SPLUNK_PORT: int = 8089

    SPLUNK_USERNAME: str

    SPLUNK_PASSWORD: str

    # =========================
    # Gemini AI
    # =========================

    GEMINI_API_KEY: str

    # =========================
    # JWT
    # =========================
    # SECRET_KEY is required and validated below — the application refuses to
    # start with a missing, default or weak key (fail closed, never fall back
    # to a hardcoded secret).
    SECRET_KEY: str

    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # =========================
    # Auth users
    # =========================
    # Credentials live in environment storage (.env) as PBKDF2-SHA256 hashes —
    # never as plaintext. Generate hashes with:
    #   python -c "from app.auth.auth_service import hash_password; print(hash_password('<password>'))"
    ADMIN_USERNAME: str = "admin"

    ADMIN_PASSWORD_HASH: str

    ANALYST_USERNAME: str = "analyst"

    ANALYST_PASSWORD_HASH: str

    # =========================
    # Optional, EXPLICIT admin bootstrap (disabled by default)
    # =========================
    # A database administrator account is ONLY created on a fresh database
    # when BOTH of these variables are configured. There is never an
    # auto-created default admin with a fixed/public password. When
    # BOOTSTRAP_ADMIN_EMAIL is set without BOOTSTRAP_ADMIN_PASSWORD the
    # bootstrap is skipped with a warning (fail safe - never an insecure
    # account). Password is stored as a PBKDF2-SHA256 hash only.
    BOOTSTRAP_ADMIN_EMAIL: str = ""

    BOOTSTRAP_ADMIN_PASSWORD: str = ""

    # =========================
    # Threat Intelligence (Task 22)
    # =========================
    # Optional provider API keys. Providers WITHOUT a key report a real
    # "Provider not configured" state — reputation is never fabricated and
    # keys are never returned to clients.
    VT_API_KEY: str = ""

    ABUSEIPDB_API_KEY: str = ""

    # =========================
    # CORS (Task 25)
    # =========================
    # Comma-separated list of allowed browser origins. Local development
    # defaults keep the Vite dev server working; production hosts are added
    # via CORS_ORIGINS in the environment without source-code edits.
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # =========================
    # Logging
    # =========================

    LOG_LEVEL: str = "INFO"

    LOG_FILE: str = "socra.log"

    LOG_MAX_BYTES: int = 10 * 1024 * 1024

    LOG_BACKUP_COUNT: int = 5

    @field_validator("SECRET_KEY")
    @classmethod
    def _validate_secret_key(cls, value: str) -> str:
        if not value or value in ("change-me-in-production", "socra-ai-secret"):
            raise ValueError(
                "SECRET_KEY must be set to a strong random value "
                "(at least 32 characters). Generate one with: "
                "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        if len(value) < 32:
            raise ValueError(
                "SECRET_KEY is too short — use a strong random value of at least 32 characters."
            )
        return value

    class Config:

        env_file = ".env"

        case_sensitive = True


settings = Settings()
