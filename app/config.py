"""
Application configuration.

All settings are loaded from environment variables (via a .env file).
The application must work correctly even when optional settings
(like OPENAI_API_KEY) are missing.
"""
import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _get_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    # General
    APP_NAME: str = "CyberShield AI"
    APP_TAGLINE: str = "Think Before You Click."
    ENV: str = os.getenv("ENV", "development")
    DEBUG: bool = _get_bool("DEBUG", True)

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    ALGORITHM: str = "HS256"
    SESSION_COOKIE_NAME: str = "cybershield_session"

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'cybershield.db'}")

    # Uploads
    UPLOAD_DIR: Path = BASE_DIR / "uploads"
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "5"))
    ALLOWED_IMAGE_TYPES: tuple = ("image/jpeg", "image/png", "image/webp", "image/jpg")
    PERSIST_UPLOADED_IMAGES: bool = _get_bool("PERSIST_UPLOADED_IMAGES", False)

    # Optional AI provider (never required for the app to work)
    OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY") or None

    # Optional threat-intel providers (future-ready, not required)
    VIRUSTOTAL_API_KEY: str | None = os.getenv("VIRUSTOTAL_API_KEY") or None
    GOOGLE_SAFE_BROWSING_API_KEY: str | None = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None

    # CORS
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")

    # Request handling
    REQUEST_TIMEOUT_SECONDS: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "5"))


settings = Settings()

# Ensure required directories exist at import time (safe, idempotent)
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
