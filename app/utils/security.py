"""
Password hashing and session token utilities.

Uses passlib(bcrypt) for password hashing and a signed itsdangerous token
for session cookies (simple, dependable, no extra services required).
"""
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="cybershield-session")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(plain_password, password_hash)
    except Exception:
        # Never leak details about why verification failed
        return False


def create_session_token(user_id: int) -> str:
    return _serializer.dumps({"user_id": user_id})


def decode_session_token(token: str) -> int | None:
    """Return the user_id encoded in the token, or None if invalid/expired."""
    max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    try:
        data = _serializer.loads(token, max_age=max_age)
        return data.get("user_id")
    except (BadSignature, SignatureExpired, Exception):
        return None
