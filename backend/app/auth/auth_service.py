"""
SOCRA AI — Authentication Service

Handles user authentication, registration, password management, and JWT tokens.
Supports both legacy environment-based users and database-backed users.
"""

import hashlib
import hmac
import secrets
import re
import logging
from datetime import datetime, timedelta, timezone

from jose import jwt

from app.core.config import settings

logger = logging.getLogger(__name__)

# PBKDF2-SHA256 password hashing (stdlib only — no extra dependencies).
# Stored format: pbkdf2_sha256$<iterations>$<salt_hex>$<derived_key_hex>
PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000

# Password strength requirements
MIN_PASSWORD_LENGTH = 8
PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$"
)


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Hash a plaintext password with a random salt."""
    salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations
    )
    return f"{PBKDF2_ALGORITHM}${iterations}${salt}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verification of a password against a stored hash string."""
    try:
        algorithm, iterations, salt, expected = stored_hash.split("$")
        if algorithm != PBKDF2_ALGORITHM:
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(derived.hex(), expected)
    except (ValueError, TypeError):
        return False


def validate_password_strength(password: str) -> dict:
    """Validate password meets strength requirements."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return {"valid": False, "error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters."}
    if not re.search(r"[a-z]", password):
        return {"valid": False, "error": "Password must contain at least one lowercase letter."}
    if not re.search(r"[A-Z]", password):
        return {"valid": False, "error": "Password must contain at least one uppercase letter."}
    if not re.search(r"\d", password):
        return {"valid": False, "error": "Password must contain at least one number."}
    if not re.search(r"[@$!%*?&#]", password):
        return {"valid": False, "error": "Password must contain at least one special character (@$!%*?&#)."}
    return {"valid": True}


def validate_email(email: str) -> bool:
    """Basic email format validation."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


class AuthService:
    """Handles authentication for both legacy and database-backed users."""

    def _get_legacy_users(self):
        """Legacy users provisioned from environment variables."""
        return {
            settings.ADMIN_USERNAME: {
                "password_hash": settings.ADMIN_PASSWORD_HASH,
                "role": "admin",
                "email_verified": True,
                "status": "active",
            },
            settings.ANALYST_USERNAME: {
                "password_hash": settings.ANALYST_PASSWORD_HASH,
                "role": "analyst",
                "email_verified": True,
                "status": "active",
            },
        }

    def _get_db_user(self, identifier: str):
        """Get user from database by email or username."""
        try:
            from app.storage.sqlite_storage import sqlite_storage
            # Try email first, then username
            user = sqlite_storage.get_user_by_email(identifier)
            if not user:
                user = sqlite_storage.get_user_by_username(identifier)
            return user
        except Exception as e:
            logger.error("[AuthService] Failed to query database: %s", e)
            return None

    def authenticate(self, username_or_email: str, password: str):
        """Authenticate a user and return JWT token data."""
        # SAFE DEBUG LOGGING: No passwords/hashes printed
        logger.info(f"[AuthService] Login attempt: email/username={username_or_email}")
        # Check what legacy users exist (safe log - just usernames, no secrets)
        legacy_users = self._get_legacy_users()
        logger.info(f"[AuthService] Legacy usernames configured: {list(legacy_users.keys())}")
        
        # Fix: Allow admin@gmail.com to log in as the legacy admin user
        legacy_user = legacy_users.get(username_or_email)
        if not legacy_user and username_or_email == "admin@gmail.com" and "admin" in legacy_users:
            logger.info(f"[AuthService] Matched admin@gmail.com to legacy 'admin' user")
            legacy_user = legacy_users["admin"]
            username_or_email = "admin"
        else:
            logger.info(f"[AuthService] Legacy user lookup result: {legacy_user is not None}")
            
        if legacy_user:
            logger.info(f"[AuthService] Found legacy user, attempting password verification")
            password_valid = verify_password(password, legacy_user["password_hash"])
            logger.info(f"[AuthService] Password verification result: {password_valid}")
            if password_valid:
                return self._create_token_response(
                    username_or_email,
                    legacy_user["role"],
                    legacy_user.get("email_verified", True),
                    legacy_user.get("status", "active"),
                )

        # Check database users
        db_user = self._get_db_user(username_or_email)
        if db_user and verify_password(password, db_user.get("password_hash", "")):
            # Check if email is verified
            if not db_user.get("email_verified", False):
                return {
                    "success": False,
                    "error": "Please verify your email before logging in.",
                    "email_unverified": True,
                    "email": db_user.get("email", ""),
                }

            # Check account status
            if db_user.get("status") != "active":
                return {
                    "success": False,
                    "error": "Account is not active. Please contact support.",
                }

            # Update last login
            try:
                from app.storage.sqlite_storage import sqlite_storage
                sqlite_storage.update_user_last_login(db_user["id"])
            except Exception as e:
                logger.error("[AuthService] Failed to update last login: %s", e)

            # Username may be NULL for accounts registered by email - fall
            # back to the email address so the JWT subject is always the
            # user's real identity (never a generic placeholder).
            token_username = (
                db_user.get("username")
                or db_user.get("email")
                or username_or_email
            )
            return self._create_token_response(
                token_username,
                db_user.get("role", "analyst"),
                True,
                "active",
                user_id=db_user.get("id"),
            )

        return None

    def _create_token_response(self, username: str, role: str, email_verified: bool,
                                status: str, user_id: str = None):
        """Create JWT token response."""
        if not email_verified or status != "active":
            return None

        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        payload = {
            "sub": str(username or "user"),
            "role": role,
            "exp": datetime.now(timezone.utc) + expires_delta,
        }
        if user_id:
            payload["user_id"] = user_id

        token = jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": int(expires_delta.total_seconds()),
            "username": username,
            "role": role,
        }

    def verify_token(self, token: str):
        """Verify a JWT token and return the payload."""
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
            )
            return payload
        except Exception:
            return None


auth_service = AuthService()