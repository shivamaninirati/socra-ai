"""
SOCRA AI — OTP Service

Handles OTP generation, hashing, verification, and lifecycle management.
OTPs are never stored in plaintext — only secure hashes are persisted.
"""

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

# Route through the SOCRA logger tree (console + rotating file handlers) so
# OTP lifecycle messages are actually visible; the bare root logger has no
# INFO handler under uvicorn and would drop them.
from app.core.logger import get_module_logger

logger = get_module_logger("services.otp_service")

# OTP configuration
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60


def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP."""
    return f"{secrets.randbelow(10**OTP_LENGTH):0{OTP_LENGTH}d}"


def hash_otp(otp: str) -> str:
    """Hash an OTP using SHA-256 for secure storage."""
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def verify_otp_hash(otp: str, otp_hash: str) -> bool:
    """Constant-time comparison of OTP against stored hash."""
    computed = hash_otp(otp)
    return hmac.compare_digest(computed, otp_hash)


class OTPService:
    """Manages OTP lifecycle: generation, verification, and cleanup."""

    def __init__(self):
        # In-memory store for dev mode (when SQLite OTP table is not used)
        # In production, use the database-backed store
        self._otp_store = {}
        self._lock = __import__("threading").Lock()

    def create_otp(self, user_id: str, purpose: str) -> str:
        """Create a new OTP for a user and purpose. Returns the plaintext OTP."""
        otp = generate_otp()
        otp_hash_val = hash_otp(otp)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=OTP_EXPIRY_MINUTES)

        with self._lock:
            # Invalidate any existing OTPs for this user+purpose
            key_prefix = f"{user_id}:{purpose}"
            keys_to_remove = [k for k in self._otp_store if k.startswith(key_prefix)]
            for k in keys_to_remove:
                del self._otp_store[k]

            # Store new OTP
            self._otp_store[key_prefix] = {
                "otp_hash": otp_hash_val,
                "purpose": purpose,
                "user_id": user_id,
                "expires_at": expires_at,
                "attempts": 0,
                "used": False,
                "created_at": now,
                "last_sent_at": now,
            }

        logger.info("[OTPService] OTP created for user=%s purpose=%s", user_id, purpose)
        return otp

    def verify_otp(self, user_id: str, purpose: str, otp: str) -> dict:
        """Verify an OTP. Returns {success, error?, message?}."""
        key = f"{user_id}:{purpose}"

        with self._lock:
            stored = self._otp_store.get(key)

            if not stored:
                return {"success": False, "error": "No verification code found. Please request a new one."}

            # Check if OTP was already used
            if stored["used"]:
                return {"success": False, "error": "This code has already been used. Please request a new one."}

            # Check expiration
            now = datetime.now(timezone.utc)
            if now > stored["expires_at"]:
                del self._otp_store[key]
                return {"success": False, "error": "Verification code expired. Request a new code."}

            # Check attempt limit
            stored["attempts"] += 1
            if stored["attempts"] > OTP_MAX_ATTEMPTS:
                del self._otp_store[key]
                return {"success": False, "error": "Too many attempts. Please request a new code."}

            # Verify OTP
            if not verify_otp_hash(otp, stored["otp_hash"]):
                remaining = OTP_MAX_ATTEMPTS - stored["attempts"]
                return {"success": False, "error": f"Invalid code. {remaining} attempts remaining."}

            # Mark as used
            stored["used"] = True

        logger.info("[OTPService] OTP verified for user=%s purpose=%s", user_id, purpose)
        return {"success": True, "message": "Code verified successfully."}

    def can_resend(self, user_id: str, purpose: str) -> bool:
        """Check if OTP can be resent (resend cooldown)."""
        key = f"{user_id}:{purpose}"
        with self._lock:
            stored = self._otp_store.get(key)
            if not stored:
                return True
            now = datetime.now(timezone.utc)
            elapsed = (now - stored["last_sent_at"]).total_seconds()
            return elapsed >= OTP_RESEND_COOLDOWN_SECONDS

    def get_remaining_cooldown(self, user_id: str, purpose: str) -> int:
        """Get remaining seconds before resend is allowed."""
        key = f"{user_id}:{purpose}"
        with self._lock:
            stored = self._otp_store.get(key)
            if not stored:
                return 0
            now = datetime.now(timezone.utc)
            elapsed = (now - stored["last_sent_at"]).total_seconds()
            remaining = OTP_RESEND_COOLDOWN_SECONDS - elapsed
            return max(0, int(remaining))

    def invalidate_all(self, user_id: str, purpose: str = None):
        """Invalidate all OTPs for a user (optionally filtered by purpose)."""
        with self._lock:
            keys_to_remove = []
            for k in self._otp_store:
                if k.startswith(f"{user_id}:"):
                    if purpose is None or f":{purpose}" in k:
                        keys_to_remove.append(k)
            for k in keys_to_remove:
                del self._otp_store[k]

    def cleanup_expired(self):
        """Remove expired OTPs from memory."""
        now = datetime.now(timezone.utc)
        with self._lock:
            keys_to_remove = [
                k for k, v in self._otp_store.items()
                if now > v["expires_at"]
            ]
            for k in keys_to_remove:
                del self._otp_store[k]


otp_service = OTPService()
