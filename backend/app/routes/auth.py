"""
SOCRA AI — Authentication Routes

Handles login, registration, email verification, forgot password, and reset password.
"""

import threading
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

from app.auth.auth_service import (
    auth_service,
    hash_password,
    validate_password_strength,
    validate_email,
)
from app.services.email_service import email_service
from app.services.otp_service import otp_service
from app.core.logger import get_module_logger

logger = get_module_logger("routes.auth")

router = APIRouter(tags=["Authentication"])

# ---------------------------------------------------------------------------
# Rate limiting (brute-force protection)
# ---------------------------------------------------------------------------
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300  # 5 minutes

_login_failures = defaultdict(deque)
_login_lock = threading.Lock()

# Registration rate limiting
REGISTER_MAX_PER_IP = 3
REGISTER_WINDOW_SECONDS = 3600  # 1 hour

_register_attempts = defaultdict(deque)
_register_lock = threading.Lock()


def _login_failure_count(key: str) -> int:
    now = time.monotonic()
    with _login_lock:
        window = _login_failures[key]
        while window and window[0] <= now - LOGIN_WINDOW_SECONDS:
            window.popleft()
        return len(window)


def _login_record_failure(key: str) -> bool:
    now = time.monotonic()
    with _login_lock:
        window = _login_failures[key]
        while window and window[0] <= now - LOGIN_WINDOW_SECONDS:
            window.popleft()
        window.append(now)
        return len(window) > LOGIN_MAX_ATTEMPTS


def _register_check_rate_limit(ip: str) -> bool:
    now = time.monotonic()
    with _register_lock:
        window = _register_attempts[ip]
        while window and window[0] <= now - REGISTER_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= REGISTER_MAX_PER_IP:
            return False
        window.append(now)
        return True


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    full_name: str
    email: str
    password: str
    confirm_password: str


class VerifyEmailRequest(BaseModel):
    email: str
    otp: str


class ResendVerificationRequest(BaseModel):
    email: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    otp: str
    new_password: str
    confirm_password: str


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@router.post("/login")
def login(request: LoginRequest, http_request: Request):
    """Authenticate a user and return a JWT access token."""
    client_ip = http_request.client.host if http_request.client else "unknown"
    key = f"{client_ip}|{request.username.strip().lower()}"

    if _login_failure_count(key) >= LOGIN_MAX_ATTEMPTS:
        logger.warning("Login rate limit reached: user=%s ip=%s", request.username, client_ip)
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"success": False, "error": "Too many login attempts. Please try again later."},
        )

    result = auth_service.authenticate(request.username, request.password)

    if result is None:
        _login_record_failure(key)
        logger.warning("Failed login attempt: user=%s ip=%s", request.username, client_ip)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"success": False, "error": "Invalid username or password."},
        )

    # Handle email unverified response
    if isinstance(result, dict) and result.get("email_unverified"):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=result,
        )

    return {"success": True, **result}


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

@router.post("/register")
def register(request: RegisterRequest, http_request: Request):
    """Register a new user account."""
    client_ip = http_request.client.host if http_request.client else "unknown"

    # Rate limit check
    if not _register_check_rate_limit(client_ip):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"success": False, "error": "Too many registration attempts. Please try again later."},
        )

    # Validate inputs
    if not request.full_name.strip():
        return {"success": False, "error": "Full name is required."}

    if not validate_email(request.email):
        return {"success": False, "error": "Invalid email format."}

    if request.password != request.confirm_password:
        return {"success": False, "error": "Passwords do not match."}

    password_check = validate_password_strength(request.password)
    if not password_check["valid"]:
        return {"success": False, "error": password_check["error"]}

    # Check if email already exists
    try:
        from app.storage.sqlite_storage import sqlite_storage
        existing = sqlite_storage.get_user_by_email(request.email.lower().strip())
        if existing:
            return {"success": False, "error": "An account with this email already exists."}
    except Exception as e:
        logger.error("Failed to check existing user: %s", e)
        return {"success": False, "error": "Registration failed. Please try again."}

    # Create user
    try:
        user = sqlite_storage.create_user(
            email=request.email.lower().strip(),
            full_name=request.full_name.strip(),
            password_hash=hash_password(request.password),
            status="pending_verification",
        )
        if not user:
            return {"success": False, "error": "Registration failed. Please try again."}
    except Exception as e:
        logger.error("Failed to create user: %s", e)
        return {"success": False, "error": "Registration failed. Please try again."}

    # Generate and send OTP
    try:
        otp = otp_service.create_otp(user["id"], "EMAIL_VERIFICATION")
        email_service.send_verification_otp(user["email"], otp, user.get("full_name", ""))
    except Exception as e:
        logger.error("Failed to send verification email: %s", e)
        # Don't fail registration if email fails - user can resend

    return {
        "success": True,
        "message": "Verification code sent to your email.",
        "email": user["email"],
    }


# ---------------------------------------------------------------------------
# Verify Email
# ---------------------------------------------------------------------------

@router.post("/verify-email")
def verify_email(request: VerifyEmailRequest):
    """Verify email with OTP code."""
    if not request.email or not request.otp:
        return {"success": False, "error": "Email and verification code are required."}

    # Get user by email
    try:
        from app.storage.sqlite_storage import sqlite_storage
        user = sqlite_storage.get_user_by_email(request.email.lower().strip())
        if not user:
            return {"success": False, "error": "User not found."}

        if user.get("email_verified"):
            return {"success": False, "error": "Email is already verified."}

        if user.get("status") != "pending_verification":
            return {"success": False, "error": "Invalid account status."}
    except Exception as e:
        logger.error("Failed to get user for verification: %s", e)
        return {"success": False, "error": "Verification failed. Please try again."}

    # Verify OTP
    result = otp_service.verify_otp(user["id"], "EMAIL_VERIFICATION", request.otp)
    if not result["success"]:
        return {"success": False, "error": result.get("error", "Verification failed.")}

    # Activate account
    try:
        sqlite_storage.activate_user(user["id"])
    except Exception as e:
        logger.error("Failed to activate user: %s", e)
        return {"success": False, "error": "Failed to activate account. Please try again."}

    # Invalidate used OTPs
    otp_service.invalidate_all(user["id"], "EMAIL_VERIFICATION")

    return {"success": True, "message": "Email verified successfully. You can now log in."}


# ---------------------------------------------------------------------------
# Resend Verification
# ---------------------------------------------------------------------------

@router.post("/resend-verification")
def resend_verification(request: ResendVerificationRequest):
    """Resend email verification OTP."""
    if not request.email:
        return {"success": False, "error": "Email is required."}

    try:
        from app.storage.sqlite_storage import sqlite_storage
        user = sqlite_storage.get_user_by_email(request.email.lower().strip())
        if not user:
            # Don't reveal if user exists
            return {"success": True, "message": "If an account exists with this email, a verification code has been sent."}

        if user.get("email_verified"):
            return {"success": False, "error": "Email is already verified."}

        # Check resend cooldown
        if not otp_service.can_resend(user["id"], "EMAIL_VERIFICATION"):
            remaining = otp_service.get_remaining_cooldown(user["id"], "EMAIL_VERIFICATION")
            return {"success": False, "error": f"Please wait {remaining} seconds before requesting a new code."}

        # Generate and send new OTP
        otp = otp_service.create_otp(user["id"], "EMAIL_VERIFICATION")
        email_service.send_verification_otp(user["email"], otp, user.get("full_name", ""))

    except Exception as e:
        logger.error("Failed to resend verification: %s", e)

    # Always return success to prevent email enumeration
    return {"success": True, "message": "If an account exists with this email, a verification code has been sent."}


# ---------------------------------------------------------------------------
# Forgot Password
# ---------------------------------------------------------------------------

@router.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    """Send password reset OTP to email."""
    if not request.email:
        return {"success": False, "error": "Email is required."}

    try:
        from app.storage.sqlite_storage import sqlite_storage
        user = sqlite_storage.get_user_by_email(request.email.lower().strip())
        if not user:
            # Don't reveal if user exists
            return {"success": True, "message": "If an account exists with this email, a reset code has been sent."}

        # Check resend cooldown
        if not otp_service.can_resend(user["id"], "PASSWORD_RESET"):
            remaining = otp_service.get_remaining_cooldown(user["id"], "PASSWORD_RESET")
            return {"success": False, "error": f"Please wait {remaining} seconds before requesting a new code."}

        # Generate and send OTP
        otp = otp_service.create_otp(user["id"], "PASSWORD_RESET")
        email_service.send_password_reset_otp(user["email"], otp, user.get("full_name", ""))

    except Exception as e:
        logger.error("Failed to process forgot password: %s", e)

    return {"success": True, "message": "If an account exists with this email, a reset code has been sent."}


# ---------------------------------------------------------------------------
# Reset Password
# ---------------------------------------------------------------------------

@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest):
    """Reset password using OTP verification."""
    if not request.email or not request.otp or not request.new_password:
        return {"success": False, "error": "All fields are required."}

    if request.new_password != request.confirm_password:
        return {"success": False, "error": "Passwords do not match."}

    password_check = validate_password_strength(request.new_password)
    if not password_check["valid"]:
        return {"success": False, "error": password_check["error"]}

    try:
        from app.storage.sqlite_storage import sqlite_storage
        user = sqlite_storage.get_user_by_email(request.email.lower().strip())
        if not user:
            return {"success": False, "error": "Invalid request."}

        # Verify OTP
        result = otp_service.verify_otp(user["id"], "PASSWORD_RESET", request.otp)
        if not result["success"]:
            return {"success": False, "error": result.get("error", "Reset failed.")}

        # Update password
        new_hash = hash_password(request.new_password)
        sqlite_storage.update_user_password(user["id"], new_hash)

        # Invalidate all reset OTPs
        otp_service.invalidate_all(user["id"], "PASSWORD_RESET")

    except Exception as e:
        logger.error("Failed to reset password: %s", e)
        return {"success": False, "error": "Failed to reset password. Please try again."}

    return {"success": True, "message": "Password reset successful. You can now log in."}
