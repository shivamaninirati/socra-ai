"""
SOCRA AI — Exception Handling

Custom exception hierarchy and global exception handlers for FastAPI.
All exceptions inherit from SocraError for consistent handling.
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from app.core.logger import get_module_logger

logger = get_module_logger("exceptions")


# ═══════════════════════════════════════════════════════════════
# Custom Exception Hierarchy
# ═══════════════════════════════════════════════════════════════

class SocraError(Exception):
    """Base exception for all SOCRA AI errors."""

    def __init__(self, message: str = "An internal error occurred", status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class NotFoundError(SocraError):
    """Resource not found."""

    def __init__(self, message: str = "Resource not found"):
        super().__init__(message=message, status_code=404)


class AuthenticationError(SocraError):
    """Authentication failure."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message=message, status_code=401)


class AuthorizationError(SocraError):
    """Insufficient permissions."""

    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message=message, status_code=403)


class ValidationError(SocraError):
    """Input validation failure."""

    def __init__(self, message: str = "Validation error"):
        super().__init__(message=message, status_code=422)


class AIServiceError(SocraError):
    """AI/LLM service failure."""

    def __init__(self, message: str = "AI service unavailable"):
        super().__init__(message=message, status_code=503)


class CollectorError(SocraError):
    """Event collector failure."""

    def __init__(self, message: str = "Collector error"):
        super().__init__(message=message, status_code=500)


class SplunkError(SocraError):
    """Splunk connection or query failure."""

    def __init__(self, message: str = "Splunk service unavailable"):
        super().__init__(message=message, status_code=503)


class StorageError(SocraError):
    """Database/storage operation failure."""

    def __init__(self, message: str = "Storage error"):
        super().__init__(message=message, status_code=500)


# ═══════════════════════════════════════════════════════════════
# Global Exception Handlers (registered with FastAPI)
# ═══════════════════════════════════════════════════════════════

async def socra_exception_handler(request: Request, exc: SocraError):
    """Handle all custom SOCRA exceptions with structured response."""
    logger.warning(
        f"{exc.__class__.__name__}: {exc.message} | "
        f"path={request.url.path} method={request.method}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.message,
            "error_type": exc.__class__.__name__,
        },
    )


async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all handler for unhandled exceptions.
    Logs the full traceback but returns a safe message to the client.
    """
    logger.error(
        f"Unhandled exception: {exc.__class__.__name__}: {exc} | "
        f"path={request.url.path} method={request.method}",
        exc_info=True,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": "An internal server error occurred. Please try again later.",
            "error_type": "InternalServerError",
        },
    )


async def not_found_handler(request: Request, exc: Exception):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "error": f"Endpoint not found: {request.url.path}",
            "error_type": "NotFound",
        },
    )