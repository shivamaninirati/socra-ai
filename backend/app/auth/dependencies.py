"""
Reusable FastAPI authentication / authorization dependencies.

Use on any protected route or router:

    router = APIRouter(prefix="/logs", tags=["Logs"], dependencies=[Depends(get_current_user)])

or on a single endpoint:

    @router.get("/foo")
    def foo(user: dict = Depends(get_current_user)): ...

Admin-only routes can use `require_admin` the same way.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.auth_service import auth_service

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Require a valid JWT bearer token and return its decoded payload.

    Raises 401 (with WWW-Authenticate: Bearer) when the header is missing,
    the token is invalid, or the token has expired.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = auth_service.verify_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def require_admin(payload: dict = Depends(get_current_user)) -> dict:
    """Require a valid JWT with the admin role.

    Raises 403 when the authenticated user is not an admin.
    """
    if payload.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return payload
