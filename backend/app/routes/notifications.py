import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.storage.storage_manager import storage_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class MarkReadRequest(BaseModel):
    notification_id: int


class AcknowledgeRequest(BaseModel):
    notification_id: int


class ResolveRequest(BaseModel):
    notification_id: int


NOTIFICATION_SEVERITIES = {"Critical", "High"}


def _resolve_user_id(current_user: dict) -> str:
    """Extract the authenticated user's ID; never accept it from the request."""
    user_id = current_user.get("user_id") or current_user.get("id")
    if user_id is None or str(user_id).strip() == "":
        # Retain compatibility with installations that still use the legacy admin.
        logger.warning(
            "[Notifications] Authenticated user has no user_id/id; using legacy_shared_admin"
        )
        return "legacy_shared_admin"
    return str(user_id)


def _normalize_severity_filter(severity: Optional[str]):
    """Return a valid subset of Critical/High, or None for both."""
    if not severity:
        return None
    requested = {item.strip().capitalize() for item in severity.split(",") if item.strip()}
    filtered = sorted(requested.intersection(NOTIFICATION_SEVERITIES))
    # An absent/invalid filter should not accidentally hide all valid alerts.
    return filtered or None


# ============================================================
# Security Attention Center endpoints
# ============================================================


@router.get("/summary")
def get_notification_summary(current_user: dict = Depends(get_current_user)):
    """Return severity counts for active, non-resolved persisted notifications."""
    user_id = _resolve_user_id(current_user)
    try:
        return storage_manager.get_notification_summary(user_id)
    except Exception as exc:
        logger.error("[Notifications] Failed to fetch summary: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load notification summary")


@router.patch("/acknowledge")
def acknowledge_notification(
    request: AcknowledgeRequest,
    current_user: dict = Depends(get_current_user),
):
    """Acknowledge a persisted notification."""
    user_id = _resolve_user_id(current_user)
    try:
        success = storage_manager.acknowledge_notification(user_id, request.notification_id)
        if not success:
            raise HTTPException(status_code=404, detail="Notification not found or could not be acknowledged")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[Notifications] Failed to acknowledge: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to acknowledge notification")


@router.patch("/resolve")
def resolve_notification(
    request: ResolveRequest,
    current_user: dict = Depends(get_current_user),
):
    """Resolve a persisted notification."""
    user_id = _resolve_user_id(current_user)
    try:
        success = storage_manager.resolve_notification(user_id, request.notification_id)
        if not success:
            raise HTTPException(status_code=404, detail="Notification not found or could not be resolved")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[Notifications] Failed to resolve: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to resolve notification")


# ============================================================
# Notification bell endpoints
#
# Use the SAME event-derived source for the list, unread count, and read
# actions. This keeps the UI consistent with today's High/Critical events
# already shown on the dashboard, even when no separate notification row
# was created for an older/imported event.
# ============================================================


@router.get("/today")
def get_today_notifications(
    current_user: dict = Depends(get_current_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
):
    """Return today's High/Critical event-derived notifications, read and unread."""
    user_id = _resolve_user_id(current_user)
    severity_filter = _normalize_severity_filter(severity)

    try:
        result = storage_manager.get_derived_notifications(
            user_id,
            page=page,
            page_size=page_size,
            severity_filter=severity_filter,
        )
        if not isinstance(result, dict):
            logger.error("[Notifications] Derived notification query returned an unexpected result")
            raise HTTPException(status_code=500, detail="Invalid notification response")

        # Defensive filter: only High/Critical items may appear in the bell,
        # regardless of the severity values or filters passed by the caller.
        items = result.get("items", [])
        if not isinstance(items, list):
            items = []
        eligible_items = [
            item for item in items
            if isinstance(item, dict)
            and str(item.get("severity", "")).strip().capitalize() in NOTIFICATION_SEVERITIES
            and (
                severity_filter is None
                or str(item.get("severity", "")).strip().capitalize() in severity_filter
            )
        ]

        result["items"] = eligible_items
        result.setdefault("page", page)
        result.setdefault("page_size", page_size)
        result.setdefault("total", len(eligible_items))
        result.setdefault("unread_count", storage_manager.get_derived_unread_count(user_id))
        result.setdefault("has_more", False)
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[Notifications] Failed to fetch today's alerts: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load notifications")


@router.get("/unread-count")
def get_unread_count(current_user: dict = Depends(get_current_user)):
    """Return unread High/Critical event-derived count for the bell badge."""
    user_id = _resolve_user_id(current_user)
    try:
        count = storage_manager.get_derived_unread_count(user_id)
        return {"count": max(0, int(count or 0))}
    except Exception as exc:
        logger.error("[Notifications] Failed to fetch unread count: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load unread count")


@router.patch("/mark-read")
async def mark_notification_read(
    request: MarkReadRequest,
    current_user: dict = Depends(get_current_user),
):
    """Mark one event-derived notification as read for this user."""
    user_id = _resolve_user_id(current_user)
    try:
        success = storage_manager.mark_derived_read(user_id, request.notification_id)
        if not success:
            raise HTTPException(status_code=404, detail="Notification not found or could not be marked as read")

        from app.services.live_soc_service import live_soc
        await live_soc._broadcast_notification_update()
        return {"success": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[Notifications] Failed to mark as read: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to mark as read")


@router.patch("/mark-all-read")
async def mark_all_notifications_read(current_user: dict = Depends(get_current_user)):
    """Mark today's High/Critical event-derived notifications as read."""
    user_id = _resolve_user_id(current_user)
    try:
        success = storage_manager.mark_all_derived_read(user_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to mark all as read")

        from app.services.live_soc_service import live_soc
        await live_soc._broadcast_notification_update()
        logger.info("[Notifications] Mark all read: user_id=%s", user_id)
        return {"success": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[Notifications] Failed to mark all as read: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to mark all as read")
