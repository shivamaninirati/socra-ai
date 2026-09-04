import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional

from app.auth.dependencies import get_current_user
from app.storage.storage_manager import storage_manager

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/notifications",
    tags=["Notifications"]
)


class MarkReadRequest(BaseModel):
    notification_id: int


class AcknowledgeRequest(BaseModel):
    notification_id: int


class ResolveRequest(BaseModel):
    notification_id: int


def _resolve_user_id(current_user: dict) -> str:
    """Extract authenticated user ID from JWT. Never trust frontend-supplied user_id."""
    user_id = current_user.get("user_id") or current_user.get("id")
    return user_id or "legacy_shared_admin"


# ============================================================
# Security Attention Center Endpoints
# ============================================================

@router.get("/summary", dependencies=[Depends(get_current_user)])
def get_notification_summary(current_user: dict = Depends(get_current_user)):
    """Severity counts for active (non-resolved) notifications.

    Returns: {critical, high, system, total_attention}
    """
    user_id = _resolve_user_id(current_user)
    try:
        return storage_manager.get_notification_summary(user_id)
    except Exception as e:
        logger.error("[Notifications] Failed to fetch summary: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load notification summary")


@router.patch("/acknowledge", dependencies=[Depends(get_current_user)])
def acknowledge_notification(request: AcknowledgeRequest, current_user: dict = Depends(get_current_user)):
    """Acknowledge a notification — analyst has reviewed it.

    Different from 'read': a notification can be viewed without being
    acknowledged. Acknowledging means the analyst has taken ownership.
    """
    user_id = _resolve_user_id(current_user)
    try:
        success = storage_manager.acknowledge_notification(user_id, request.notification_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to acknowledge notification")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("[Notifications] Failed to acknowledge: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to acknowledge notification")


@router.patch("/resolve", dependencies=[Depends(get_current_user)])
def resolve_notification(request: ResolveRequest, current_user: dict = Depends(get_current_user)):
    """Resolve a notification — the security issue has been handled.

    Resolved notifications leave the active attention queue.
    """
    user_id = _resolve_user_id(current_user)
    try:
        success = storage_manager.resolve_notification(user_id, request.notification_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to resolve notification")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("[Notifications] Failed to resolve: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to resolve notification")


# ============================================================
# Legacy endpoints (backward-compatible)
# ============================================================

@router.get("/today", dependencies=[Depends(get_current_user)])
def get_today_notifications(
    current_user: dict = Depends(get_current_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
):
    """Get today's notifications (derived from events table).

    Now filtered to Critical/High only by default.
    """
    user_id = _resolve_user_id(current_user)
    severity_filter = None
    if severity:
        severity_filter = [s.strip().capitalize() for s in severity.split(",")]
        severity_filter = [s for s in severity_filter if s in ("Critical", "High")]
        if not severity_filter:
            severity_filter = None

    try:
        # Query the notifications table directly (source of truth)
        all_notifs = storage_manager.get_today_notifications(user_id)

        # Apply severity filter
        if severity_filter:
            all_notifs = [n for n in all_notifs if n.get("severity") in severity_filter]

        # Pagination
        total = len(all_notifs)
        start = (page - 1) * page_size
        end = start + page_size
        items = all_notifs[start:end]

        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "has_more": end < total,
        }
    except Exception as e:
        logger.error("[Notifications] Failed to fetch today: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load notifications")


@router.get("/unread-count", dependencies=[Depends(get_current_user)])
def get_unread_count(current_user: dict = Depends(get_current_user)):
    """Authoritative unread count for the bell badge.

    Counts unread (read=0) notifications from the notifications table.
    Only HIGH/CRITICAL severity notifications are created, so no
    additional severity filter needed here.
    """
    user_id = _resolve_user_id(current_user)
    try:
        count = storage_manager.get_unread_count(user_id)
        return {"count": count}
    except Exception as e:
        logger.error("[Notifications] Failed to fetch unread count: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load unread count")


@router.patch("/mark-read", dependencies=[Depends(get_current_user)])
def mark_notification_read(request: MarkReadRequest, current_user: dict = Depends(get_current_user)):
    """Mark a single notification as read (backward-compatible)."""
    user_id = _resolve_user_id(current_user)
    try:
        success = storage_manager.mark_derived_read(user_id, request.notification_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to mark as read")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("[Notifications] Failed to mark-read: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to mark as read")


@router.patch("/mark-all-read", dependencies=[Depends(get_current_user)])
async def mark_all_notifications_read(current_user: dict = Depends(get_current_user)):
    """Mark all of today's HIGH/CRITICAL notifications as read for this user.

    After persisting the read state, broadcasts a notification_update frame
    to all connected WebSocket clients so other tabs update their badge.
    """
    user_id = _resolve_user_id(current_user)
    try:
        success = storage_manager.mark_all_derived_read(user_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to mark all as read")

        # Broadcast notification_update so all connected clients (other tabs)
        # refresh their badge count.
        from app.services.live_soc_service import live_soc
        await live_soc._broadcast_notification_update()

        logger.info("[Notifications] Mark all read: user_id=%s", user_id)
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("[Notifications] Failed to mark-all-read: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to mark all as read")
