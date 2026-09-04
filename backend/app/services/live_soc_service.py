import asyncio
import json
import logging
import time
from datetime import date, datetime
from typing import List, Optional
from fastapi import WebSocket
from app.analytics.analytics_engine import analytics_engine

logger = logging.getLogger(__name__)


def _json_default(value):
    """JSON fallback for values plain json.dumps cannot serialize.

    WebSocket frames are pre-serialized before send (see _safe_send) so a
    single non-serializable field can never crash send_json mid-frame and get
    a healthy socket dropped from the connection manager.
    """
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


class LiveSOCService:

    def __init__(self):

        self.active_connections: List[WebSocket] = []
        # Per-connection asyncio.Lock keyed by id(websocket). Multiple tasks
        # (the in-process collector per-event broadcast, the periodic metrics
        # broadcast, alert/status broadcasts) can call send_json() on the SAME
        # socket concurrently. Uvicorn's websocket transport is not safe for
        # interleaved sends — concurrent sends raise and broadcast() then
        # wrongly drops healthy sockets from active_connections (the client
        # keeps its TCP connection, so it never notices — the backend "loses"
        # clients that are still connected). Serializing sends per connection
        # makes concurrent broadcasts safe.
        self._send_locks: dict = {}
        self._metrics_task: Optional[asyncio.Task] = None
        self._metrics_interval = 2.0  # Broadcast metrics snapshot every 2 seconds

    async def connect(self, websocket: WebSocket, subprotocol: str = None):

        await websocket.accept(subprotocol=subprotocol)

        # Register the per-connection send lock BEFORE the socket becomes
        # visible to broadcasters, so no broadcast can race an unregistered
        # socket.
        self._send_locks[id(websocket)] = asyncio.Lock()
        self.active_connections.append(websocket)
        logger.info(f"[LiveSOC] New client connected. Total active clients: {len(self.active_connections)}")

        # Start periodic metrics broadcast if not already running
        if self._metrics_task is None or self._metrics_task.done():
            self._metrics_task = asyncio.create_task(self._periodic_metrics_broadcast())

    def disconnect(self, websocket: WebSocket):

        self._send_locks.pop(id(websocket), None)

        if websocket in self.active_connections:

            self.active_connections.remove(websocket)
            logger.info(f"[LiveSOC] Client disconnected. Total active clients: {len(self.active_connections)}")

        # Stop the periodic metrics broadcast when the last client leaves — no
        # periodic work (and no dashboard analytics recomputation) while there
        # are zero connected clients. Reconnects restart it in connect().
        if (
            not self.active_connections
            and self._metrics_task is not None
            and not self._metrics_task.done()
        ):
            self._metrics_task.cancel()
            self._metrics_task = None

    async def broadcast(self, message: dict):

        disconnected = []

        # If this is an alert event, create notifications for all active users
        # and then notify connected clients to refresh their notification state.
        notifications_created = False
        if message.get("type") == "alert":
            notifications_created = await self._create_alert_notifications(message)

        # Iterate over a snapshot: other tasks (connect/disconnect) mutate
        # active_connections while we send.
        for connection in list(self.active_connections):
            if not await self._safe_send(connection, message):
                disconnected.append(connection)

        for connection in disconnected:

            self.disconnect(connection)

        # After broadcasting an alert, push a lightweight notification_update
        # frame so every connected client knows to refresh its unread count
        # and notification list without polling.
        if notifications_created:
            await self._broadcast_notification_update()

    # Only these severities warrant analyst attention as notifications.
    # Informational/Low/Medium telemetry stays in Events/Timeline/Alerts
    # but does NOT create a notification.
    _NOTIFICATION_SEVERITIES = {"Critical", "High"}

    async def _create_alert_notifications(self, event: dict):
        """Create notification records for all active users when an alert arrives.

        Only creates notifications for Critical and High severity alerts.
        Normal telemetry, Informational, Low, and Medium events stay in
        Events/Timeline/Alerts but do NOT become notifications.

        Returns True if at least one notification was queued successfully.
        """
        # Severity gate — only Critical/High create notifications
        detection = event.get("detection") or {}
        severity = (detection.get("severity") or "").strip().capitalize()
        if severity not in self._NOTIFICATION_SEVERITIES:
            return False

        try:
            from app.storage.storage_manager import storage_manager

            # Get all users from the database
            users = storage_manager.get_all_users()
            if not users:
                logger.warning("[LiveSOC] get_all_users() returned empty — no notifications will be created")
                return False

            created = 0
            # Shared legacy user ID so all legacy accounts (admin/analyst) get notifications
            LEGACY_SHARED_USER_ID = "legacy_shared_admin"
            for user in users:
                user_id = user.get("id")
                # If no database ID, use the shared legacy user ID so notifications are created
                if not user_id:
                    user_id = LEGACY_SHARED_USER_ID
                result = storage_manager.create_notification(user_id, event)
                if result:
                    created += 1

            logger.info("[LiveSOC] Created %d notification(s) for %d user(s)", created, len(users))

            # Flush the write queue so notifications are committed to SQLite
            # BEFORE the notification_update frame reaches the frontend.
            # Without this, the frontend reads 0 because the writes are still
            # queued asynchronously.
            storage_manager.history_store.flush(timeout=3.0)
            return created > 0

        except Exception as e:
            logger.error("[LiveSOC] Failed to create notification: %s", e, exc_info=True)
            return False

    async def _safe_send(self, websocket: WebSocket, message: dict) -> bool:
        """Send one JSON frame to a client, serialized against concurrent sends.

        Every broadcaster (collector per-event, periodic metrics, alert status,
        notification updates) routes sends through this so frames on the same
        socket are never interleaved — concurrent raw sends on one uvicorn
        WebSocket raise, which previously made broadcast() drop healthy
        connections (backend lost clients the browser still considered open).

        The frame is pre-serialized to text (with a safe JSON fallback) so a
        payload containing a non-serializable value (e.g. a stray datetime)
        can never raise inside the transport send and take a healthy socket
        down with it — serialization errors are logged, not fatal.
        """
        lock = self._send_locks.get(id(websocket))
        if lock is None:
            # Socket vanished between snapshot and send — treat as disconnected.
            return False
        try:
            payload = json.dumps(message, default=_json_default)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("[LiveSOC] Frame serialization failed: %s", exc)
            return True  # Not a socket failure — skip frame, keep connection.
        try:
            async with lock:
                await websocket.send_text(payload)
            return True
        except Exception:
            # Only a genuine transport failure reaches here — drop the socket.
            return False

    async def _broadcast_notification_update(self):
        """Push a lightweight notification_update frame to every connected client.

        After notification records are persisted, this frame tells the frontend
        to re-fetch its unread count and notification list so the badge and
        panel stay accurate without requiring a full REST poll on a timer.
        """
        if not self.active_connections:
            return
        disconnected = []
        for connection in list(self.active_connections):
            if not await self._safe_send(connection, {"type": "notification_update"}):
                disconnected.append(connection)
        for connection in disconnected:
            self.disconnect(connection)

    def stats(self):

        return {

            "connected_clients": len(self.active_connections),

            "status": "Live" if len(self.active_connections) > 0 else "Standby"

        }

    async def _periodic_metrics_broadcast(self):
        """Periodically broadcast current dashboard metrics snapshot for self-correction"""
        while True:
            try:
                if self.active_connections:
                    # Get current analytics snapshot from pre-imported module
                    try:
                        dashboard_data = analytics_engine.dashboard()
                        
                        metrics_snapshot = {
                            "type": "dashboard_stats",
                            "data": {
                                # Canonical totals from backend database - frontend syncs to these every 2s
                                "totalEvents": dashboard_data.get("summary", {}).get("total_events", 0),
                                "highSeverity": dashboard_data.get("summary", {}).get("high", 0),
                                "critical": dashboard_data.get("summary", {}).get("critical", 0),
                                "medium": dashboard_data.get("summary", {}).get("medium", 0),
                                "low": dashboard_data.get("summary", {}).get("low", 0),
                                "informational": dashboard_data.get("summary", {}).get("informational", 0),
                                "windowsHosts": dashboard_data.get("summary", {}).get("hosts", 0),
                                "eventsPerSec": dashboard_data.get("summary", {}).get("eps", 0),
                                "severityDistribution": dashboard_data.get("severity_distribution", []),
                                "trendData": dashboard_data.get("cyber_threat_horizon", {}).get("data", []),
                                "topHosts": dashboard_data.get("top_hosts", []),
                                "collector": dashboard_data.get("collector_status", {}),
                                "recentCriticalAlerts": dashboard_data.get("recent_critical_alerts", []),
                                # Live sequence watermark: lets clients detect
                                # missed events (server ahead of them) and run
                                # catch-up instead of polling.
                                "currentSeq": dashboard_data.get("current_seq", 0),
                                "timestamp": time.time()
                            }
                        }
                        
                        await self.broadcast(metrics_snapshot)
                    except Exception as e:
                        logger.warning("[LiveSOC] Metrics broadcast error: %s", e)
                
                await asyncio.sleep(self._metrics_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("[LiveSOC] Periodic broadcast error: %s", e)
                await asyncio.sleep(self._metrics_interval)


live_soc = LiveSOCService()