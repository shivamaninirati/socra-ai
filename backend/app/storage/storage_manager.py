"""Coordinate SOCRA AI's live event store and persistent SQLite storage."""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from app.collector.event_store import event_store
from app.storage.sqlite_storage import sqlite_storage

logger = logging.getLogger(__name__)


class StorageManager:
    """Coordinate live in-memory events and persistent SQLite storage."""

    NOTIFICATION_SEVERITIES = frozenset({"high", "critical"})

    def __init__(self) -> None:
        """Initialize storage manager and restore today's persisted events."""
        self.live_store = event_store
        self.history_store = sqlite_storage

        logger.info("[StorageManager] Initializing storage manager...")
        self._restore_todays_events()
        logger.info("[StorageManager] Storage manager initialization completed")

    @staticmethod
    def _normalize_severity(value: Any) -> str:
        """Normalize a severity value for comparisons without guessing unknowns."""
        if not isinstance(value, str):
            return ""
        return value.strip().casefold()

    @classmethod
    def _notification_severity(cls, event_data: Any) -> str:
        """Return the severity from supported event shapes, or an empty string."""
        if not isinstance(event_data, dict):
            return ""

        detection = event_data.get("detection")
        if isinstance(detection, dict) and detection.get("severity") is not None:
            return cls._normalize_severity(detection.get("severity"))

        # Support existing normalized callers that place severity at the root
        # or inside the event object. Unknown values remain ineligible.
        root_severity = event_data.get("severity")
        if root_severity is not None:
            return cls._normalize_severity(root_severity)

        event = event_data.get("event")
        if isinstance(event, dict):
            return cls._normalize_severity(event.get("severity"))

        return ""

    def _restore_todays_events(self) -> None:
        """Restore today's events from SQLite into the live store on startup."""
        try:
            started = datetime.now()
            todays_events = self.history_store.get_todays_events()
            logger.info(
                "[StorageManager] Found %d today's events in persistence",
                len(todays_events),
            )

            for event in todays_events:
                self.live_store.add_event(event)

            elapsed = (datetime.now() - started).total_seconds()
            logger.info(
                "[StorageManager] Restored %d events in %.2fs",
                len(todays_events),
                elapsed,
            )
        except Exception:
            logger.exception("[StorageManager] Failed to restore today's events")

    def invalidate_cache(self) -> None:
        """Invalidate cached dashboard analytics after storage changes."""
        try:
            from app.analytics.analytics_engine import analytics_engine

            with analytics_engine.cache_lock:
                analytics_engine.cache.pop("dashboard", None)
                analytics_engine.cache_timestamps.pop("dashboard", None)
        except Exception:
            # Analytics cache invalidation is best-effort and must not break
            # event collection or notification persistence.
            logger.debug("[StorageManager] Analytics cache invalidation skipped", exc_info=True)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the live store and enqueue it for SQLite persistence."""
        try:
            self.live_store.add_event(event)
        except Exception:
            logger.exception("[StorageManager] Live storage write failure")

        try:
            save_success = self.history_store.save_event(event)
            if not save_success:
                logger.warning("[StorageManager] History store rejected event (queue full)")
        except Exception:
            logger.exception("[StorageManager] History storage write failure")

        self.invalidate_cache()

    def get_live_events(self):
        """Return live events, or an empty list if the live store is unavailable."""
        try:
            return self.live_store.get_events()
        except Exception:
            logger.exception("[StorageManager] Failed to read live events")
            return []

    def get_history_events(self, limit: int = 100000):
        """Return persisted events, or an empty list if storage is unavailable."""
        try:
            return self.history_store.get_events(limit)
        except Exception:
            logger.exception("[StorageManager] Failed to read historical events")
            return []

    def get_events(self, source: str = "live", limit: int = 100000):
        """Return events from the requested source: live, history, or all."""
        if source == "history":
            return self.get_history_events(limit)
        if source == "all":
            return self.get_live_events() + self.get_history_events(limit)
        return self.get_live_events()

    @staticmethod
    def _event_fingerprint(event: Any) -> Optional[str]:
        """Read a fingerprint safely from an event, if one exists."""
        if not isinstance(event, dict):
            return None
        metadata = event.get("metadata")
        if not isinstance(metadata, dict):
            return None
        fingerprint = metadata.get("fingerprint")
        return str(fingerprint) if fingerprint else None

    def get_todays_events(self):
        """Get today's events from live and persisted stores, deduplicated by fingerprint."""
        live_events = self.get_live_events()
        todays_history_events = self.history_store.get_todays_events()
        seen = set()
        combined = []

        for event in live_events + todays_history_events:
            fingerprint = self._event_fingerprint(event)
            if fingerprint:
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
            combined.append(event)
        return combined

    def get_todays_events_with_seq(self):
        """Return today's deduplicated events and the corresponding live sequence watermark."""
        live_events, seq = self.live_store.snapshot_events()
        todays_history_events = self.history_store.get_todays_events()
        seen = set()
        combined = []

        for event in live_events + todays_history_events:
            fingerprint = self._event_fingerprint(event)
            if fingerprint:
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
            combined.append(event)
        return combined, seq

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def live_count(self) -> int:
        """Return the number of events currently held in the live store."""
        try:
            return self.live_store.count()
        except Exception:
            logger.exception("[StorageManager] Failed to count live events")
            return 0

    def history_count(self) -> int:
        """Return the number of persisted events."""
        try:
            return self.history_store.count()
        except Exception:
            logger.exception("[StorageManager] Failed to count historical events")
            return 0

    def total_count(self) -> int:
        """Return the sum of live and historical counts (keeps existing semantics)."""
        return self.live_count() + self.history_count()

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def create_notification(
        self,
        user_id: Any,
        event_data: Dict[str, Any],
        fingerprint: Optional[str] = None,
    ) -> bool:
        """Enqueue a notification only for a genuine HIGH or CRITICAL event.

        The returned value indicates whether the storage layer accepted the
        write into its queue; it does not by itself prove the transaction has
        committed. Callers requiring durable visibility must flush the store.
        """
        try:
            if user_id is None or str(user_id).strip() == "":
                logger.warning("[StorageManager] Rejecting notification without a user ID")
                return False

            if not isinstance(event_data, dict):
                logger.warning("[StorageManager] Rejecting notification with invalid event payload")
                return False

            severity = self._notification_severity(event_data)
            if severity not in self.NOTIFICATION_SEVERITIES:
                logger.debug(
                    "[StorageManager] Notification skipped for non-eligible severity=%r",
                    severity or "unknown",
                )
                return False

            accepted = self.history_store.create_notification(
                user_id, event_data, fingerprint
            )
            if not accepted:
                logger.warning(
                    "[StorageManager] Notification write was not accepted by the storage queue"
                )
                return False

            return True
        except Exception:
            logger.exception("[StorageManager] Notification storage write failure")
            return False
        finally:
            self.invalidate_cache()

    def get_today_notifications(self, user_id):
        """Get today's persisted notifications for a specific user."""
        return self.history_store.get_today_notifications(user_id)

    def get_unread_count(self, user_id):
        """Get the count of today's unread persisted notifications for a user."""
        return self.history_store.get_unread_count(user_id)

    def get_all_today_notifications(self):
        """Get today's notifications for the existing legacy-user flow."""
        return self.history_store.get_all_today_notifications()

    def get_all_unread_count(self):
        """Get today's unread notification count for the existing legacy-user flow."""
        return self.history_store.get_all_unread_count()

    def mark_notification_read(self, notification_id, user_id):
        """Mark one persisted notification as read and flush queued writes."""
        result = self.history_store.mark_notification_read(notification_id, user_id)
        self.history_store.flush()
        return result

    def mark_all_notifications_read(self, user_id):
        """Mark all of a user's persisted notifications as read."""
        result = self.history_store.mark_all_notifications_read(user_id)
        self.history_store.flush()
        return result

    # ------------------------------------------------------------------
    # Derived notifications (from events table)
    # ------------------------------------------------------------------

    def get_derived_notifications(
        self, user_id, page: int = 1, page_size: int = 50, severity_filter=None
    ):
        """Get today's HIGH/CRITICAL notifications derived from persisted events."""
        return self.history_store.get_derived_notifications(
            user_id,
            page=page,
            page_size=page_size,
            severity_filter=severity_filter,
        )

    def get_derived_unread_count(self, user_id):
        """Get the unread count for the existing event-derived notification flow."""
        return self.history_store.get_derived_unread_count(user_id)

    def mark_derived_read(self, user_id, alert_id):
        """Mark one event-derived notification as read."""
        result = self.history_store.mark_derived_read(user_id, alert_id)
        self.history_store.flush(timeout=10.0)
        return result

    def mark_all_derived_read(self, user_id):
        """Mark all event-derived notifications as read for the user."""
        result = self.history_store.mark_all_derived_read(user_id)
        self.history_store.flush(timeout=10.0)
        return result

    # ------------------------------------------------------------------
    # Security attention lifecycle
    # ------------------------------------------------------------------

    def get_notification_summary(self, user_id):
        """Get severity counts for active notifications."""
        return self.history_store.get_notification_summary(user_id)

    def acknowledge_notification(self, user_id, notification_id):
        """Acknowledge one notification and flush the queued write."""
        result = self.history_store.acknowledge_notification(user_id, notification_id)
        self.history_store.flush(timeout=10.0)
        return result

    def resolve_notification(self, user_id, notification_id):
        """Resolve one notification and flush the queued write."""
        result = self.history_store.resolve_notification(user_id, notification_id)
        self.history_store.flush(timeout=10.0)
        return result

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    def get_all_users(self):
        """Return active users known to the persistence layer."""
        return self.history_store.get_all_users()

    # ------------------------------------------------------------------
    # Clear storage (destructive; preserve existing explicit method)
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Clear live and persistent stores; call only from explicit admin workflows."""
        try:
            self.live_store.clear()
        except Exception:
            logger.exception("[StorageManager] Failed to clear live store")

        try:
            self.history_store.clear()
        except Exception:
            logger.exception("[StorageManager] Failed to clear history store")


storage_manager = StorageManager()
