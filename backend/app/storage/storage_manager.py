import logging
from datetime import datetime
from typing import Dict, Any

from app.collector.event_store import event_store
from app.storage.sqlite_storage import sqlite_storage

# Enterprise-grade structured logging
logger = logging.getLogger(__name__)


class StorageManager:
    """Enterprise storage manager that coordinates between live in-memory store and persistent SQLite"""
    
    def __init__(self):
        """Initialize storage manager with automatic persistence restoration"""
        self.live_store = event_store
        self.history_store = sqlite_storage
        
        logger.info("[StorageManager] Initializing storage manager...")
        # On startup: load all today's events from history into live store for immediate dashboard access
        self._restore_todays_events()
        logger.info("[StorageManager] Storage manager initialization completed")
    
    def _restore_todays_events(self):
        """Restore today's events from database to live store on startup"""
        try:
            start_time = datetime.now()
            todays_events = self.history_store.get_todays_events()
            logger.info(f"[StorageManager] Found {len(todays_events)} today's events in persistence")
            
            for event in todays_events:
                self.live_store.add_event(event)
            
            restore_duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"[StorageManager] Successfully restored {len(todays_events)} events in {restore_duration:.2f}s - dashboard will show complete data immediately")
        except Exception as e:
            logger.error(f"[StorageManager] Critical failure during event restoration: {str(e)}", exc_info=True)
    
    def invalidate_cache(self):
        """Invalidate analytics cache when new events are added to keep metrics fresh"""
        try:
            from app.analytics.analytics_engine import analytics_engine
            with analytics_engine.cache_lock:
                analytics_engine.cache.pop("dashboard", None)
                analytics_engine.cache_timestamps.pop("dashboard", None)
        except Exception:
            # Fail silently - cache invalidation is non-critical
            pass

    # ---------------------------------------------------------
    # Save Event
    # ---------------------------------------------------------

    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to both live store and persistent storage
        
        Automatically invalidates analytics cache to ensure fresh metrics.
        """
        # Add to live in-memory store for real-time access
        try:
            self.live_store.add_event(event)
        except Exception as e:
            logger.error(f"[StorageManager] Live storage write failure: {str(e)}", exc_info=True)

        # Persist to SQLite database for durability
        try:
            save_success = self.history_store.save_event(event)
            if not save_success:
                logger.warning("[StorageManager] History store rejected event (queue full)")
        except Exception as e:
            logger.error(f"[StorageManager] History storage write failure: {str(e)}", exc_info=True)
            
        # Invalidate analytics cache to ensure dashboard shows updated metrics
        self.invalidate_cache()

    # ---------------------------------------------------------
    # Live Events
    # ---------------------------------------------------------

    def get_live_events(self):

        try:

            return self.live_store.get_events()

        except Exception:

            return []

    # ---------------------------------------------------------
    # Historical Events
    # ---------------------------------------------------------

    def get_history_events(self, limit=100000):

        try:

            return self.history_store.get_events(limit)

        except Exception:

            return []

    # ---------------------------------------------------------
    # Unified Event Source
    # ---------------------------------------------------------

    def get_events(self, source="live", limit=100000):

        if source == "history":

            return self.get_history_events(limit)

        elif source == "all":

            return (

                self.get_live_events()

                +

                self.get_history_events(limit)

            )

        return self.get_live_events()

    # ---------------------------------------------------------
    # Get Today's Events (Analytics Only)
    # ---------------------------------------------------------
    def get_todays_events(self):
        """Get all events from today (both live and history) for analytics"""
        live_events = self.get_live_events()
        todays_history_events = self.history_store.get_todays_events()
        # Combine and deduplicate events (keep most recent)
        seen = set()
        combined = []
        for event in live_events + todays_history_events:
            fp = event.get("metadata", {}).get("fingerprint")
            if fp and fp not in seen:
                seen.add(fp)
                combined.append(event)
            elif not fp:
                combined.append(event)
        return combined

    def get_todays_events_with_seq(self):
        """Atomically return (today's deduplicated events, current_seq).

        The live snapshot and its sequence watermark are read together so the
        seq the frontend receives exactly matches the events the dashboard
        totals were computed from — the REST/WebSocket sync boundary.
        """
        live_events, seq = self.live_store.snapshot_events()
        todays_history_events = self.history_store.get_todays_events()
        seen = set()
        combined = []
        for event in live_events + todays_history_events:
            fp = event.get("metadata", {}).get("fingerprint")
            if fp and fp not in seen:
                seen.add(fp)
                combined.append(event)
            elif not fp:
                combined.append(event)
        return combined, seq

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    def live_count(self):

        try:

            return self.live_store.count()

        except Exception:

            return 0

    def history_count(self):

        try:

            return self.history_store.count()

        except Exception:

            return 0

    def total_count(self):

        return (

            self.live_count()

            +

            self.history_count()

        )    # ---------------------------------------------------------
    # Notifications
    # ---------------------------------------------------------

    def create_notification(self, user_id, event_data, fingerprint=None):
        """Create a notification for a security event."""
        return self.history_store.create_notification(user_id, event_data, fingerprint)

    def get_today_notifications(self, user_id):
        """Get today's notifications for a user."""
        return self.history_store.get_today_notifications(user_id)

    def get_unread_count(self, user_id):
        """Get the count of unread notifications for today."""
        return self.history_store.get_unread_count(user_id)

    def get_all_today_notifications(self):
        """Get all today's notifications (for legacy users without database ID)."""
        return self.history_store.get_all_today_notifications()

    def get_all_unread_count(self):
        """Get all unread notification count (for legacy users)."""
        return self.history_store.get_all_unread_count()

    def mark_notification_read(self, notification_id, user_id):
        """Mark a single notification as read."""
        result = self.history_store.mark_notification_read(notification_id, user_id)
        self.history_store.flush()
        return result

    def mark_all_notifications_read(self, user_id):
        """Mark all of a user's notifications as read."""
        result = self.history_store.mark_all_notifications_read(user_id)
        self.history_store.flush()
        return result

    # ---------------------------------------------------------
    # Derived Notifications (from events table)
    # ---------------------------------------------------------

    def get_derived_notifications(self, user_id, page=1, page_size=50,
                                  severity_filter=None):
        """Get today's notifications derived from the events table."""
        return self.history_store.get_derived_notifications(
            user_id, page=page, page_size=page_size,
            severity_filter=severity_filter
        )

    def get_derived_unread_count(self, user_id):
        """Get unread notification count derived from events."""
        return self.history_store.get_derived_unread_count(user_id)

    def mark_derived_read(self, user_id, alert_id):
        """Mark a single derived notification as read."""
        result = self.history_store.mark_derived_read(user_id, alert_id)
        self.history_store.flush(timeout=10.0)
        return result

    def mark_all_derived_read(self, user_id):
        """Mark all of a user's notifications as read."""
        result = self.history_store.mark_all_derived_read(user_id)
        self.history_store.flush(timeout=10.0)
        return result

    # ---------------------------------------------------------
    # Security Attention Memory — Lifecycle
    # ---------------------------------------------------------

    def get_notification_summary(self, user_id):
        """Get severity counts for active notifications."""
        return self.history_store.get_notification_summary(user_id)

    def acknowledge_notification(self, user_id, notification_id):
        """Acknowledge a single notification."""
        result = self.history_store.acknowledge_notification(user_id, notification_id)
        self.history_store.flush(timeout=10.0)
        return result

    def resolve_notification(self, user_id, notification_id):
        """Resolve a single notification."""
        result = self.history_store.resolve_notification(user_id, notification_id)
        self.history_store.flush(timeout=10.0)
        return result

    # ---------------------------------------------------------
    # User Management
    # ---------------------------------------------------------

    def get_all_users(self):
        """Get all active users."""
        return self.history_store.get_all_users()

    # ---------------------------------------------------------
    # Clear Storage
    # ---------------------------------------------------------

    def clear(self):

        try:
            self.live_store.clear()

        except Exception:

            pass

        try:
            self.history_store.clear()

        except Exception:

            pass


storage_manager = StorageManager()