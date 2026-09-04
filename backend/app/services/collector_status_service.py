"""Collector runtime status - single source of truth.

Every surface that reports collector health (/analytics/dashboard broadcast,
/live/status, /settings/status) must describe the SAME reality, so this module
owns that decision. Status is never hardcoded:

* A standalone collector process reports its real state through
  backend/data/collector_status.json (privilege errors, counters, running
  flag). A stale file whose PID is dead is reported as stopped.
* Otherwise the in-process development collector state (collector_service)
  is used when it is running.
* Otherwise the collector is simply reported as stopped.

Metric definitions (kept stable across all surfaces):

* ``running`` / ``status``  - whether any collector is actually running.
* ``mode``                  - "standalone" | "in-process" | "none".
* ``security_log_accessible`` / ``privilege_error`` - real Windows Security
  Event Log privilege state ("Administrator privileges required for Security
  Event Log collection.") - never hidden, never assumed.
* ``live_events``           - events in the live in-memory store (today's
  persisted events restored at startup plus events ingested this session),
  held for real-time delivery. This is a cache, not a total.
* ``history_events``        - total rows persisted in the SQLite events table
  (all time). This is the durable total.
* ``total_collected``       - events successfully collected and persisted
  since this collector process started (session counter).
* ``total_processed``       - same as total_collected (every collected event
  is processed); kept for backward compatibility.
* ``total_failed``          - events that failed validation/processing since
  start.
* ``last_error``            - the last collection error, if any (errors are
  visible, never silent).
"""

from app.collector.single_instance import (
    external_collector_running,
    read_collector_status,
)


def get_collector_runtime_status() -> dict:
    """Return the real, current collector runtime status for API consumers."""
    # Imported lazily to avoid import cycles (collector_service imports
    # live_soc_service which imports analytics_engine at module scope).
    from app.collector.collector_service import collector
    from app.storage.storage_manager import storage_manager

    status_file = read_collector_status()
    external_running = external_collector_running()
    in_process_running = bool(getattr(collector, "running", False))

    live_events = storage_manager.live_count()
    history_events = storage_manager.history_count()

    # ── 1. Standalone collector actively running (authoritative file). ──
    if external_running and status_file is not None:
        data = dict(status_file)
        privilege_error = data.get("privilege_error") or None
        message = data.get("message")
        if not message:
            message = (
                "Standalone collector is running and ingesting telemetry."
            )
        return {
            "running": True,
            "status": "Running",
            "mode": "standalone",
            "external_running": True,
            "in_process": False,
            "security_log_accessible": data.get("security_log_accessible"),
            "privilege_error": privilege_error,
            "message": message,
            "live_events": int(data.get("live_events", live_events) or live_events),
            "history_events": int(data.get("history_events", history_events) or history_events),
            "total_collected": int(data.get("total_collected") or 0),
            "total_processed": int(data.get("total_processed") or 0),
            "total_failed": int(data.get("total_failed") or 0),
            "started_at": data.get("started_at"),
            "last_collection_time": data.get("last_collection_time"),
            "last_error": data.get("last_error"),
            "channels": data.get("channels") or [],
        }

    # ── 2. In-process development collector running. ──
    if in_process_running:
        stats = collector.stats()
        privilege_error = getattr(collector, "privilege_error", None)
        if privilege_error:
            message = (
                "In-process collector is running but " + privilege_error +
                " System/Application channels are collected; Security channel "
                "events are skipped until the backend runs elevated."
            )
        else:
            message = (
                "In-process development collector is running. Install a "
                "standalone collector for production use."
            )
        return {
            "running": True,
            "status": "Running",
            "mode": "in-process",
            "external_running": external_running,
            "in_process": True,
            "security_log_accessible": getattr(collector, "security_log_accessible", None),
            "privilege_error": privilege_error,
            "message": message,
            "live_events": live_events,
            "history_events": history_events,
            "total_collected": stats.get("total_collected", 0),
            "total_processed": stats.get("total_processed", 0),
            "total_failed": stats.get("total_failed", 0),
            "started_at": getattr(collector, "started_at", None),
            "last_collection_time": getattr(collector, "last_collection_time", None),
            "last_error": getattr(collector, "last_error", None),
            "channels": stats.get("channels", []),
        }

    # ── 3. Standalone status file exists but the process is not alive. ──
    if status_file is not None:
        data = dict(status_file)
        return {
            "running": False,
            "status": "Stopped",
            "mode": "standalone" if external_running else "none",
            "external_running": external_running,
            "in_process": False,
            "security_log_accessible": data.get("security_log_accessible"),
            "privilege_error": data.get("privilege_error") or None,
            "message": data.get("message")
            or "Collector is not running. Events will not be collected.",
            "live_events": live_events,
            "history_events": history_events,
            "total_collected": int(data.get("total_collected") or 0),
            "total_processed": int(data.get("total_processed") or 0),
            "total_failed": int(data.get("total_failed") or 0),
            "started_at": data.get("started_at"),
            "last_collection_time": data.get("last_collection_time"),
            "last_error": data.get("last_error"),
            "channels": data.get("channels") or [],
        }

    # ── 4. Nothing running. ──
    return {
        "running": False,
        "status": "Stopped",
        "mode": "none",
        "external_running": external_running,
        "in_process": False,
        "security_log_accessible": None,
        "privilege_error": None,
        "message": "No collector is running. Events will not be collected.",
        "live_events": live_events,
        "history_events": history_events,
        "total_collected": 0,
        "total_processed": 0,
        "total_failed": 0,
        "started_at": None,
        "last_collection_time": None,
        "last_error": None,
        "channels": [],
    }
