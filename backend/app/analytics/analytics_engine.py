from datetime import datetime
import threading
import logging
from typing import Dict, Any

from app.collector.event_store import event_store
from app.services.collector_status_service import get_collector_runtime_status
from app.storage.sqlite_storage import sqlite_storage
from app.storage.storage_manager import storage_manager

logger = logging.getLogger(__name__)

# Fixed severity color mapping (NEVER CHANGE - enterprise donut chart depends on order)
SEVERITY_NAMES = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#22c55e",
    "Informational": "#3b82f6",
}

# Safe cache lifetime: the WebSocket dashboard_stats broadcast (every 2s while
# clients are connected) keeps the frontend numbers live, and storage-manager
# cache invalidation on every ingested event still refreshes promptly on the
# next read. The REST snapshot is only fetched once per page mount.
CACHE_TTL_SECONDS = 15.0


class AnalyticsEngine:

    def __init__(self):
        self.cache: Dict[str, Any] = {}
        self.cache_ttl = CACHE_TTL_SECONDS
        self.cache_timestamps: Dict[str, float] = {}
        self.cache_lock = threading.Lock()
        # No background cache warmer. Aggregation is on-demand only: the
        # Dashboard REST fetch on mount and the live metrics broadcast, which
        # runs only while WebSocket clients are connected. Nothing computes
        # continuously when there are no clients.

    # --------------------------------------------------
    # Single-pass dashboard assembly from SQL aggregates
    # --------------------------------------------------
    def _assemble_dashboard(self, agg: Dict[str, Any]) -> Dict[str, Any]:
        """Assemble the Dashboard response from server-side SQL aggregates.

        All counting/grouping already happened in SQLite; this only shapes the
        response (severity zero-fill, hourly bucket labels, EPS formula) - no
        event envelopes are iterated here.
        """
        now = datetime.now()
        current_hour = now.hour
        total = agg["total"]

        severity_counts = {s: 0 for s in SEVERITY_NAMES}
        severity_counts.update(agg["severity_counts"])

        # Hourly buckets 00:00..current local hour (same cap as before).
        hourly_data = [
            {"hour": f"{h:02d}:00", "series": {s: 0 for s in SEVERITY_NAMES}, "total": 0}
            for h in range(current_hour + 1)
        ]
        for sev, hour_int, count in agg["hourly"]:
            entry = hourly_data[hour_int]
            entry["series"][sev] += count
            entry["total"] += count

        # EPS identical to the previous formula (local-midnight seconds).
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_elapsed = (now - today_start).total_seconds()
        eps = round(total / seconds_elapsed, 2) if seconds_elapsed > 0 and total >= 2 else 0

        total_high = severity_counts["High"] + severity_counts["Critical"]

        return {
            "summary": {
                "total_events": total,
                "high": total_high,
                "high_severity": total_high,
                "critical": severity_counts["Critical"],
                "hosts": agg["hosts_distinct"],
                "windows_hosts": agg["hosts_distinct"],
                "eps": eps,
                "events_per_sec": eps,
                "medium": severity_counts["Medium"],
                "low": severity_counts["Low"],
                "informational": severity_counts["Informational"],
            },
            # Real collector runtime status (standalone status file or the
            # in-process collector) - never a hardcoded "Running". The
            # frontend dashboard derives its Collector Status card from this.
            "collector_status": get_collector_runtime_status(),
            "severity_distribution": [
                {"name": s, "value": severity_counts[s], "color": SEVERITY_COLORS[s]}
                for s in SEVERITY_NAMES
            ],
            "cyber_threat_horizon": {
                "data": hourly_data,
                "colors": {**SEVERITY_COLORS},
                "last_updated": now.isoformat(),
            },
            "top_hosts": agg["top_hosts"],
            "recent_critical_alerts": agg["critical_alerts"],
            "top_processes": agg["top_processes"],
            "top_event_ids": agg["top_event_ids"],
            "mitre": agg["mitre"],
            "cache_timestamp": now.isoformat(),
        }

    # --------------------------------------------------
    # Complete Dashboard
    # --------------------------------------------------
    def dashboard(self):
        """Complete dashboard - every metric computed by SQL aggregation.

        Returns the cached snapshot within the TTL; otherwise recomputes via
        SQLite (COUNT / GROUP BY, no full-dataset Python load).
        """
        current_time = datetime.now().timestamp()

        with self.cache_lock:
            if "dashboard" in self.cache and "dashboard" in self.cache_timestamps:
                cache_age = current_time - self.cache_timestamps["dashboard"]
                if cache_age < self.cache_ttl:
                    return self.cache["dashboard"]

        try:
            agg = sqlite_storage.get_todays_analytics()
            result = self._assemble_dashboard(agg)
            # REST/WS sync boundary: the live watermark extended by the events
            # persisted but not yet forwarded into the live store (standalone
            # collector path). The REST totals therefore cover exactly the
            # event set the client treats as "already counted" (everything
            # with _seq <= current_seq) - nothing is double-applied when those
            # rows later arrive over the WebSocket.
            pending = max(0, agg["total"] - event_store.count())
            result["current_seq"] = event_store.current_seq() + pending
            with self.cache_lock:
                self.cache["dashboard"] = result
                self.cache_timestamps["dashboard"] = current_time
            return result
        except Exception as e:
            logger.error("[Analytics] Dashboard error: %s", e, exc_info=True)
            return {
                "summary": {
                    "total_events": 0, "critical": 0, "high": 0,
                    "medium": 0, "low": 0, "informational": 0,
                    "hosts": 0, "eps": 0,
                },
                "error": "Dashboard data is temporarily unavailable.",
            }

    # --------------------------------------------------
    # Public API methods (SQL-driven, same signatures)
    # --------------------------------------------------

    def total_events(self):
        return sqlite_storage.count_todays_events()

    def distinct_hosts(self):
        return sqlite_storage.get_todays_analytics()["hosts_distinct"]

    def severity_distribution(self):
        agg = sqlite_storage.get_todays_analytics()
        severity_counts = {s: 0 for s in SEVERITY_NAMES}
        severity_counts.update(agg["severity_counts"])
        return [
            {"name": s, "value": severity_counts[s], "color": SEVERITY_COLORS[s]}
            for s in SEVERITY_NAMES
        ]

    def events_per_hour(self):
        agg = sqlite_storage.get_todays_analytics()
        now = datetime.now()
        hourly_data = [
            {"hour": f"{h:02d}:00", "series": {s: 0 for s in SEVERITY_NAMES}, "total": 0}
            for h in range(now.hour + 1)
        ]
        for sev, hour_int, count in agg["hourly"]:
            entry = hourly_data[hour_int]
            entry["series"][sev] += count
            entry["total"] += count
        return {
            "data": hourly_data,
            "colors": {**SEVERITY_COLORS},
            "last_updated": now.isoformat(),
        }

    def top_hosts(self, limit=10):
        return sqlite_storage.get_todays_analytics()["top_hosts"][:limit]

    def get_critical_events(self, limit=1000):
        return sqlite_storage.get_todays_analytics()["critical_alerts"][:limit]

    def top_processes(self, limit=10):
        return sqlite_storage.get_todays_analytics()["top_processes"][:limit]

    def top_event_ids(self, limit=10):
        return sqlite_storage.get_todays_analytics()["top_event_ids"][:limit]

    def mitre_distribution(self):
        agg = sqlite_storage.get_todays_analytics()
        # Matches the previous behaviour: events with a non-dict/missing MITRE
        # (no tactic) were reported under 'Unknown'.
        mitre = dict(agg["mitre"])
        mitre["Unknown"] = mitre.get("Unknown", 0) + agg["mitre_missing"]
        return mitre

    def events_per_second(self):
        total = self.total_events()
        if total < 2:
            return 0
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_today = (now - today_start).total_seconds()
        return round(total / seconds_today, 2) if seconds_today > 0 else 0


analytics_engine = AnalyticsEngine()
