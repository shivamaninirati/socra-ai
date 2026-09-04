"""
Enterprise Filter Cache Service

Maintains in-memory counters for all SIEM filter categories:
- Processes (process_name)
- Event IDs (event_id)  
- Hosts
- Users
- MITRE Techniques (detection.mitre.id)
- Severities

The cache updates INCREMENTALLY from incoming events rather than rescanning
the full dataset, providing O(1) lookup for filter values with counts.

Usage:
    from app.services.filter_cache_service import filter_cache
    
    # On new event arrival:
    filter_cache.ingest_event(processed_event)
    
    # Get all filter values with counts:
    filters = filter_cache.get_all()
"""

import logging
from collections import Counter
from threading import Lock

logger = logging.getLogger(__name__)


class FilterCacheService:
    """In-memory incremental filter cache for enterprise SIEM dropdowns."""
    
    def __init__(self):
        self._lock = Lock()
        self._bootstrapped = False
        self._bootstrap_lock = Lock()
        
        # Counters for each filter category - uses Counter for O(1) increment
        self._processes = Counter()      # process_name -> count
        self._event_ids = Counter()      # event_id -> count
        self._hosts = Counter()          # host -> count
        self._users = Counter()          # user -> count
        self._mitre_ids = Counter()      # mitre.id -> count
        self._severities = Counter()     # severity -> count
        self._statuses = Counter()       # status -> count
        self._ips = Counter()            # ip address -> count
        self._pids = Counter()           # process_id -> count
        
        # Track seen event identity keys so we don't double-count on live
        # ingest. Uses the same record identity as the SQLite unique index
        # (channel, computer, record_number, time_created) — NOT the coarse
        # metadata fingerprint, which collapses distinct events that share a
        # timestamp (e.g. a burst of identical events in one second).
        # Insertion-ordered dict enables FIFO eviction of the oldest entry.
        self._seen_keys = {}
        self._max_seen_keys = 100000
        
        logger.info("[FilterCache] Initialized enterprise filter cache")
    
    # Maximum length for a suggestion value
    _MAX_SUGGESTION_LEN = 150

    @classmethod
    def _is_valid_suggestion(cls, value: str) -> bool:
        """Return True if a value is suitable for autocomplete suggestions.

        Rejects raw XML payloads, overly long strings, and content that
        looks like raw telemetry rather than clean structured metadata.
        """
        if not value or not isinstance(value, str):
            return False
        if len(value) > cls._MAX_SUGGESTION_LEN:
            return False
        # Reject strings containing XML tags or angle brackets
        if '<' in value or '>' in value:
            return False
        # Reject strings with newlines (multi-line payloads)
        if '\n' in value or '\r' in value:
            return False
        # Reject Base64-like strings (very long, all alphanumeric + /+=)
        if len(value) > 60 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in value):
            return False
        return True

    def ingest_event(self, event: dict) -> None:
        """Ingest a single processed event into the filter cache.
        
        Deduplicates on the DB record identity (channel, computer, record
        number, time) so the same record is never double-counted across live +
        history or WebSocket repeats, while distinct events with identical
        timestamps are each counted exactly once.
        
        Args:
            event: Processed event dict with 'event' and 'detection' keys
        """
        if not event or not isinstance(event, dict):
            return

        # Deduplicate on the DB record identity (same key as the SQLite unique
        # index), falling back to the metadata fingerprint for events that
        # carry no record number. Distinct events are never collapsed.
        seen_key = self._record_key(event)
        if seen_key:
            with self._lock:
                if seen_key in self._seen_keys:
                    return
                # Evict the oldest key when at capacity (FIFO)
                if len(self._seen_keys) >= self._max_seen_keys:
                    oldest = next(iter(self._seen_keys))
                    del self._seen_keys[oldest]
                self._seen_keys[seen_key] = None
        
        ev = event.get("event", {}) or {}
        det = event.get("detection", {}) or {}
        
        # --- Process Name ---
        # The 'Not available in event' sentinel is the normalized value for
        # events with no process info — it must not appear as a filter option.
        proc = ev.get("process_name", "")
        if proc and proc not in ("-", "None", "", "Not available in event"):
            proc_clean = proc.split("\\")[-1]  # Extract basename from full path
            if self._is_valid_suggestion(proc_clean):
                with self._lock:
                    self._processes[proc_clean] += 1

        # --- Process ID / PID (real Windows PID, separate from process name) ---
        pid = str(ev.get("process_id", "") or "").strip()
        if pid and pid not in ("-", "None", "0", "Not available") and self._is_valid_suggestion(pid):
            with self._lock:
                self._pids[pid] += 1
        
        # --- Event ID ---
        eid = str(ev.get("event_id", ""))
        if eid and eid not in ("None", "") and self._is_valid_suggestion(eid):
            with self._lock:
                self._event_ids[eid] += 1
        
        # --- Host ---
        host = ev.get("host") or ev.get("computer", "")
        if host and host not in ("-", "None", "") and self._is_valid_suggestion(host):
            with self._lock:
                self._hosts[host] += 1
        
        # --- User ---
        user = ev.get("user", "")
        if user and user not in ("-", "None", "SYSTEM", "") and self._is_valid_suggestion(user):
            with self._lock:
                self._users[user] += 1
        
        # --- MITRE Technique ID ---
        # Canonical detection.mitre is a list of blocks; tolerate a single
        # dict (legacy rows) and a plain string as well.
        mitre = det.get("mitre", {})
        mid = ""
        if isinstance(mitre, list):
            first = mitre[0] if mitre else {}
            mid = first.get("id", "") if isinstance(first, dict) else str(first or "")
        elif isinstance(mitre, dict):
            mid = mitre.get("id", "")
        elif mitre is not None:
            mid = str(mitre)
        if mid and mid not in ("N/A", "Unknown", "Unmapped", "") and self._is_valid_suggestion(mid):
            with self._lock:
                self._mitre_ids[mid] += 1
        
        # --- Severity ---
        sev = det.get("severity", "")
        if sev and sev not in ("", "None"):
            with self._lock:
                self._severities[sev] += 1
        
        # --- IP Addresses (common network fields) ---
        for ip_field in ("ip_address", "source_ip", "destination_ip", "ip", "src_ip", "dst_ip"):
            ip = ev.get(ip_field, "")
            if ip and ip not in ("-", "None", "") and self._is_valid_suggestion(str(ip)):
                with self._lock:
                    self._ips[str(ip)] += 1
        
        # --- Status ---
        status_val = ev.get("status") or det.get("status") or "New"
        if status_val:
            with self._lock:
                self._statuses[str(status_val)] += 1
    
    @staticmethod
    def _record_key(event: dict):
        """Stable identity for an event, mirroring the SQLite unique index.

        Returns (channel, computer, record_number, time) when a record number
        is present — the same identity the database uses to reject duplicates.
        Falls back to the metadata fingerprint for records without one.
        """
        ev = event.get("event", {}) or {}
        record = ev.get("record_number")
        if record not in (None, ""):
            return (
                str(ev.get("channel", "")),
                str(ev.get("host", "") or ev.get("computer", "")),
                str(record),
                str(ev.get("time", "")),
            )
        fp = (event.get("metadata", {}) or {}).get("fingerprint")
        if fp:
            return ("fp", fp)
        return None

    def ingest_batch(self, events: list) -> None:
        """Ingest a batch of events (e.g., on initial load from storage).
        
        Does NOT use dedup during batch load since we want to 
        bootstrap from stored data accurately.
        
        Args:
            events: List of processed event dicts
        """
        for event in events:
            self.ingest_event(event)
        with self._lock:
            logger.info(
                f"[FilterCache] Batch ingested {len(events)} events. "
                f"Hosts={len(self._hosts)}, Processes={len(self._processes)}, "
                f"EventIDs={len(self._event_ids)}, MITRE={len(self._mitre_ids)}, "
                f"Users={len(self._users)}, Severities={len(self._severities)}"
            )
    
    def get_all(self) -> dict:
        """Get all filter values with their counts.
        
        Returns:
            dict with keys: processes, event_ids, hosts, users, mitre_ids, severities
            Each value is a list of {"value": str, "count": int} sorted by count desc
        """
        with self._lock:
            def to_sorted_list(counter):
                return [
                    {"value": k, "count": v}
                    for k, v in counter.most_common()
                ]
            
            return {
                "processes": to_sorted_list(self._processes),
                "event_ids": to_sorted_list(self._event_ids),
                "hosts": to_sorted_list(self._hosts),
                "users": to_sorted_list(self._users),
                "mitre_ids": to_sorted_list(self._mitre_ids),
                "severities": to_sorted_list(self._severities),
                "statuses": to_sorted_list(self._statuses),
                "ips": to_sorted_list(self._ips),
                "pids": to_sorted_list(self._pids),
                "total_tracked": len(self._seen_keys),
            }
    
    def get_filter_options(self) -> dict:
        """Get filter values formatted for SIEM dropdowns.
        
        Returns flat lists sorted alphabetically (for dropdown display).
        Each entry includes both value and count for display like 'powershell.exe (98)'.
        """
        data = self.get_all()
        return data
    
    def ensure_bootstrapped(self) -> None:
        """One-time bootstrap of the cache from persisted telemetry.

        The cache is kept fresh incrementally by the collector afterwards, so
        this only runs once per process (guarded). Loading up to 100k events
        once at first use is far cheaper than rescanning the database on every
        suggestion keystroke.
        """
        if self._bootstrapped:
            return
        with self._bootstrap_lock:
            if self._bootstrapped:
                return
            try:
                from app.storage.sqlite_storage import sqlite_storage
                aggregates = sqlite_storage.get_filter_aggregates()
                self.bootstrap_from_aggregates(aggregates)
                logger.info(
                    "[FilterCache] Bootstrapped cache from server-side aggregates "
                    f"(events={sum(e['count'] for e in aggregates.get('event_ids', []))}, "
                    f"event_ids={len(aggregates.get('event_ids', []))}, "
                    f"processes={len(aggregates.get('processes', []))}, "
                    f"pids={len(aggregates.get('pids', []))}, "
                    f"hosts={len(aggregates.get('hosts', []))}, "
                    f"users={len(aggregates.get('users', []))}, "
                    f"mitre={len(aggregates.get('mitre_ids', []))})"
                )
            except Exception as e:
                logger.error(f"[FilterCache] Bootstrap failed: {e}")
            finally:
                self._bootstrapped = True

    def bootstrap_from_aggregates(self, aggregates: dict) -> None:
        """Seed the cache from server-side GROUP BY counts (complete dataset).

        Called once per process from persisted telemetry so every distinct
        value present in the database is available to the dropdowns — no
        arbitrary 100k-event cap. Incremental ingest keeps it fresh afterwards.
        """
        if not aggregates:
            return
        with self._lock:
            def _seed(counter, entries):
                counter.clear()
                for entry in entries or []:
                    value = entry.get("value")
                    count = entry.get("count", 0)
                    if value is not None and value != "":
                        val_str = str(value)
                        if self._is_valid_suggestion(val_str):
                            counter[val_str] += int(count)

            _seed(self._processes, aggregates.get("processes", []))
            _seed(self._event_ids, aggregates.get("event_ids", []))
            _seed(self._hosts, aggregates.get("hosts", []))
            _seed(self._users, aggregates.get("users", []))
            _seed(self._mitre_ids, aggregates.get("mitre_ids", []))
            _seed(self._severities, aggregates.get("severities", []))
            _seed(self._pids, aggregates.get("pids", []))

    def clear(self) -> None:
        """Reset all counters (for testing or full resync)."""
        with self._lock:
            self._processes.clear()
            self._event_ids.clear()
            self._hosts.clear()
            self._users.clear()
            self._mitre_ids.clear()
            self._severities.clear()
            self._statuses.clear()
            self._ips.clear()
            self._pids.clear()
            self._seen_keys.clear()
            self._bootstrapped = False
            logger.info("[FilterCache] Cache cleared")


# Singleton instance
filter_cache = FilterCacheService()
