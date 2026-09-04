import hashlib
import json
import os
import threading
import time
from math import ceil
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query

from app.auth.dependencies import get_current_user
from app.core.logger import get_module_logger
from app.search.search_engine import search_engine

logger = get_module_logger("routes.logs")

# ==========================================================================
# ENRICHED BASE DATASET CACHE
# --------------------------------------------------------------------------
# The expensive part of /logs/windows is loading (live + history) and
# enriching every event. Enrichment only depends on the raw event content,
# never on the request filters, so we can build the enriched base once and
# reuse it for every filter/pagination request within a short TTL. New live
# events are still delivered instantly over the WebSocket stream, so a few
# seconds of staleness here is safe.
# ==========================================================================
LOGS_BASE_CACHE_TTL = 4.0
_logs_base_lock = threading.Lock()
_logs_base_cache = {}
_logs_base_cache_ts = {}

SEVERITY_COUNT_KEYS = ["Critical", "High", "Medium", "Low", "Informational"]


def _event_dedup_key(event: dict):
    """Stable deduplication key for an event.

    Prefers the metadata fingerprint when present, then falls back to the
    Windows record identity (host + channel + record number + time) and finally
    to a content hash. SQLite-stored events only carry {event, detection}, so
    a fingerprint-only dedup would silently collapse every persisted event into
    one — the root cause of "missing" alerts.
    """
    fp = event.get("metadata", {}).get("fingerprint")
    if fp:
        return ("fp", fp)
    ev = event.get("event", {}) or {}
    record = ev.get("record_number")
    if record not in (None, ""):
        return ("rec", str(ev.get("host", "")), str(ev.get("channel", "")), str(record), str(ev.get("time", "")))
    try:
        payload = json.dumps(ev, default=str, sort_keys=True)
        return ("hash", hashlib.sha256(payload.encode()).hexdigest())
    except Exception:
        return ("idx", id(event))


def _load_raw_results(query: str, source: str):
    """Load live/history events and deduplicate with the robust key."""
    if source == "live":
        return search_engine.search(query=query, source="live", limit=100000)
    if source == "history":
        return search_engine.search(query=query, source="history", limit=100000)

    live = search_engine.search(query=query, source="live", limit=100000)
    history = search_engine.search(query=query, source="history", limit=100000)

    seen = set()
    raw_results = []
    for event in live + history:
        key = _event_dedup_key(event)
        if key in seen:
            continue
        seen.add(key)
        raw_results.append(event)
    return raw_results


def _normalize_stored_severity(raw):
    """Map the stored severity engine value to a canonical display level.

    Delegates to the unified registry's normalizer (same canonical taxonomy,
    same Unknown/empty handling) so display stays consistent with SQL-side
    counting and the dashboard analytics.
    """
    return _normalize_severity_value(raw)


def _enrich_item(item: dict, keep_stored_severity: bool = False) -> dict:
    """Apply process-name sanitization + event registry enrichment in place.

    keep_stored_severity=True (SQL/live paths): display the severity engine's
    stored value so the table stays consistent with SQL counts and the
    dashboard analytics. False (keyword search path): legacy registry override.
    """
    event_block = item.get("event", {})
    detection_block = item.get("detection", {})

    event_block["process_name"] = sanitize_process_name(
        event_block.get("image", ""),
        event_block.get("process_name", "")
    )

    # Same normalized PID sentinel the pipeline stores ('Not available' when
    # the event carries no PID) — idempotent, so live and historical rows
    # render identically.
    event_block["process_id"] = normalize_process_id(
        event_block.get("process_id", "")
    )

    # Task 19: shared Sysmon classification — determined ONLY from the actual
    # channel/source/provider, never inferred from the numeric Event ID.
    # Alerts and Timeline use the same helper (registry.resolve_event_lookup_id)
    # so the same event always classifies identically.
    lookup_id = resolve_event_lookup_id(event_block)

    enriched = enrich_log_payload(
        lookup_id,
        detection_block.get("severity", ""),
        event_block.get("command_line", "")
    )

    detection_block["detection"] = enriched["detection"]

    if keep_stored_severity:
        detection_block["severity"] = _normalize_stored_severity(detection_block.get("severity"))
    else:
        incoming_sev = str(detection_block.get("severity", "")).strip().lower()
        if incoming_sev in ["info", "informational", "", "none"] or enriched["severity"] in ["Medium", "High", "Critical"]:
            detection_block["severity"] = enriched["severity"]
        else:
            detection_block["severity"] = detection_block.get("severity", enriched["severity"])

    detection_block["mitre"] = enriched["mitre"]

    # Canonical description: unmapped events display the explicit
    # 'Unknown Windows Event' label (never a legacy default string).
    detection_block["description"] = normalize_event_description(
        detection_block.get("description", "")
    )
    return item


def _build_enriched_base(source: str, keep_stored_severity: bool = False):
    raw_results = _load_raw_results("", source)
    for item in raw_results:
        _enrich_item(item, keep_stored_severity=keep_stored_severity)
    return raw_results


def _get_enriched_base(source: str, keep_stored_severity: bool = False):
    """Return the enriched base dataset, cached for a few seconds."""
    cache_key = (source, keep_stored_severity)
    now = time.time()
    with _logs_base_lock:
        cached = _logs_base_cache.get(cache_key)
        cached_ts = _logs_base_cache_ts.get(cache_key, 0.0)
        if cached is not None and (now - cached_ts) < LOGS_BASE_CACHE_TTL:
            return cached
    data = _build_enriched_base(source, keep_stored_severity=keep_stored_severity)
    with _logs_base_lock:
        _logs_base_cache[cache_key] = data
        _logs_base_cache_ts[cache_key] = time.time()
    return data


# ==========================================================================
# ENRICHED SEARCH RESULT CACHE
# --------------------------------------------------------------------------
# Keyword search enriches every match before filtering, and a single query can
# match thousands of events. Enrichment only depends on the raw event content
# and the query, never on the request filters, so the enriched match set is
# cached briefly per (query, source). The true match total (SQL COUNT) is
# cached alongside it. New live events are still delivered over the WebSocket.
# ==========================================================================
SEARCH_CACHE_TTL = 4.0
_search_cache_lock = threading.Lock()
_search_cache = {}
_search_cache_ts = {}


def _get_enriched_search(query: str, source: str, limit: int):
    """Enriched keyword-search match set, cached for a few seconds."""
    cache_key = (query, source)
    now = time.time()
    with _search_cache_lock:
        cached = _search_cache.get(cache_key)
        cached_ts = _search_cache_ts.get(cache_key, 0.0)
        if cached is not None and (now - cached_ts) < SEARCH_CACHE_TTL:
            return cached
    raw_results, search_total = search_engine.search_with_count(
        query, source, limit=limit
    )
    for item in raw_results:
        _enrich_item(item, keep_stored_severity=False)
    cached = (raw_results, search_total)
    with _search_cache_lock:
        _search_cache[cache_key] = cached
        _search_cache_ts[cache_key] = time.time()
    return cached


def _time_range_cutoff(time_range: Optional[str]):
    """ISO cutoff for SQL-side time-window filtering, or None for all time."""
    if not time_range or time_range == "all":
        return None
    now = datetime.utcnow()
    if time_range == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    mapping = {
        "last_15m": timedelta(minutes=15),
        "last_3h": timedelta(hours=3),
        "last_6h": timedelta(hours=6),
        "last_12h": timedelta(hours=12),
        "last_24h": timedelta(hours=24),
        "last_7d": timedelta(days=7),
        "last_30d": timedelta(days=30),
    }
    delta = mapping.get(time_range)
    if not delta:
        return None
    return (now - delta).isoformat()


def _matches_request_filters(item, severity, host, mitre, event_id, process, process_id, user, status):
    """True when the enriched event passes the request field filters.

    Mirrors _apply_filters_in_memory (minus severity counts and the time
    range, which the SQL page already applies) for the fast newest-first
    live merge on page 1.
    """
    event_block = item.get("event", {})
    detection_block = item.get("detection", {})

    if severity and severity != "All" and detection_block.get("severity") != severity:
        return False
    if host and host != "All" and event_block.get("host") != host:
        return False
    if mitre and mitre != "All" and detection_block.get("mitre", {}).get("id") != mitre:
        return False
    if event_id and event_id != "All" and str(event_block.get("event_id", "")) != event_id:
        return False
    if process and process != "All" and event_block.get("process_name") != process:
        return False
    if process_id and process_id != "All" and str(event_block.get("process_id", "")) != process_id:
        return False
    if user and user != "All" and event_block.get("user") != user:
        return False
    if status and status != "All":
        actual_status = event_block.get("status") or detection_block.get("status") or "New"
        if actual_status != status:
            return False
    return True


def _filter_live_newest(items, limit, severity=None, host=None, mitre=None, event_id=None, process=None, process_id=None, user=None, status=None):
    """Newest-first bounded live filter.

    The live store is already ordered newest-first, so the first `limit`
    matching events are the newest matches — stop there instead of scanning
    the entire live store (up to 50k events) on every page-1 request.
    """
    filtered = []
    for item in items:
        if _matches_request_filters(item, severity, host, mitre, event_id, process, process_id, user, status):
            filtered.append(item)
            if len(filtered) >= limit:
                break
    return filtered


def _apply_filters_in_memory(raw_results, severity, host, mitre, event_id, process, process_id, user, status, time_range):
    """In-memory filter pass (used for the live store and keyword searches)."""
    filtered_results = []
    severity_counts = {key: 0 for key in SEVERITY_COUNT_KEYS}
    current_utc_now = datetime.utcnow()

    for item in raw_results:
        event_block = item.get("event", {})
        detection_block = item.get("detection", {})
        raw_id = str(event_block.get("event_id", ""))

        if severity and severity != "All" and detection_block.get("severity") != severity:
            continue
        if host and host != "All" and event_block.get("host") != host:
            continue
        if mitre and mitre != "All" and detection_block.get("mitre", {}).get("id") != mitre:
            continue
        if event_id and event_id != "All" and raw_id != event_id:
            continue
        if process and process != "All" and event_block.get("process_name") != process:
            continue
        if process_id and process_id != "All" and str(event_block.get("process_id", "")) != process_id:
            continue
        if user and user != "All" and event_block.get("user") != user:
            continue
        if status and status != "All":
            actual_status = event_block.get("status") or detection_block.get("status") or "New"
            if actual_status != status:
                continue
        if time_range and time_range != "all" and not _within_time_range(
            event_block.get("time"), time_range, current_utc_now
        ):
            continue

        sev_name = detection_block.get("severity", "Informational")
        if sev_name in severity_counts:
            severity_counts[sev_name] += 1
        else:
            severity_counts["Informational"] += 1
        filtered_results.append(item)

    return filtered_results, severity_counts


def _slice_response(filtered_results, severity_counts, page, limit, query, source, known_total=None):
    """Sort newest-first and slice the page (response contract preserved).

    known_total: when the search pipeline already computed the true match
    count (SQL COUNT), use it instead of the bounded fetched result length.
    """
    filtered_results.sort(
        key=lambda x: x.get("event", {}).get("time", ""),
        reverse=True
    )
    total_matches = known_total if known_total is not None else len(filtered_results)
    start_index = (page - 1) * limit
    end_index = start_index + limit
    return {
        "page": page,
        "limit": limit,
        "count": total_matches,
        "total": total_matches,
        "pages": ceil(total_matches / limit) if total_matches else 1,
        "query": query if query else "",
        "source": source,
        "severity_counts": severity_counts,
        "results": filtered_results[start_index:end_index],
    }


def _within_time_range(event_time_str, time_range, current_utc_now):
    """Return True when the event falls inside the requested window."""
    if not event_time_str:
        return True
    try:
        clean_time_str = event_time_str.split(".")[0].replace("Z", "")
        event_dt = datetime.fromisoformat(clean_time_str)
    except Exception:
        return True

    time_delta = current_utc_now - event_dt

    if time_range == "today":
        today_start = current_utc_now.replace(hour=0, minute=0, second=0, microsecond=0)
        return event_dt >= today_start
    if time_range == "last_15m":
        return time_delta <= timedelta(minutes=15)
    if time_range == "last_3h":
        return time_delta <= timedelta(hours=3)
    if time_range == "last_6h":
        return time_delta <= timedelta(hours=6)
    if time_range == "last_12h":
        return time_delta <= timedelta(hours=12)
    if time_range == "last_24h":
        return time_delta <= timedelta(hours=24)
    if time_range == "last_7d":
        return time_delta <= timedelta(days=7)
    if time_range == "last_30d":
        return time_delta <= timedelta(days=30)
    return True

router = APIRouter(
    prefix="/logs",
    tags=["Logs"],
    dependencies=[Depends(get_current_user)]
)

# ==========================================================================
# ==========================================================================
# UNIFIED WINDOWS EVENT REGISTRY (single source of truth)
# --------------------------------------------------------------------------
# Event ID name/severity/MITRE/detection now lives in
# app/registry/windows_event_registry.py — all read paths consume that one
# registry so the same event always receives the same severity. These names
# are re-exported for backward compatibility with existing importers.
# ==========================================================================
from app.registry.windows_event_registry import (
    WINDOWS_EVENT_RULES as WINDOWS_EVENT_REGISTRY,
    _normalize_severity_value,
    MITRE_MATRIX_GLOSSARY,
    enrich_log_payload,
    resolve_event_lookup_id,
    sanitize_process_name,
    normalize_process_id,
    normalize_event_description,
    get_event_rule,
    get_process_rule,
    supported_event_ids,
    supported_processes,
)

@router.get("/windows")
def get_windows_logs(
    page: int = 1,
    limit: int = 100,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    host: Optional[str] = None,
    mitre: Optional[str] = None,
    event_id: Optional[str] = None,
    process: Optional[str] = None,
    process_id: Optional[str] = None,
    user: Optional[str] = None,
    status: Optional[str] = None,
    time_range: Optional[str] = None,
    source: str = "all",
):
    page = max(page, 1)
    limit = max(min(limit, 100000), 1)
    engine_query = search if search else ""

    # ------------------------------------------------------------------
    # PATH 1 — Keyword search (enterprise global-search integration)
    # Filters raw events before enrichment, so it keeps the existing
    # in-memory pipeline untouched.
    # ------------------------------------------------------------------
    if engine_query:
        # Bounded fetch for the page (the true match total comes from SQL COUNT,
        # so we never materialize the entire match set just to show page 1).
        # The enriched match set is cached briefly so repeated or paginated
        # searches don't re-enrich thousands of events on every request.
        search_limit = min(max(limit, 50), 5000)
        raw_results, search_total = _get_enriched_search(
            engine_query, source, search_limit
        )
        filtered_results, severity_counts = _apply_filters_in_memory(
            raw_results, severity, host, mitre, event_id, process, process_id, user, status, time_range
        )
        # The SQL keyword COUNT alone ignores the field filters applied in
        # memory above, which would overstate the total on combined searches.
        # When any field filter is active, recompute the total as a single SQL
        # COUNT over keyword + field filters (exact semantics, indexed).
        if any(v for v in [severity, host, mitre, event_id, process, process_id, user, status, time_range] if v and v != "All"):
            try:
                search_total = search_engine.count_with_filters(engine_query, {
                    "severity": severity, "host": host, "mitre": mitre,
                    "event_id": event_id, "process": process,
                    "process_id": process_id, "user": user, "status": status,
                    "time_from": _time_range_cutoff(time_range),
                })
            except Exception:
                # Fall back to the keyword-only total; results remain correct.
                pass
        return _slice_response(
            filtered_results, severity_counts, page, limit, engine_query, source,
            known_total=search_total
        )

    # ------------------------------------------------------------------
    # PATH 2 — Live in-memory store (small, freshest events)
    # ------------------------------------------------------------------
    if source == "live":
        raw_results = _get_enriched_base("live", keep_stored_severity=True)
        filtered_results, severity_counts = _apply_filters_in_memory(
            raw_results, severity, host, mitre, event_id, process, process_id, user, status, time_range
        )
        return _slice_response(filtered_results, severity_counts, page, limit, engine_query, source)

    # ------------------------------------------------------------------
    # PATH 3 — SQL-pushdown over the complete history dataset
    # Filtering, counting and pagination run inside SQLite (indexed columns)
    # so the full matching dataset stays reachable without loading it into
    # memory. The freshest live events are merged onto page 1.
    # ------------------------------------------------------------------
    from app.storage.sqlite_storage import sqlite_storage
    from app.collector.event_store import event_store

    filters = {
        "time_from": _time_range_cutoff(time_range),
        "host": host,
        "event_id": event_id,
        "process_name": process,
        "process_id": process_id,
        "mitre": mitre,
        "severity": severity,
        "user": user,
        "status": status,
        "limit": limit,
        "offset": (page - 1) * limit,
    }
    qresult = sqlite_storage.query_events(filters)

    results = []
    for item in qresult.get("results", []):
        _enrich_item(item, keep_stored_severity=True)
        results.append(item)

    severity_counts = {key: 0 for key in SEVERITY_COUNT_KEYS}
    for sev_key, count in (qresult.get("severity_counts") or {}).items():
        severity_counts[sev_key] = count

    total = qresult.get("total", 0)

    if source == "all":
        # Reuse the cached enriched live base (4s TTL) instead of enriching the
        # entire live store (up to 50k events) on every page-1 request, and
        # keep only the newest `limit` matches (the live store is newest-first)
        # — the freshest events still arrive instantly over the WebSocket.
        live_items = _get_enriched_base("live", keep_stored_severity=True)
        live_filtered = _filter_live_newest(
            live_items, limit, severity, host, mitre, event_id, process, process_id, user, status
        )
        live_filtered.sort(key=lambda x: x.get("event", {}).get("time", ""), reverse=True)

        if page == 1 and live_filtered:
            seen = {_event_dedup_key(r) for r in results}
            for item in live_filtered:
                key = _event_dedup_key(item)
                if key in seen:
                    continue
                seen.add(key)
                results.append(item)
            results.sort(key=lambda x: x.get("event", {}).get("time", ""), reverse=True)
            results = results[:limit]

    return {
        "page": page,
        "limit": limit,
        "count": total,
        "total": total,
        "pages": ceil(total / limit) if total else 1,
        "query": "",
        "source": source,
        "severity_counts": severity_counts,
        "results": results,
    }


# ==========================================================================
# 🎯 ENTERPRISE AGGREGATE ANALYTICS ENGINE (TODAY WINDOW BOUNDARY)
# ==========================================================================
@router.get("/analytics/dashboard")
def get_dashboard_today_analytics(
    search: Optional[str] = None,
    host: Optional[str] = None,
    severity: Optional[str] = None,
    mitre: Optional[str] = None,
):
    """
    Centralized Aggregation Pipeline: Slices and extracts aggregate trends from midnight today 
    across full data pools, mirroring enterprise Splunk structures natively.
    """
    # Use enterprise single source of truth: storage_manager.get_todays_events()
    # Returns ALL 11,452+ today's events (deduplicated, filtered to today only)
    from app.storage.storage_manager import storage_manager
    today_logs = storage_manager.get_todays_events()
    
    # Initialize time variables for trend chart calculations
    current_utc_now = datetime.utcnow()
    today_start_utc = current_utc_now.replace(hour=0, minute=0, second=0, microsecond=0)
    logger.debug("Dashboard using FULL today's dataset: %s events", len(today_logs))
    severity_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    top_host_map = {}
    unique_hosts = set()
    events_per_hour = {}

    current_hour = current_utc_now.hour
    for h in range(current_hour + 1):
        label = f"{str(h).zfill(2)}:00"
        events_per_hour[label] = {"time": label, "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

    for item in today_logs:
        ev = item.get("event", {})
        det = item.get("detection", {})

        # Task 19: shared Sysmon classification (registry helper) — the same
        # classifier the Alerts table uses, so dashboard and alerts agree.
        lookup_id = resolve_event_lookup_id(ev)
        
        enriched = enrich_log_payload(lookup_id, det.get("severity", ""), ev.get("command_line", ""))
        sev_name = enriched["severity"].capitalize()
        if sev_name not in severity_distribution:
            sev_name = "Informational"

        if host and host != "All" and ev.get("host") != host: continue
        if severity and severity != "All" and sev_name != severity: continue
        if mitre and mitre != "All" and enriched["mitre_id"] != mitre: continue
        if search:
            m_query = search.lower()
            text_match = (
                m_query in raw_id or
                m_query in ev.get("host", "").lower() or
                m_query in ev.get("user", "").lower() or
                m_query in sev_name.lower() or
                m_query in enriched["mitre_id"].lower()
            )
            if not text_match: continue

        severity_distribution[sev_name] += 1
        log_host = ev.get("host") or ev.get("computer")
        if log_host:
            unique_hosts.add(log_host)
            top_host_map[log_host] = top_host_map.get(log_host, 0) + 1

        try:
            clean_time = ev.get("time", "").split(".")[0].replace("Z", "")
            dt = datetime.fromisoformat(clean_time)
            if dt.hour <= current_hour:
                h_label = f"{str(dt.hour).zfill(2)}:00"
                if h_label in events_per_hour:
                    events_per_hour[h_label][sev_name] += 1
        except Exception:
            pass

    seconds_elapsed = (current_utc_now - today_start_utc).total_seconds()
    eps_rate = round(len(today_logs) / (seconds_elapsed if seconds_elapsed > 0 else 1), 2)

    return {
        "summary": {
            "total_events": len(today_logs),
            "high": severity_distribution["High"] + severity_distribution["Critical"],
            "hosts": len(unique_hosts),
            "eps": eps_rate,
            "critical": severity_distribution["Critical"]
        },
        "severity": severity_distribution,
        "events_per_hour": events_per_hour,
        "top_hosts": sorted(top_host_map.items(), key=lambda x: x[1], reverse=True)[:8],
        "collector": {
            "live_events": len(today_logs),
            "history_events": len(today_logs)
        }
    }