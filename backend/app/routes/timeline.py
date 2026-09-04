import hashlib
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.auth.dependencies import get_current_user
from app.registry.windows_event_registry import (
    enrich_log_payload,
    resolve_event_lookup_id,
    sanitize_process_name,
)
from app.routes.logs import _normalize_stored_severity
from app.services.filter_cache_service import filter_cache

router = APIRouter(
    prefix="/timeline",
    tags=["Timeline"],
    dependencies=[Depends(get_current_user)]
)


# ==========================================================================
# SERVER-SIDE TIME RANGES
# ==========================================================================
TIME_RANGE_DELTAS = {
    "last_24h": timedelta(hours=24),
    "last_7d": timedelta(days=7),
    "last_30d": timedelta(days=30),
}


def _parse_iso_naive(value):
    """Parse an ISO timestamp into a naive (UTC) ISO string for SQL comparison.

    Stored event_time values are naive UTC ISO strings, so timezone-aware
    inputs (including 'Z') are normalized to naive UTC before comparison.
    """
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.isoformat(timespec="seconds")
    except Exception:
        return None


def _timeline_time_window(time_range, from_time, to_time):
    """Resolve a time range selector into (time_from, time_to) ISO strings."""
    if time_range == "today":
        start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        return start.isoformat(timespec="seconds"), None
    if time_range in TIME_RANGE_DELTAS:
        cutoff = datetime.utcnow() - TIME_RANGE_DELTAS[time_range]
        return cutoff.isoformat(timespec="seconds"), None
    # "all" or explicit custom from/to
    return _parse_iso_naive(from_time), _parse_iso_naive(to_time)


# ==========================================================================
# TIMELINE ENTRY BUILDER (real event details)
# ==========================================================================
NO_MATCH_DESCRIPTIONS = {
    "no detection rule matched.",
    "no enterprise detection rule matched this windows event.",
    "no detection rules matched.",
    "unknown windows event",
}


def _timeline_fingerprint(event):
    """Fingerprint identical to EventProcessor.generate_fingerprint so live
    WebSocket events and persisted SQLite rows dedupe against each other."""
    value = (
        f"{event.get('host', '')}"
        f"{event.get('event_id', '')}"
        f"{event.get('time', '')}"
        f"{event.get('process_name', '')}"
    )
    return hashlib.sha256(value.encode()).hexdigest()


def _build_timeline_entry(item):
    """Project one stored {event, detection} row into the timeline card shape.

    Severity and MITRE come from the persisted (real) values so what the user
    filters on is exactly what they see; the action label is enriched from the
    Windows event registry for a readable name.
    """
    ev = item.get("event", {}) or {}
    det = item.get("detection", {}) or {}

    raw_id = str(ev.get("event_id", "") or "")
    # Task 19: shared Sysmon classification (registry helper) — identical to
    # the Alerts path, so the same event never resolves differently between
    # Alerts and Timeline.
    lookup_id = resolve_event_lookup_id(ev)
    enriched = enrich_log_payload(
        lookup_id, det.get("severity", ""), ev.get("command_line", "")
    )

    mitre_raw = det.get("mitre")
    if isinstance(mitre_raw, list):
        first = mitre_raw[0] if mitre_raw else {}
        mitre_id = str(first.get("id", "") or "") if isinstance(first, dict) else str(first or "")
    elif isinstance(mitre_raw, dict):
        mitre_id = str(mitre_raw.get("id", "") or "")
    else:
        mitre_id = str(mitre_raw or "")
    if not mitre_id or mitre_id in ("None", "null", "Unknown", "N/A"):
        mitre_id = "Unmapped"

    # Task 27: the stored process field may carry enterprise metadata suffixes
    # ('app.exe, version: ...') — always serve the clean actual process name.
    # Events with no process information resolve to the explicit sentinel
    # ('Not available in event'), never a fabricated placeholder.
    process = sanitize_process_name("", ev.get("process_name"))
    if process in ("-", "None", "null", "[System Process]"):
        process = "Not available in event"

    description = det.get("description") or ""
    if description.strip().lower() in NO_MATCH_DESCRIPTIONS:
        description = ""

    return {
        "timestamp": ev.get("time"),
        "event_id": raw_id,
        "user": ev.get("user") or "SYSTEM",
        "process": process,
        "host": ev.get("host") or ev.get("computer") or "Unknown",
        "action": enriched["detection"],
        "severity": _normalize_stored_severity(det.get("severity")),
        "mitre_id": mitre_id,
        "process_id": ev.get("process_id"),
        "parent_process_id": ev.get("parent_process_id"),
        "details": {
            "command_line": ev.get("command_line") or "",
            "parent_process": ev.get("parent_process") or ev.get("parent_image") or "N/A",
            "description": description,
        },
        "fingerprint": _timeline_fingerprint(ev),
    }


@router.get("/events")
def get_timeline_events(
    range: str = "all",
    from_time: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = Query(None),
    host: Optional[str] = None,
    user: Optional[str] = None,
    process: Optional[str] = None,
    event_id: Optional[str] = None,
    severity: Optional[str] = None,
    mitre: Optional[str] = None,
    page: int = 1,
    limit: int = 100,
):
    """Server-side timeline over real historical SQLite telemetry.

    Time window, filtering (host / user / process / event id / severity /
    MITRE) and pagination are pushed down into SQLite — the browser only ever
    receives the requested page, never the full dataset.
    """
    page = max(page, 1)
    limit = max(min(limit, 500), 1)

    time_from, time_to = _timeline_time_window(range, from_time, to)

    from app.storage.sqlite_storage import sqlite_storage

    filters = {
        "time_from": time_from,
        "time_to": time_to,
        "host": host if host and host != "All" else None,
        "user": user if user and user != "All" else None,
        "process_name": process if process and process != "All" else None,
        "event_id": event_id if event_id and event_id != "All" else None,
        "severity": severity if severity and severity != "All" else None,
        "mitre": mitre if mitre and mitre != "All" else None,
        "limit": limit,
        "offset": (page - 1) * limit,
    }
    qresult = sqlite_storage.query_events(filters)

    total = qresult.get("total", 0)
    results = [_build_timeline_entry(item) for item in qresult.get("results", [])]

    return {
        "range": range,
        "page": page,
        "limit": limit,
        "count": total,
        "total": total,
        "pages": ceil(total / limit) if total else 1,
        "results": results,
    }


@router.get("/filters")
def get_timeline_filter_options():
    """Real filter option values (hosts, users, processes, event IDs, MITRE,
    severities) served from the incrementally-maintained filter cache so the
    dropdowns never depend on whatever page happens to be loaded."""
    filter_cache.ensure_bootstrapped()
    data = filter_cache.get_all()

    def options(entries):
        return ["All"] + [str(e["value"]) for e in entries]

    return {
        "hosts": options(data.get("hosts", [])),
        "users": options(data.get("users", [])),
        "processes": options(data.get("processes", [])),
        "event_ids": options(data.get("event_ids", [])),
        "mitres": options(data.get("mitre_ids", [])),
        "severities": ["All", "Critical", "High", "Medium", "Low", "Informational"],
    }


@router.get("/windows")
def get_windows_timeline():
    """Legacy Splunk-only timeline path (Task 26).

    The local Windows telemetry system runs entirely on SQLite — see
    GET /timeline/events. This endpoint existed for the old Splunk-backed
    pipeline and is kept as an explicit feature flag: it never attempts a
    Splunk connection and never returns raw exceptions.
    """
    return {
        "available": False,
        "detail": "Splunk integration required.",
        "message": (
            "This endpoint served the legacy Splunk-backed timeline. "
            "Local telemetry is available via GET /timeline/events."
        ),
    }
