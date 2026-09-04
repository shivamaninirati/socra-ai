"""Threat Hunting — native SQLite-backed hunting path (Task 21).

The core SOCRA AI telemetry lives in SQLite, so hunts run as server-side
queries over that data — no Splunk required. Predefined hunts are expressed as
REAL field/keyword filters (never Splunk SPL), and analysts can run custom
hunts over Event ID / Process / PID / Host / User / IP / Hash / MITRE /
Severity / time range / keyword. Only matching rows are returned to the
browser (SQL pushdown) — the full dataset is never loaded client-side.
"""

from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.core.logger import get_module_logger

logger = get_module_logger("routes.threat_hunting")

router = APIRouter(
    prefix="/hunt",
    tags=["Threat Hunting"],
    dependencies=[Depends(get_current_user)],
)

# Time-range selectors -> SQL event_time cutoff (same taxonomy as /logs).
_TIME_RANGE_DELTAS = {
    "last_15m": timedelta(minutes=15),
    "last_3h": timedelta(hours=3),
    "last_6h": timedelta(hours=6),
    "last_12h": timedelta(hours=12),
    "last_24h": timedelta(hours=24),
    "last_7d": timedelta(days=7),
    "last_30d": timedelta(days=30),
}


def _time_from(time_range):
    if not time_range or time_range in ("all", "today"):
        return None
    if time_range == "today":
        return datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    delta = _TIME_RANGE_DELTAS.get(time_range)
    if delta:
        return (datetime.utcnow() - delta).isoformat()
    return None


# Predefined hunts. `filters` are REAL telemetry criteria (structured columns,
# JSON fields, keywords) executed server-side by _hunt_where — every result is
# a genuine stored event, never fabricated.
HUNTS = {
    "powershell": {
        "name": "PowerShell Abuse",
        "mitre": "T1059.001",
        "severity": "High",
        "description": "Process creation involving PowerShell",
        "filters": {"process": "powershell", "limit": 200},
    },
    "encoded": {
        "name": "Encoded PowerShell",
        "mitre": "T1059.001",
        "severity": "Critical",
        "description": "PowerShell with encoded / bypass arguments",
        "filters": {"process": "powershell", "keywords": ["-enc", "encodedcommand", "bypass"], "limit": 200},
    },
    "rdp": {
        "name": "Remote Desktop Logons",
        "mitre": "T1021.001",
        "severity": "Medium",
        "description": "Logon event 4624 with logon type 10 (RDP)",
        "filters": {"event_id": "4624", "json_fields": [{"field": "$.event.logon_type", "value": "10"}], "limit": 200},
    },
    "bruteforce": {
        "name": "Brute Force Login",
        "mitre": "T1110",
        "severity": "High",
        "description": "Failed logon events (4625)",
        "filters": {"event_id": "4625", "limit": 200},
    },
    "persistence": {
        "name": "Persistence Activity",
        "mitre": "T1547",
        "severity": "High",
        "description": "Scheduled tasks / Run keys / startup activity",
        "filters": {"keywords": ["schtasks", "RunOnce", "reg add", "autorun"], "limit": 200},
    },
}


def _escape_like(value: str) -> str:
    """Escape LIKE wildcards so hunt terms match literally (same as the search
    engine)."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def _hunt_where(filters: dict):
    """Build a SQLite WHERE clause + params from real hunt criteria.

    Structured fields use the indexed denormalized columns; keywords / IOC
    values (IP, hash, domain) match over the stored envelope via LIKE. JSON
    field equality (e.g. logon_type) uses json_extract.
    """
    where = []
    params = []

    col_map = {
        "host": "host",
        "event_id": "event_id",
        "pid": "process_id",
        "user": "user",
        "mitre": "mitre",
        "severity": "severity",
    }
    for key, col in col_map.items():
        value = filters.get(key)
        if value and value != "All":
            where.append(f"{col} = ?")
            params.append(value)

    process = filters.get("process")
    if process and process != "All":
        like = _escape_like(process)
        where.append("process_name LIKE '%' || ? || '%' ESCAPE '\\'")
        params.append(like)

    time_from = filters.get("time_from")
    if time_from:
        where.append("event_time >= ?")
        params.append(time_from)

    kw_terms = []
    if filters.get("keyword"):
        kw_terms.append(filters["keyword"])
    kw_terms += filters.get("keywords") or []
    if kw_terms:
        clauses = []
        for term in kw_terms:
            like = _escape_like(term)
            clauses.append("raw_json LIKE '%' || ? || '%' ESCAPE '\\'")
            params.append(like)
        where.append("(" + " OR ".join(clauses) + ")")

    for jf in filters.get("json_fields") or []:
        where.append("json_extract(raw_json, ?) = ?")
        params.extend([jf.get("field"), jf.get("value")])

    return (" AND ".join(where) if where else "1=1"), params


class HuntRequest(BaseModel):
    hunt: str


class HuntSearchRequest(BaseModel):
    """Custom hunt criteria — every field is optional; all are ANDed."""
    event_id: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    mitre: Optional[str] = None
    severity: Optional[str] = None
    time_range: Optional[str] = None
    keyword: Optional[str] = None
    limit: int = 200


def _sanitize_hunt_results(results):
    """Task 27: serve clean process names — strip enterprise metadata
    suffixes ('app.exe, version: ...') from hunt results."""
    from app.registry.windows_event_registry import sanitize_process_name

    for item in results:
        ev = item.get("event") or {}
        if ev.get("process_name"):
            ev["process_name"] = sanitize_process_name("", ev.get("process_name"))
    return results


def _execute_hunt(filters: dict):
    """Run a hunt server-side over SQLite and return matching events.

    Structured + keyword criteria are pushed into SQL; only the matching rows
    are loaded (bounded by `limit`).
    """
    from app.storage.sqlite_storage import sqlite_storage

    limit = max(1, min(int(filters.get("limit", 200)), 2000))
    where_sql, params = _hunt_where(filters)
    result = sqlite_storage.search_events(where_sql, params, limit=limit)
    results = _sanitize_hunt_results(result["results"])
    return {
        "total": result["total"],
        "results": results,
        "count": len(results),
    }


@router.get("/list")
def list_hunts():
    """Hunt metadata (names, MITRE, severity) — definitions live server-side."""
    return {
        "count": len(HUNTS),
        "hunts": {
            key: {
                "name": h["name"],
                "mitre": h.get("mitre"),
                "severity": h.get("severity"),
                "description": h.get("description", ""),
            }
            for key, h in HUNTS.items()
        },
    }


@router.post("/run")
def run_hunt(request: HuntRequest):
    """Run a predefined hunt against local SQLite telemetry (no Splunk)."""
    hunt = HUNTS.get(request.hunt)
    if not hunt:
        return {"success": False, "error": "Unknown hunt."}

    filters = dict(hunt.get("filters") or {})
    try:
        outcome = _execute_hunt(filters)
    except Exception as e:
        logger.error("Hunt execution failed: %s", e, exc_info=True)
        return {"success": False, "error": "Hunt failed. Please try again."}

    return {
        "success": True,
        "hunt": {
            "key": request.hunt,
            "name": hunt["name"],
            "mitre": hunt.get("mitre"),
            "severity": hunt.get("severity"),
        },
        "total": outcome["total"],
        "count": outcome["count"],
        "results": outcome["results"],
    }


@router.get("/filters")
def get_hunt_filters():
    """Dynamically generated filter options from the telemetry store.

    Returns distinct hosts, processes, event IDs, MITRE techniques, users,
    severities and PIDs with counts — the same pattern used by /alerts/filters
    but scoped to the hunt workspace.
    """
    from app.storage.sqlite_storage import sqlite_storage

    try:
        conn = sqlite_storage._get_conn()
        cursor = conn.cursor()

        def _distinct(column, table="events", limit=200):
            try:
                cursor.execute(
                    f"SELECT {column}, COUNT(*) as cnt FROM {table} "
                    f"WHERE {column} IS NOT NULL AND {column} != '' "
                    f"GROUP BY {column} ORDER BY cnt DESC LIMIT ?",
                    (limit,),
                )
                return [{"value": row[0], "count": row[1]} for row in cursor.fetchall()]
            except Exception:
                return []

        hosts = _distinct("host")
        users = _distinct("user")
        processes = _distinct("process_name")
        event_ids = _distinct("event_id")
        mitres = _distinct("mitre")
        severities = _distinct("severity")
        pids = _distinct("process_id")

        return {
            "hosts": hosts,
            "users": users,
            "processes": processes,
            "event_ids": event_ids,
            "mitres": mitres,
            "severities": severities if severities else [
                {"value": "Critical", "count": 0},
                {"value": "High", "count": 0},
                {"value": "Medium", "count": 0},
                {"value": "Low", "count": 0},
                {"value": "Informational", "count": 0},
            ],
            "pids": pids,
        }
    except Exception as e:
        logger.error("Failed to load hunt filters: %s", e, exc_info=True)
        return {
            "hosts": [], "users": [], "processes": [],
            "event_ids": [], "mitres": [],
            "severities": [
                {"value": "Critical", "count": 0},
                {"value": "High", "count": 0},
                {"value": "Medium", "count": 0},
                {"value": "Low", "count": 0},
                {"value": "Informational", "count": 0},
            ],
            "pids": [],
        }


@router.post("/search")
def custom_hunt(request: HuntSearchRequest):
    """Custom analyst hunt over the local telemetry store.

    Combines any of: event id, process, PID, host, user, IP/hash/keyword,
    MITRE, severity and time range — all pushed into SQLite server-side.
    """
    filters = {
        "event_id": request.event_id if request.event_id and request.event_id != "All" else None,
        "process": request.process if request.process and request.process != "All" else None,
        "pid": request.pid if request.pid and request.pid != "All" else None,
        "host": request.host if request.host and request.host != "All" else None,
        "user": request.user if request.user and request.user != "All" else None,
        "mitre": request.mitre if request.mitre and request.mitre != "All" else None,
        "severity": request.severity if request.severity and request.severity != "All" else None,
        "time_from": _time_from(request.time_range),
        "keyword": request.keyword,
        "limit": request.limit,
    }
    if not any(v for k, v in filters.items() if k not in ("limit", "time_from")):
        return {"success": False, "error": "Provide at least one hunt criterion."}

    try:
        outcome = _execute_hunt(filters)
    except Exception as e:
        logger.error("Custom hunt failed: %s", e, exc_info=True)
        return {"success": False, "error": "Hunt failed. Please try again."}

    return {
        "success": True,
        "hunt": {"key": "custom", "name": "Custom Hunt"},
        "total": outcome["total"],
        "count": outcome["count"],
        "results": outcome["results"],
    }
