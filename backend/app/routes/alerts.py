"""
Alerts Module — Enterprise Filter Metadata + Real Alert Status

GET /alerts/filters
-------------------
Returns the complete, dynamically generated filter vocabulary for the Alerts
table, derived from ACTUAL collected telemetry (never hardcoded):

    * hosts       — every host seen in telemetry (with counts)
    * users       — every user account seen
    * processes   — every process basename observed
    * pids        — every real Windows Process ID observed (separate from
                    process name)
    * event_ids   — every Event ID present, labeled with its registry
                    description when known (e.g. "4688 — New Process Created")
    * mitre_ids   — every MITRE ATT&CK technique id present, labeled with
                    its technique name from the ATT&CK glossary
    * severities  — severities produced by the severity engine (with counts)
    * statuses    — the real triage lifecycle (New / Investigating /
                    Contained / Resolved / Closed) with counts from the
                    persisted alert rows (Task 17)

Values are served from an incrementally maintained in-memory cache
(filter_cache_service) that is updated per-event as new telemetry arrives,
so dropdowns never trigger a full dataset rescan.

POST /alerts/status
-------------------
Persists an authenticated analyst's alert triage status change to SQLite and
broadcasts it to every connected live client. The analyst is recorded on the
row (changed_by / changed_at) for auditability.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.registry.windows_event_registry import WINDOWS_EVENT_RULES as WINDOWS_EVENT_REGISTRY, MITRE_MATRIX_GLOSSARY
from app.services.filter_cache_service import filter_cache

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
    dependencies=[Depends(get_current_user)],
)

# Severity ordering follows the enterprise analytics taxonomy (never change).
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

# The real alert triage lifecycle (Task 17). These are the ONLY valid alert
# statuses — distinct from investigation status (app/services/
# investigation_service.py), which is a separate workspace concept.
ALERT_STATUSES = ["New", "Investigating", "Contained", "Resolved", "Closed"]


class AlertStatusRequest(BaseModel):
    """Body of POST /alerts/status.

    alert_id is the persisted events.id; fingerprint is the metadata
    fingerprint fallback for live envelopes that have not been assigned an id
    yet. At least one must be present.
    """
    alert_id: Optional[int] = None
    fingerprint: Optional[str] = None
    status: str


def _bootstrap_filter_cache():
    """One-time lazy bootstrap of the filter cache from persisted telemetry."""
    filter_cache.ensure_bootstrapped()


def _event_id_label(eid: str) -> str:
    """Resolve '4688' -> '4688 — New Process Created', else the bare numeric id."""
    info = WINDOWS_EVENT_REGISTRY.get(eid)
    if not info:
        info = WINDOWS_EVENT_REGISTRY.get(f"sysmon_{eid}")
    if info:
        return f"{eid} — {info['name']}"
    return eid


def _mitre_label(mid: str) -> str:
    glossary = MITRE_MATRIX_GLOSSARY.get(mid)
    if glossary and glossary.get("technique"):
        return f"{mid} — {glossary['technique']}"
    return mid


@router.get("/filters")
def get_alert_filters():
    """Dynamically generated filter options with counts for the Alerts table."""
    _bootstrap_filter_cache()
    data = filter_cache.get_all()

    event_ids = [
        {"value": item["value"], "count": item["count"], "label": _event_id_label(item["value"])}
        for item in data.get("event_ids", [])
    ]
    mitre_ids = [
        {"value": item["value"], "count": item["count"], "label": _mitre_label(item["value"])}
        for item in data.get("mitre_ids", [])
    ]

    sev_index = {name: i for i, name in enumerate(SEVERITY_ORDER)}
    severities = sorted(
        data.get("severities", []),
        key=lambda item: sev_index.get(str(item["value"]).capitalize(), len(SEVERITY_ORDER)),
    )
    for item in severities:
        item["value"] = str(item["value"]).capitalize()

    # Task 17: the status dropdown is the real triage lifecycle, with counts
    # from the persisted alert rows (NULL rows are the "New" default). The
    # telemetry-derived cache only ever saw "New", so it cannot drive this.
    from app.storage.sqlite_storage import sqlite_storage
    status_counts = sqlite_storage.get_alert_status_counts()
    statuses = [
        {"value": name, "count": status_counts.get(name, 0)}
        for name in ALERT_STATUSES
    ]

    return {
        "hosts": data.get("hosts", []),
        "users": data.get("users", []),
        "processes": data.get("processes", []),
        "event_ids": event_ids,
        "mitre_ids": mitre_ids,
        "pids": data.get("pids", []),
        "severities": severities,
        "statuses": statuses,
        "total_tracked": data.get("total_tracked", 0),
        "updated_at": datetime.utcnow().isoformat(),
    }


@router.post("/status")
async def update_alert_status(request: AlertStatusRequest, user: dict = Depends(get_current_user)):
    """Change the triage status of a real alert (persisted, analyst-audited).

    The authenticated analyst is recorded on the row (changed_by) and the
    update is broadcast to every connected live client so open Alerts pages
    reflect the new status immediately.
    """
    status = (request.status or "").strip()
    if not status or status not in ALERT_STATUSES:
        return {
            "success": False,
            "error": f"Invalid status. Must be one of: {', '.join(ALERT_STATUSES)}",
        }

    if request.alert_id is None and not request.fingerprint:
        return {
            "success": False,
            "error": "Either alert_id or fingerprint is required.",
        }

    from app.storage.sqlite_storage import sqlite_storage

    alert_id = request.alert_id
    if alert_id is None:
        alert_id = sqlite_storage.find_alert_id_by_fingerprint(request.fingerprint)
        if alert_id is None:
            return {
                "success": False,
                "error": "Alert not found for the given fingerprint.",
            }

    analyst = user.get("sub") or user.get("username") or "unknown"
    record = sqlite_storage.update_alert_status(alert_id, status, analyst)
    if record is None:
        return {
            "success": False,
            "error": "Alert not found.",
        }

    # Live clients (all connected Alerts pages) get the update immediately.
    try:
        from app.services.live_soc_service import live_soc
        await live_soc.broadcast({
            "type": "alert_status",
            "data": record,
        })
    except Exception as e:
        logger.warning("[Alerts] Could not broadcast alert status update: %s", e)

    return {"success": True, "alert": record}
