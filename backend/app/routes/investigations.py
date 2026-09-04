from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.services.investigation_service import (
    INVESTIGATION_STATUSES,
    investigation_service,
)

router = APIRouter(
    prefix="/investigations",
    tags=["Investigations"],
    dependencies=[Depends(get_current_user)],
)


class EventRequest(BaseModel):
    event: dict


class StatusRequest(BaseModel):
    status: str


class NoteRequest(BaseModel):
    note: str


@router.post("")
def create_investigation(request: EventRequest):
    """Create a persistent investigation for an alert, or reuse the existing
    record when this alert was already investigated."""
    investigation = investigation_service.create_or_get(request.event)
    return {"success": True, "investigation": investigation}


@router.get("")
def list_investigations():
    investigations = investigation_service.list()
    return {
        "success": True,
        "count": len(investigations),
        "investigations": investigations,
    }


@router.get("/{investigation_id}")
def get_investigation(investigation_id: str):
    investigation = investigation_service.get(investigation_id)
    if not investigation:
        return {"success": False, "error": "Investigation not found"}
    return {"success": True, "investigation": investigation}


@router.put("/{investigation_id}/status")
def update_status(investigation_id: str, request: StatusRequest):
    status = request.status
    if status not in INVESTIGATION_STATUSES:
        return {
            "success": False,
            "error": f"Invalid status. Must be one of: {', '.join(INVESTIGATION_STATUSES)}",
        }
    investigation = investigation_service.update_status(investigation_id, status)
    if not investigation:
        return {"success": False, "error": "Investigation not found"}
    return {"success": True, "investigation": investigation}


@router.put("/{investigation_id}/notes")
def add_note(investigation_id: str, request: NoteRequest):
    note = request.note.strip()
    if not note:
        return {"success": False, "error": "Note cannot be empty."}
    investigation = investigation_service.add_note(investigation_id, note)
    if not investigation:
        return {"success": False, "error": "Investigation not found"}
    return {"success": True, "investigation": investigation}


@router.get("/{investigation_id}/iocs")
def get_event_iocs(investigation_id: str):
    """Deep field-aware IOC extraction from the event's full envelope.
    Inspects structured fields, raw XML, EventData, and command lines."""
    from app.ioc.event_ioc_extractor import event_ioc_extractor
    investigation = investigation_service.get(investigation_id)
    if not investigation:
        return {"success": False, "error": "Investigation not found"}
    event = investigation.get("event") or {}
    iocs = event_ioc_extractor.extract_from_event(event)
    return {"success": True, "iocs": iocs}


@router.get("/{investigation_id}/related-events")
def related_events(investigation_id: str, window: int = 60):
    """Related events for the investigation from real historical telemetry,
    within a configurable time window (minutes) around the alert timestamp."""
    if window < 1:
        window = 60
    investigation = investigation_service.refresh_related(investigation_id, window)
    if not investigation:
        return {"success": False, "error": "Investigation not found"}
    return {
        "success": True,
        "window_minutes": window,
        "related_events": investigation.get("related_events", []),
        "process_tree": investigation.get("process_tree", []),
    }
