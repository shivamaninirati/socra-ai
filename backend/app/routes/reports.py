from datetime import datetime, timedelta
import threading
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.auth.dependencies import get_current_user
from app.reports.report_generator import ReportGenerator
from app.storage.sqlite_storage import sqlite_storage
from app.ai.ai_engine import AIEngine

# AI analysis is best-effort: if Ollama is slow or down, the report must
# still return instantly. Anything beyond this budget is treated as
# "AI findings unavailable" rather than making the report hang.
AI_TIMEOUT_SECONDS = 10

router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
    dependencies=[Depends(get_current_user)]
)

report = ReportGenerator()
ai = AIEngine()


def _default_time_from():
    """Default report window: the last 24 hours of persisted telemetry."""
    return (datetime.utcnow() - timedelta(hours=24)).isoformat()


@router.get("/windows")
def get_windows_report(
    limit: int = Query(500, ge=1, le=100000),
    host: Optional[str] = Query(None, description="Restrict report to a host"),
    user: Optional[str] = Query(None, description="Restrict report to a user"),
    event_id: Optional[str] = Query(None, description="Restrict report to an event id"),
    severity: Optional[str] = Query(None, description="Restrict report to a severity"),
    process_name: Optional[str] = Query(None, description="Restrict report to a process"),
    mitre: Optional[str] = Query(None, description="Restrict report to a MITRE technique id"),
    time_from: Optional[str] = Query(None, description="ISO start of the report window"),
    time_to: Optional[str] = Query(None, description="ISO end of the report window"),
    investigation_id: Optional[str] = Query(None, description="Attach real investigation findings"),
    include_ai: bool = Query(False, description="Attempt AI analysis when Ollama is available"),
):
    """Generate a SOC report from REAL persisted SQLite telemetry.

    No Splunk dependency: the report is compiled from the same persistent
    event envelopes the Alerts / Timeline / Investigation modules read.
    """
    filters = {
        "time_from": time_from or _default_time_from(),
        "time_to": time_to,
        "host": host,
        "user": user,
        "event_id": event_id,
        "severity": severity,
        "process_name": process_name,
        "mitre": mitre,
        "limit": limit,
        "offset": 0,
    }
    # Drop empty filters so query_events ignores them.
    filters = {k: v for k, v in filters.items() if v not in (None, "")}

    data = sqlite_storage.query_events(filters)
    events = data.get("results", [])

    investigation = None
    if investigation_id:
        investigation = sqlite_storage.get_investigation(investigation_id)

    ai_findings = None
    if include_ai and events:
        # Run the Ollama call on a daemon thread with a hard budget so a slow
        # or unreachable Ollama can never stall report generation.
        result_box = {}

        def _run_ai():
            try:
                result_box["result"] = ai.investigate(events[0])
            except Exception:
                result_box["result"] = None

        thread = threading.Thread(target=_run_ai, daemon=True)
        thread.start()
        thread.join(timeout=AI_TIMEOUT_SECONDS)
        result = result_box.get("result")
        if result:
            analysis = (result or {}).get("analysis") or {}
            text = analysis.get("analysis") if isinstance(analysis, dict) else None
            # Ollama returns an error banner (not an exception) when it is
            # unavailable — treat that as "no AI findings", never as data.
            if text and "Unable to contact Ollama" not in text and "# SOCRA AI Error" not in text:
                ai_findings = {
                    "provider": analysis.get("provider") or "Ollama",
                    "model": analysis.get("model") or "llama3",
                    "analysis": text,
                }

    return report.generate(
        events,
        investigation=investigation,
        ai_findings=ai_findings,
        options={
            "scope": (
                f"persisted telemetry | {len(events)} events"
                f"{' | investigation ' + investigation_id if investigation_id else ''}"
            )
        },
    )
