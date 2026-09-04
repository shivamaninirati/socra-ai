"""
SOCRA AI — Settings Routes

Provides a single aggregate status endpoint for the Settings page. Every value
is REAL backend state gathered from the live services:

- API: this endpoint responding
- Collector: the standalone collector's runtime status file (never hardcoded)
- WebSocket: live SOC connection registry
- AI/Ollama: the existing AI health probe (service reachable + model installed)
- Database: a real SQLite query + file size

Nothing here is fabricated; when a service is unavailable the payload says so.
"""

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app.ai.ai_engine import AIEngine
from app.auth.dependencies import get_current_user
from app.services.collector_status_service import get_collector_runtime_status
from app.services.live_soc_service import live_soc
from app.storage.sqlite_storage import sqlite_storage

router = APIRouter(
    prefix="/settings",
    tags=["Settings"],
    dependencies=[Depends(get_current_user)],
)

ai = AIEngine()


@router.get("/status")
def settings_status():
    """Real backend state for the Settings page (API, collector, WS, AI, DB)."""

    # --- Collector: real runtime status (single source of truth) ---
    collector_status = get_collector_runtime_status()

    # --- WebSocket: live connection registry ---
    ws_stats = live_soc.stats()

    # --- AI/Ollama: reuse the existing AI health probe ---
    ai_health = ai.health()

    # --- Database: real query + file size ---
    db_status = {"status": "ok"}
    try:
        db_status["events"] = sqlite_storage.count()
        db_path = sqlite_storage.db_path
        if db_path and os.path.exists(db_path):
            db_status["size_bytes"] = os.path.getsize(db_path)
    except Exception as exc:  # pragma: no cover - DB failure edge case
        db_status = {
            "status": "error",
            "error": str(exc),
            "detail": "The SQLite database could not be queried.",
        }

    return {
        "api": {"status": "ok", "detail": "API is reachable."},
        "collector": collector_status,
        "websocket": {
            "status": ws_stats.get("status", "Standby"),
            "connected_clients": ws_stats.get("connected_clients", 0),
            "detail": (
                f"{ws_stats.get('connected_clients', 0)} live client(s) connected."
                if ws_stats.get("connected_clients")
                else "No live clients currently connected."
            ),
        },
        "ai": ai_health,
        "database": db_status,
        "version": "0.1.0",
    }