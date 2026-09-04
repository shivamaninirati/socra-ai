"""
SOCRA AI — API-side live event forwarder.

When the standalone Windows collector runs in its own process, it cannot
broadcast events over the FastAPI process's WebSocket connections. Instead it
persists every event to SQLite (unchanged) and this module polls the events
table for new rows and replays them through the EXISTING live pipeline:

    event_store.add_event(...)      -> live in-memory store (dashboard, /logs live)
    filter_cache.ingest_event(...)  -> dropdown vocabulary stays fresh
    live_soc.broadcast(...)         -> WebSocket {type: "alert", ...} frames

This preserves the exact real-time behavior the frontend had when the
collector ran inside the API process, while the actual collection now runs
independently of the API.

Only one of {in-process collector, live forwarder} is active at a time —
main.py starts the forwarder only when a standalone collector is detected.
"""

import asyncio
import logging

from app.collector.event_store import event_store
from app.services.filter_cache_service import filter_cache
from app.services.live_soc_service import live_soc
from app.storage.sqlite_storage import sqlite_storage

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 1.0
BATCH_LIMIT = 500


async def live_forwarder_loop():
    """Forward newly persisted events to the live pipeline until cancelled.

    Resumes from the highest event id already present at startup, so historical
    rows are never re-broadcast and the frontend's initial REST snapshot
    remains the authoritative baseline (the same contract as the in-process
    collector).
    """
    last_id = sqlite_storage.max_event_id()
    logger.info(
        "[LiveForwarder] Started — resuming from event id %s", last_id
    )
    while True:
        try:
            rows = sqlite_storage.get_events_after_id(last_id, limit=BATCH_LIMIT)
            for row_id, event in rows:
                event_store.add_event(event)
                try:
                    filter_cache.ingest_event(event)
                except Exception:
                    pass
                await live_soc.broadcast({"type": "alert", **event})
                last_id = row_id
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logger.info("[LiveForwarder] Stopped at event id %s", last_id)
            raise
        except Exception as exc:
            logger.error("[LiveForwarder] Error: %s", exc)
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
