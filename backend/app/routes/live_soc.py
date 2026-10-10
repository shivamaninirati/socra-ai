from datetime import datetime
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect

from app.auth.dependencies import get_current_user
from app.auth.ws_ticket_service import extract_ticket, ws_ticket_service
from app.collector.event_store import event_store
from app.core.config import settings
from app.core.logger import get_module_logger
from app.services.collector_status_service import get_collector_runtime_status
from app.services.live_soc_service import live_soc
from app.storage.storage_manager import storage_manager

logger = get_module_logger("routes.live_soc")

router = APIRouter(
    prefix="/live",
    tags=["Live SOC"]
)


@router.get("/status", dependencies=[Depends(get_current_user)])
def live_status():

    stats = live_soc.stats()
    stats["current_seq"] = event_store.current_seq()

    # Real collector runtime status (standalone status file or the in-process
    # collector) - single source of truth, never a hardcoded "Running".
    stats["collector"] = get_collector_runtime_status()

    return stats


@router.get("/telemetry", dependencies=[Depends(get_current_user)])
def get_canonical_telemetry():
    """Canonical source of truth for all telemetry statistics.
    
    This endpoint provides the single authoritative source for all event counts
    and metrics, eliminating the possibility of mismatched counters between
    backend collector and frontend dashboard.
    """
    from app.analytics.analytics_engine import analytics_engine
    dashboard_data = analytics_engine.dashboard()
    summary = dashboard_data.get("summary", {})
    
    return {
        "total_events": summary.get("total_events", 0),
        "events_today": summary.get("total_events", 0),
        "events_last_second": summary.get("eps", 0),
        "events_last_minute": round(summary.get("eps", 0) * 60, 2),
        "events_ingested": storage_manager.history_count(),
        "last_event_timestamp": dashboard_data.get("cache_timestamp"),
        "collector_status": dashboard_data.get("collector_status", {}),
        "severity_counts": {
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "informational": summary.get("informational", 0)
        },
        "hosts_count": summary.get("hosts", 0),
        "current_seq": event_store.current_seq(),
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/events", dependencies=[Depends(get_current_user)])
def get_live_events_after(
    after_seq: int = Query(0, ge=0, description="Apply events with _seq > after_seq"),
    limit: int = Query(1000, ge=1, le=5000),
):
    """Catch-up endpoint: the missed events a client needs after a reconnect.

    Returns every live event with _seq strictly greater than `after_seq`
    (oldest first), plus the server's current sequence so the client can
    advance its last-processed watermark exactly once. Deterministic and
    idempotent — replaying the same events changes nothing.
    """
    events = event_store.get_events_after(after_seq, limit=limit)

    # Apply the same read-time enrichment the REST paths use (process-name
    # sanitization, severity normalization, enriched MITRE block) so live
    # catch-up events — including today's rows restored into the live store at
    # startup — render identically to history (Task: enrichment completeness).
    try:
        from app.routes.logs import _enrich_item
        for event in events:
            _enrich_item(event, keep_stored_severity=True)
    except Exception:
        pass

    return {
        "after_seq": after_seq,
        "current_seq": event_store.current_seq(),
        "count": len(events),
        "events": events,
    }


@router.post("/ws-ticket")
def issue_websocket_ticket(user: dict = Depends(get_current_user)):
    """Issue a short-lived, single-use WebSocket handshake ticket.

    The browser exchanges its JWT here — over authenticated HTTP — for a
    random ticket that is valid for the next WebSocket handshake only: a few
    seconds, exactly once, and bound to the verified user from the JWT. The
    JWT itself is never sent on the WebSocket connection (not in the URL,
    not in a header), and the ticket is never echoed back or logged.
    """
    ticket, expires_in = ws_ticket_service.issue(user)
    return {
        "ticket": ticket,
        "token_type": "websocket_ticket",
        "expires_in": expires_in,
    }


def _origin_allowed(websocket: WebSocket, origin: str) -> bool:
    """Cross-site WebSocket hijacking check for the handshake.

    Browsers always send an Origin header on a WebSocket upgrade, so a page
    hosted on an attacker-controlled origin fails this check and is rejected
    before authentication. Requests with no Origin header come from
    non-browser clients, which have no ambient credentials to abuse — they
    still need a valid single-use ticket to connect.
    """
    if not origin:
        return True

    allowed = {
        o.strip().rstrip("/")
        for o in settings.CORS_ORIGINS.split(",")
        if o.strip()
    }
    # Same-host origins: the frontend may be served by this API itself, in
    # which case the Origin matches the WebSocket endpoint's own host.
    netloc = websocket.url.netloc
    if netloc:
        allowed.add(f"http://{netloc}")
        allowed.add(f"https://{netloc}")

    return origin.rstrip("/") in allowed


@router.websocket("/live")
async def websocket_endpoint(websocket: WebSocket):

    # Origin first: handshakes from origins outside CORS_ORIGINS (e.g. a
    # cross-site page trying to hijack the live event stream) are rejected
    # before any authentication challenge or event data is exposed.
    origin = websocket.headers.get("origin", "")
    if not _origin_allowed(websocket, origin):
        logger.warning("[LiveSOC] WebSocket handshake rejected: origin not allowed")
        await websocket.close(code=4403, reason="Forbidden: Origin not allowed")
        return

    # Authentication: a short-lived, single-use ticket previously requested
    # from POST /live/ws-ticket (authenticated HTTP). The ticket rides in the
    # Sec-WebSocket-Protocol header — never in the URL — and is consumed
    # atomically below, so it cannot be replayed.
    subprotocol_header = websocket.headers.get("sec-websocket-protocol", "")
    from app.auth.ws_ticket_service import TICKET_SUBPROTOCOL_PREFIX
    
    # Extract the full subprotocol entry that contains our valid ticket
    valid_subprotocol = None
    if subprotocol_header:
        for entry in subprotocol_header.split(","):
            entry = entry.strip()
            if entry.startswith(TICKET_SUBPROTOCOL_PREFIX):
                valid_subprotocol = entry
                break
    
    ticket = extract_ticket(subprotocol_header)
    if not ticket:
        logger.warning("[LiveSOC] WebSocket handshake rejected: no ticket provided")
        await websocket.close(code=4401, reason="Unauthorized: No ticket provided")
        return

    identity = ws_ticket_service.consume(ticket)
    if identity is None:
        # Missing (already consumed), invalid, expired, or replayed ticket.
        logger.warning(
            "[LiveSOC] WebSocket handshake rejected: ticket invalid, expired, or already used"
        )
        await websocket.close(code=4401, reason="Unauthorized: Invalid ticket")
        return

    # Log only non-sensitive identity fields — never the ticket, the JWT,
    # or any other credential.
    logger.info(
        "[LiveSOC] WebSocket authenticated: user=%s role=%s",
        identity.get("sub"),
        identity.get("role"),
    )

    # Pass the valid subprotocol to live_soc_service which handles the single accept() call
    await live_soc.connect(websocket, valid_subprotocol=valid_subprotocol)

    try:

        await websocket.send_json({
            "type": "system",
            "message": "Connected to SOCRA AI Live SOC",
            "current_seq": event_store.current_seq(),
        })

        while True:
            # Maintain persistent connection with proper heartbeat handling
            try:
                data = await websocket.receive_text()
                # Accept both raw "heartbeat" and any JSON message containing heartbeat
                if data and (data == "heartbeat" or 'heartbeat' in data.lower()):
                    continue
                # If we get any other valid data, just continue listening
                continue
            except WebSocketDisconnect:
                live_soc.disconnect(websocket)
                break
            except Exception as e:
                logger.warning("[LiveSOC] WebSocket receive error: %s", e)
                live_soc.disconnect(websocket)
                break

    except WebSocketDisconnect:
        live_soc.disconnect(websocket)
    except Exception:
        live_soc.disconnect(websocket)