from datetime import datetime
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect

from app.auth.auth_service import auth_service
from app.auth.dependencies import get_current_user
from app.collector.event_store import event_store
from app.services.collector_status_service import get_collector_runtime_status
from app.services.live_soc_service import live_soc
from app.storage.storage_manager import storage_manager

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


@router.websocket("/live")
async def websocket_endpoint(websocket: WebSocket):

    # Require a valid JWT on the WebSocket handshake. The frontend sends it as
    # a WebSocket subprotocol (Sec-WebSocket-Protocol header) so the token
    # never appears in the URL query string / access logs. The chosen
    # subprotocol is echoed back on accept to complete the negotiation.
    # Unauthenticated connections are rejected with a 4401 close.
    token = ""
    subprotocol_header = websocket.headers.get("sec-websocket-protocol", "")
    if subprotocol_header:
        # A client may offer several protocols; take the first offered token.
        token = subprotocol_header.split(",")[0].strip()

    print(f"[WEBSOCKET_HANDSHAKE] Received subprotocol header: {subprotocol_header}")
    print(f"[WEBSOCKET_HANDSHAKE] Extracted token: {token[:20]}... (truncated)")
    
    if not token:
        print("[WEBSOCKET_HANDSHAKE] No token provided, closing with 4401")
        await websocket.close(code=4401, reason="Unauthorized: No token provided")
        return
        
    token_valid = auth_service.verify_token(token)
    print(f"[WEBSOCKET_HANDSHAKE] Token verification result: {token_valid}")
    
    if not token_valid:
        await websocket.close(code=4401, reason="Unauthorized: Invalid token")
        return

    await live_soc.connect(websocket, subprotocol=token)

    try:

        await websocket.send_json({
            "type": "system",
            "message": "Connected to SOCRA AI Live SOC",
            "current_seq": event_store.current_seq(),
        })

        while True:

            # Wait for heartbeat from frontend - can be JSON or raw text
            try:
                data = await websocket.receive_text()
                # Accept both raw "heartbeat" and JSON formatted heartbeats
                if data and (data == "heartbeat" or 'heartbeat' in data.lower()):
                    continue
            except WebSocketDisconnect:
                live_soc.disconnect(websocket)
                break
            except Exception:
                live_soc.disconnect(websocket)
                break

    except WebSocketDisconnect:
        live_soc.disconnect(websocket)
    except Exception:
        live_soc.disconnect(websocket)