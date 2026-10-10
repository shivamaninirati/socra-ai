"""
SOCRA AI — Phase 1: WebSocket authentication security fix — verification suite.

Run from the backend directory:

    ../venv/Scripts/python.exe test_websocket_auth.py

Covers (as required by the task):
1. POST /live/ws-ticket requires a valid, non-expired JWT and issues a
   short-lived single-use ticket bound to the verified user. The response
   never contains a JWT.
2. WebSocket /live/live accepts ONLY a valid single-use ticket:
   a valid ticket succeeds; missing, invalid, expired and replayed
   (already-used) tickets are rejected; the legacy JWT-as-subprotocol
   scheme is rejected and never echoed back.
3. Origin validation: cross-site origins are rejected (before any
   authentication), allowed CORS and same-host origins succeed, and
   non-browser clients (no Origin header) still work with a ticket.
4. Unauthorized connections receive no live SOC frames.
5. Admin/Analyst access controls remain intact (ticket endpoint and
   /live/status stay authenticated; require_admin still 403s analysts).
6. Logs contain no authentication tokens (JWT or ticket, in full or prefix).
7. Existing WebSocket functionality still works: system handshake frame,
   heartbeat, and server broadcast to a connected client.
"""
import contextlib
import io
import logging
import time
from datetime import datetime, timedelta, timezone

from jose import jwt
from starlette.websockets import WebSocketDisconnect

from app.auth.ws_ticket_service import TICKET_SUBPROTOCOL_PREFIX, ws_ticket_service
from app.core.config import settings

RESULTS = []


def record(name, ok, detail=""):
    detail = str(detail)
    if len(detail) > 200:
        detail = detail[:200] + "...(truncated)"
    RESULTS.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def make_token(role="analyst", exp_minutes=5):
    payload = {
        "sub": role,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=exp_minutes),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def issue_ticket(client, token):
    return client.post("/live/ws-ticket", headers=auth_header(token))


def attempt_ws(client, subprotocols=None, headers=None):
    """Try a WebSocket handshake.

    Returns ("accepted", session) or ("rejected", close_code).
    The caller must close an accepted session (session.__exit__).
    """
    kwargs = {}
    if subprotocols is not None:
        kwargs["subprotocols"] = subprotocols
    if headers:
        kwargs["headers"] = dict(headers)
    try:
        session = client.websocket_connect("/live/live", **kwargs)
        session.__enter__()
    except WebSocketDisconnect as exc:
        return "rejected", getattr(exc, "code", None)
    except Exception as exc:  # denial response or other rejection form
        code = getattr(exc, "status_code", None)
        return "rejected", code if code is not None else f"{type(exc).__name__}: {exc}"
    return "accepted", session


def close_ws(session):
    try:
        session.__exit__(None, None, None)
    except Exception:
        pass


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []
        self.setFormatter(logging.Formatter("%(name)s|%(levelname)s|%(message)s"))

    def emit(self, record):
        try:
            self.lines.append(self.format(record))
        except Exception:
            pass


@contextlib.contextmanager
def capture_logs():
    """Capture everything the app logs (SOCRA logger tree + root) and prints."""
    handler = _Capture()
    targets = [logging.getLogger("SOCRA"), logging.getLogger()]
    for target in targets:
        target.addHandler(handler)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            yield lambda: "\n".join(handler.lines) + "\n" + buf.getvalue()
    finally:
        for target in targets:
            target.removeHandler(handler)


# ---------------------------------------------------------------------------
# 1. Ticket endpoint authentication
# ---------------------------------------------------------------------------

def test_ticket_endpoint(client):
    resp = client.post("/live/ws-ticket")
    record("POST /live/ws-ticket rejects unauthenticated calls",
           resp.status_code == 401, f"status={resp.status_code}")

    resp = client.post("/live/ws-ticket", headers=auth_header("not-a-jwt"))
    record("POST /live/ws-ticket rejects a garbage token",
           resp.status_code == 401, f"status={resp.status_code}")

    expired = make_token(exp_minutes=-5)
    resp = client.post("/live/ws-ticket", headers=auth_header(expired))
    record("POST /live/ws-ticket rejects an expired JWT",
           resp.status_code == 401, f"status={resp.status_code}")

    admin_token = make_token("admin")
    resp = issue_ticket(client, admin_token)
    body = resp.json() if resp.status_code == 200 else {}
    ticket = body.get("ticket", "")
    record("POST /live/ws-ticket issues a ticket to an authenticated admin",
           resp.status_code == 200 and bool(ticket),
           f"status={resp.status_code}")
    record("Ticket response never contains the JWT",
           bool(ticket) and admin_token not in resp.text and "access_token" not in body)
    record("Ticket expires quickly (<= 60s)",
           bool(body.get("expires_in")) and body.get("expires_in", 999) <= 60,
           f"expires_in={body.get('expires_in')}")
    record("Ticket is a random opaque value (not the JWT)",
           bool(ticket) and ticket != admin_token)

    analyst_token = make_token("analyst")
    resp = issue_ticket(client, analyst_token)
    record("POST /live/ws-ticket issues a ticket to an authenticated analyst",
           resp.status_code == 200 and bool(resp.json().get("ticket")),
           f"status={resp.status_code}")

    return ticket


# ---------------------------------------------------------------------------
# 2. WebSocket handshake: valid ticket succeeds, everything else rejected
# ---------------------------------------------------------------------------

def test_ws_handshake(client, admin_token):
    # --- Valid ticket succeeds -------------------------------------------
    resp = issue_ticket(client, admin_token)
    ticket = resp.json()["ticket"]
    status, session = attempt_ws(
        client,
        subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}{ticket}"],
        headers={"Origin": "http://localhost:5173"},
    )
    accepted = status == "accepted"
    record("Valid ticket: WebSocket handshake accepted", accepted, f"status={status} detail={session if not accepted else ''}")
    if not accepted:
        return

    # Never echo the ticket (or any credential) back as accepted subprotocol.
    record("Server never echoes the ticket as the accepted subprotocol",
           session.accepted_subprotocol not in (ticket, admin_token),
           f"accepted_subprotocol={session.accepted_subprotocol!r}")

    # Existing functionality: system handshake frame with current_seq.
    try:
        first = session.receive_json()
        ok = first.get("type") == "system" and "current_seq" in first
    except Exception as exc:
        ok, first = False, str(exc)
    record("Existing functionality: system handshake frame received", ok, str(first))

    # Heartbeat accepted without dropping the connection; then a server
    # broadcast must reach this client.
    try:
        session.send_text("heartbeat")
        probe = {"type": "system", "message": "broadcast-probe"}
        from app.services.live_soc_service import live_soc
        session.portal.call(live_soc.broadcast, probe)
        # Periodic dashboard_stats frames may be queued ahead of the probe —
        # drain until the probe arrives.
        ok = False
        got = None
        for _ in range(30):
            got = session.receive_json()
            if got.get("message") == "broadcast-probe":
                ok = True
                break
    except Exception as exc:
        ok, got = False, str(exc)
    record("Existing functionality: heartbeat + server broadcast reach the client", ok, str(got))

    close_ws(session)

    # --- Missing ticket ---------------------------------------------------
    status, code = attempt_ws(client, subprotocols=["socra.ws"],
                              headers={"Origin": "http://localhost:5173"})
    record("Missing ticket is rejected (4401)",
           status == "rejected" and code == 4401, f"status={status} code={code}")

    status, code = attempt_ws(client, headers={"Origin": "http://localhost:5173"})
    record("No Sec-WebSocket-Protocol header is rejected (4401)",
           status == "rejected" and code == 4401, f"status={status} code={code}")

    # --- Invalid ticket ---------------------------------------------------
    status, code = attempt_ws(
        client,
        subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}definitely-not-a-real-ticket"],
        headers={"Origin": "http://localhost:5173"},
    )
    record("Invalid ticket is rejected (4401)",
           status == "rejected" and code == 4401, f"status={status} code={code}")

    # --- Expired ticket ---------------------------------------------------
    original_ttl = ws_ticket_service.ttl_seconds
    try:
        ws_ticket_service.ttl_seconds = 0.2
        expired_ticket = issue_ticket(client, admin_token).json()["ticket"]
        time.sleep(0.4)
        status, code = attempt_ws(
            client,
            subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}{expired_ticket}"],
            headers={"Origin": "http://localhost:5173"},
        )
        record("Expired ticket is rejected (4401)",
               status == "rejected" and code == 4401, f"status={status} code={code}")
    finally:
        ws_ticket_service.ttl_seconds = original_ttl

    # --- Replayed (already used) ticket ----------------------------------
    replay_ticket = issue_ticket(client, admin_token).json()["ticket"]
    status, session = attempt_ws(
        client,
        subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}{replay_ticket}"],
        headers={"Origin": "http://localhost:5173"},
    )
    first_use_ok = status == "accepted"
    if first_use_ok:
        close_ws(session)
    status2, code2 = attempt_ws(
        client,
        subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}{replay_ticket}"],
        headers={"Origin": "http://localhost:5173"},
    )
    record("Replayed (single-use) ticket is rejected on second use",
           first_use_ok and status2 == "rejected" and code2 == 4401,
           f"first={status} second={status2} code={code2}")

    # --- Legacy scheme: raw JWT offered as subprotocol --------------------
    legacy_jwt = make_token("admin")
    status, code = attempt_ws(
        client,
        subprotocols=[legacy_jwt],
        headers={"Origin": "http://localhost:5173"},
    )
    record("Legacy JWT-as-subprotocol handshake is rejected (4401)",
           status == "rejected" and code == 4401, f"status={status} code={code}")

    # --- Unauthorized user receives no live events ------------------------
    before = client.get("/live/status", headers=auth_header(admin_token)).json().get("connected_clients", 0)
    status, _ = attempt_ws(client, headers={"Origin": "http://localhost:5173"})
    after = client.get("/live/status", headers=auth_header(admin_token)).json().get("connected_clients", 0)
    record("Unauthorized connection is not registered (receives no events)",
           status == "rejected" and after <= before,
           f"status={status} clients before={before} after={after}")


# ---------------------------------------------------------------------------
# 3. Origin validation
# ---------------------------------------------------------------------------

def test_origin_validation(client, admin_token):
    ticket = issue_ticket(client, admin_token).json()["ticket"]
    proto = [f"{TICKET_SUBPROTOCOL_PREFIX}{ticket}"]

    status, code = attempt_ws(client, subprotocols=proto,
                              headers={"Origin": "https://evil.example"})
    record("Cross-site origin is rejected (4403)",
           status == "rejected" and code == 4403, f"status={status} code={code}")

    status, code = attempt_ws(client, headers={"Origin": "https://evil.example"})
    record("Cross-site origin is rejected even before ticket handling (4403)",
           status == "rejected" and code == 4403, f"status={status} code={code}")

    ticket = issue_ticket(client, admin_token).json()["ticket"]
    proto = [f"{TICKET_SUBPROTOCOL_PREFIX}{ticket}"]
    status, session = attempt_ws(client, subprotocols=proto,
                                 headers={"Origin": "http://localhost:5173"})
    record("Configured CORS origin is accepted", status == "accepted",
           f"status={status}")
    if status == "accepted":
        close_ws(session)

    ticket = issue_ticket(client, admin_token).json()["ticket"]
    proto = [f"{TICKET_SUBPROTOCOL_PREFIX}{ticket}"]
    status, session = attempt_ws(client, subprotocols=proto,
                                 headers={"Origin": "http://testserver"})
    record("Same-host origin is accepted", status == "accepted", f"status={status}")
    if status == "accepted":
        close_ws(session)

    ticket = issue_ticket(client, admin_token).json()["ticket"]
    status, session = attempt_ws(client, subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}{ticket}"])
    record("Non-browser client (no Origin) still authenticates with a ticket",
           status == "accepted", f"status={status}")
    if status == "accepted":
        close_ws(session)


# ---------------------------------------------------------------------------
# 4. Admin/Analyst access controls remain intact
# ---------------------------------------------------------------------------

def test_admin_analyst_controls(client, admin_token, analyst_tok):
    resp = client.get("/live/status")
    record("GET /live/status still requires authentication",
           resp.status_code == 401, f"status={resp.status_code}")

    resp = client.get("/live/status", headers=auth_header(analyst_tok))
    record("Analyst can read /live/status (existing access preserved)",
           resp.status_code == 200, f"status={resp.status_code}")

    resp = client.get("/live/status", headers=auth_header(admin_token))
    record("Admin can read /live/status (existing access preserved)",
           resp.status_code == 200, f"status={resp.status_code}")

    resp = client.get("/splunk/test", headers=auth_header(analyst_tok))
    record("require_admin still rejects analyst (403)",
           resp.status_code == 403, f"status={resp.status_code}")

    resp = client.get("/splunk/test")
    record("require_admin still rejects unauthenticated callers (401)",
           resp.status_code == 401, f"status={resp.status_code}")

    # Both roles can complete the WS handshake with their own ticket.
    for label, tok in (("admin", admin_token), ("analyst", analyst_tok)):
        ticket = issue_ticket(client, tok).json().get("ticket", "")
        status, session = attempt_ws(
            client,
            subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}{ticket}"],
            headers={"Origin": "http://localhost:5173"},
        )
        record(f"{label.capitalize()} completes the WebSocket handshake",
               status == "accepted", f"status={status}")
        if status == "accepted":
            close_ws(session)


# ---------------------------------------------------------------------------
# 5. Logs contain no authentication tokens
# ---------------------------------------------------------------------------

def test_logs_contain_no_tokens(client):
    token = make_token("admin")
    with capture_logs() as get_text:
        resp = issue_ticket(client, token)
        ticket = resp.json().get("ticket", "")

        # Valid handshake (authenticated path logs).
        status, session = attempt_ws(
            client,
            subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}{ticket}"],
            headers={"Origin": "http://localhost:5173"},
        )
        if status == "accepted":
            try:
                session.receive_json()
            except Exception:
                pass
            close_ws(session)

        # Legacy JWT-as-subprotocol handshake (previously logged the token).
        status, _ = attempt_ws(
            client,
            subprotocols=[token],
            headers={"Origin": "http://localhost:5173"},
        )

        # Missing/invalid ticket handshakes.
        attempt_ws(client, headers={"Origin": "http://localhost:5173"})
        attempt_ws(client, subprotocols=[f"{TICKET_SUBPROTOCOL_PREFIX}bogus"],
                   headers={"Origin": "http://localhost:5173"})

    text = get_text()
    problems = []
    if token in text:
        problems.append("full JWT found in logs")
    if token[:20] in text:
        problems.append("JWT prefix (first 20 chars) found in logs")
    if ticket and ticket in text:
        problems.append("full ticket found in logs")
    if ticket and ticket[:20] in text:
        problems.append("ticket prefix (first 20 chars) found in logs")
    record("Logs contain no authentication tokens (JWT or ticket)",
           not problems, "; ".join(problems) or "clean")


# ---------------------------------------------------------------------------
# 6. REST live endpoints still work (regression)
# ---------------------------------------------------------------------------

def test_rest_live_endpoints(client, analyst_tok):
    resp = client.get("/live/events?after_seq=0&limit=5", headers=auth_header(analyst_tok))
    body = resp.json() if resp.status_code == 200 else {}
    record("GET /live/events catch-up endpoint still works",
           resp.status_code == 200 and "current_seq" in body,
           f"status={resp.status_code}")


def main():
    print("=" * 70)
    print("SOCRA AI - PHASE 1: WEBSOCKET AUTHENTICATION SECURITY FIX")
    print("=" * 70)

    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)
    admin_token = make_token("admin")
    analyst_tok = make_token("analyst")

    for fn, args in (
        (test_ticket_endpoint, (client,)),
        (test_ws_handshake, (client, admin_token)),
        (test_origin_validation, (client, admin_token)),
        (test_admin_analyst_controls, (client, admin_token, analyst_tok)),
        (test_logs_contain_no_tokens, (client,)),
        (test_rest_live_endpoints, (client, analyst_tok)),
    ):
        try:
            fn(*args)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            record(fn.__name__, False, f"exception: {exc}")

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = len(RESULTS) - passed
    print("=" * 70)
    print(f"RESULT: {passed}/{len(RESULTS)} checks passed, {failed} failed")
    if failed:
        print("FAILED CHECKS:")
        for name, ok, detail in RESULTS:
            if not ok:
                print(f"  - {name} :: {detail}")
    print("=" * 70)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
