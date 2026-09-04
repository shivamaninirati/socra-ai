"""
TASK 17 — REAL ALERT STATUS — verification suite.

Run from the backend directory:

    ../venv/Scripts/python.exe test_alert_status.py

Steps covered (as required by the task):
1. Every one of the five triage statuses (New, Investigating, Contained,
   Resolved, Closed) can be persisted to SQLite and read back through a
   brand-new connection (status survives a restart).
2. The status filter actually works — query_events filters to exactly the
   rows carrying each status (and NULL rows resolve to the "New" default).
3. Served envelopes carry the persisted status + alert row id, so the
   frontend table, drawer and live stream all see the real status.
4. /alerts/status (the analyst API) requires authentication, rejects invalid
   statuses, and persists a valid change with the analyst recorded.
5. /alerts/filters reports real per-status counts for the dropdown.

Test rows use a unique host marker and are cleaned up afterwards.
"""
import json
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone

from jose import jwt

from app.core.config import settings
from app.storage.sqlite_storage import sqlite_storage

STATUSES = ["New", "Investigating", "Contained", "Resolved", "Closed"]

HOST_MARKER = f"STATUS-TEST-{uuid.uuid4().hex[:8].upper()}"
RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def flush_writer(timeout=180):
    """Wait for the single writer thread to drain AND commit all queued ops."""
    if not sqlite_storage.flush(timeout=timeout):
        raise TimeoutError("Writer thread did not flush within timeout")


def fresh_read(alert_id):
    """Read the status columns through a brand-new connection (fresh process)."""
    conn = sqlite3.connect(sqlite_storage.db_path, timeout=30)
    try:
        row = conn.execute(
            "SELECT id, status, status_changed_by, status_changed_at "
            "FROM events WHERE id = ?",
            (alert_id,),
        ).fetchone()
        return row
    finally:
        conn.close()


def make_event(record_number, event_id="4688", sev="High"):
    return {
        "event": {
            "host": HOST_MARKER,
            "computer": HOST_MARKER,
            "event_id": event_id,
            "time": "2026-08-16T10:00:00",
            "channel": "Security",
            "record_number": record_number,
            "user": "soc.analyst",
            "process_name": "powershell.exe",
            "parent_process": "explorer.exe",
            "command_line": "powershell -enc SQBFAFgA",
            "source": "Windows",
            "provider": "Microsoft-Windows-Security-Auditing",
        },
        "detection": {
            "severity": sev,
            "detection": "Suspicious PowerShell",
            "description": "Encoded PowerShell command detected.",
            "mitre": {"id": "T1059.001", "technique": "PowerShell", "tactic": "Execution"},
        },
        "ioc": {"ips": ["198.51.100.7"], "hashes": ["0123456789abcdef0123456789abcdef"]},
        "metadata": {
            "fingerprint": f"status-fp-{record_number}",
            "risk_score": 80,
            "processed_at": "2026-08-16T10:00:01",
        },
    }


def cleanup():
    conn = sqlite3.connect(sqlite_storage.db_path, timeout=30)
    try:
        conn.execute("DELETE FROM events WHERE host = ?", (HOST_MARKER,))
        conn.commit()
    finally:
        conn.close()


def test_storage_persistence_and_filter():
    """Storage-level: every status persists, survives restart, filters work."""
    # Insert one alert per canonical status (5 distinct alerts).
    alert_ids = {}
    for i, status in enumerate(STATUSES):
        rec = 920000 + i
        sqlite_storage.save_event(make_event(rec))
        flush_writer()
        alert_ids[status] = sqlite_storage.find_alert_id_by_fingerprint(f"status-fp-{rec}")
        record(
            f"Insert alert for status '{status}'",
            alert_ids[status] is not None,
            f"id={alert_ids[status]}",
        )

    # Change each alert through EVERY status and verify the change persists
    # through a brand-new connection (simulated backend restart).
    for target in STATUSES:
        for status in STATUSES:
            record_out = sqlite_storage.update_alert_status(alert_ids[target], status, "analyst")
            record(
                f"Set '{target}' -> '{status}' via writer thread",
                record_out is not None and record_out["status"] == status
                and record_out["changed_by"] == "analyst",
                json.dumps(record_out),
            )
            row = fresh_read(alert_ids[target])
            record(
                f"'{target}' -> '{status}' survives restart (fresh connection)",
                row is not None and row[1] == status and row[2] == "analyst",
                f"row={row}",
            )

    # Leave each alert on its own status (one alert per status) so the
    # filter test is meaningful: exactly one match per status.
    for status in STATUSES:
        sqlite_storage.update_alert_status(alert_ids[status], status, "analyst")
    flush_writer()

    # Status filter actually works for every status.
    for status in STATUSES:
        qresult = sqlite_storage.query_events({"status": status, "host": HOST_MARKER, "limit": 100})
        matched = [
            r for r in qresult["results"]
            if (r.get("metadata", {}) or {}).get("fingerprint", "").startswith("status-fp-")
        ]
        record(
            f"Status filter '{status}' returns only matching alerts",
            len(matched) == 1 and all(
                (r.get("event", {}) or {}).get("status") == status for r in matched
            ),
            f"matched={len(matched)} expected=1",
        )

    # Served envelopes carry _id + the persisted status.
    qresult = sqlite_storage.query_events({"host": HOST_MARKER, "limit": 100})
    seen = {r["_id"]: r for r in qresult["results"]}
    all_ok = all(
        seen.get(alert_ids[s], {}).get("event", {}).get("status") == s
        for s in STATUSES
    ) and all(seen.get(alert_ids[s], {}).get("_id") == alert_ids[s] for s in STATUSES)
    record("query_events attaches _id + persisted status to every row", all_ok)

    # search_events (keyword-search path) attaches the same fields.
    sresult = sqlite_storage.search_events("host = ? COLLATE NOCASE", [HOST_MARKER], limit=100)
    sseen = {r["_id"]: r for r in sresult["results"]}
    search_ok = all(
        sseen.get(alert_ids[s], {}).get("event", {}).get("status") == s
        for s in STATUSES
    )
    record("search_events attaches _id + persisted status", search_ok)

    # Live-forwarder path (get_events_after_id) attaches the same fields.
    after_rows = sqlite_storage.get_events_after_id(alert_ids["New"] - 1, limit=100)
    fseen = {r[0]: r[1] for r in after_rows}
    forward_ok = all(
        fseen.get(alert_ids[s], {}).get("event", {}).get("status") == s
        for s in STATUSES
    )
    record("get_events_after_id attaches _id + persisted status (live forwarder)", forward_ok)

    # Real counts: every status has exactly one alert.
    counts = sqlite_storage.get_alert_status_counts()
    record(
        "get_alert_status_counts reports one alert per status",
        all(counts[s] == 1 for s in STATUSES),
        json.dumps(counts),
    )

    # New alert (no status row value) resolves to the "New" default.
    rec_new = 921000
    sqlite_storage.save_event(make_event(rec_new, event_id="4624", sev="Low"))
    flush_writer()
    new_id = sqlite_storage.find_alert_id_by_fingerprint(f"status-fp-{rec_new}")
    qnew = sqlite_storage.query_events({"status": "New", "host": HOST_MARKER, "limit": 100})
    new_matched = [r for r in qnew["results"] if r.get("_id") == new_id]
    record(
        "NULL status resolves to the 'New' default in the filter",
        len(new_matched) == 1 and new_matched[0]["event"]["status"] == "New",
    )


def test_api_endpoint():
    """Route-level: /alerts/status auth, validation, persistence, broadcast."""
    from fastapi.testclient import TestClient
    from main import app

    token = jwt.encode(
        {
            "sub": "analyst",
            "role": "analyst",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    headers = {"Authorization": f"Bearer {token}"}

    client = TestClient(app)

    # 1. Authentication required.
    resp = client.post("/alerts/status", json={"alert_id": 1, "status": "Resolved"})
    record("POST /alerts/status rejects unauthenticated calls", resp.status_code == 401,
           f"status={resp.status_code}")

    # 2. Invalid status rejected.
    resp = client.post(
        "/alerts/status",
        json={"alert_id": 1, "status": "Banana"},
        headers=headers,
    )
    record("POST /alerts/status rejects invalid statuses",
           resp.status_code == 200 and resp.json().get("success") is False,
           json.dumps(resp.json()))

    # 3. Missing identity rejected.
    resp = client.post("/alerts/status", json={"status": "Resolved"}, headers=headers)
    record("POST /alerts/status requires alert_id or fingerprint",
           resp.json().get("success") is False)

    # 4. Real update by alert_id persists + analyst recorded.
    rec = 922000
    sqlite_storage.save_event(make_event(rec))
    flush_writer()
    alert_id = sqlite_storage.find_alert_id_by_fingerprint(f"status-fp-{rec}")
    resp = client.post(
        "/alerts/status",
        json={"alert_id": alert_id, "status": "Investigating"},
        headers=headers,
    )
    body = resp.json()
    record(
        "POST /alerts/status persists a valid change with the analyst",
        body.get("success") is True
        and body.get("alert", {}).get("status") == "Investigating"
        and body.get("alert", {}).get("changed_by") == "analyst",
        json.dumps(body),
    )
    row = fresh_read(alert_id)
    record("API change survives restart (fresh connection)",
           row is not None and row[1] == "Investigating" and row[2] == "analyst")

    # 5. Update by fingerprint (live-envelope fallback) works too.
    resp = client.post(
        "/alerts/status",
        json={"fingerprint": f"status-fp-{rec}", "status": "Closed"},
        headers=headers,
    )
    body = resp.json()
    record(
        "POST /alerts/status resolves by fingerprint",
        body.get("success") is True and body.get("alert", {}).get("status") == "Closed",
        json.dumps(body),
    )
    row = fresh_read(alert_id)
    record("Fingerprint update persisted", row is not None and row[1] == "Closed")

    # 6. /alerts/filters serves the canonical status list with real counts.
    resp = client.get("/alerts/filters", headers=headers)
    statuses = {s["value"]: s["count"] for s in resp.json().get("statuses", [])}
    record(
        "GET /alerts/filters serves all five statuses with real counts",
        set(statuses.keys()) == set(STATUSES) and statuses.get("Closed", 0) >= 1,
        json.dumps(statuses),
    )


def main():
    print("=" * 70)
    print("SOCRA AI - TASK 17: REAL ALERT STATUS")
    print("=" * 70)

    test_storage_persistence_and_filter()
    try:
        test_api_endpoint()
    except Exception as e:
        import traceback
        traceback.print_exc()
        record("API endpoint tests", False, str(e))

    cleanup()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = len(RESULTS) - passed
    print("=" * 70)
    print(f"RESULT: {passed}/{len(RESULTS)} checks passed, {failed} failed")
    if failed:
        print("FAILED CHECKS:")
        for name, ok, _ in RESULTS:
            if not ok:
                print(f"  - {name}")
    print("=" * 70)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
