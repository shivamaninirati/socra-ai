"""
TASK 6 - PERSIST COMPLETE EVENT DATA — verification suite.

Run from the backend directory:

    ../venv/Scripts/python.exe test_persistence.py

Steps covered (as required by the task):
1. Insert event (full envelope: event + detection + metadata + IOC).
2. "Restart" backend — read back through a brand-new SQLite connection.
3. Retrieve event — verify metadata/IOC/fingerprint/risk_score still exist,
   both in raw_json and in the dedicated envelope columns.
4. Verify deduplication still works (identical event is not stored twice).
5. Verify legacy {event, detection} records remain readable and get their
   computed fingerprint / risk score backfilled.

Test rows use a unique host marker and are cleaned up afterwards.
"""
import json
import sqlite3
import time
import uuid

from app.storage.sqlite_storage import sqlite_storage

HOST_MARKER = f"PERSIST-TEST-{uuid.uuid4().hex[:8].upper()}"
RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def flush_writer(timeout=180):
    """Wait for the single writer thread to drain AND commit all queued
    operations (Queue.join alone can return before the batched commit)."""
    if not sqlite_storage.flush(timeout=timeout):
        raise TimeoutError("Writer thread did not flush within timeout")


def fresh_read(event_time, host, record_number):
    """Read the stored row through a brand-new connection (simulates a fresh
    backend process reading the same database file)."""
    conn = sqlite3.connect(sqlite_storage.db_path, timeout=30)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT event_time, host, event_id, severity, mitre, process_name, "
            "user, parent_process, metadata_json, ioc_json, risk_score, "
            "fingerprint, raw_json "
            "FROM events WHERE host = ? AND record_number = ?",
            (host, record_number),
        )
        return cur.fetchone()
    finally:
        conn.close()


def make_full_event(record_number):
    return {
        "event": {
            "host": HOST_MARKER,
            "computer": HOST_MARKER,
            "event_id": "4688",
            "time": "2026-08-15T12:00:00",
            "channel": "Security",
            "record_number": record_number,
            "user": "soc.analyst",
            "process_name": "powershell.exe",
            "parent_process": "explorer.exe",
            "parent_image": "C:\\Windows\\explorer.exe",
            "command_line": "powershell -enc SQBFAFgA",
            "source": "Windows",
            "provider": "Microsoft-Windows-Security-Auditing",
        },
        "detection": {
            "severity": "High",
            "detection": "Suspicious PowerShell",
            "description": "Encoded PowerShell command detected.",
            "mitre": {"id": "T1059.001", "technique": "PowerShell", "tactic": "Execution"},
        },
        "ioc": {
            "ips": ["198.51.100.7"],
            "hashes": ["0123456789abcdef0123456789abcdef"],
        },
        "metadata": {
            "fingerprint": f"task6-fp-{record_number}",
            "risk_score": 80,
            "processed_at": "2026-08-15T12:00:01",
        },
    }


def make_legacy_event(record_number):
    """The shape stored before Task 6: only {event, detection}."""
    return {
        "event": {
            "host": HOST_MARKER,
            "computer": HOST_MARKER,
            "event_id": "4624",
            "time": "2026-08-15T11:00:00",
            "channel": "Security",
            "record_number": record_number,
            "user": "legacy.user",
            "process_name": "lsass.exe",
            "parent_process": "wininit.exe",
        },
        "detection": {
            "severity": "Low",
            "detection": "Successful Logon",
            "mitre": {"id": "T1078"},
        },
    }


def cleanup():
    conn = sqlite3.connect(sqlite_storage.db_path, timeout=30)
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM events WHERE host = ?", (HOST_MARKER,))
        conn.commit()
    finally:
        conn.close()


def main():
    print("=" * 70)
    print("SOCRA AI - TASK 6: COMPLETE EVENT DATA PERSISTENCE")
    print("=" * 70)

    # ------------------------------------------------------------
    # 1. Insert a full-envelope event
    # ------------------------------------------------------------
    full_record = 900000 + int(uuid.uuid4().int % 100000)
    full = make_full_event(full_record)
    queued = sqlite_storage.save_event(full)
    record("Insert full-envelope event (queued)", queued is True)

    # Insert the identical event again — must be deduplicated, not stored twice.
    queued_dup = sqlite_storage.save_event(dict(full))
    record("Duplicate insert queued (dedup path)", queued_dup is True)

    # 2. Insert a legacy-shaped event (no metadata/IOC)
    legacy_record = 910000 + int(uuid.uuid4().int % 100000)
    queued_legacy = sqlite_storage.save_event(make_legacy_event(legacy_record))
    record("Insert legacy {event, detection} event (queued)", queued_legacy is True)

    # Wait for the writer thread to drain (simulates completed persistence).
    flush_writer()

    # ------------------------------------------------------------
    # 3. "Restart": read back through a fresh connection
    # ------------------------------------------------------------
    row = fresh_read("2026-08-15T12:00:00", HOST_MARKER, full_record)
    record("Retrieve event after restart (fresh connection)", row is not None,
           f"rows found: {1 if row else 0}")

    if not row:
        cleanup()
        return

    (_event_time, _host, _eid, _sev, _mitre, _proc, user, parent, meta_json,
     ioc_json, risk_score, fingerprint, raw_json) = row

    payload = json.loads(raw_json)

    # ------------------------------------------------------------
    # 4. Verify the complete envelope survived
    # ------------------------------------------------------------
    ok_raw_meta = (payload.get("metadata") or {}).get("fingerprint") == f"task6-fp-{full_record}"
    record("raw_json keeps metadata (fingerprint)", ok_raw_meta)

    ok_raw_ioc = (payload.get("ioc") or {}).get("ips") == ["198.51.100.7"]
    record("raw_json keeps IOC data", ok_raw_ioc,
           f"ioc: {payload.get('ioc')}")

    ok_cols = (
        user == "soc.analyst"
        and parent == "explorer.exe"
        and meta_json is not None and "task6-fp" in meta_json
        and ioc_json is not None and "198.51.100.7" in ioc_json
        and risk_score == 80
        and fingerprint == f"task6-fp-{full_record}"
    )
    record("Envelope columns populated (user, parent, metadata, IOC, risk, fingerprint)",
           ok_cols,
           f"user={user} parent={parent} risk={risk_score} fp={str(fingerprint)[:20]}...")

    # ------------------------------------------------------------
    # 5. Deduplication still works
    # ------------------------------------------------------------
    conn = sqlite3.connect(sqlite_storage.db_path, timeout=30)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM events WHERE host = ? AND record_number = ?",
            (HOST_MARKER, full_record),
        )
        count = cur.fetchone()[0]
    finally:
        conn.close()
    record("Deduplication blocks duplicates (unique index)", count == 1, f"stored rows: {count}")

    # ------------------------------------------------------------
    # 6. Legacy records remain readable + get backfilled
    # ------------------------------------------------------------
    lrow = fresh_read("2026-08-15T11:00:00", HOST_MARKER, legacy_record)
    legacy_readable = lrow is not None and "event" in json.loads(lrow[12]) and "detection" in json.loads(lrow[12])
    record("Legacy {event, detection} record still readable", legacy_readable)

    if lrow:
        (_, _, _, _, _, _, luser, lparent, lmeta, lioc, lrisk, lfp, lraw) = lrow
        lpayload = json.loads(lraw)
        # Storage deliberately always writes the full envelope shape
        # ({event, detection, metadata, ioc}) so readers can reconstruct it;
        # for legacy rows metadata/ioc are empty dicts (never fabricated data).
        # The original {event, detection} content must remain byte-intact.
        meta = lpayload.get("metadata")
        ioc = lpayload.get("ioc")
        record("Legacy record keeps original envelope intact",
               "event" in lpayload
               and "detection" in lpayload
               and meta in (None, {})
               and ioc in (None, {}))
        record("Legacy record backfilled fingerprint",
               lfp is not None and len(lfp) == 64,
               f"fp={str(lfp)[:20]}...")
        record("Legacy record backfilled risk score",
               lrisk is not None,
               f"risk={lrisk}")

    # ------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------
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
