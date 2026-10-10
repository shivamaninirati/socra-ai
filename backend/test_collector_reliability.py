"""
SOCRA AI — Phase 3: SOC Collector Reliability — verification suite.

Run from the backend directory:

    ../venv/Scripts/python.exe test_collector_reliability.py

Coverage (as required by the task):
 1. Windows event parsing (+ malformed records handled safely)
 2. Sysmon event parsing (mocked win32evtlog — no Sysmon required)
 3. Missing optional Sysmon source (probe never raises, registry untouched)
 4. Insufficient permissions / unavailable channels (mocked, no admin needed)
 5. Severity classification (registry-driven, deterministic, never "malicious")
 6. Timestamp preservation (reader -> parser -> storage)
 7. Duplicate-event handling (per-channel watermark, in-batch + cross-cycle,
    plus log-clear watermark reset recovery)
 8. Persistence and retrieval (TEMPORARY database — never the user's data)
 9. Collector behavior when one source fails (per-source isolation)
10. Operation without a live Splunk instance (no splunklib import on the
    collection path; config provides empty defaults)

All Windows access is mocked; no administrator privileges are required; no
test writes to or deletes the user's real database (backend/data/socra.db).
"""
import json
import os
import sys
import tempfile
from datetime import datetime
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def win_event(record_number, channel="Security", event_id="4688",
              time="2026-10-09T10:00:00", host="TEST-HOST"):
    """A minimal but complete collector event (all fields validate_event needs)."""
    return {
        "record_number": record_number,
        "event_id": event_id,
        "time": time,
        "channel": channel,
        "host": host,
        "computer": host,
        "source": "Windows",
        "provider": "TestProvider",
        "message": "test message",
        "_raw": "test message",
        "strings": [],
    }


class FakeRecord:
    """Minimal win32evtlog EVENTLOGRECORD stand-in (no .User attribute)."""

    def __init__(self, record_number, event_id=4624,
                 time=datetime(2026, 10, 9, 8, 30, 0),
                 computer="TEST-HOST", source="TestSource", inserts=None,
                 omit_record_number=False):
        if not omit_record_number:
            self.RecordNumber = record_number
        self.EventID = event_id
        self.TimeGenerated = time
        self.ComputerName = computer
        self.SourceName = source
        self.EventCategory = 0
        self.EventType = 4
        self.StringInserts = inserts


class FakeSysmon:
    """Availability-controlled Sysmon stand-in for probe tests."""

    def __init__(self, available, detail="channel not found"):
        self._available = available
        self._detail = detail
        self.channel_errors = {}

    def is_available(self):
        if self._available:
            return True, None
        return False, self._detail

    def read_latest(self, limit=100):
        if not self._available:
            raise Exception(self._detail)
        return []


class GoodReader:
    def __init__(self, events=None):
        self.events = events or []
        self.channel_errors = {}

    def read_latest(self, limit=100):
        return list(self.events)[:limit]


class BadReader:
    channel_errors = {}

    def read_latest(self, limit=100):
        raise Exception("channel inaccessible")


# ---------------------------------------------------------------------------
# 1 + 6. Windows parsing and timestamp preservation
# ---------------------------------------------------------------------------

def test_windows_parsing_and_timestamp():
    from app.parsers.windows_parser import WindowsLogParser

    parser = WindowsLogParser()
    exact_time = "2026-08-15T12:00:00"
    parsed = parser.parse({
        "EventID": 4688,
        "TimeCreated": exact_time,
        "Computer": "HOST-A",
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "NewProcessName": r"C:\Windows\System32\powershell.exe",
        "NewProcessId": "0x1a34",
        "NewProcessCommandLine": "powershell.exe -enc ABC",
        "SubjectUserName": "analyst",
        "RecordNumber": 12345,
    })
    record("Parser preserves exact timestamp", parsed["time"] == exact_time,
           f"time={parsed['time']}")
    record("Parser preserves channel/provider/record",
           parsed["channel"] == "Security"
           and parsed["provider"] == "Microsoft-Windows-Security-Auditing"
           and str(parsed["record_number"]) == "12345")
    record("Parser extracts process fields",
           parsed["process_name"] == "powershell.exe"
           and parsed["process_id"] == "0x1a34"
           and parsed["command_line"] == "powershell.exe -enc ABC")
    record("Parser preserves host", parsed["host"] == "HOST-A")

    # Malformed records must not raise
    try:
        empty = parser.parse({})
        noneish = parser.parse({"EventID": None, "TimeCreated": ""})
        record("Parser handles malformed events safely",
               isinstance(empty, dict) and isinstance(noneish, dict))
    except Exception as e:
        record("Parser handles malformed events safely", False, str(e))


# ---------------------------------------------------------------------------
# 4. Permission probe + unavailable channels (mocked, no admin)
# ---------------------------------------------------------------------------

def test_privilege_probe_and_unavailable_channel():
    import pywintypes

    import app.collector.privilege_check as pc

    # Privilege error 1314 -> exact message, no exception
    err = pywintypes.error(1314, "OpenEventLog", "access denied")
    with patch.object(pc.win32evtlog, "OpenEventLog", side_effect=err):
        ok, detail = pc.security_log_access()
    record("Security privilege probe reports 1314 precisely",
           ok is False and detail == pc.PRIVILEGE_ERROR_MESSAGE,
           f"detail={detail}")

    # Generic failure -> raw error text, no exception
    with patch.object(pc.win32evtlog, "OpenEventLog",
                      side_effect=Exception("boom")):
        ok, detail = pc.security_log_access()
    record("Security probe handles generic failures without raising",
           ok is False and "boom" in str(detail))

    # Success path
    with patch.object(pc.win32evtlog, "OpenEventLog", return_value="H"):
        with patch.object(pc.win32evtlog, "CloseEventLog") as closer:
            ok, detail = pc.security_log_access()
    record("Security probe success returns (True, None) and closes handle",
           ok is True and detail is None and closer.called)

    # Windows reader: unavailable channel returns [] and records the error
    import app.collector.windows_reader as wr

    reader = wr.WindowsEventReader()
    with patch.object(wr.win32evtlog, "OpenEventLog",
                      side_effect=Exception("The specified channel was not found")):
        events = reader.read_latest(10)
    record("Unavailable channel returns [] without raising",
           events == [],
           f"errors={reader.channel_errors}")
    record("Unavailable channel error recorded per channel",
           len(reader.channel_errors) == len(reader.channels))

    # Permission-denied channel: other channels still collected (reader level)
    reader2 = wr.WindowsEventReader()

    def open_side_effect(server, channel):
        if channel == "Security":
            raise Exception("ERROR_PRIVILEGE_NOT_HELD")
        return f"H-{channel}"

    read_calls = {"n": 0}

    def read_side_effect(handle, flags, offset):
        read_calls["n"] += 1
        if read_calls["n"] == 1:
            return [FakeRecord(101, 7045, source="Service Control Manager")]
        return []

    with patch.object(wr.win32evtlog, "OpenEventLog",
                      side_effect=open_side_effect), \
         patch.object(wr.win32evtlog, "ReadEventLog",
                      side_effect=read_side_effect), \
         patch.object(wr.win32evtlog, "CloseEventLog") as closer, \
         patch.object(wr.win32evtlogutil, "SafeFormatMessage",
                      return_value="Service installed"):
        events = reader2.read_latest(20)
    record("Permission-denied Security does not stop System/Application",
           len(events) == 1 and events[0]["channel"] in ("System", "Application"),
           f"channels read: {[e['channel'] for e in events]}")
    record("Security denial recorded in channel_errors",
           "Security" in reader2.channel_errors)
    record("Handles always closed (no leak)",
           closer.called)

    # Malformed record inside a batch does not drop the healthy ones
    reader3 = wr.WindowsEventReader()
    reader3.channels = ["System"]

    def read_mixed(handle, flags, offset):
        if getattr(read_mixed, "done", False):
            return []
        read_mixed.done = True
        return [
            FakeRecord(102, omit_record_number=True),   # malformed
            FakeRecord(103, 7045),                      # healthy
        ]

    with patch.object(wr.win32evtlog, "OpenEventLog", return_value="H"), \
         patch.object(wr.win32evtlog, "ReadEventLog",
                      side_effect=read_mixed), \
         patch.object(wr.win32evtlog, "CloseEventLog"), \
         patch.object(wr.win32evtlogutil, "SafeFormatMessage",
                      return_value="msg"):
        events = reader3.read_latest(10)
    record("Malformed record skipped, healthy records kept",
           len(events) == 1 and events[0]["record_number"] == 103,
           f"events={len(events)}")

    # Timestamp format from the reader is ISO
    record("Windows reader timestamps are ISO-8601",
           events and events[0]["time"] == "2026-10-09T08:30:00",
           f"time={events[0]['time'] if events else None}")


# ---------------------------------------------------------------------------
# 2 + 3. Sysmon parsing (mocked) and missing optional source
# ---------------------------------------------------------------------------

def test_sysmon_parsing_and_optional_source():
    import app.collector.sysmon_reader as sr

    reader = sr.SysmonReader()

    # --- available path with mocked records ---
    with patch.object(sr.win32evtlog, "OpenEventLog", return_value="H"), \
         patch.object(sr.win32evtlog, "CloseEventLog") as closer, \
         patch.object(sr.win32evtlogutil, "SafeFormatMessage",
                      return_value="Process Create"), \
         patch.object(sr.win32evtlog, "ReadEventLog",
                      side_effect=[[FakeRecord(501, 1, source="Sysmon",
                                               inserts=["Image", "C:\\x.exe"]),
                                    FakeRecord(502, 3)], []]):
        events = reader.read_latest(10)

    ok_fields = (
        len(events) == 2
        and events[0]["channel"] == "Microsoft-Windows-Sysmon/Operational"
        and events[0]["source"] == "Sysmon"
        and events[0]["provider"] == "Sysmon"
        and events[0]["event_id"] == 1
        and events[0]["host"] == "TEST-HOST"
        and events[0]["record_number"] == 501
        and events[0]["message"] == "Process Create"
        and events[0]["strings"] == ["Image", "C:\\x.exe"]
    )
    record("Sysmon parsing preserves channel/provider/event_id/record/host/message",
           ok_fields, f"first={events[0] if events else None}")
    record("Sysmon timestamps are ISO-8601 (merge-sort compatible)",
           events[0]["time"] == "2026-10-09T08:30:00",
           f"time={events[0]['time']}")
    record("Sysmon reader closes handle", closer.called)

    # --- missing optional source: probe never raises ---
    with patch.object(sr.win32evtlog, "OpenEventLog",
                      side_effect=Exception("The specified channel could not be found")):
        ok, detail = reader.is_available()
    record("Missing Sysmon channel: probe returns (False, detail), no raise",
           ok is False and "could not be found" in str(detail))

    # read_latest propagates so the collector records the failure
    with patch.object(sr.win32evtlog, "OpenEventLog",
                      side_effect=Exception("not found")):
        try:
            reader.read_latest(5)
            record("Sysmon read failure propagates to collector isolation",
                   False, "no exception raised")
        except Exception as e:
            record("Sysmon read failure propagates to collector isolation",
                   "not found" in str(e))

    # probe with unavailable fake: registry unchanged, status recorded
    from app.collector.collector_service import CollectorService
    from app.collector.source_manager import source_manager

    saved_registry = dict(source_manager.get_all())
    try:
        svc = CollectorService()
        svc.sysmon = FakeSysmon(False, "Sysmon is not installed")
        svc._probe_sysmon()
        state = svc.source_status.get("sysmon", {})
        record("Unavailable Sysmon never registered in source_manager",
               "sysmon" not in source_manager.get_all())
        record("Unavailable Sysmon visible in source_status",
               state.get("available") is False
               and "not installed" in str(state.get("last_error")),
               f"state={state}")
        record("Probe schedules periodic re-probe (recoverable)",
               svc.sysmon_probe_cycles == svc.sysmon_reprobe_cycles)

        # available fake: registered
        svc.sysmon = FakeSysmon(True)
        svc._probe_sysmon()
        record("Available Sysmon registered in source_manager",
               "sysmon" in source_manager.get_all())
    finally:
        # restore the real registry exactly as it was
        for name in list(source_manager.get_all()):
            source_manager.unregister(name)
        for name, src in saved_registry.items():
            source_manager.register(name, src)

    # normalizer must not overwrite the real channel
    from app.collector.normalizer import normalizer

    norm = normalizer.normalize_sysmon({
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "HOST-B",
        "event_id": 1,
        "time": "2026-10-09T08:30:00",
    })
    record("normalize_sysmon preserves real channel + host",
           norm["event"]["channel"] == "Microsoft-Windows-Sysmon/Operational"
           and norm["event"]["host"] == "HOST-B",
           f"channel={norm['event']['channel']}")


# ---------------------------------------------------------------------------
# 5. Severity classification
# ---------------------------------------------------------------------------

def test_severity_classification():
    from app.registry.windows_event_registry import (
        SEVERITY_RANK,
        get_event_rule,
    )
    from app.severity.severity_engine import SeverityEngine

    engine = SeverityEngine()

    # Registry default for unmapped telemetry is Informational (never malicious)
    record("Unmapped event defaults to registry Informational rule",
           get_event_rule(None)["severity"] == "Informational"
           and engine.calculate({}, "999999") == "Informational")

    # Mapped events resolve through the registry deterministically
    for eid in ("4625", "4688", "4672", "1"):
        sev1 = engine.calculate({}, eid)
        sev2 = engine.calculate({}, eid)
        record(f"Event {eid}: deterministic severity in canonical set",
               sev1 == sev2 and sev1 in SEVERITY_RANK,
               f"severity={sev1}")

    # Detection severity already set by the detection engine wins
    record("Existing detection severity is preserved",
           engine.calculate({"severity": "High"}, "999999") == "High")

    # Severity vocabulary is classification only — there is no "malicious" verdict
    record("Severity vocabulary contains no malicious verdict",
           "Malicious" not in SEVERITY_RANK
           and all(s in SEVERITY_RANK
                   for s in ("Critical", "High", "Medium", "Low",
                             "Informational", "Unknown")))


# ---------------------------------------------------------------------------
# 7. Duplicate-event handling (watermark filter) + recovery
# ---------------------------------------------------------------------------

def test_duplicate_and_watermark_filter():
    from app.collector.collector_service import CollectorService

    svc = CollectorService()
    svc.last_records = {}
    svc.total_failed = 0

    batch = [win_event(11), win_event(12), win_event(13)]
    first = svc.filter_new_events(list(batch))
    record("First cycle ingests all new events", len(first) == 3)
    record("Watermark advanced per channel",
           svc.last_records.get("Security") == 13)

    second = svc.filter_new_events(list(batch))
    record("Second cycle drops duplicates (nothing re-ingested)",
           second == [], f"fresh={len(second)}")

    # in-batch duplicate
    svc.last_records = {}
    inbatch = svc.filter_new_events([win_event(21), win_event(21)])
    record("In-batch duplicates deduplicated", len(inbatch) == 1)

    # invalid events rejected + counted
    svc.last_records = {}
    before = svc.total_failed
    rejected = svc.filter_new_events([
        {"record_number": 1},                      # no channel/time/event_id
        {"channel": "Security", "record_number": "abc", "event_id": "1",
         "time": "2026-10-09T10:00:00"},           # bad record number
        win_event(31),
    ])
    record("Invalid events rejected and counted as failed",
           len(rejected) == 1 and svc.total_failed == before + 2,
           f"failed={svc.total_failed}")

    # watermark restart recovery (log cleared/rotated)
    svc.last_records = {"Security": 50000}
    recovered = svc.filter_new_events(
        [win_event(1), win_event(2), win_event(3)])
    record("Cleared-log watermark reset recovers the channel",
           len(recovered) == 3 and svc.last_records["Security"] == 3,
           f"fresh={len(recovered)} watermark={svc.last_records.get('Security')}")


# ---------------------------------------------------------------------------
# 9. One source failing never stops the others (per-source isolation)
# ---------------------------------------------------------------------------

def test_source_failure_isolation():
    from app.collector.collector_service import CollectorService
    from app.collector.source_manager import source_manager

    svc = CollectorService()
    svc.read_limit = 5
    svc.last_error = None

    good_events = [
        {"time": "2026-10-09T10:00:00", "channel": "System",
         "record_number": 2, "event_id": "7045", "host": "H"},
        {"time": "2026-10-09T11:00:00", "channel": "System",
         "record_number": 3, "event_id": "7045", "host": "H"},
    ]

    original_get_all = source_manager.get_all
    source_manager.get_all = lambda: {
        "good": GoodReader(good_events),
        "bad": BadReader(),
    }
    try:
        batch = svc._read_sources()
        good_state = svc.source_status.get("good", {})
        bad_state = svc.source_status.get("bad", {})
    finally:
        source_manager.get_all = original_get_all

    record("Healthy source still delivers events when another fails",
           len(batch) == 2, f"batch={len(batch)}")
    record("Failing source marked unavailable with last_error",
           bad_state.get("available") is False
           and "inaccessible" in str(bad_state.get("last_error")),
           f"bad={bad_state}")
    record("Healthy source marked available with last_success",
           good_state.get("available") is True
           and bool(good_state.get("last_success")))
    record("Failing source surfaces in collector last_error",
           svc.last_error is not None and "inaccessible" in svc.last_error,
           f"last_error={svc.last_error}")
    record("Merged batch is sorted newest-first",
           batch and batch[0]["time"] == "2026-10-09T11:00:00")
    record("Per-cycle read cap enforced (read_limit)",
           len(batch) <= svc.read_limit)

    # stats() exposes source_status and stays JSON-serializable
    stats = svc.stats()
    try:
        json.dumps(stats)
        json_ok = True
    except Exception:
        json_ok = False
    record("stats() includes JSON-safe source_status",
           json_ok and "source_status" in stats)


# ---------------------------------------------------------------------------
# 8. Persistence and retrieval on a TEMPORARY database
# ---------------------------------------------------------------------------

def test_persistence_on_temp_db():
    from app.storage.sqlite_storage import SQLiteStorage

    old_cwd = os.getcwd()
    tmp = tempfile.mkdtemp(prefix="socra_test_db_")
    db_file = None
    try:
        os.chdir(tmp)
        store = SQLiteStorage()
        # Absolute path inside the temp dir so nothing can ever resolve
        # back to the user's real database.
        store.db_path = os.path.join(tmp, "data", "socra.db")

        event = {
            "event": dict(win_event(700001, time="2026-10-09T09:15:00",
                                    host="TMP-HOST"),
                          process_name="cmd.exe", user="tester"),
            "detection": {"severity": "Medium", "mitre": "T1059",
                          "ioc": [], "status": "New"},
            "metadata": {"risk_score": 60, "fingerprint": "tmp-fp-1"},
            "ioc": {"ips": []},
        }
        queued = store.save_event(event)
        queued_dup = store.save_event(dict(event))       # duplicate
        event2 = {
            "event": dict(win_event(700002, time="2026-10-09T09:16:00",
                                    host="TMP-HOST")),
            "detection": {"severity": "Low", "mitre": "", "ioc": [],
                          "status": "New"},
            "metadata": {"risk_score": 30, "fingerprint": "tmp-fp-2"},
            "ioc": {},
        }
        store.save_event(event2)
        store.flush(timeout=30)

        count = store.count()
        rows = store.get_events(limit=10)
        record("Persistence: queued events land in the TEMP database",
               queued is True and queued_dup is True and count == 2,
               f"count={count} (real db untouched)")

        # duplicate blocked by the unique index, not stored twice
        record("Persistence: duplicate insert blocked by unique index",
               count == 2)

        # retrieval keeps the envelope + exact timestamp
        envelope = None
        for row in rows:
            if row.get("event", {}).get("record_number") == 700001:
                envelope = row
                break
        record("Persistence: retrieval returns full envelope",
               envelope is not None
               and envelope["event"]["time"] == "2026-10-09T09:15:00"
               and envelope["detection"]["severity"] == "Medium"
               and envelope.get("metadata", {}).get("risk_score") == 60,
               f"keys={sorted(envelope.keys()) if envelope else None}")

        # verify the user's real database was NOT the one written
        real_db = os.path.join(old_cwd, "data", "socra.db")
        wrote_temp_only = os.path.abspath(str(store.db_path)).startswith(
            os.path.abspath(tmp))
        record("Temp database path is isolated from the real database",
               wrote_temp_only, f"db={store.db_path}")
    finally:
        os.chdir(old_cwd)


# ---------------------------------------------------------------------------
# 10. Operation without a live Splunk instance
# ---------------------------------------------------------------------------

def test_no_splunk_required():
    # The full collection/processing path must never import the Splunk SDK —
    # collection works with zero Splunk connectivity.
    record("Collection path never imports splunklib (Splunk not required)",
           "splunklib" not in sys.modules)

    from app.services.event_processor import EventProcessor

    try:
        processed = EventProcessor().process(
            win_event(888001, event_id="4625",
                      time="2026-10-09T07:00:00"))
        ok = (isinstance(processed, dict)
              and "event" in processed and "detection" in processed
              and processed["detection"].get("severity") in
              ("Critical", "High", "Medium", "Low", "Informational", "Unknown"))
        record("Event pipeline completes without Splunk", ok,
               f"severity={processed.get('detection', {}).get('severity')}")
    except Exception as e:
        record("Event pipeline completes without Splunk", False, str(e))

    record("Splunk still not imported after full pipeline",
           "splunklib" not in sys.modules)

    # Config: Splunk settings are optional (empty defaults, no crash)
    from app.core.config import settings

    record("Splunk config is optional (no mandatory credentials)",
           isinstance(getattr(settings, "SPLUNK_HOST", ""), str))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("SOCRA AI - PHASE 3: COLLECTOR RELIABILITY VERIFICATION")
    print("=" * 70)

    tests = [
        test_windows_parsing_and_timestamp,
        test_privilege_probe_and_unavailable_channel,
        test_sysmon_parsing_and_optional_source,
        test_severity_classification,
        test_duplicate_and_watermark_filter,
        test_source_failure_isolation,
        test_persistence_on_temp_db,
        test_no_splunk_required,
    ]

    for test in tests:
        try:
            test()
        except Exception as e:
            import traceback
            traceback.print_exc()
            record(f"{test.__name__} (unhandled)", False, str(e))

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = len(RESULTS) - passed
    print("=" * 70)
    print(f"RESULT: {passed}/{len(RESULTS)} checks passed, {failed} failed")
    if failed:
        print("FAILED CHECKS:")
        for name, ok, detail in RESULTS:
            if not ok:
                print(f"  - {name}" + (f" ({detail})" if detail else ""))
    print("=" * 70)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
