import asyncio
from datetime import datetime

from app.collector.windows_reader import WindowsEventReader
from app.collector.sysmon_reader import SysmonReader
from app.collector.source_manager import source_manager

from app.storage.storage_manager import storage_manager
from app.services.event_processor import EventProcessor
from app.services.live_soc_service import live_soc


class CollectorService:

    def __init__(self):

        self.windows = WindowsEventReader()

        self.sysmon = SysmonReader()

        # The shared source_manager is the active registry (the collection
        # loop reads exactly what is registered there). Re-register OUR
        # Windows instance so the Security-channel privilege filter applied
        # in start() governs the registered source too — one instance only.
        source_manager.register("windows", self.windows)

        self.source_status = {
            "windows": {
                "available": True,
                "detail": None,
                "last_error": None,
                "last_success": None,
            }
        }

        # Re-probe the optional Sysmon channel every ~5 minutes (1s cadence)
        self.sysmon_reprobe_cycles = 300
        self.sysmon_probe_cycles = 0  # probe immediately at start

        # Per-cycle read cap across all sources (unchanged from previous 100)
        self.read_limit = 100

        self.processor = EventProcessor()

        self.running = False

        # Last processed record per channel
        self.last_records = {}

        # Statistics
        self.total_collected = 0

        self.total_processed = 0

        self.total_failed = 0

        self.started_at = None

        self.last_collection_time = None

        self.last_error = None

        self.sleep_interval = 1

        # Real Security Event Log privilege state (probed once at start).
        # Never silently assumed: when the Security channel cannot be opened
        # this stays False and the channel is skipped until the process runs
        # elevated (see start()).
        self.security_log_accessible = None
        self.privilege_error = None

    # ---------------------------------------------------------
    # Event Validation
    # ---------------------------------------------------------

    def validate_event(self, event):

        if not event:
            return False

        if not isinstance(event, dict):
            return False

        if not event.get("event_id"):
            return False

        if not event.get("record_number"):
            return False

        if not event.get("time"):
            return False

        if not event.get("channel"):
            return False

        return True

    # ---------------------------------------------------------
    # Start Collector
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # Sources (Windows + optional Sysmon)
    # ---------------------------------------------------------

    def _probe_sysmon(self):
        """Register (or drop) the optional Sysmon source based on a real probe.

        Sysmon is never assumed: when the channel is missing the source is
        simply not registered, its unavailability is recorded in
        source_status, and the probe repeats every sysmon_reprobe_cycles so a
        later Sysmon install is picked up without restarting the collector.
        """
        ok, detail = self.sysmon.is_available()
        status = self.source_status.setdefault("sysmon", {})
        status["available"] = bool(ok)
        status["detail"] = detail
        status["last_error"] = None if ok else (detail or "Sysmon channel unavailable")
        registered = "sysmon" in source_manager.get_all()
        if ok and not registered:
            source_manager.register("sysmon", self.sysmon)
            print(
                "[Collector] Sysmon channel available — source registered "
                "(Microsoft-Windows-Sysmon/Operational)"
            )
        elif not ok and registered:
            source_manager.unregister("sysmon")
            print(f"[Collector] Sysmon source removed: {status['last_error']}")
        elif not ok:
            print(
                f"[Collector] Sysmon optional source not available: "
                f"{status['last_error']} "
                f"(re-probe every {self.sysmon_reprobe_cycles}s)"
            )
        self.sysmon_probe_cycles = self.sysmon_reprobe_cycles

    def _read_sources(self):
        """Read every registered source with per-source isolation.

        A source that fails is recorded in source_status and skipped for this
        cycle — one unavailable source never stops the others. The merged
        batch keeps the previous contract: newest first, capped at read_limit.
        """
        batch = []
        for name, reader in list(source_manager.get_all().items()):
            status = self.source_status.setdefault(
                name,
                {
                    "available": True,
                    "detail": None,
                    "last_error": None,
                    "last_success": None,
                },
            )
            try:
                events = reader.read_latest(self.read_limit) or []
            except Exception as e:
                status["available"] = False
                status["last_error"] = str(e)
                self.last_error = f"{name}: {e}"
                print(f"[Collector] {name} source read failed: {e}")
                if name == "sysmon":
                    # Re-probe next cycle: the channel may have been removed.
                    self.sysmon_probe_cycles = 0
                continue
            status["available"] = True
            status["last_error"] = None
            status["last_success"] = datetime.utcnow().isoformat()
            channel_errors = getattr(reader, "channel_errors", None)
            if channel_errors:
                status["channel_errors"] = dict(channel_errors)
            else:
                status.pop("channel_errors", None)
            batch.extend(events)
        batch.sort(key=lambda x: x.get("time", ""), reverse=True)
        return batch[: self.read_limit]

    def filter_new_events(self, events):
        """Validate events and return only those past the per-channel watermark.

        Watermarks advance in memory here; the loop still persists each
        event's watermark right before processing it (unchanged crash
        semantics). Also recovers from a restarted channel: when a batch's
        newest record for a channel sits BELOW the stored watermark, the
        watermark is stale (log cleared/rotated) and is reset — otherwise
        every future event on that channel would be dropped forever.
        """
        newest = {}
        for event in events:
            if not isinstance(event, dict):
                continue
            channel = event.get("channel")
            if not channel:
                continue
            try:
                record = int(event.get("record_number"))
            except (TypeError, ValueError):
                continue
            if record > newest.get(channel, -1):
                newest[channel] = record

        for channel, record in newest.items():
            last = self.last_records.get(channel, 0)
            if last and record < last:
                print(
                    f"[Collector] {channel}: record numbering restarted "
                    f"({record} < saved {last}) — resetting watermark"
                )
                self.last_records[channel] = 0

        fresh = []
        for event in events:
            if not self.validate_event(event):
                self.total_failed += 1
                continue
            channel = event["channel"]
            try:
                record = int(event["record_number"])
            except (TypeError, ValueError):
                self.total_failed += 1
                continue
            if record <= self.last_records.get(channel, 0):
                continue
            self.last_records[channel] = record
            fresh.append(event)
        return fresh

    # ---------------------------------------------------------
    # Start Collector
    # ---------------------------------------------------------

    async def start(self):

        if self.running:
            return

        self.running = True

        self.started_at = datetime.utcnow()
        
        # Load saved collector state from database for resumability
        try:
            from app.storage.sqlite_storage import sqlite_storage
            saved_state = sqlite_storage.load_collector_state()
            for channel, state in saved_state.items():
                self.last_records[channel] = state["last_record"]
            print(f"[Collector] Loaded saved last records: {self.last_records}")
        except Exception as e:
            print(f"[Collector] Could not load saved state: {e}")

        # Explicit Security Event Log privilege probe - never silent. When the
        # Security channel is not accessible (missing Administrator privileges)
        # the channel is dropped from this process's read set so the reader does
        # not print the same privilege error on every poll cycle. System and
        # Application channels continue to be collected normally.
        try:
            from app.collector.privilege_check import security_log_access
            ok, detail = security_log_access()
            self.security_log_accessible = ok
            self.privilege_error = None if ok else detail
        except Exception as e:
            self.security_log_accessible = None
            self.privilege_error = None
            print(f"[Collector] Could not probe Security Event Log access: {e}")
        if self.security_log_accessible is False:
            print("=" * 60)
            print(f"[Collector] {self.privilege_error}")
            print(
                "[Collector] System/Application channels will still be "
                "collected; Security channel events are skipped until this "
                "process runs elevated (Administrator shell or Task Scheduler "
                "'Run with highest privileges')."
            )
            print("=" * 60)
            original_channels = getattr(self.windows, "channels", [])
            self.windows.channels = [
                c for c in original_channels if c.lower() != "security"
            ]

        print("=" * 60)
        self._probe_sysmon()

        print("[SOCRA] Native Collector Started")
        print("=" * 60)

        while self.running:

            try:

                self.last_collection_time = datetime.utcnow()

                if self.sysmon_probe_cycles <= 0:
                    self._probe_sysmon()
                else:
                    self.sysmon_probe_cycles -= 1

                events = self._read_sources()

                if not events:

                    await asyncio.sleep(self.sleep_interval)

                    continue

                events.reverse()

                new_events = 0

                for event in self.filter_new_events(events):

                    try:

                        if not self.validate_event(event):

                            self.total_failed += 1

                            continue

                        channel = event["channel"]

                        record = int(event["record_number"])

                        last_record = self.last_records.get(channel, 0)

                        if record < last_record:  # dedup already applied by filter_new_events()
                            continue

                        self.last_records[channel] = record

                        # Save the updated state to database for resumability
                        try:
                            from app.storage.sqlite_storage import sqlite_storage
                            computer = event.get("host", "unknown")
                            sqlite_storage.save_collector_state(channel, record, computer)
                        except Exception as e:
                            print(f"[Collector] Could not save collector state: {e}")

                        processed = self.processor.process(event)

                        if not processed:
                            self.total_failed += 1
                            continue

                        if not isinstance(processed, dict):
                            self.total_failed += 1
                            continue

                        if "event" not in processed:
                            self.total_failed += 1
                            continue

                        storage_manager.add_event(processed)

                        # Incrementally update the enterprise filter metadata cache
                        # so dropdown values (hosts, users, processes, event IDs,
                        # MITRE, severity, status) stay in sync with live telemetry
                        # without ever rescanning the full dataset.
                        try:
                            from app.services.filter_cache_service import filter_cache
                            filter_cache.ingest_event(processed)
                        except Exception as filter_error:
                            print(f"[Collector FilterCache Error] {filter_error}")

                        await live_soc.broadcast({
                            "type": "alert",
                            **processed
                        })

                        self.total_processed += 1

                        self.total_collected += 1

                        new_events += 1

                    except Exception as event_error:

                        self.total_failed += 1

                        print(
                            f"[Collector Event Error] {event_error}"
                        )

                if new_events:
                    # Metrics are defined and unambiguous (see stats()):
                    #   New       = events ingested this collection cycle
                    #   Live      = events in the live in-memory store (today's
                    #               persisted events + this session's events)
                    #   History   = total rows persisted in SQLite (all time)
                    #   Collected = events collected since this process started
                    print(

                        f"[Collector] "

                        f"New={new_events} | "

                        f"Live={storage_manager.live_count()} | "

                        f"History={storage_manager.history_count()} | "

                        f"Collected={self.total_collected}"

                    )

            except Exception as e:

                self.last_error = str(e)

                print(f"[Collector Error] {e}")

            await asyncio.sleep(self.sleep_interval)

    # ---------------------------------------------------------
    # Stop
    # ---------------------------------------------------------

    def stop(self):

        if not self.running:
            return

        self.running = False

        print("=" * 60)
        print("[SOCRA] Native Collector Stopped")
        print("=" * 60)

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    def stats(self):

        uptime = None

        if self.started_at:

            uptime = str(

                datetime.utcnow()

                -

                self.started_at

            )

        # JSON-safe timestamps: raw datetime objects are NOT serializable by
        # json.dumps. REST responses survive via FastAPI's jsonable_encoder,
        # but the WebSocket dashboard_stats broadcast serializes with plain
        # json.dumps — a datetime here crashed send_json, which dropped the
        # socket from the live connection manager (backend lost every client
        # seconds after it connected). ISO strings are safe on every surface.
        def _iso(value):
            return value.isoformat() if isinstance(value, datetime) else value

        # Metric definitions (all surfaces consume these through
        # app/services/collector_status_service.py):
        #   running/live_events/history_events/total_collected/
        #   total_processed/total_failed/security_log_accessible/privilege_error
        return {

            "running": self.running,

            "started_at": _iso(self.started_at),

            "last_collection_time": _iso(self.last_collection_time),

            "uptime": uptime,

            "last_error": self.last_error,

            "total_collected": self.total_collected,

            "total_processed": self.total_processed,

            "total_failed": self.total_failed,

            "live_events": storage_manager.live_count(),

            "history_events": storage_manager.history_count(),

            "channels": list(self.last_records.keys()),

            "security_log_accessible": self.security_log_accessible,

            "privilege_error": self.privilege_error,

            "source_status": dict(self.source_status),

            "sources": [

                "Windows",

                "Native Collector"

            ]

        }


collector = CollectorService()