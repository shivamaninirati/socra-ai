import asyncio
from datetime import datetime

from app.collector.windows_reader import WindowsEventReader

from app.storage.storage_manager import storage_manager
from app.services.event_processor import EventProcessor
from app.services.live_soc_service import live_soc


class CollectorService:

    def __init__(self):

        self.windows = WindowsEventReader()

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
        print("[SOCRA] Native Collector Started")
        print("=" * 60)

        while self.running:

            try:

                self.last_collection_time = datetime.utcnow()

                events = self.windows.read_latest(100)

                if not events:

                    await asyncio.sleep(self.sleep_interval)

                    continue

                events.reverse()

                new_events = 0

                for event in events:

                    try:

                        if not self.validate_event(event):

                            self.total_failed += 1

                            continue

                        channel = event["channel"]

                        record = int(event["record_number"])

                        last_record = self.last_records.get(channel, 0)

                        if record <= last_record:
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

            "sources": [

                "Windows",

                "Native Collector"

            ]

        }


collector = CollectorService()