from collections import deque
from threading import Lock
from uuid import uuid4
from datetime import datetime

from app.core.logger import get_module_logger

logger = get_module_logger("collector.event_store")


class EventStore:

    def __init__(self, live_cache_size=50000):

        # Live in-memory cache
        self.events = deque(maxlen=live_cache_size)

        self.lock = Lock()

        # Monotonic sequence for REST/WebSocket synchronization. Every event
        # entering the live store gets a strictly increasing _seq which acts as
        # the reliable last-event ID: clients track the highest seq they have
        # applied and can ask for anything newer (catch-up) after a reconnect.
        self._seq_counter = 0

    def _next_seq(self):
        self._seq_counter += 1
        return self._seq_counter

    def add_event(self, event):

        with self.lock:

            # Internal SOCRA Event ID
            if "_socra_id" not in event:
                event["_socra_id"] = str(uuid4())

            # Storage timestamp
            if "_stored_at" not in event:
                event["_stored_at"] = datetime.utcnow().isoformat()

            # Sequence: assign if missing; otherwise keep the event's existing
            # seq (events restored from persistence) and never regress the
            # counter below it, so seq stays monotonic across server restarts.
            existing_seq = event.get("_seq")
            if existing_seq is None:
                event["_seq"] = self._next_seq()
            else:
                try:
                    self._seq_counter = max(self._seq_counter, int(existing_seq))
                except (TypeError, ValueError):
                    event["_seq"] = self._next_seq()

            self.events.appendleft(event)

    def current_seq(self):
        """Highest sequence currently in the live store (sync boundary)."""
        with self.lock:
            return self._seq_counter

    def get_events_after(self, seq, limit=1000):
        """Events with _seq > seq, oldest first — the missed-event set for
        a client that last applied up to `seq`. Deterministic and idempotent:
        replaying them again changes nothing."""
        with self.lock:
            missed = [
                event for event in self.events
                if isinstance(event.get("_seq"), int) and event["_seq"] > seq
            ]
            missed.sort(key=lambda e: e["_seq"])
            return missed[:limit]

    def snapshot_events(self):
        """Atomically return (events, current_seq) — the REST snapshot boundary.

        Reading both under the same lock guarantees the seq a client receives
        exactly covers the event set the snapshot totals were computed from, so
        the client can skip anything with _seq <= current_seq without risking
        double counting or missed events.
        """
        with self.lock:
            return list(self.events), self._seq_counter

    def get_events(self):
        with self.lock:
            event_count = len(self.events)
            logger.debug("EventStore.get_events() - Returning %s live events", event_count)
            return list(self.events)

    def get_latest(self, limit=100):

        with self.lock:

            if limit <= 0:
                return list(self.events)

            return list(self.events)[:limit]

    def search(self, keyword):

        keyword = keyword.lower()

        with self.lock:

            return [

                event

                for event in self.events

                if keyword in str(event).lower()

            ]

    def filter_events(

        self,

        host=None,

        severity=None,

        event_id=None,

        process=None,

        mitre=None,

    ):

        with self.lock:

            results = []

            for event in self.events:

                e = event.get("event", {})

                d = event.get("detection", {})

                if host and e.get("host") != host:
                    continue

                if severity and d.get("severity") != severity:
                    continue

                if event_id and str(e.get("event_id")) != str(event_id):
                    continue

                if process:

                    process_name = e.get("process_name", "").lower()

                    if process.lower() not in process_name:
                        continue

                if mitre:

                    mitre_id = ""
                    mitre_raw = d.get("mitre")
                    if isinstance(mitre_raw, list):
                        for block in mitre_raw:
                            if isinstance(block, dict) and block.get("id") == mitre:
                                mitre_id = mitre
                                break
                            elif isinstance(block, str) and block == mitre:
                                mitre_id = mitre
                                break
                    elif isinstance(mitre_raw, dict):
                        mitre_id = mitre_raw.get("id", "")
                    elif mitre_raw is not None:
                        mitre_id = str(mitre_raw)

                    if mitre_id != mitre:
                        continue

                results.append(event)

            return results

    def count(self):

        with self.lock:

            return len(self.events)

    def clear(self):

        with self.lock:

            self.events.clear()


event_store = EventStore()