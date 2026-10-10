import win32evtlog
import win32evtlogutil

#_win32evtlog.EvtQuery signature (pywin32): (query, flags)
#  - query: channel path string, e.g. "Microsoft-Windows-Sysmon/Operational"
#  - flags: OR of EvtQuery* direction/path constants
#
# WARNING: On some pywin32 builds, calling EvtNext()/EvtRender() on a
# query handle segfaults (exit 139). We therefore use EvtQuery ONLY for
# the availability probe in is_available() — the actual event reading
# path stays on the legacy OpenEventLog/ReadEventLog API.
#
# CRITICAL: the legacy OpenEventLog API silently falls back to the
# Application log when asked for an unknown channel name. Calling
# OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational") returns
# a handle that reads Application records, not Sysmon records — a false
# positive that would mislabel Application events as Sysmon events.
# The modern EvtQuery API does NOT lie: it raises error(5, "Access is
# denied") when the channel ACL denies the caller, which is the honest
# outcome on a non-elevated process.

EVT_QUERY_FLAGS = (
    win32evtlog.EvtQueryChannelPath
    | win32evtlog.EvtQueryReverseDirection
    | win32evtlog.EvtQueryTolerateQueryErrors
)


class SysmonReader:

    """
    Reads Microsoft Sysmon Operational logs.

    OPTIONAL source: Sysmon may not be installed or configured. Call
    is_available() before registering this reader with the collector — a
    missing channel must never break the other sources.

    Requires:
        - Sysmon installed
        - Sysmon Event Log enabled
        - Process has read access to the channel (elevated process, or
          an ACL grant such as "SO" SID S-1-5-32-573)

    Event IDs:
        1  - Process Create
        3  - Network Connection
        7  - Image Loaded
        8  - Create Remote Thread
        11 - File Create
        12 - Registry Object Create/Delete
        13 - Registry Value Set
        22 - DNS Query
    """

    def __init__(self):

        self.server = "localhost"

        self.channel = "Microsoft-Windows-Sysmon/Operational"

        # Per-channel read errors (surfaced to the collector's source status)
        self.channel_errors = {}

        self.last_error = None

    def is_available(self):
        """Probe the Sysmon channel without reading any events.

        Uses the modern EvtQuery API (not the legacy OpenEventLog API)
        because OpenEventLog silently falls back to the Application log
        when asked for an unknown channel — returning a "success" handle
        that actually reads Application records, not Sysmon records.
        EvtQuery is honest: it raises error(5) "Access is denied" when
        the channel ACL denies this process.

        Returns (ok, detail): ok is True when the channel exists and the
        caller has read access. Never raises — a missing/unavailable
        channel is a normal, optional condition, not a collector failure.
        """
        try:
            win32evtlog.EvtQuery(self.channel, EVT_QUERY_FLAGS)
            return True, None
        except win32evtlog.error as exc:
            # error(5) = access denied (channel installed, ACL blocks us)
            # error(15007) = channel not found (Sysmon not installed)
            winerror = getattr(exc, "winerror", None)
            if winerror is None and exc.args:
                winerror = exc.args[0] if isinstance(exc.args[0], int) else None
            if winerror == 5:
                return False, "Sysmon channel present but access denied (run elevated to read)"
            if winerror == 15007:
                return False, "Sysmon channel not found (Sysmon not installed)"
            return False, str(exc)
        except Exception as e:
            return False, str(e)

    def _format_message(self, record):
        try:
            return win32evtlogutil.SafeFormatMessage(record, self.channel) or ""
        except Exception:
            return ""

    def read_latest(self, limit=100):

        events = []

        self.channel_errors.pop(self.channel, None)

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        handle = None

        try:

            handle = win32evtlog.OpenEventLog(
                self.server,
                self.channel
            )

            total = 0

            while total < limit:

                records = win32evtlog.ReadEventLog(
                    handle,
                    flags,
                    0
                )

                if not records:
                    break

                for record in records:

                    # One malformed record must not abort the whole channel
                    # batch — skip it and keep reading.
                    try:
                        time_generated = record.TimeGenerated
                        if hasattr(time_generated, "isoformat"):
                            time_value = time_generated.isoformat()
                        else:
                            time_value = str(time_generated)

                        message = self._format_message(record)
                        computer = getattr(record, "ComputerName", "") or ""
                        provider = getattr(record, "SourceName", None) or "Sysmon"

                        events.append({

                            "source": "Sysmon",

                            "channel": self.channel,

                            # Provider read from the record itself (never invented)
                            "provider": provider,

                            "event_id": record.EventID & 0xFFFF,

                            # ISO format — identical shape to WindowsEventReader
                            # so merged multi-source sorting stays correct
                            "time": time_value,

                            "host": computer,

                            "computer": computer,

                            "category": record.EventCategory,

                            "type": record.EventType,

                            "record_number": record.RecordNumber,

                            "message": message,

                            "_raw": message,

                            "strings": list(record.StringInserts or [])
                        })

                    except Exception as record_error:

                        self.channel_errors[self.channel] = str(record_error)

                        continue

                    total += 1

                    if total >= limit:
                        break

            self.last_error = None

        except Exception as e:

            # Propagate so the collector's per-source isolation records the
            # failure in source_status instead of pretending success. The
            # collector only reads this channel after is_available() passed.
            self.last_error = str(e)
            raise

        finally:
            if handle is not None:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass

        return events
