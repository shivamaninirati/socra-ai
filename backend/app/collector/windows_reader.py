import win32evtlog
import win32evtlogutil


class WindowsEventReader:

    def __init__(self):

        self.server = "localhost"

        # Enterprise channels
        self.channels = [
            "Security",
            "System",
            "Application"
        ]

        # Per-channel read errors (surfaced to the collector's source status)
        self.channel_errors = {}

        print(
            f"[Windows Reader] Initialized for channels: {self.channels}"
        )

    def _read_channel(self, channel, limit):

        events = []

        # Errors from the previous poll are superseded by this poll's result.
        self.channel_errors.pop(channel, None)

        handle = None

        try:

            handle = win32evtlog.OpenEventLog(
                self.server,
                channel
            )

            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                |
                win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            while len(events) < limit:

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

                        try:

                            message = win32evtlogutil.SafeFormatMessage(
                                record,
                                channel
                            )

                        except Exception:

                            message = ""

                        # Extract user information from record
                        user = ""
                        if hasattr(record, 'User') and record.User:
                            user = record.User
                        elif record.StringInserts and len(record.StringInserts) > 5:  # Common position for user in many events
                            user = record.StringInserts[5]

                        # Extract process information from StringInserts when available
                        process_id = ""
                        process_name = ""
                        command_line = ""
                        if record.StringInserts:
                            # Try to extract PID and process name from common event formats
                            for s in record.StringInserts:
                                if s and str(s).isdigit() and len(str(s)) <= 6:  # PID is typically a number < 65535
                                    process_id = s
                                elif s and '\\' in s and ('.exe' in s.lower() or '\\' in s):
                                    if not process_name:
                                        process_name = s
                                elif s and len(s) > 20 and ' ' in s:  # Likely a command line
                                    command_line = s

                        events.append({
                            "record_number": record.RecordNumber,
                            "event_id": record.EventID & 0xFFFF,
                            "time": record.TimeGenerated.isoformat(),
                            "host": record.ComputerName,
                            "computer": record.ComputerName,
                            "channel": channel,
                            "source": record.SourceName,
                            "provider": record.SourceName,
                            "category": record.EventCategory,
                            "event_type": record.EventType,
                            "user": user,
                            "process_id": process_id,
                            "process_name": process_name,
                            "command_line": command_line,
                            "message": message,
                            "_raw": message,
                            "strings": record.StringInserts or []
                        })

                    except Exception as record_error:

                        self.channel_errors[channel] = str(record_error)

                        continue

                    if len(events) >= limit:
                        break

        except Exception as e:

            self.channel_errors[channel] = str(e)

            print(
                f"[Windows Reader] {channel}: {e}"
            )

        finally:

            if handle is not None:

                try:

                    win32evtlog.CloseEventLog(handle)

                except Exception:

                    pass

        return events

    def read_latest(self, limit=100):

        all_events = []

        if not self.channels:
            return []

        per_channel = max(20, limit // len(self.channels))

        for channel in self.channels:

            all_events.extend(

                self._read_channel(
                    channel,
                    per_channel
                )

            )

        all_events.sort(

            key=lambda x: x.get("time", ""),

            reverse=True

        )

        return all_events[:limit]
