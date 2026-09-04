import win32evtlog


class SysmonReader:

    """
    Reads Microsoft Sysmon Operational logs.

    Requires:
        - Sysmon installed
        - Sysmon Event Log enabled

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

    def read_latest(self, limit=100):

        events = []

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

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

                    events.append({

                        "source": "Sysmon",

                        "channel": self.channel,

                        "event_id": record.EventID & 0xFFFF,

                        "time": str(record.TimeGenerated),

                        "computer": record.ComputerName,

                        "category": record.EventCategory,

                        "type": record.EventType,

                        "record_number": record.RecordNumber

                    })

                    total += 1

                    if total >= limit:
                        break

        except Exception as e:

            print(f"[SysmonReader] {e}")

        return events