from datetime import datetime


class EventNormalizer:

    """
    Converts every log source into the SOCRA AI event format.

    Windows
    Sysmon
    EVTX
    JSON
    Splunk

    → One common structure
    """

    def normalize_windows(self, event):
        # Preserve ALL parsed fields from windows_parser - only set defaults for missing fields
        normalized_event = {
            "source": "Windows",
            # Preserve existing host/computer - don't overwrite!
            "host": event.get("host") or event.get("computer", None),
            "channel": event.get("channel", None),
            "event_id": event.get("event_id", None),
            "time": event.get("time", str(datetime.utcnow())),
            # Preserve all process fields - critical!
            "process_name": event.get("process_name", None),
            "process_id": event.get("process_id", None),
            "process_id_decimal": event.get("process_id_decimal", None),
            "parent_process_name": event.get("parent_process_name", None),
            "parent_process_id": event.get("parent_process_id", None),
            "parent_process_id_decimal": event.get("parent_process_id_decimal", None),
            "command_line": event.get("command_line", None),
            "user": event.get("user", None),
            "subject_user": event.get("subject_user", None),
            "subject_domain": event.get("subject_domain", None),
            "ip": event.get("ip", None),
            "source_address": event.get("source_address", None),
            "token_elevation_type": event.get("token_elevation_type", None),
            "mandatory_label": event.get("mandatory_label", None),
            "provider": event.get("provider", None),
            "level": event.get("level", None),
            # Always preserve the raw event
            "raw": event
        }
        # Remove any keys that were already in the input event to avoid duplicates
        # Merge all existing event fields into normalized_event - preserve everything!
        for key, value in event.items():
            if key not in normalized_event:
                normalized_event[key] = value
        
        return {
            "event": normalized_event,
            "detection": {
                "severity": "Low",
                "mitre": "Unknown",
                "ioc": [],
                "status": "New"
            }
        }

    def normalize_sysmon(self, event):

        return {

            "event": {

                "source": "Sysmon",

                "host": event.get("computer", ""),

                "channel": "Sysmon",

                "event_id": event.get("event_id", ""),

                "time": event.get("time", ""),

                "process_name": event.get("image", ""),

                "user": event.get("user", ""),

                "ip": event.get("ip", ""),

                "raw": event

            },

            "detection": {

                "severity": "Low",

                "mitre": "Unknown",

                "ioc": [],

                "status": "New"

            }

        }


normalizer = EventNormalizer()