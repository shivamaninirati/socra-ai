import html
import re
import xml.etree.ElementTree as ET


class WindowsLogParser:

    EMPTY_VALUES = {
        "",
        "-",
        "N/A",
        "n/a",
        "None",
        "none",
        "NULL",
        "null",
        "(null)",
        None,
    }

    FIELD_ALIASES = {
        "event_id": [
            "event_id", "event_code", "eventcode", "EventCode", "EventID",
            "EventIdentifier", "EventId"
        ],
        "provider": [
            "provider", "provider_name", "ProviderName", "SourceName",
            "source_name", "Provider"
        ],
        "user": [
            "user", "username", "account_name", "AccountName",
            "TargetUserName", "SubjectUserName", "User", "TargetAccount"
        ],
        "domain": [
            "domain", "account_domain", "AccountDomain", "TargetDomainName",
            "SubjectDomainName", "TargetDomain", "Domain"
        ],
        "image": [
            "image", "process_name", "process", "Image", "NewProcessName",
            "ProcessName", "ApplicationName", "Application", "TargetImage",
            "SourceImage", "ServiceFileName", "ImagePath", "TargetProcessName"
        ],
        "parent_image": [
            "parent_image", "parent_process", "ParentImage",
            "ParentProcessName", "CreatorProcessName", "Creator_Process_Name",
            "ParentImagePath"
        ],
        "command_line": [
            "command_line", "CommandLine", "process_command_line",
            "ProcessCommandLine", "NewProcessCommandLine"
        ],
        "process_id": [
            "process_id", "ProcessId", "ProcessID", "NewProcessId",
            "NewProcessID", "SourceProcessId", "TargetProcessId",
            "ClientProcessId", "ProcessIdentifier"
        ],
        "parent_process_id": [
            "parent_process_id", "ParentProcessId", "ParentProcessID",
            "CreatorProcessId", "CreatorProcessID", "Creator_Process_Id",
            "ParentProcessIdentifier"
        ],
        "integrity_level": [
            "integrity_level", "IntegrityLevel", "MandatoryLabel"
        ],
        "hash": [
            "hash", "hashes", "Hash", "Hashes"
        ],
        "file_path": [
            "file_path", "target_filename", "TargetFilename", "FileName",
            "ObjectName", "TargetObject", "ImageLoaded"
        ],
        "service_name": [
            "service_name", "ServiceName", "Service"
        ],
        "task_name": [
            "task_name", "TaskName"
        ],
        "ip_address": [
            "ip_address", "source_ip", "SourceIp", "IpAddress", "ip",
            "ClientAddress", "ClientIPAddress", "SourceAddress"
        ],
        "destination_ip": [
            "destination_ip", "DestinationIp", "DestinationAddress",
            "DestinationHostname", "DestinationHostName", "dest_ip"
        ],
        "destination_port": [
            "destination_port", "DestinationPort", "dest_port"
        ],
        "source_port": [
            "source_port", "SourcePort"
        ],
        "protocol": [
            "protocol", "Protocol"
        ],
        "logon_type": [
            "logon_type", "LogonType"
        ],
        "workstation": [
            "workstation", "WorkstationName", "Workstation"
        ],
    }

    FIELD_PATTERNS = {
        "event_id": [
            r"\bEventCode\s*=\s*(\d+)",
            r"\bEvent ID:\s*(\d+)",
            r"\bEventID:\s*(\d+)",
            r"<EventID[^>]*>\s*(\d+)\s*</EventID>",
        ],
        "provider": [
            r"Provider Name:\s*(.+)",
            r"Source Name:\s*(.+)",
            r"<Provider[^>]+Name=['\"]([^'\"]+)['\"]",
        ],
        "user": [
            r"Target User Name:\s*(.+)",
            r"Subject User Name:\s*(.+)",
            r"Account Name:\s*(.+)",
            r"User:\s*(.+)",
        ],
        "domain": [
            r"Target Domain Name:\s*(.+)",
            r"Subject Domain Name:\s*(.+)",
            r"Account Domain:\s*(.+)",
            r"Domain:\s*(.+)",
        ],
        "image": [
            r"New Process Name:\s*(.+)",
            r"Process Name:\s*(.+)",
            r"Application Name:\s*(.+)",
            r"Image Path:\s*(.+)",
            r"Image:\s*(.+)",
        ],
        "parent_image": [
            r"Creator Process Name:\s*(.+)",
            r"Parent Process Name:\s*(.+)",
            r"Parent Image:\s*(.+)",
        ],
        "command_line": [
            r"New Process Command Line:\s*(.+)",
            r"Process Command Line:\s*(.+)",
            r"Command Line:\s*(.+)",
        ],
        "process_id": [
            r"New Process ID:\s*(.+)",
            r"Process ID:\s*(.+)",
            r"ProcessId:\s*(.+)",
        ],
        "parent_process_id": [
            r"Creator Process ID:\s*(.+)",
            r"Parent Process ID:\s*(.+)",
            r"ParentProcessId:\s*(.+)",
        ],
        "integrity_level": [
            r"Mandatory Label:\s*(.+)",
            r"Integrity Level:\s*(.+)",
        ],
        "hash": [
            r"Hashes:\s*(.+)",
            r"Hash:\s*(.+)",
        ],
        "file_path": [
            r"TargetFilename:\s*(.+)",
            r"Target Filename:\s*(.+)",
            r"File Name:\s*(.+)",
            r"Object Name:\s*(.+)",
            r"Target Object:\s*(.+)",
            r"Image Loaded:\s*(.+)",
            r"Image:\s*(.+)",
        ],
        "service_name": [
            r"Service Name:\s*(.+)",
            r"ServiceName:\s*(.+)",
        ],
        "task_name": [
            r"Task Name:\s*(.+)",
            r"TaskName:\s*(.+)",
        ],
        "ip_address": [
            r"Source Network Address:\s*(.+)",
            r"Client Address:\s*(.+)",
            r"Client IP Address:\s*(.+)",
            r"SourceIp:\s*(.+)",
            r"IpAddress:\s*(.+)",
            r"Source Address:\s*(.+)",
        ],
        "destination_ip": [
            r"Destination Address:\s*(.+)",
            r"DestinationIp:\s*(.+)",
            r"Destination Host Name:\s*(.+)",
        ],
        "destination_port": [
            r"Destination Port:\s*(.+)",
            r"DestinationPort:\s*(.+)",
        ],
        "source_port": [
            r"Source Port:\s*(.+)",
            r"SourcePort:\s*(.+)",
        ],
        "protocol": [
            r"Protocol:\s*(.+)",
        ],
        "logon_type": [
            r"Logon Type:\s*(.+)",
        ],
        "workstation": [
            r"Workstation Name:\s*(.+)",
            r"Workstation:\s*(.+)",
        ],
    }

    def _clean(self, value):

        if isinstance(value, (list, tuple)):
            for item in value:
                cleaned = self._clean(item)
                if cleaned:
                    return cleaned
            return None

        if isinstance(value, dict):
            return None

        if value in self.EMPTY_VALUES:
            return None

        cleaned = html.unescape(str(value)).strip()

        if cleaned in self.EMPTY_VALUES:
            return None

        return cleaned

    def _first(self, event, keys):

        for key in keys:
            value = self._clean(event.get(key))
            if value:
                return value

        return None

    def _field(self, event, field):

        return self._first(event, self.FIELD_ALIASES.get(field, [field]))

    def _extract(self, raw, field):

        for pattern in self.FIELD_PATTERNS.get(field, []):
            match = re.search(
                pattern,
                raw or "",
                re.MULTILINE | re.IGNORECASE
            )

            if match:
                value = self._clean(match.group(1))
                if value:
                    return value

        return ""

    def _basename(self, value):

        value = self._clean(value)
        if not value:
            return ""

        return value.replace("/", "\\").split("\\")[-1].lower()

    def _executable_from_command_line(self, command_line):

        command_line = self._clean(command_line)
        if not command_line:
            return ""

        if command_line.startswith('"'):
            end_quote = command_line.find('"', 1)
            if end_quote > 1:
                candidate = command_line[1:end_quote]
                if self._basename(candidate):
                    return candidate

        match = re.search(
            r"([a-zA-Z]:\\[^\"<>|]+?\.exe|[a-zA-Z0-9_.-]+\.exe)\b",
            command_line,
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

        return command_line.split()[0] if command_line.split() else ""

    def _local_name(self, tag):

        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    def _extract_xml_fields(self, raw):

        raw = self._clean(raw)
        if not raw or "<Event" not in raw:
            return {}

        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return {}

        fields = {}
        event_data = {}

        for element in root.iter():
            name = self._local_name(element.tag)
            text = self._clean(element.text)

            if name == "Provider":
                fields["ProviderName"] = self._clean(element.attrib.get("Name"))
            elif name == "EventID":
                fields["EventID"] = text
            elif name == "Channel":
                fields["Channel"] = text
            elif name == "Computer":
                fields["Computer"] = text
            elif name == "TimeCreated":
                fields["TimeCreated"] = self._clean(element.attrib.get("SystemTime"))
            elif name == "EventRecordID":
                fields["RecordNumber"] = text
            elif name == "Data":
                data_name = self._clean(element.attrib.get("Name"))
                if data_name:
                    event_data[data_name] = text

        fields.update(event_data)

        if event_data:
            fields["event_data"] = event_data

        return fields

    def _merge_discovered_fields(self, event, raw):

        discovered = self._extract_xml_fields(raw)
        if not discovered:
            return event

        merged = discovered.copy()
        merged.update({
            key: value
            for key, value in event.items()
            if self._clean(value)
        })

        return merged

    def _extract_string_insert_fields(self, event):

        strings = event.get("strings") or event.get("StringInserts") or []

        if not isinstance(strings, (list, tuple)):
            return {}

        values = [self._clean(value) for value in strings]

        event_id = str(
            self._field(event, "event_id")
            or self._extract(self._raw_message(event), "event_id")
        ).strip()

        if event_id == "4688" and len(values) >= 9:

            fields = {
                "SubjectUserName": values[1],
                "SubjectDomainName": values[2],
                "NewProcessId": values[4],
                "NewProcessName": values[5],
                "CreatorProcessId": values[7],
                "NewProcessCommandLine": values[8],
            }

            if len(values) > 13:
                fields["CreatorProcessName"] = values[13]

            if len(values) > 14:
                fields["MandatoryLabel"] = values[14]

            return {
                key: value
                for key, value in fields.items()
                if value
            }

        return {}

    def _raw_message(self, event):

        for key in ["message", "_raw", "raw"]:
            value = event.get(key)

            if isinstance(value, dict):
                nested = self._raw_message(value)
                if nested:
                    return nested
                continue

            value = self._clean(value)
            if value:
                return value

        return ""

    def _unwrap(self, event):

        normalized = event.get("event")

        if isinstance(normalized, dict):
            raw = normalized.get("raw")

            if isinstance(raw, dict):
                merged = raw.copy()
                merged.update({
                    key: value
                    for key, value in normalized.items()
                    if key != "raw" and value not in self.EMPTY_VALUES
                })
                return merged

            return normalized

        return event

    def parse(self, event):

        event = self._unwrap(event or {})
        raw = self._raw_message(event)
        event = self._merge_discovered_fields(event, raw)
        event = {
            **self._extract_string_insert_fields(event),
            **event,
        }

        event_id = (
            self._field(event, "event_id")
            or self._extract(raw, "event_id")
        )

        command_line = (
            self._field(event, "command_line")
            or self._extract(raw, "command_line")
        )

        image = (
            self._field(event, "image")
            or self._extract(raw, "image")
            or self._executable_from_command_line(command_line)
        )

        process_name = self._basename(image)

        parent_image = (
            self._field(event, "parent_image")
            or self._extract(raw, "parent_image")
        )

        host = self._first(event, ["computer", "host", "Computer", "hostname"])

        # Calculate process ID decimal values while preserving original hex
        raw_process_id = self._field(event, "process_id") or self._extract(raw, "process_id") or self._first(event, ["NewProcessId", "ProcessId"])
        process_id_decimal = None
        if raw_process_id and isinstance(raw_process_id, str) and raw_process_id.startswith("0x"):
            try:
                process_id_decimal = int(raw_process_id, 16)
            except:
                process_id_decimal = None

        raw_parent_process_id = self._field(event, "parent_process_id") or self._extract(raw, "parent_process_id") or self._first(event, ["CreatorProcessId", "ParentProcessId"])
        parent_process_id_decimal = None
        if raw_parent_process_id and isinstance(raw_parent_process_id, str) and raw_parent_process_id.startswith("0x"):
            try:
                parent_process_id_decimal = int(raw_parent_process_id, 16)
            except:
                parent_process_id_decimal = None

        return {

            "id": self._first(event, ["_socra_id", "id"]),

            "time": self._first(event, ["time", "_time", "timestamp", "TimeCreated"]),

            "host": host,

            "computer": host,

            "channel": self._first(event, ["channel", "source", "Channel"]),

            "source": self._first(event, ["source", "SourceName"]) or "Windows",

            "provider": (
                self._field(event, "provider")
                or self._extract(raw, "provider")
            ),

            "event_id": str(event_id).strip(),

            "event_type": self._first(event, ["event_type", "EventType"]),

            "category": self._first(event, ["category", "EventCategory"]),

            "record_number": self._first(event, ["record_number", "RecordNumber"]),

            "user": (
                self._field(event, "user")
                or self._extract(raw, "user")
                or self._first(event, ["TargetUserName", "SubjectUserName", "User"])
            ),

            "domain": (
                self._field(event, "domain")
                or self._extract(raw, "domain")
            ),

            "process_name": process_name,

            "image": image,

            "parent_process": self._basename(parent_image),

            # Normalized alias so consumers (e.g. the Investigation drawer)
            # read one canonical name — kept separate from the parent PID.
            "parent_process_name": self._basename(parent_image),

            "parent_image": parent_image,

            "command_line": (
                command_line
            ),

            "process_id": raw_process_id,
            "process_id_decimal": process_id_decimal,

            "parent_process_id": raw_parent_process_id,
            "parent_process_id_decimal": parent_process_id_decimal,

            "integrity_level": (
                self._field(event, "integrity_level")
                or self._extract(raw, "integrity_level")
            ),

            "hash": (
                self._field(event, "hash")
                or self._extract(raw, "hash")
            ),

            "file_path": (
                self._field(event, "file_path")
                or self._extract(raw, "file_path")
                or image
            ),

            "service_name": (
                self._field(event, "service_name")
                or self._extract(raw, "service_name")
            ),

            "task_name": (
                self._field(event, "task_name")
                or self._extract(raw, "task_name")
            ),

            "ip_address": (
                self._field(event, "ip_address")
                or self._extract(raw, "ip_address")
            ),

            "destination_ip": (
                self._field(event, "destination_ip")
                or self._extract(raw, "destination_ip")
            ),

            "destination_port": (
                self._field(event, "destination_port")
                or self._extract(raw, "destination_port")
            ),

            "source_port": (
                self._field(event, "source_port")
                or self._extract(raw, "source_port")
            ),

            "protocol": (
                self._field(event, "protocol")
                or self._extract(raw, "protocol")
            ),

            "logon_type": (
                self._field(event, "logon_type")
                or self._extract(raw, "logon_type")
            ),

            "workstation": (
                self._field(event, "workstation")
                or self._extract(raw, "workstation")
            ),

            "event_data": event.get("event_data", {}),

            "message": raw,

        }