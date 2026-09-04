"""Event-Level IOC Extraction — deep field-aware extraction from full event envelope.

Inspects structured fields, raw XML, EventData, and command lines to extract
IOCs with evidence sources for analyst trust. Never fabricates IOCs.
"""

import re
import json
import logging
import xml.etree.ElementTree as ET
import ipaddress

from app.ioc.ip_extractor import IPExtractor
from app.ioc.hash_extractor import HashExtractor

logger = logging.getLogger(__name__)

# Windows fields known to contain IP addresses
_IP_FIELDS = {
    "IpAddress", "SourceIp", "SourceIP", "DestinationIp", "DestinationIP",
    "RemoteAddress", "LocalAddress", "ClientAddress", "ServerAddress",
    "SourceNetworkAddress", "DestinationNetworkAddress", "NetworkAddress",
    "RemoteHost", "ClientIP", "WorkstationAddress", "source_address",
}

# Windows fields known to contain user info
_USER_FIELDS = {
    "TargetUserName", "SubjectUserName", "AccountName",
}

# Noise values that are not real IOCs
_NOISE_IPS = {"", "-", "None", "null", "MANI", "LOCALHOST", "localhost", "0.0.0.0", "255.255.255.255"}
_NOISE_USERS = {"", "-", "None", "null", "SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE"}
_NOISE_HOSTS = {"", "-", "None", "null", "Unknown"}

# Regex for domain extraction (simple but avoids noise)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,10}\b")
# Regex for URL extraction
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s<>\"']{5,500}", re.IGNORECASE)


def _is_valid_ip(value):
    """Check if a string is a real IP address (not a hostname, PID, etc)."""
    value = (value or "").strip()
    if not value or value.lower() in _NOISE_IPS:
        return False
    try:
        addr = ipaddress.ip_address(value)
        if addr.is_loopback and value != "127.0.0.1":
            return False
        return True
    except ValueError:
        return False


def _classify_ip(value):
    """Classify IP as Public/Private/Loopback etc."""
    try:
        addr = ipaddress.ip_address(value.strip())
        if addr.is_private:
            return "Private / Local"
        if addr.is_loopback:
            return "Loopback"
        if addr.is_link_local:
            return "Link-local"
        if addr.is_multicast:
            return "Multicast"
        return "Public"
    except ValueError:
        return "Unknown"


def _is_valid_hash(value):
    """Check if a string is a real hash (MD5/SHA-1/SHA-256)."""
    value = (value or "").strip().lower()
    if not value:
        return False
    if re.fullmatch(r"[a-f0-9]{32}", value):
        return "MD5"
    if re.fullmatch(r"[a-f0-9]{40}", value):
        return "SHA-1"
    if re.fullmatch(r"[a-f0-9]{64}", value):
        return "SHA-256"
    return False


def _is_noise_domain(domain):
    """Filter out XML namespace URLs, Windows schema URLs, process names, and noise domains."""
    domain = (domain or "").lower()
    noise = {
        "example.com", "example.org", "example.net",
        "schemas.microsoft.com", "www.w3.org", "schemas.openxmlformats.org",
        "schemas.openxmlformats.org", "microsoft.com",
        "localhost", "localdomain",
    }
    if domain in noise:
        return True
    # Skip XML namespace-like domains
    if "schemas." in domain or "xmlns" in domain:
        return True
    # Skip common Windows executables and process-like strings
    base = domain.split(".")[0]
    win_exes = {
        "powershell", "cmd", "svchost", "explorer", "lsass", "csrss",
        "services", "wininit", "winlogon", "smss", "conhost", "dismhost",
        "taskhostw", "runtimebroker", "searchprotocolhost", "searchfilterhost",
        "backgroundtaskhost", "dllhost", "gpupdate", "whoami", "net", "ipconfig",
        "system", "null", "none", "nul", "com", "con", "prn", "aux",
    }
    if base in win_exes:
        return True
    # Skip if TLD is too short or looks like an executable extension
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    exe_tlds = {"exe", "dll", "sys", "drv", "ocx", "cpl", "msc", "scr", "bat", "cmd", "ps1", "vbs", "js"}
    if tld in exe_tlds:
        return True
    return False


class EventIOCExtractor:
    """Extract IOCs from a SOCRA event envelope with full evidence tracking."""

    def __init__(self):
        self.ip_extractor = IPExtractor()
        self.hash_extractor = HashExtractor()

    def extract_from_event(self, event_data):
        """Extract IOCs from a complete SOCRA event envelope.

        Returns categorized IOCs with evidence sources:
        {
            "ips": [{"value": "1.2.3.4", "type": "IPv4", "role": "Source IP",
                     "field": "IpAddress", "source_event": "4625"}],
            "domains": [{"value": "example.com", "field": "CommandLine", "source_event": "4688"}],
            "urls": [{"value": "https://...", "field": "CommandLine", "source_event": "4688"}],
            "hashes": [{"value": "abc...", "type": "SHA-256", "field": "Hashes", "source_event": "Sysmon"}],
            "users": ["MANI"],
            "processes": ["powershell.exe"],
            "checked_fields": ["IP addresses", "Domains", ...],
        }
        """
        ev = event_data.get("event", {}) if isinstance(event_data, dict) else {}
        det = event_data.get("detection", {}) if isinstance(event_data, dict) else {}
        raw_event = ev.get("raw", {}) if isinstance(ev.get("raw"), dict) else {}

        event_id = str(ev.get("event_id", "") or raw_event.get("EventID", ""))
        host = ev.get("host") or raw_event.get("Computer", "")

        ips = []
        domains = []
        urls = []
        hashes = []
        users = set()
        processes = set()

        seen_ips = set()
        seen_domains = set()
        seen_urls = set()
        seen_hashes = set()

        evidence_tag = f"Event {event_id}" if event_id else "Event"

        def _add_ip(value, role="IP Address", field="", source_event=""):
            norm = (value or "").strip()
            if not norm or norm in seen_ips or not _is_valid_ip(norm):
                return
            seen_ips.add(norm)
            ips.append({
                "value": norm,
                "type": "IPv4" if ":" not in norm else "IPv6",
                "classification": _classify_ip(norm),
                "role": role,
                "field": field,
                "source_event": source_event or evidence_tag,
            })

        def _add_domain(value, field="", source_event=""):
            norm = (value or "").strip().lower().rstrip(".")
            if not norm or norm in seen_domains or len(norm) < 4 or _is_noise_domain(norm):
                return
            # Skip if it looks like an IP
            parts = norm.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return
            seen_domains.add(norm)
            domains.append({
                "value": norm,
                "field": field,
                "source_event": source_event or evidence_tag,
            })

        def _add_url(value, field="", source_event=""):
            norm = (value or "").strip()
            if not norm or norm in seen_urls or len(norm) < 10:
                return
            seen_urls.add(norm)
            urls.append({
                "value": norm,
                "field": field,
                "source_event": source_event or evidence_tag,
            })
            # Extract domain from URL too
            try:
                from urllib.parse import urlparse
                parsed = urlparse(norm)
                if parsed.hostname:
                    _add_domain(parsed.hostname, field=field, source_event=source_event)
            except Exception:
                pass

        def _add_hash(value, h_type="", field="", source_event=""):
            norm = (value or "").strip().lower()
            if not norm or norm in seen_hashes:
                return
            if not h_type:
                h_type = _is_valid_hash(norm)
                if not h_type:
                    return
            seen_hashes.add(norm)
            hashes.append({
                "value": norm,
                "type": h_type,
                "field": field,
                "source_event": source_event or evidence_tag,
            })

        # ─── 1. Structured Fields ──────────────────────────────
        for field_name in _IP_FIELDS:
            val = ev.get(field_name) or raw_event.get(field_name, "")
            if val and isinstance(val, str) and val.strip() not in _NOISE_IPS:
                role = "IP Address"
                lower = field_name.lower()
                if "source" in lower:
                    role = "Source IP"
                elif "destination" in lower or "dest" in lower:
                    role = "Destination IP"
                elif "remote" in lower:
                    role = "Remote IP"
                elif "local" in lower:
                    role = "Local IP"
                elif "client" in lower:
                    role = "Client IP"
                for ip in self.ip_extractor.extract(val):
                    _add_ip(ip, role=role, field=field_name, source_event=evidence_tag)

        # ev.ip and ev.source_address
        for src_field in ("ip", "source_address"):
            val = ev.get(src_field, "")
            if val and isinstance(val, str):
                for ip in self.ip_extractor.extract(val):
                    _add_ip(ip, role="Source IP" if src_field == "source_address" else "IP Address",
                            field=src_field, source_event=evidence_tag)

        # Command line inspection
        cmd_line = ev.get("command_line") or raw_event.get("CommandLine", "")
        if cmd_line and isinstance(cmd_line, str):
            for ip in self.ip_extractor.extract(cmd_line):
                _add_ip(ip, role="Command Line IP", field="CommandLine", source_event=evidence_tag)
            for url in _URL_RE.findall(cmd_line):
                _add_url(url, field="CommandLine", source_event=evidence_tag)
            for domain in _DOMAIN_RE.findall(cmd_line):
                _add_domain(domain, field="CommandLine", source_event=evidence_tag)
            for h in self.hash_extractor.extract(cmd_line):
                if isinstance(h, dict):
                    _add_hash(h.get("value", ""), h.get("type", ""), field="CommandLine", source_event=evidence_tag)
                else:
                    _add_hash(h, field="CommandLine", source_event=evidence_tag)

        # Process name
        proc = ev.get("process_name", "")
        if proc and isinstance(proc, str) and proc not in ("-", "None", ""):
            processes.add(proc.split("\\")[-1])

        # Users
        for u_field in _USER_FIELDS:
            val = ev.get(u_field) or raw_event.get(u_field, "")
            if val and isinstance(val, str) and val.strip() not in _NOISE_USERS:
                users.add(val.strip())

        # Also check general user field
        user_val = ev.get("user", "")
        if user_val and isinstance(user_val, str) and user_val.strip() not in _NOISE_USERS:
            users.add(user_val.strip())

        # ─── 2. EventData dict inspection ──────────────────────
        event_data_block = raw_event.get("EventData", {})
        if isinstance(event_data_block, str):
            try:
                event_data_block = json.loads(event_data_block)
            except Exception:
                event_data_block = {}

        if isinstance(event_data_block, dict):
            for field_name, field_value in event_data_block.items():
                if not field_name or not field_value or not isinstance(field_value, str):
                    continue
                if field_value.strip() in ("-", "None", "", "MANI"):
                    continue

                field_lower = field_name.lower()
                # IP fields in EventData
                if any(ip_key in field_lower for ip_key in ("ipaddress", "sourceip", "destinationip",
                    "remoteaddress", "localaddress", "clientaddress", "serveraddress")):
                    role = "IP Address"
                    if "source" in field_lower:
                        role = "Source IP"
                    elif "destination" in field_lower:
                        role = "Destination IP"
                    elif "remote" in field_lower:
                        role = "Remote IP"
                    for ip in self.ip_extractor.extract(field_value):
                        _add_ip(ip, role=role, field=f"EventData.{field_name}", source_event=evidence_tag)

                # User fields in EventData
                if any(u_key in field_lower for u_key in ("username", "accountname", "targetusername", "subjectusername")):
                    if field_value.strip() not in _NOISE_USERS:
                        users.add(field_value.strip())

                # Hash fields in EventData
                if any(h_key in field_lower for h_key in ("hash", "sha", "md5")):
                    for h in self.hash_extractor.extract(field_value):
                        if isinstance(h, dict):
                            _add_hash(h.get("value", ""), h.get("type", ""), field=f"EventData.{field_name}", source_event=evidence_tag)
                        else:
                            _add_hash(h, field=f"EventData.{field_name}", source_event=evidence_tag)

        # ─── 3. Raw XML string inspection ──────────────────────
        raw_xml = raw_event.get("raw_xml") or raw_event.get("Xml", "")
        if raw_xml and isinstance(raw_xml, str) and len(raw_xml) > 10:
            try:
                cleaned = re.sub(r'xmlns[^"]*"[^"]*"', '', raw_xml)
                root = ET.fromstring(cleaned)
                for data_elem in root.iter("Data"):
                    name = data_elem.get("Name", "")
                    value = (data_elem.text or "").strip()
                    if not value or value in ("-", "None", "", "MANI"):
                        continue
                    name_lower = name.lower()
                    if any(ip_key in name_lower for ip_key in ("ipaddress", "sourceip", "destinationip",
                        "remoteaddress", "localaddress", "clientaddress", "serveraddress")):
                        role = "IP Address"
                        if "source" in name_lower:
                            role = "Source IP"
                        elif "destination" in name_lower:
                            role = "Destination IP"
                        for ip in self.ip_extractor.extract(value):
                            _add_ip(ip, role=role, field=f"XML.{name}", source_event=evidence_tag)
                    if any(u_key in name_lower for u_key in ("username", "accountname")):
                        if value not in _NOISE_USERS:
                            users.add(value)
                    if any(h_key in name_lower for h_key in ("hash", "sha", "md5")):
                        for h in self.hash_extractor.extract(value):
                            if isinstance(h, dict):
                                _add_hash(h.get("value", ""), h.get("type", ""), field=f"XML.{name}", source_event=evidence_tag)
                            else:
                                _add_hash(h, field=f"XML.{name}", source_event=evidence_tag)
                    if "url" in name_lower:
                        for url in _URL_RE.findall(value):
                            _add_url(url, field=f"XML.{name}", source_event=evidence_tag)
            except ET.ParseError:
                pass
            except Exception:
                pass

        # ─── 4. Full raw event scan (fallback only) ─────────────
        raw_text = json.dumps(raw_event) if raw_event else ""
        if raw_text:
            if not seen_ips:
                for ip in self.ip_extractor.extract(raw_text):
                    _add_ip(ip, role="Raw Event", field="raw_event", source_event=evidence_tag)
            if not seen_urls:
                for url in _URL_RE.findall(raw_text):
                    _add_url(url, field="raw_event", source_event=evidence_tag)

        return {
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "hashes": hashes,
            "users": sorted(users),
            "processes": sorted(processes),
            "event_id": event_id,
            "host": host,
            "checked_fields": [
                "IP addresses", "Domains", "URLs", "File hashes",
                "Command line", "EventData", "Raw XML", "User fields",
            ],
        }


event_ioc_extractor = EventIOCExtractor()
