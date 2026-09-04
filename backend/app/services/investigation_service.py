from datetime import datetime, timedelta
import os
import uuid

from app.services.event_processor import EventProcessor
from app.storage.sqlite_storage import sqlite_storage
from app.routes.logs import _normalize_stored_severity
from app.routes.timeline import _build_timeline_entry

# Investigation lifecycle (Task 5)
INVESTIGATION_STATUSES = ("New", "Investigating", "Contained", "Resolved", "Closed")

RELATED_EVENT_LIMIT = 50
PROCESS_TREE_MAX_DEPTH = 4

# Users/processes that carry no investigative signal and would only add noise
# to the related-event query.
NOISE_USERS = {"", "-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "LOCALSYSTEM"}
NOISE_PROCESSES = {"", "-", "N/A", "[System Process]"}


class InvestigationService:

    def __init__(self):
        self.processor = EventProcessor()

    # ---------------------------------------------------------
    # Alert identity
    # ---------------------------------------------------------

    @staticmethod
    def _alert_id(event):
        """Stable identity for an alert: metadata fingerprint, else a fallback
        derived from real event fields (never fabricated)."""
        meta = event.get("metadata") or {}
        fp = meta.get("fingerprint")
        if fp:
            return str(fp)
        ev = event.get("event", {}) or {}
        return f"{ev.get('host', '')}|{ev.get('event_id', '')}|{ev.get('time', '')}"

    @staticmethod
    def _parse_time(value):
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00").split(".")[0])
        except Exception:
            return None

    # ---------------------------------------------------------
    # Real scores
    # ---------------------------------------------------------

    def _risk_score(self, event):
        """Use the actual metadata.risk_score produced by the collection
        pipeline; only fall back to the same deterministic severity mapping
        when the stored event predates metadata persistence."""
        meta = event.get("metadata") or {}
        score = meta.get("risk_score")
        if isinstance(score, (int, float)):
            return int(score)
        det = event.get("detection") or {}
        return self.processor.calculate_risk(det.get("severity", "Informational"))

    def _confidence(self, event, risk_score, related_count):
        """Confidence derived from real telemetry signals (never hardcoded):
        risk score, whether a real detection rule matched, whether MITRE was
        mapped, and how much corroborating context exists in related events."""
        det = event.get("detection") or {}
        score = int(risk_score)

        detection_name = str(det.get("detection", "")).strip()
        if detection_name and detection_name.lower() not in (
            "unknown", "no detection matched", "no detection rule matched.",
        ):
            score += 10

        mitre = det.get("mitre")
        if isinstance(mitre, list):
            first = mitre[0] if mitre else {}
            mitre_id = first.get("id") if isinstance(first, dict) else str(first or "")
        elif isinstance(mitre, dict):
            mitre_id = mitre.get("id", "")
        else:
            mitre_id = str(mitre or "")
        if mitre_id and mitre_id not in ("N/A", "Unknown", ""):
            score += 10

        score += min(max(related_count, 0), 5) * 2

        return max(0, min(100, int(score)))

    # ---------------------------------------------------------
    # Related events (real historical telemetry)
    # ---------------------------------------------------------

    @staticmethod
    def _basename(value):
        if not value:
            return ""
        return str(value).replace("/", "\\").split("\\")[-1].strip()

    def _same_event(self, item, event):
        """True when a stored row is the same real event as the alert."""
        e1 = item.get("event", {}) or {}
        e2 = (event.get("event") or {}) if isinstance(event, dict) else {}
        if e1.get("record_number") and e2.get("record_number"):
            return (
                e1.get("host") == e2.get("host")
                and str(e1.get("record_number")) == str(e2.get("record_number"))
            )
        return (
            e1.get("host") == e2.get("host")
            and str(e1.get("event_id")) == str(e2.get("event_id"))
            and e1.get("time") == e2.get("time")
            and e1.get("process_name") == e2.get("process_name")
        )

    def related_events(self, event, window_minutes=60):
        """Events around the alert on the same host (plus user/process when
        those fields carry signal) from real SQLite telemetry."""
        ev = event.get("event", {}) or {}
        timestamp = ev.get("time")
        ts = self._parse_time(timestamp)
        if not ts:
            return []

        time_from = (ts - timedelta(minutes=int(window_minutes))).isoformat(timespec="seconds")
        time_to = (ts + timedelta(minutes=int(window_minutes))).isoformat(timespec="seconds")

        host = ev.get("host") or ev.get("computer") or ""
        user = ev.get("user") or ""
        process = ev.get("process_name") or ""

        filters = {
            "time_from": time_from,
            "time_to": time_to,
            "host": host if host and host != "Unknown" else None,
            "user": user if user not in NOISE_USERS else None,
            "process_name": process if process not in NOISE_PROCESSES else None,
            "limit": RELATED_EVENT_LIMIT,
            "offset": 0,
        }
        qresult = sqlite_storage.query_events(filters)

        results = []
        for item in qresult.get("results", []):
            if self._same_event(item, event):
                continue
            results.append(_build_timeline_entry(item))
        return results

    # ---------------------------------------------------------
    # Real process tree (actual parser fields only)
    # ---------------------------------------------------------

    def process_tree(self, event, related_events):
        """Build a process tree from ACTUAL parser fields (process_name,
        process_id, parent_process, parent_process_id, command_line). The
        parent chain is walked across related telemetry by process id; when a
        parent is not observed in the window the real parsed parent field is
        shown with an explicit note — no fabricated fallback process."""
        ev = event.get("event", {}) or {}
        process_name = ev.get("process_name") or ev.get("image") or "Unknown"
        if process_name in NOISE_PROCESSES:
            process_name = "Unknown"
        process_id = ev.get("process_id")
        parent_process_id = ev.get("parent_process_id")
        parent_process = self._basename(ev.get("parent_process") or ev.get("parent_image") or "")
        command_line = ev.get("command_line") or ""

        current = {
            "name": process_name,
            "process_id": str(process_id) if process_id not in (None, "") else "",
            "command_line": command_line,
            "note": "",
            "children": [],
        }

        # Map related events by real process id to walk the parent chain.
        by_pid = {}
        for item in related_events:
            pid = item.get("process_id")
            if pid not in (None, ""):
                by_pid[str(pid)] = item

        chain = []
        pid = parent_process_id
        depth = 0
        while pid not in (None, "") and depth < PROCESS_TREE_MAX_DEPTH:
            parent_entry = by_pid.get(str(pid))
            if not parent_entry:
                break
            chain.append(parent_entry)
            pid = parent_entry.get("parent_process_id")
            depth += 1

        if chain:
            root = {
                "name": chain[-1].get("process") or "Unknown",
                "process_id": str(chain[-1].get("process_id") or ""),
                "command_line": (chain[-1].get("details") or {}).get("command_line") or "",
                "note": "",
                "children": [],
            }
            node = root
            for parent_entry in reversed(chain[:-1]):
                child = {
                    "name": parent_entry.get("process") or "Unknown",
                    "process_id": str(parent_entry.get("process_id") or ""),
                    "command_line": (parent_entry.get("details") or {}).get("command_line") or "",
                    "note": "",
                    "children": [],
                }
                node["children"] = [child]
                node = child
            node["children"] = [current]
            return [root]

        if parent_process and parent_process not in NOISE_PROCESSES:
            return [{
                "name": parent_process,
                "process_id": str(parent_process_id) if parent_process_id not in (None, "") else "",
                "command_line": "",
                "note": "Parent event not observed in the related-event window.",
                "children": [current],
            }]

        return [current]

    # ---------------------------------------------------------
    # Record lifecycle
    # ---------------------------------------------------------

    def _create(self, event, alert_id):
        ev = event.get("event", {}) or {}
        det = event.get("detection", {}) or {}

        mitre = det.get("mitre")
        if isinstance(mitre, list):
            first = mitre[0] if mitre else {}
            mitre_id = first.get("id") if isinstance(first, dict) else str(first or "")
        elif isinstance(mitre, dict):
            mitre_id = mitre.get("id", "")
        else:
            mitre_id = str(mitre or "")
        if not mitre_id or mitre_id in ("None", "null", "Unknown"):
            mitre_id = "N/A"

        severity = _normalize_stored_severity(det.get("severity"))
        host = ev.get("host") or ev.get("computer") or "Unknown"
        user = ev.get("user") or "SYSTEM"
        if user in ("-", "None"):
            user = "SYSTEM"
        process = ev.get("process_name") or "N/A"
        if process in ("-", "None", "null"):
            process = "N/A"
        parent_process = self._basename(ev.get("parent_process") or ev.get("parent_image") or "")
        if not parent_process:
            parent_process = "N/A"
        ioc = event.get("ioc") or det.get("ioc") or {}

        now = datetime.utcnow().isoformat(timespec="seconds")
        investigation = {
            "id": f"INV-{str(uuid.uuid4())[:8].upper()}",
            "alert_id": alert_id,
            "status": "New",
            "severity": severity,
            "host": host,
            "user": user,
            "process": process,
            "parent_process": parent_process,
            "event_id": str(ev.get("event_id", "") or ""),
            "timestamp": ev.get("time"),
            "mitre": mitre_id,
            "risk_score": self._risk_score(event),
            "confidence": None,
            "created_at": now,
            "updated_at": now,
            "notes": [],
            "ioc": ioc,
            "event": event,
            "related_events": [],
            "process_tree": [],
        }

        related = self.related_events(event, window_minutes=60)
        investigation["related_events"] = related
        investigation["process_tree"] = self.process_tree(event, related)
        investigation["confidence"] = self._confidence(
            event, investigation["risk_score"], len(related)
        )

        sqlite_storage.save_investigation(investigation)
        return investigation

    def create_or_get(self, event):
        """Create a persistent investigation for an alert, or return the
        existing record when this alert was already investigated."""
        alert_id = self._alert_id(event)
        existing = sqlite_storage.find_investigation_by_alert(alert_id)
        if existing:
            return existing
        return self._create(event, alert_id)

    def get(self, investigation_id):
        return sqlite_storage.get_investigation(investigation_id)

    def list(self):
        return sqlite_storage.get_investigations()

    def update_status(self, investigation_id, status):
        inv = sqlite_storage.get_investigation(investigation_id)
        if not inv:
            return None
        inv["status"] = status
        inv["updated_at"] = datetime.utcnow().isoformat(timespec="seconds")
        sqlite_storage.save_investigation(inv)
        return inv

    def add_note(self, investigation_id, note):
        inv = sqlite_storage.get_investigation(investigation_id)
        if not inv:
            return None
        notes = list(inv.get("notes") or [])
        notes.append({
            "time": datetime.utcnow().isoformat(timespec="seconds"),
            "note": note,
        })
        inv["notes"] = notes
        inv["updated_at"] = datetime.utcnow().isoformat(timespec="seconds")
        sqlite_storage.save_investigation(inv)
        return inv

    def refresh_related(self, investigation_id, window_minutes=60):
        """Recompute related events + process tree + confidence with a new
        configurable time window and persist the updated record."""
        inv = sqlite_storage.get_investigation(investigation_id)
        if not inv:
            return None
        event = inv.get("event") or {}
        related = self.related_events(event, window_minutes=window_minutes)
        inv["related_events"] = related
        inv["process_tree"] = self.process_tree(event, related)
        inv["confidence"] = self._confidence(
            event, inv.get("risk_score") or 0, len(related)
        )
        inv["updated_at"] = datetime.utcnow().isoformat(timespec="seconds")
        sqlite_storage.save_investigation(inv)
        return inv


investigation_service = InvestigationService()
