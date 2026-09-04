from datetime import datetime
import uuid

from app.storage.sqlite_storage import sqlite_storage

# Real case lifecycle (Task 20) - distinct from investigation status.
CASE_STATUSES = ("Open", "Investigating", "Contained", "Resolved", "Closed")

# Priority levels match the severity vocabulary the platform already uses.
CASE_PRIORITIES = ("Critical", "High", "Medium", "Low", "Informational")


class CaseManager:
    """Persistent case management backed by SQLite (single-writer queue).

    Every mutation is queued on the same writer thread as events and
    investigations, so cases survive a backend restart and concurrent writes
    are serialized. Cases are created from REAL alerts/investigations - the
    alert event envelope plus the linked investigation id are stored with the
    case.

    Cases are shared SOC-team resources: any authenticated analyst can see and
    act on every case. Attribution (who created / updated the case) is recorded
    on the timeline via the acting user where available.
    """

    # ---------------------------------------------------------
    # Create Case
    # ---------------------------------------------------------

    def create_case(self, event, investigation_id=None, created_by=None):
        """Create a case from a real alert event (optionally linked to its
        persisted investigation). One case per alert; reuses an existing case
        when this alert was already escalated.
        """
        ev = event.get("event", {}) or {}
        det = event.get("detection", {}) or {}
        meta = event.get("metadata") or {}

        alert_id = meta.get("fingerprint")
        if not alert_id:
            alert_id = f"{ev.get('host', '')}|{ev.get('event_id', '')}|{ev.get('time', '')}"

        existing = self.find_by_alert(alert_id)
        if existing:
            return existing

        now = datetime.now().isoformat()
        case = {
            "case_id": f"SOC-{str(uuid.uuid4())[:8].upper()}",
            "status": "Open",
            "priority": det.get("severity", "Medium"),
            "title": det.get("detection", "Security Alert"),
            "host": ev.get("host") or ev.get("computer") or "Unknown",
            "event_id": str(ev.get("event_id", "") or ""),
            "user": ev.get("user") or "",
            "process": ev.get("process_name") or "",
            "assigned_to": "Unassigned",
            "alert_id": alert_id,
            "investigation_id": investigation_id,
            "created_at": now,
            "updated_at": now,
            "event": event,
            "timeline": [
                {
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "Case Created",
                    "by": created_by or "SOC Analyst",
                }
            ],
            "notes": [],
        }

        sqlite_storage.save_case(case)
        # Read-after-write consistency: the caller may list/read the case
        # immediately, so wait for the writer to commit before returning.
        sqlite_storage.flush(timeout=30.0)
        return case

    # ---------------------------------------------------------
    # Get All Cases
    # ---------------------------------------------------------

    def get_cases(self):
        return sqlite_storage.get_cases()

    # ---------------------------------------------------------
    # Get Single Case
    # ---------------------------------------------------------

    def get_case(self, case_id):
        return sqlite_storage.get_case(case_id)

    def find_by_alert(self, alert_id):
        """Return the existing case for an alert id, if any (SQL lookup)."""
        if not alert_id:
            return None
        return sqlite_storage.get_case_by_alert(alert_id)

    # ---------------------------------------------------------
    # Update Case (generic editable fields)
    # ---------------------------------------------------------

    def update_case(self, case_id, updates, changed_by=None):
        """Apply editable scalar fields (priority / title) to a case.

        ``updates`` is a dict of allowed keys mapped to their new values.
        Invalid values raise ValueError so the route can return a clear error
        instead of persisting inconsistent data.
        """
        case = self.get_case(case_id)
        if not case:
            return None

        changed = []
        for key in ("priority", "title"):
            if key not in (updates or {}):
                continue
            value = updates[key]
            if value is None or str(value).strip() == "":
                continue
            value = str(value).strip()
            if key == "priority" and value not in CASE_PRIORITIES:
                raise ValueError(
                    f"Invalid priority. Must be one of: {', '.join(CASE_PRIORITIES)}"
                )
            if case.get(key) != value:
                case[key] = value
                changed.append(key)

        if changed:
            case["updated_at"] = datetime.now().isoformat()
            action = "Updated: " + ", ".join(k.capitalize() for k in changed)
            case["timeline"].append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": action,
                "by": changed_by or "SOC Analyst",
            })
            sqlite_storage.save_case(case)
            sqlite_storage.flush(timeout=30.0)
        return case

    # ---------------------------------------------------------
    # Update Status
    # ---------------------------------------------------------

    def update_status(self, case_id, status, changed_by=None):
        if status not in CASE_STATUSES:
            raise ValueError(
                f"Invalid status. Must be one of: {', '.join(CASE_STATUSES)}"
            )
        case = self.get_case(case_id)
        if not case:
            return None
        case["status"] = status
        case["updated_at"] = datetime.now().isoformat()
        case["timeline"].append({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": f"Status changed to {status}",
            "by": changed_by or "SOC Analyst",
        })
        sqlite_storage.save_case(case)
        sqlite_storage.flush(timeout=30.0)
        return case

    # ---------------------------------------------------------
    # Assign Analyst
    # ---------------------------------------------------------

    def assign_case(self, case_id, analyst, assigned_by=None):
        case = self.get_case(case_id)
        if not case:
            return None
        case["assigned_to"] = analyst
        case["updated_at"] = datetime.now().isoformat()
        case["timeline"].append({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": f"Assigned to {analyst}",
            "by": assigned_by or "SOC Analyst",
        })
        sqlite_storage.save_case(case)
        sqlite_storage.flush(timeout=30.0)
        return case

    # ---------------------------------------------------------
    # Add Note
    # ---------------------------------------------------------

    def add_note(self, case_id, note, author=None):
        case = self.get_case(case_id)
        if not case:
            return None
        note_entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "note": note,
        }
        if author:
            note_entry["author"] = author
        case["notes"].append(note_entry)
        case["timeline"].append({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "Investigation Note Added",
            "by": author or "SOC Analyst",
        })
        case["updated_at"] = datetime.now().isoformat()
        sqlite_storage.save_case(case)
        sqlite_storage.flush(timeout=30.0)
        return case

    # ---------------------------------------------------------
    # Dashboard Statistics
    # ---------------------------------------------------------

    def statistics(self):
        stats = {
            "total": 0,
            "open": 0,
            "investigating": 0,
            "contained": 0,
            "resolved": 0,
            "closed": 0,
            # Backward-compatible aliases used by the existing frontend cards.
            "in_progress": 0,
        }
        for case in self.get_cases():
            stats["total"] += 1
            status = case.get("status") or "Open"
            if status == "Open":
                stats["open"] += 1
            elif status == "Investigating":
                stats["investigating"] += 1
                stats["in_progress"] += 1
            elif status == "Contained":
                stats["contained"] += 1
            elif status == "Resolved":
                stats["resolved"] += 1
            elif status == "Closed":
                stats["closed"] += 1
        return stats


case_manager = CaseManager()
