from collections import Counter
from datetime import datetime
import uuid

# Canonical severity order — matches the unified registry.
SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

RISK_BY_SEVERITY = {
    "Critical": 95,
    "High": 80,
    "Medium": 60,
    "Low": 30,
    "Informational": 10,
}


class ReportGenerator:

    def generate(
        self,
        events,
        investigation=None,
        ai_findings=None,
        options=None,
    ):
        """Build an enterprise SOC report from real persisted event envelopes.

        Args:
            events: list of full persisted envelopes, each shaped
                {event, detection, ioc, metadata} exactly as stored by the
                collector pipeline (Task 6). IOCs live at the TOP LEVEL of
                the envelope ({"ips": [...], "hashes": [...]}).
            investigation: optional persisted investigation record (Task 5)
                whose real status / notes / risk score / confidence /
                process tree are included as investigation findings.
            ai_findings: optional dict {"provider", "model", "analysis"}
                with real AI analysis when available.
            options: optional dict (e.g. {"scope": "last_24h"} for metadata).

        Returns the one consistent report schema consumed by the frontend:
        report_metadata, executive_summary, investigation_statistics,
        mitre_summary, ioc_summary, detections, timeline, threat_assessment,
        containment, recovery, recommendation, final_verdict, plus
        investigation / ai_findings / resolution when available.
        """
        events = events or []

        if not events:
            return {
                "success": False,
                "error": "No security event data available to report on.",
            }

        hosts = set()
        users = set()
        processes = set()
        event_ids = set()

        severity_counter = Counter()
        mitre_counter = Counter()
        recommendations = []
        ioc_ips = set()
        ioc_hashes = set()

        detections = []
        timeline = []

        highest_severity = "Informational"
        primary_detection = None
        primary_event = None

        for item in events:
            event = item.get("event", {}) or {}
            detection = item.get("detection", {}) or {}

            host = event.get("host") or event.get("computer")
            user = event.get("user")
            process = event.get("process_name")
            event_id = event.get("event_id")

            severity = self._canonical_severity(
                detection.get("severity", "Informational")
            )

            mitre = detection.get("mitre")
            if isinstance(mitre, list):
                mitre = mitre[0] if mitre and isinstance(mitre[0], dict) else {}
            elif not isinstance(mitre, dict):
                mitre = {}

            # IOCs are stored at the TOP LEVEL of the persisted envelope
            # ({"ips": [...], "hashes": [...]}). The legacy detection.ioc
            # location is only a fallback for very old rows.
            ioc = item.get("ioc") or {}
            if not isinstance(ioc, dict):
                ioc = {}
            if not ioc and isinstance(detection.get("ioc"), dict):
                ioc = detection["ioc"]

            if host:
                hosts.add(host)
            if user:
                users.add(user)
            if process:
                processes.add(process)
            if event_id:
                event_ids.add(str(event_id))

            severity_counter[severity] += 1
            if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(highest_severity):
                highest_severity = severity
                primary_detection = detection.get("detection")
                primary_event = item

            mitre_id = mitre.get("id") if isinstance(mitre, dict) else None
            if mitre_id and mitre_id not in ("N/A", "Unknown"):
                mitre_counter[mitre_id] += 1

            # Real per-rule recommendations from the unified registry.
            rec = detection.get("recommendation")
            if rec and rec not in recommendations:
                recommendations.append(rec)

            # Real IOCs from the envelope.
            ips = ioc.get("ips") or []
            hashes = ioc.get("hashes") or []
            if isinstance(ips, list):
                ioc_ips.update(str(x) for x in ips if x)
            if isinstance(hashes, list):
                ioc_hashes.update(str(x) for x in hashes if x)

            detections.append({
                "time": event.get("time"),
                "host": host,
                "user": user,
                "event_id": event_id,
                "process": process,
                "detection": detection.get("detection"),
                "severity": severity,
                "description": detection.get("description"),
                "mitre": mitre,
                "recommendation": detection.get("recommendation"),
                "ioc": {
                    "ips": sorted(ips) if isinstance(ips, list) else [],
                    "hashes": sorted(hashes) if isinstance(hashes, list) else [],
                },
            })

            timeline.append({
                "time": event.get("time"),
                "host": host,
                "user": user,
                "event_id": event_id,
                "process": process,
                "severity": severity,
                "detection": detection.get("detection"),
            })

        timeline.sort(key=lambda x: x.get("time") or "")
        detections.sort(key=lambda x: x.get("time") or "")

        risk_score = RISK_BY_SEVERITY.get(highest_severity, 10)
        threat_level = highest_severity

        report = {
            "success": True,
            "report_metadata": {
                "report_id": str(uuid.uuid4()),
                "title": "SOCRA AI Enterprise Incident Report",
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "SOCRA AI",
                "version": "2.0",
                "scope": (options or {}).get("scope", "persisted telemetry"),
            },
            "executive_summary": {
                "overall_severity": highest_severity,
                "risk_score": risk_score,
                "primary_detection": primary_detection,
                "affected_hosts": len(hosts),
                "affected_users": len(users),
                "affected_processes": len(processes),
                "total_events": len(events),
            },
            "investigation_statistics": {
                "critical": severity_counter["Critical"],
                "high": severity_counter["High"],
                "medium": severity_counter["Medium"],
                "low": severity_counter["Low"],
                "informational": severity_counter["Informational"],
                "unique_hosts": sorted(hosts),
                "unique_users": sorted(users),
                "unique_processes": sorted(processes),
                "unique_event_ids": sorted(event_ids),
            },
            "mitre_summary": {
                "total_techniques": len(mitre_counter),
                "techniques": dict(mitre_counter),
            },
            "ioc_summary": {
                "ip_addresses": sorted(ioc_ips),
                "file_hashes": sorted(ioc_hashes),
                "total_ips": len(ioc_ips),
                "total_hashes": len(ioc_hashes),
            },
            "detections": detections,
            "timeline": timeline,
            "threat_assessment": {
                "severity": highest_severity,
                "risk_score": risk_score,
                "threat_level": threat_level,
            },
            "containment": [],
            "recovery": [],
            "recommendation": recommendations,
            "final_verdict": {
                "status": threat_level,
                "summary": self._verdict_summary(
                    highest_severity, risk_score, len(events), investigation
                ),
            },
        }

        # Real investigation findings (Task 5) when available.
        if investigation:
            report["investigation"] = {
                "id": investigation.get("id"),
                "alert_id": investigation.get("alert_id"),
                "status": investigation.get("status"),
                "severity": investigation.get("severity"),
                "host": investigation.get("host"),
                "user": investigation.get("user"),
                "process": investigation.get("process"),
                "event_id": investigation.get("event_id"),
                "timestamp": investigation.get("timestamp"),
                "mitre": investigation.get("mitre"),
                "risk_score": investigation.get("risk_score"),
                "confidence": investigation.get("confidence"),
                "notes": investigation.get("notes") or [],
                "related_event_count": len(investigation.get("related_events") or []),
                "process_tree": investigation.get("process_tree") or [],
                "created_at": investigation.get("created_at"),
                "updated_at": investigation.get("updated_at"),
            }
            # Resolution/status reflects the real lifecycle state.
            report["resolution"] = {
                "status": investigation.get("status") or "New",
                "updated_at": investigation.get("updated_at"),
            }
            # If the investigation is closed/resolved, its notes inform the verdict.
            report["final_verdict"]["status"] = (
                investigation.get("status") or threat_level
            )
            report["executive_summary"]["risk_score"] = (
                investigation.get("risk_score")
                if isinstance(investigation.get("risk_score"), (int, float))
                else risk_score
            )
            report["threat_assessment"]["risk_score"] = (
                investigation.get("risk_score")
                if isinstance(investigation.get("risk_score"), (int, float))
                else risk_score
            )

        # Real AI findings (Ollama) when available.
        if ai_findings and isinstance(ai_findings, dict):
            report["ai_findings"] = {
                "provider": ai_findings.get("provider"),
                "model": ai_findings.get("model"),
                "analysis": ai_findings.get("analysis"),
            }

        # Data-derived containment / recovery: split the real per-rule
        # recommendations by the severity of the events that produced them.
        containment, recovery = self._split_recommendations(events, detections)
        report["containment"] = containment
        report["recovery"] = recovery

        return report

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _canonical_severity(raw):
        if not raw:
            return "Informational"
        value = str(raw).capitalize()
        return value if value in SEVERITY_ORDER else "Informational"

    def _split_recommendations(self, events, detections):
        """Split real registry recommendations into containment (High/Critical
        events) and recovery (everything else). Nothing is fabricated — every
        action traces back to a detection rule that actually fired."""
        containment = []
        recovery = []
        for det in detections:
            rec = det.get("recommendation")
            if not rec:
                continue
            sev = self._canonical_severity(det.get("severity"))
            if sev in ("High", "Critical"):
                if rec not in containment:
                    containment.append(rec)
            else:
                if rec not in recovery:
                    recovery.append(rec)
        if not containment and not recovery:
            # No per-rule recommendations in the dataset — leave both empty
            # rather than emit generic boilerplate.
            return [], []
        if not containment:
            # All matched rules were informational/low: nothing is urgent.
            return [], recovery
        return containment, recovery

    @staticmethod
    def _verdict_summary(severity, risk_score, total_events, investigation):
        if investigation:
            notes = investigation.get("notes") or []
            note_text = f" Latest notes: {' | '.join(str(n.get('note', '')) for n in notes)}." if notes else ""
            return (
                f"SOCRA AI analyzed {total_events} persisted security event(s) tied to "
                f"investigation {investigation.get('id')}. Status: {investigation.get('status')}. "
                f"Overall incident severity is {severity} with a calculated risk score of "
                f"{risk_score}/100.{note_text}"
            )
        return (
            f"SOCRA AI analyzed {total_events} persisted security event(s). "
            f"Overall incident severity is {severity} with a calculated risk score of "
            f"{risk_score}/100."
        )
