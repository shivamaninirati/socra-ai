from datetime import datetime
import hashlib

from app.parsers.windows_parser import WindowsLogParser
from app.detection.windows_detection import WindowsDetection
from app.severity.severity_engine import SeverityEngine
from app.mitre.mitre_engine import MitreEngine
from app.ioc.ioc_engine import IOCEngine
from app.registry.windows_event_registry import (
    sanitize_process_name,
    normalize_process_id,
)


class EventProcessor:

    def __init__(self):

        self.parser = WindowsLogParser()

        self.detector = WindowsDetection()

        self.severity = SeverityEngine()

        self.mitre = MitreEngine()

        self.ioc = IOCEngine()

    # ----------------------------------------------------
    # Enterprise Risk Score
    # ----------------------------------------------------

    def calculate_risk(self, severity):

        mapping = {

            "Critical": 95,

            "High": 80,

            "Medium": 60,

            "Low": 30,

            "Informational": 10,

            "Unknown": 0

        }

        return mapping.get(severity, 0)

    # ----------------------------------------------------

    def generate_fingerprint(self, parsed):

        value = (

            f"{parsed.get('host','')}"
            f"{parsed.get('event_id','')}"
            f"{parsed.get('time','')}"
            f"{parsed.get('process_name','')}"

        )

        return hashlib.sha256(
            value.encode()
        ).hexdigest()

    # ----------------------------------------------------

    def process(self, event):

        # ==========================================
        # Parse Event
        # ==========================================

        parsed = self.parser.parse(event)

        # ==========================================
        # Normalize (single shared enrichment layer)
        # ------------------------------------------
        # Centralized process / PID normalization using the registry helpers
        # that every read path re-applies (idempotent): a real process name or
        # PID is preserved, and events that genuinely contain none get the
        # explicit 'Not available in event' / 'Not available' sentinels — never
        # a fabricated '[System Process]'. This is the NORMALIZER stage of the
        # pipeline, so live events, persisted rows and every consumer see the
        # exact same values.
        # ==========================================

        parsed["process_name"] = sanitize_process_name(
            parsed.get("image", ""),
            parsed.get("process_name", ""),
        )
        parsed["process_id"] = normalize_process_id(
            parsed.get("process_id", "")
        )

        # ==========================================
        # Detection
        # ==========================================

        detection = self.detector.detect(parsed)

        # ==========================================
        # Severity
        # ==========================================

        severity = self.severity.calculate(
            detection,
            parsed.get("event_id")
        )

        detection["severity"] = severity

        # ==========================================
        # MITRE
        # ==========================================

        detection["mitre"] = self.mitre.map(
            detection
        )

        # ==========================================
        # IOC Extraction
        # ==========================================

        raw_text = event.get(

            "message",

            event.get("_raw", "")

        )

        iocs = self.ioc.extract(raw_text)

        # ==========================================
        # Enterprise Metadata
        # ==========================================

        metadata = {

            "collector": "SOCRA Native Collector",

            "collector_version": "Phase-27",

            "processed_at": datetime.utcnow().isoformat(),

            "fingerprint": self.generate_fingerprint(parsed),

            "risk_score": self.calculate_risk(severity),

            "pipeline": [

                "Parser",

                "Detection",

                "Severity",

                "MITRE",

                "IOC",

                "Storage"

            ]

        }

        # ==========================================
        # Final Enterprise Event
        # ==========================================

        return {

            "event": parsed,

            "detection": detection,

            "ioc": iocs,

            "metadata": metadata

        }