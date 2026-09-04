from app.registry.windows_event_registry import (
    SEVERITY_ORDER,
    SEVERITY_RANK,
    get_event_rule,
    WINDOWS_EVENT_RULES,
)


class SeverityEngine:

    def __init__(self):
        # Reverse index: detection label -> registry default severity, built
        # once from the authoritative registry so this engine can never drift
        # from the event rules.
        self._detection_severity = {}
        for rule in WINDOWS_EVENT_RULES.values():
            det = rule.get("detection")
            sev = rule.get("severity")
            if det and sev and sev in SEVERITY_RANK:
                current = self._detection_severity.get(det)
                if current is None or SEVERITY_RANK[sev] > SEVERITY_RANK[current]:
                    self._detection_severity[det] = sev

    def calculate(self, detection, event_id=None):
        """Resolve the authoritative severity for a detection result.

        A concrete severity already attached by the detection engine (which
        itself reads the registry) wins. Otherwise the Event ID's registry
        default applies — never a hardcoded fallback — so the same event always
        receives the same severity regardless of API path.
        """
        existing = detection.get("severity")

        if existing and existing in SEVERITY_RANK:
            return existing

        if event_id is not None:
            rule = get_event_rule(event_id)
            if rule and rule.get("severity") in SEVERITY_RANK:
                return rule["severity"]

        detection_name = detection.get("detection")
        if detection_name:
            mapped = self._detection_severity.get(detection_name)
            if mapped:
                return mapped

        # Registry default for unmapped telemetry (explicitly justified there).
        return get_event_rule(None)["severity"]
