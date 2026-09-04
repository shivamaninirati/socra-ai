"""
Task 7 — UNIFY EVENT ID AND SEVERITY LOGIC

Verifies that the single authoritative Event ID registry
(app/registry/windows_event_registry.py) drives identical severities across
every backend path for the required Event IDs:

    4624  4625  4688  4697  4720  4732
    4768  4769  4776  5140  5156  7045

Paths checked per Event ID:
  1. registry.get_event_rule()          — registry default severity
  2. registry.enrich_log_payload()      — /logs + /timeline + /enterprise display
  3. SeverityEngine.calculate()         — collection-time severity engine
  4. WindowsDetection().detect()        — full detection engine output
  5. EventProcessor().process()         — end-to-end pipeline (stored envelope)
All must agree, and no path may reclassify a registry-known event as
Unknown/Informational against the registry.

Run:  python test_event_registry.py
"""

from app.registry.windows_event_registry import (
    WINDOWS_EVENT_RULES,
    get_event_rule,
    enrich_log_payload,
    SEVERITY_RANK,
    SEVERITY_ORDER,
)
from app.severity.severity_engine import SeverityEngine
from app.detection.windows_detection import WindowsDetection
from app.services.event_processor import EventProcessor

REQUIRED_IDS = ["4624", "4625", "4688", "4697", "4720", "4732",
                "4768", "4769", "4776", "5140", "5156", "7045"]

# Expected canonical severities from the authoritative registry
# (rules-first merge, matches stored telemetry where present).
EXPECTED = {
    "4624": "Low",
    "4625": "Medium",
    "4688": "Medium",
    "4697": "High",
    "4720": "High",
    "4732": "High",
    "4768": "Low",
    "4769": "Low",
    "4776": "Low",
    "5140": "Low",
    "5156": "Informational",
    "7045": "Critical",
}

FAILURES = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
    if not condition:
        FAILURES.append(name)


def main():
    print("=" * 70)
    print("TASK 7 — UNIFIED EVENT ID / SEVERITY REGISTRY TESTS")
    print("=" * 70)

    # ---------------------------------------------------------------
    # 1. Every required Event ID exists in the registry with a valid severity
    # ---------------------------------------------------------------
    print("\n--- 1. Registry coverage ---")
    for eid in REQUIRED_IDS:
        rule = WINDOWS_EVENT_RULES.get(eid)
        check(f"registry has {eid}", rule is not None)
        if rule:
            check(
                f"{eid} severity in taxonomy",
                rule["severity"] in SEVERITY_RANK,
                rule["severity"],
            )
            check(
                f"{eid} has name + detection + mitre",
                bool(rule.get("name")) and bool(rule.get("detection"))
                and bool(rule.get("mitre", {}).get("id")),
                f"{rule.get('name')} | {rule.get('mitre', {}).get('id')}",
            )
            check(
                f"{eid} expected {EXPECTED[eid]}",
                rule["severity"] == EXPECTED[eid],
                rule["severity"],
            )

    # ---------------------------------------------------------------
    # 2. Same severity across every backend path
    # ---------------------------------------------------------------
    print("\n--- 2. Cross-path severity consistency ---")
    detector = WindowsDetection()
    severity_engine = SeverityEngine()
    processor = EventProcessor()

    for eid in REQUIRED_IDS:
        expected = EXPECTED[eid]
        paths = {}

        rule = get_event_rule(eid)
        paths["registry"] = rule["severity"]

        enriched = enrich_log_payload(eid, "")
        paths["enrich"] = enriched["severity"]

        detection = detector.detect({"event_id": int(eid), "host": "TEST-HOST"})
        paths["detection"] = detection["severity"]

        sev = severity_engine.calculate(detection, event_id=int(eid))
        paths["severity_engine"] = sev

        processed = processor.process(
            {"event_id": int(eid), "host": "TEST-HOST", "message": "test event"}
        )
        paths["pipeline"] = processed["detection"]["severity"]

        ok = all(v == expected for v in paths.values())
        check(
            f"{eid} consistent across paths",
            ok,
            " | ".join(f"{k}={v}" for k, v in paths.items()),
        )
        if not ok:
            check(f"{eid} matches expected {expected}", False, str(paths))

    # ---------------------------------------------------------------
    # 3. No Unknown -> Informational misclassification for known IDs
    # ---------------------------------------------------------------
    print("\n--- 3. Unknown handling ---")
    for eid in REQUIRED_IDS:
        rule = WINDOWS_EVENT_RULES.get(eid)
        if rule and rule["severity"] != "Informational":
            enriched = enrich_log_payload(eid, "Unknown")
            check(
                f"{eid} stored 'Unknown' resolves to registry severity",
                enriched["severity"] == rule["severity"],
                enriched["severity"],
            )

    # Registry default for genuinely unmapped IDs is explicitly defined
    # (not a bare code fallback) — and it is Informational by design.
    default_rule = get_event_rule("999999")
    check(
        "unmapped ID gets explicit registry default",
        default_rule["severity"] in SEVERITY_RANK
        and default_rule["detection"] == "No Detection Matched",
        default_rule["severity"],
    )

    # ---------------------------------------------------------------
    # 4. Detection names resolve through the registry (severity engine)
    # ---------------------------------------------------------------
    print("\n--- 4. Detection-name resolution ---")
    sev_engine = SeverityEngine()
    for eid in REQUIRED_IDS:
        rule = WINDOWS_EVENT_RULES.get(eid)
        if rule and rule.get("detection"):
            resolved = sev_engine.calculate({"detection": rule["detection"]})
            check(
                f"detection '{rule['detection']}' -> {rule['severity']}",
                resolved == rule["severity"],
                resolved,
            )

    # ---------------------------------------------------------------
    # 5. Registry integrity
    # ---------------------------------------------------------------
    print("\n--- 5. Registry integrity ---")
    for key, rule in WINDOWS_EVENT_RULES.items():
        check(
            f"rule {key} has all fields",
            all(k in rule for k in ("name", "cat", "detection", "severity",
                                    "mitre", "description", "recommendation")),
            rule.get("severity"),
        )
        check(
            f"rule {key} mitre complete",
            all(k in rule["mitre"] for k in ("id", "technique", "tactic")),
        )

    print("\n" + "=" * 70)
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} checks")
        for f in FAILURES:
            print("  -", f)
        raise SystemExit(1)
    print(f"ALL {len(REQUIRED_IDS)} EVENT IDS VERIFIED — no failures")
    print("=" * 70)


if __name__ == "__main__":
    main()
