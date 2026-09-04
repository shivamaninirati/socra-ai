from app.core.logger import get_module_logger
from app.rules.failed_login import FailedLoginRule
from app.rules.successful_login import SuccessfulLoginRule
from app.rules.process_creation import ProcessCreationRule

logger = get_module_logger("detection.windows_detection")

from app.registry.windows_event_registry import (
    get_event_rule,
    get_process_rule,
    SEVERITY_ORDER,
    DEFAULT_EVENT_RULE,
)


class WindowsDetection:

    def __init__(self):

        self.rules = [

            # -------------------------------------------------
            # Authentication
            # -------------------------------------------------

            FailedLoginRule(),

            SuccessfulLoginRule(),

            # -------------------------------------------------
            # Process Monitoring
            # -------------------------------------------------

            ProcessCreationRule(),

            # -------------------------------------------------
            # Future Enterprise Rules
            # -------------------------------------------------

            # PowerShellRule()
            # ServiceCreationRule()
            # ScheduledTaskRule()
            # RegistryPersistenceRule()
            # WMIExecutionRule()
            # RDPBruteforceRule()
            # LsassAccessRule()
            # EncodedPowerShellRule()
            # DefenderTamperingRule()
            # SuspiciousNetworkRule()

        ]

    def _complete_detection(self, detection, event):

        base = get_event_rule(
            event.get("event_id")
        )

        completed = {}
        completed.update(base)
        completed.update(detection or {})

        completed.setdefault("detection", DEFAULT_EVENT_RULE["detection"])
        completed.setdefault("severity", DEFAULT_EVENT_RULE["severity"])
        completed.setdefault("mitre", DEFAULT_EVENT_RULE["mitre"])
        completed.setdefault(
            "description",
            DEFAULT_EVENT_RULE["description"]
        )
        completed.setdefault(
            "recommendation",
            DEFAULT_EVENT_RULE["recommendation"]
        )

        return completed

    def detect(self, event):

        matched = []

        # -------------------------------------------------
        # Enterprise Process Intelligence
        # -------------------------------------------------

        process_rule = get_process_rule(

            event.get("process_name")
            or event.get("image")
            or event.get("command_line")

        )

        if process_rule:

            return self._complete_detection(
                process_rule,
                event
            )

        # -------------------------------------------------
        # Custom Detection Rules
        # -------------------------------------------------

        for rule in self.rules:

            try:

                result = rule.check(event)

                if result:

                    matched.append(result)

            except Exception as e:

                logger.error("Detection rule error: %s", e, exc_info=True)

        # -------------------------------------------------
        # Highest Severity Wins
        # -------------------------------------------------

        if matched:

            severity_order = {
                name: i for i, name in enumerate(SEVERITY_ORDER)
            }

            matched.sort(

                key=lambda x: severity_order.get(

                    x.get("severity", "Unknown"),

                    0

                ),
                reverse=True

            )

            return self._complete_detection(
                matched[0],
                event
            )

        # -------------------------------------------------
        # Windows Event Knowledge Base
        # -------------------------------------------------

        event_rule = get_event_rule(

            event.get("event_id")

        )

        if event_rule:

            return self._complete_detection(
                event_rule,
                event
            )

        # -------------------------------------------------
        # Default
        # -------------------------------------------------

        return self._complete_detection({

            "detection": DEFAULT_EVENT_RULE["detection"],

            "severity": DEFAULT_EVENT_RULE["severity"],

            "mitre": DEFAULT_EVENT_RULE["mitre"],

            "description": DEFAULT_EVENT_RULE["description"],

            "recommendation": DEFAULT_EVENT_RULE["recommendation"]

        }, event)
