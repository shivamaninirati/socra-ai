class MitreEngine:

    def __init__(self):

        self.technique_map = {
            "T1003": {
                "technique": "OS Credential Dumping",
                "tactic": "Credential Access"
            },
            "T1003.001": {
                "technique": "LSASS Memory",
                "tactic": "Credential Access"
            },
            "T1021.002": {
                "technique": "SMB/Windows Admin Shares",
                "tactic": "Lateral Movement"
            },
            "T1047": {
                "technique": "Windows Management Instrumentation",
                "tactic": "Execution"
            },
            "T1053.005": {
                "technique": "Scheduled Task",
                "tactic": "Persistence"
            },
            "T1059": {
                "technique": "Command and Scripting Interpreter",
                "tactic": "Execution"
            },
            "T1059.001": {
                "technique": "PowerShell",
                "tactic": "Execution"
            },
            "T1059.003": {
                "technique": "Windows Command Shell",
                "tactic": "Execution"
            },
            "T1078": {
                "technique": "Valid Accounts",
                "tactic": "Defense Evasion"
            },
            "T1105": {
                "technique": "Ingress Tool Transfer",
                "tactic": "Command and Control"
            },
            "T1110": {
                "technique": "Brute Force",
                "tactic": "Credential Access"
            },
            "T1136": {
                "technique": "Create Account",
                "tactic": "Persistence"
            },
            "T1218.005": {
                "technique": "Mshta",
                "tactic": "Defense Evasion"
            },
            "T1218.010": {
                "technique": "Regsvr32",
                "tactic": "Defense Evasion"
            },
            "T1218.011": {
                "technique": "RunDLL32",
                "tactic": "Defense Evasion"
            },
            "T1543.003": {
                "technique": "Windows Service",
                "tactic": "Persistence"
            },
        }

        self.mitre_map = {

            # Authentication
            "Failed Login": {
                "id": "T1110",
                "technique": "Brute Force",
                "tactic": "Credential Access"
            },

            "Failed Logon": {
                "id": "T1110",
                "technique": "Brute Force",
                "tactic": "Credential Access"
            },

            "Successful Login": {
                "id": "T1078",
                "technique": "Valid Accounts",
                "tactic": "Defense Evasion"
            },

            "Successful Logon": {
                "id": "T1078",
                "technique": "Valid Accounts",
                "tactic": "Defense Evasion"
            },

            "Account Lockout": {
                "id": "T1110",
                "technique": "Brute Force",
                "tactic": "Credential Access"
            },

            "User Created": {
                "id": "T1136",
                "technique": "Create Account",
                "tactic": "Persistence"
            },

            # Process Execution
            "Process Creation": {
                "id": "T1059",
                "technique": "Command and Scripting Interpreter",
                "tactic": "Execution"
            },

            "Suspicious Process Execution": {
                "id": "T1059",
                "technique": "Command and Scripting Interpreter",
                "tactic": "Execution"
            },

            # Windows
            "Application Crash": {
                "id": "N/A",
                "technique": "Application Failure",
                "tactic": "Impact"
            },

            "Windows Error Reporting": {
                "id": "N/A",
                "technique": "Windows Error Reporting",
                "tactic": "Impact"
            },

            "Service Started": {
                "id": "T1543",
                "technique": "Create or Modify System Process",
                "tactic": "Persistence"
            },

            "Service Stopped": {
                "id": "T1489",
                "technique": "Service Stop",
                "tactic": "Impact"
            },

            "Event Log Started": {
                "id": "N/A",
                "technique": "Event Logging",
                "tactic": "Discovery"
            },

            "Event Log Stopped": {
                "id": "T1070",
                "technique": "Indicator Removal",
                "tactic": "Defense Evasion"
            },

            "Malware Detected": {
                "id": "T1204",
                "technique": "User Execution",
                "tactic": "Execution"
            }

        }

    def map(self, detection):
        """Resolve the enriched MITRE block(s) for one detection result.

        CANONICAL CONTRACT: always returns a LIST of MITRE blocks
        ([{id, name, technique, tactic, confidence, reason}, ...]). A single
        technique is returned as a one-element list and an unmapped event as a
        one-element list with the explicit 'Unmapped' id - so callers never
        have to branch between dict and list shapes.

        Every event that enters the detection pipeline is inspected: the
        registry rule's MITRE id (if any) is honored, then detection-name
        mapping is consulted as a fallback, and each id is normalized through
        build_mitre_block. Multiple techniques per event are fully supported.
        """
        from app.registry.windows_event_registry import build_mitre_block

        existing = detection.get("mitre")
        mitre_ids = []

        # Handle existing MITRE data - support single or multiple ids
        if isinstance(existing, list):
            # Already a list of mitre ids or blocks
            for item in existing:
                if isinstance(item, dict):
                    candidate = item.get("id")
                    if candidate not in (None, "", "Unknown", "N/A", "None", "null", "-"):
                        mitre_ids.append(str(candidate))
                elif isinstance(item, str):
                    if item not in ("", "Unknown", "N/A", "None", "null", "-"):
                        mitre_ids.append(item)
        elif isinstance(existing, dict):
            candidate = existing.get("id")
            if candidate not in (None, "", "Unknown", "N/A", "None", "null", "-"):
                mitre_ids.append(str(candidate))
        elif isinstance(existing, str):
            if existing not in ("", "Unknown", "N/A", "None", "null", "-"):
                mitre_ids.append(existing)

        detection_name = detection.get("detection", "Unknown")

        if not mitre_ids:
            # Try to map from detection name
            mapped = self.mitre_map.get(detection_name)
            if mapped:
                mitre_ids.append(mapped.get("id", "Unknown"))
            else:
                mitre_ids.append("Unknown")

        result = build_mitre_block(
            mitre_ids,
            detection_name,
            detection.get("severity", ""),
        )
        # Always a list: single technique -> [block], multiple -> [block, ...],
        # unmapped -> [Unmapped block]. Consumers that render one technique
        # use the first block (see first_mitre_block helper in the registry).
        if isinstance(result, list):
            return result
        # Defensive: build_mitre_block receives a list above so it always
        # returns a list; if that ever changes, normalize here.
        return [result]


# Singleton instance — used by search, storage, and notification routes
mitre_engine = MitreEngine()