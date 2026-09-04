class TimelineEngine:

    def build(self, events):

        if not events:
            return []

        timeline = []

        severity_order = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Informational": 0
        }

        for item in events:

            event = item.get("event", {})
            detection = item.get("detection", {})
            mitre = detection.get("mitre", {})
            ioc = detection.get("ioc", {})

            timeline.append({

                "time": event.get("time"),

                "host": event.get("host"),

                "user": event.get("user"),

                "event_id": event.get("event_id"),

                "process": event.get("process_name"),

                "source": event.get("source"),

                "provider": event.get("provider"),

                "channel": event.get("channel"),

                "severity": detection.get(
                    "severity",
                    "Informational"
                ),

                "severity_score": severity_order.get(
                    detection.get(
                        "severity",
                        "Informational"
                    ),
                    0
                ),

                "detection": detection.get(
                    "detection",
                    "Unknown"
                ),

                "description": detection.get(
                    "description",
                    ""
                ),

                "recommendation": detection.get(
                    "recommendation",
                    ""
                ),

                "mitre": {

                    "id": mitre.get(
                        "id",
                        "N/A"
                    ),

                    "technique": mitre.get(
                        "technique",
                        "Unknown"
                    ),

                    "tactic": mitre.get(
                        "tactic",
                        "Unknown"
                    )

                },

                "ioc": {

                    "ips": ioc.get(
                        "ips",
                        []
                    ),

                    "hashes": ioc.get(
                        "hashes",
                        []
                    )

                }

            })

        timeline.sort(

            key=lambda x: (

                x.get("time", ""),

                x.get("severity_score", 0)

            ),

            reverse=False

        )

        return timeline