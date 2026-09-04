class ProcessCreationRule:

    PROCESS_NAMES = [

        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "wmic.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "schtasks.exe",

    ]

    def check(self, event):

        event_id = str(event.get("event_id", ""))

        process = event.get(
            "process_name",
            ""
        ).lower()

        message = event.get(
            "message",
            ""
        ).lower()

        # Security Log Process Creation

        if event_id == "4688":

            return {

                "detection": "Process Creation",

                "severity": "Medium",

                "mitre": "T1059",

                "description": "A new Windows process was created."

            }

        # Native Collector Detection

        for process_name in self.PROCESS_NAMES:

            if process_name in process or process_name in message:

                return {

                    "detection": "Suspicious Process Execution",

                    "severity": "High",

                    "mitre": "T1059",

                    "description": f"Detected execution of {process_name}"

                }

        return None