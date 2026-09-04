class FailedLoginRule:

    def check(self, event):

        if event.get("event_id") == "4625":

            return {
                "detection": "Failed Login",
                "description": "Multiple failed login attempts may indicate a brute force attack."
            }

        return None