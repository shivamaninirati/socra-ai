class SuccessfulLoginRule:

    def check(self, event):

        if event.get("event_id") == "4624":

            return {
                "detection": "Successful Login",
                "description": "A user successfully authenticated."
            }

        return None