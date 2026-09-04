import time

import splunklib.client as client
import splunklib.results as results

from app.core.config import settings


class SplunkService:

    def connect(self):

        return client.connect(
            host=settings.SPLUNK_HOST,
            port=settings.SPLUNK_PORT,
            username=settings.SPLUNK_USERNAME,
            password=settings.SPLUNK_PASSWORD,
        )

    def search(self, query, count=100):

        service = self.connect()

        try:

            job = service.jobs.create(
                query,
                exec_mode="normal"
            )

            timeout = 30
            start = time.time()

            while not job.is_done():

                if (time.time() - start) > timeout:

                    job.cancel()

                    raise TimeoutError(
                        "Splunk search timed out after 30 seconds."
                    )

                time.sleep(0.3)

            result_stream = job.results(
                output_mode="json",
                count=count
            )

            reader = results.JSONResultsReader(result_stream)

            events = []

            for item in reader:

                if isinstance(item, dict):

                    events.append(item)

            return events

        except Exception as e:

            raise Exception(
                f"Splunk Search Failed: {str(e)}"
            )