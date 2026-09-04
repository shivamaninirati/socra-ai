import re


class IPExtractor:

    def extract(self, text):

        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

        return re.findall(ip_pattern, text)