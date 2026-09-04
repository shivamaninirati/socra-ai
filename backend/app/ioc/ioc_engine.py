from app.ioc.ip_extractor import IPExtractor
from app.ioc.hash_extractor import HashExtractor


class IOCEngine:

    def __init__(self):

        self.ip_extractor = IPExtractor()
        self.hash_extractor = HashExtractor()

    def extract(self, text):

        text = text or ""

        return {

            "ips": self.ip_extractor.extract(text),

            "hashes": self.hash_extractor.extract(text)

        }