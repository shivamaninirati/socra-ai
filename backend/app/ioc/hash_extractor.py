import re


class HashExtractor:

    def extract(self, text):

        hashes = []

        md5_pattern = r"\b[a-fA-F0-9]{32}\b"
        sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
        sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

        hashes.extend(re.findall(md5_pattern, text))
        hashes.extend(re.findall(sha1_pattern, text))
        hashes.extend(re.findall(sha256_pattern, text))

        return hashes