import time


class CacheService:

    def __init__(self):

        self.data = None

        self.updated = 0

        self.ttl = 5

    def get(self):

        if self.data is None:
            return None

        if time.time() - self.updated > self.ttl:
            return None

        return self.data

    def set(self, data):

        self.data = data

        self.updated = time.time()

    def clear(self):

        self.data = None

        self.updated = 0


cache = CacheService()