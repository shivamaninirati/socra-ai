from app.collector.windows_reader import WindowsEventReader


class SourceManager:

    """
    Registers every log source supported by SOCRA AI.

    Future:
    --------
    Windows
    Sysmon
    EVTX
    JSON
    Splunk
    Linux
    Azure
    AWS
    """

    def __init__(self):

        self.sources = {}

    def register(self, name, source):

        self.sources[name] = source

        print(f"[SourceManager] Registered: {name}")

    def unregister(self, name):

        if name in self.sources:

            del self.sources[name]

    def get(self, name):

        return self.sources.get(name)

    def get_all(self):

        return self.sources

    def count(self):

        return len(self.sources)


source_manager = SourceManager()

# Default Source
source_manager.register(
    "windows",
    WindowsEventReader()
)