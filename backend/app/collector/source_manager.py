from app.collector.windows_reader import WindowsEventReader
from app.collector.sysmon_reader import SysmonReader


class SourceManager:

    """
    Registers every log source supported by SOCRA AI.
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

# Default Windows event log source
source_manager.register(
    "windows",
    WindowsEventReader()
)

# Optional Sysmon source - only register if available
sysmon = SysmonReader()
sysmon_available, sysmon_error = sysmon.is_available()
if sysmon_available:
    source_manager.register(
        "sysmon",
        sysmon
    )
    print(f"[SourceManager] Sysmon channel detected and registered")
else:
    print(f"[SourceManager] Sysmon not available: {sysmon_error} - Sysmon events will not be collected")