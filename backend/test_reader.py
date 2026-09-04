from app.collector.windows_reader import WindowsEventReader

reader = WindowsEventReader()

events = reader.read_latest(10)

print(events)