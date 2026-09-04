SOCRA AI — ADVANCED EVENT IOC EXTRACTION + INVESTIGATION CORRELATION

IMPORTANT:
Upgrade the EXISTING Investigation/Event Details → IOCs functionality.

DO NOT create a separate IOC system.
DO NOT redesign the Investigation architecture.
DO NOT generate fake IP addresses, hashes, users, or intelligence.
DO NOT assume every Windows event contains a network IP or file hash.

The objective is:

SELECTED EVENT
    ↓
RAW EVENT + PARSED EVENT
    ↓
IOC EXTRACTION ENGINE
    ↓
IP / DOMAIN / URL / HASH / USER / NETWORK ARTIFACTS
    ↓
NORMALIZATION
    ↓
DEDUPLICATION
    ↓
THREAT INTELLIGENCE
    ↓
RELATED EVENTS
    ↓
MITRE
    ↓
INVESTIGATION

========================================================
1. EVENT DETAILS → IOCS MUST BE REAL
========================================================

When an analyst clicks:

Investigate

and opens:

Event Details → IOCs

SOCRA AI must inspect the COMPLETE selected event.

Inspect:

- parsed fields
- raw event
- XML
- EventData
- System fields
- provider-specific fields
- command line
- process information
- network fields
- authentication fields
- subject/target fields
- file information
- hashes
- URLs
- domains
- IP addresses

Do NOT only inspect one parsed field.

========================================================
2. IP EXTRACTION
========================================================

Extract IP addresses from ALL relevant event fields.

Possible Windows fields include:

IpAddress
SourceIp
SourceIP
DestinationIp
DestinationIP
RemoteAddress
LocalAddress
ClientAddress
ServerAddress
SourceNetworkAddress
DestinationNetworkAddress
NetworkAddress
RemoteHost
ClientIP
Computer
WorkstationName

Also inspect raw event/XML when structured fields are missing.

Support:

IPv4
IPv6

Example:

192.168.1.10
8.8.8.8
10.0.0.5
2001:4860:4860::8888

Normalize and deduplicate.

========================================================
3. DO NOT CONFUSE COMPUTER NAME WITH IP
========================================================

IMPORTANT:

The Windows field:

Computer = MANI

does NOT mean:

IP = MANI

Computer/hostname and IP must remain separate.

Display:

Host:
MANI

IP:
<actual IP if present>

Never convert hostname into an IP unless a legitimate resolver/enrichment process explicitly provides it.

========================================================
4. USER IP / SOURCE IP
========================================================

When the event contains a network/source address, clearly label it.

Examples:

Source IP:
192.168.1.25

Destination IP:
8.8.8.8

Remote IP:
185.x.x.x

Local IP:
192.168.1.25

Do not simply display:

IP Address

when the role is known.

Show the relationship.

========================================================
5. AUTHENTICATION EVENTS
========================================================

For authentication-related events such as:

4624
4625
4648
4768
4769
4771
4776

inspect fields that can identify:

Source Network Address
IpAddress
WorkstationName
TargetUserName
SubjectUserName
LogonType
AuthenticationPackage

Example:

Event ID:
4625

User:
administrator

Source IP:
192.168.1.50

Logon Type:
3

This makes the investigation much more useful.

========================================================
6. PROCESS EVENTS
========================================================

For process-related events such as:

4688

extract:

Process Name
New Process ID
Creator Process ID
Command Line
Parent Process
User
Integrity Level

Then inspect command line for:

IP addresses
domains
URLs
hashes
file paths

Example:

powershell.exe -c Invoke-WebRequest http://example.com/a.ps1

must extract:

URL:
http://example.com/a.ps1

Domain:
example.com

Do not mark the domain malicious automatically.

========================================================
7. FILE HASH EXTRACTION
========================================================

Extract hashes ONLY when they actually exist.

Support:

MD5
SHA-1
SHA-256

Search relevant event fields and raw data for:

Hash
Hashes
MD5
SHA1
SHA-1
SHA256
SHA-256
FileHash
FileHashes
ImageHash
TargetHash
SHA256Hash

Also inspect structured fields where a provider stores hashes.

If no hash exists:

No file hashes found in this event.

Do NOT create a hash from:

PID
Event ID
filename
command line
random text

unless the system is explicitly calculating a cryptographic hash of an actual file and that operation is intentionally supported.

========================================================
8. FILE-BASED HASHING
========================================================

Where the telemetry provides an actual file path and SOCRA has
permission and a safe local collector capability:

support optional local hash calculation:

File
↓
SHA-256
↓
IOC

But this must be:

OPTIONAL
SAFE
EXPLICIT
NON-BLOCKING

Do NOT make event ingestion wait for file hashing.

Do NOT attempt to hash files that no longer exist.

Do NOT access arbitrary remote paths.

If hashing is unavailable:

Hash not available from telemetry.

========================================================
9. DOMAIN EXTRACTION
========================================================

Extract domains from:

URLs
DNS events
network events
command lines
PowerShell
browser/network telemetry
structured event fields

Example:

https://malicious-example.com/update.ps1

extract:

URL:
https://malicious-example.com/update.ps1

Domain:
malicious-example.com

Store the normalized domain once.

========================================================
10. URL EXTRACTION
========================================================

Extract complete URLs when present.

Examples:

http://example.com/a.ps1
https://example.com/login
https://185.x.x.x/payload

Do NOT execute the URL.

Do NOT automatically visit it.

Only analyze using safe reputation/enrichment mechanisms.

========================================================
11. COMMAND-LINE IOC EXTRACTION
========================================================

This is extremely important for SOCRA.

Inspect command lines for:

IPv4
IPv6
domains
URLs
hashes

Example:

powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest
https://example.com/file.ps1"

IOC extraction:

URL:
https://example.com/file.ps1

Domain:
example.com

Technique:
T1059.001

Do not extract meaningless numbers as IOCs.

========================================================
12. IOC TYPES IN EVENT DETAILS
========================================================

The IOCs tab should be organized:

IP ADDRESSES
----------------
Source IP
Destination IP
Remote IP
Local IP

DOMAINS
----------------
example.com

URLS
----------------
https://example.com/a.ps1

FILE HASHES
----------------
SHA-256
SHA-1
MD5

OTHER ARTIFACTS
----------------
Email
Hostname
File path
Registry key

Only display sections that have meaningful data.

If a section has no data, keep the empty state clean.

========================================================
13. EVERY IOC MUST BE CLICKABLE
========================================================

Example:

185.x.x.x

Click →

IOC Investigation

Show:

IOC
Type
First Seen
Last Seen
Observations
Verdict
Risk
Confidence
Threat Intelligence
Related Events
Affected Hosts
Users
Processes
MITRE
Cases

========================================================
14. "LOOKUP" BUTTON
========================================================

Every supported IOC should have:

Lookup

Example:

185.x.x.x     [Lookup]

SHA256...     [Lookup]

example.com   [Lookup]

Lookup must open the existing Threat Intelligence workflow.

DO NOT duplicate the Threat Intelligence backend.

========================================================
15. IP LOOKUP
========================================================

For a public IP:

Lookup

should provide available:

IP
Public/Private
Country
Region
ASN
Organization
ISP
Reverse DNS
Reputation
Risk
Confidence
Sources
First Seen
Last Seen

Only display information actually returned by configured providers.

========================================================
16. PRIVATE IP HANDLING
========================================================

Examples:

10.0.0.5
192.168.1.20
172.16.0.10
127.0.0.1

Display:

Private / Local

Do NOT display:

Malicious

just because it is an IP.

Private IP reputation generally requires internal context.

========================================================
17. HASH LOOKUP
========================================================

For:

MD5
SHA-1
SHA-256

show:

Hash
Type
Reputation
Detection count where available
Malware family where available
Risk
Confidence
Sources
First Seen
Last Seen

Then:

Related SOCRA Events

========================================================
18. EVENT → IOC CORRELATION
========================================================

For every extracted IOC:

Find related events in the existing database.

Example:

Event 4688
    ↓
Command line contains:
example.com
    ↓
IOC:
example.com
    ↓
Related events:
27
    ↓
Hosts:
MANI
HOST-02
    ↓
Processes:
powershell.exe
    ↓
MITRE:
T1059.001

This should be real database correlation.

========================================================
19. IOC → RELATED EVENTS
========================================================

Inside IOC details:

RELATED EVENTS

Show:

Timestamp
Event ID
Host
User
Process
Severity
MITRE
Status

Clicking the event should open the existing Event Details/Investigation
workflow.

========================================================
20. IOC → USER CORRELATION
========================================================

When available, associate the IOC with:

Target user
Source user
Subject user
Account
Logon session

Example:

IOC:
192.168.1.50

Observed user:

MANI

Do NOT claim that an IP belongs to a user permanently.

Use wording:

Observed with user

or:

Associated with event user

========================================================
21. IOC → PROCESS CORRELATION
========================================================

Example:

IOC:
example.com

Associated processes:

powershell.exe
chrome.exe
svchost.exe

Show:

Process
PID
Parent PID
User
First Seen
Last Seen

Only show relationships backed by telemetry.

========================================================
22. IOC → MITRE
========================================================

If the event already has a valid MITRE mapping:

IOC
↓
Event
↓
MITRE

show:

T1059.001
Command and Scripting Interpreter: PowerShell

Do NOT assign MITRE techniques solely because an IOC exists.

The relationship must come from the detection/event context.

========================================================
23. IOC → ALERT
========================================================

Show alerts associated with the IOC.

Example:

Associated Alerts:
12

Highest Severity:
High

Open Alert

must use the existing Alerts system.

========================================================
24. IOC → CASE
========================================================

If the IOC is part of an existing case:

show:

Cases:
SOC-XXXX

Allow:

Add to Case

using the existing Case architecture.

========================================================
25. IOC EVIDENCE CHAIN
========================================================

Every IOC shown during investigation should answer:

WHERE DID THIS IOC COME FROM?

Example:

Source:
Event ID 4688

Field:
CommandLine

Value:
https://example.com/a.ps1

or:

Source:
Event ID 4625

Field:
IpAddress

Value:
192.168.1.50

This is extremely important for analyst trust.

========================================================
26. RAW EVENT TAB
========================================================

The Raw JSON tab should make it possible to verify the IOC.

Example:

Raw JSON
↓
IpAddress
↓
192.168.1.50

The IOC engine must never hide the evidence source.

========================================================
27. NO FALSE POSITIVES
========================================================

DO NOT treat:

PID 4688
Event ID 4688
port numbers
timestamps
Windows version numbers
GUIDs
random numeric values

as IPs or hashes.

DO NOT treat:

XML tags
XML declarations
namespace URLs
Windows schema URLs

as threat intelligence IOCs.

========================================================
28. PERFORMANCE
========================================================

IOC extraction must happen efficiently.

DO NOT perform expensive external API calls during the initial event
render.

Correct flow:

Open Event
↓
Show extracted local IOCs immediately
↓
Background enrichment
↓
Update reputation/intelligence

The investigation UI must not freeze.

========================================================
29. CACHING
========================================================

If the same IOC is repeatedly encountered:

Do not repeatedly query external providers.

Use existing IOC cache.

Example:

Same IP appears in:

1,000 events

External lookup:

NOT 1,000 requests.

Use:

IOC cache
+
deduplication
+
background enrichment

========================================================
30. DATABASE RELATIONSHIPS
========================================================

Maintain relationships:

Event
↔ IOC

IOC
↔ Alert

IOC
↔ Investigation

IOC
↔ Case

IOC
↔ MITRE context

IOC
↔ Host

IOC
↔ User

IOC
↔ Process

Do NOT duplicate IOC records unnecessarily.

========================================================
31. API DESIGN
========================================================

Create/use clean backend endpoints such as:

GET /events/{event_id}/iocs

GET /iocs/{ioc_id}

GET /iocs/{ioc_id}/events

GET /iocs/{ioc_id}/intelligence

GET /iocs/{ioc_id}/related-alerts

GET /iocs/{ioc_id}/related-cases

Use the EXISTING API architecture and naming conventions where
equivalent routes already exist.

Do not create duplicate endpoints if equivalent functionality already
exists.

========================================================
32. FRONTEND
========================================================

Upgrade:

Event Details → IOCs

Current:

IP Addresses
No IP addresses found.

File Hashes
No file hashes found.

Replace with a richer analyst view when data exists.

Example:

IP ADDRESSES

┌─────────────────────────────────────────────┐
│ Source IP                                   │
│ 192.168.1.50                                │
│ Private / Local                             │
│ Observed with: MANI                         │
│ [Lookup] [Related Events]                   │
└─────────────────────────────────────────────┘

FILE HASHES

┌─────────────────────────────────────────────┐
│ SHA-256                                     │
│ abc123...                                   │
│ Unknown                                     │
│ [Lookup] [Related Events]                   │
└─────────────────────────────────────────────┘

DOMAIN

┌─────────────────────────────────────────────┐
│ example.com                                 │
│ Unknown                                     │
│ [Lookup] [Related Events]                   │
└─────────────────────────────────────────────┘

Keep the current SOCRA dark enterprise visual language.

========================================================
33. EMPTY STATE
========================================================

If an event genuinely has no IOC:

No network or file IOCs were observed in this event.

Then show:

Checked:
IP addresses
Domains
URLs
File hashes

Do NOT simply show a huge empty card.

========================================================
34. EVENT-SPECIFIC EXPECTATIONS
========================================================

Different events contain different information.

Example:

4688:
Process
Command line
User
Potential domains/IPs/URLs

4624:
User
Logon type
Source IP
Workstation

4625:
Failed authentication
User
Source IP
Workstation

DNS/network events:
Domain
Source IP
Destination IP
Port

File events:
File
Hash
Path

Do NOT force the same IOC fields onto every event.

========================================================
35. TEST WITH REAL EVENTS
========================================================

Test at minimum:

4688
4624
4625
4648
DNS/network event
File event
PowerShell event

For each event verify:

Raw event
↓
Parsed event
↓
IOC extraction
↓
IOC type
↓
IOC evidence source
↓
Normalization
↓
Database
↓
Threat Intelligence
↓
Related Events
↓
Investigation

========================================================
36. CRITICAL TEST
========================================================

Create/use a test event containing:

Source IP:
192.168.1.50

Destination IP:
8.8.8.8

Domain:
example.com

URL:
https://example.com/test

SHA-256:
[real test hash]

Verify ALL FIVE are extracted correctly.

Then verify:

IP lookup works
Domain lookup works
URL lookup works
Hash lookup works

Then verify:

Related Events

returns the original event.

========================================================
37. NEGATIVE TEST
========================================================

Use an event containing:

PID:
4688

Event ID:
4688

Timestamp:
2026-08-28

Windows XML:

<?xml version="1.0"?>

Verify these are NOT incorrectly classified as:

IP
Hash
Domain
URL

========================================================
38. SECURITY TEST
========================================================

IOC extraction must safely process malicious-looking strings.

Never:

execute commands
execute URLs
download files
run PowerShell
open malware
execute scripts

IOC extraction is parsing only.

========================================================
39. MULTI-USER SECURITY
========================================================

The IOC information shown to a user must respect the existing
authentication and authorization model.

A user must not be able to access another user's private investigation
data merely by changing:

event_id
ioc_id
case_id

Backend must verify authorization.

Do not rely only on React route protection.

========================================================
40. FINAL ACCEPTANCE CRITERIA
========================================================

PASS ONLY IF:

✓ Real IPs are extracted
✓ Source/destination roles are preserved
✓ IPv4 works
✓ IPv6 works
✓ Private IPs are correctly identified
✓ Domains are extracted
✓ URLs are extracted
✓ MD5 works
✓ SHA-1 works
✓ SHA-256 works
✓ Command-line IOCs are extracted
✓ Raw event is inspected
✓ XML/EventData is inspected
✓ IOC evidence source is displayed
✓ Host/user/process relationships are displayed
✓ Related events work
✓ Related alerts work
✓ MITRE relationship remains evidence-based
✓ IOC Lookup works
✓ Threat Intelligence integration works
✓ IOC caching works
✓ No fake intelligence
✓ No fake IPs
✓ No fake hashes
✓ No false IOC extraction
✓ External TI failure does not break investigation
✓ UI remains fast
✓ Multi-user authorization is enforced

========================================================
FINAL VALIDATION
========================================================

After implementation:

1. Restart backend.
2. Restart frontend.
3. Verify database schema/migrations.
4. Generate fresh Windows events.
5. Open Alerts.
6. Investigate multiple event types.
7. Open IOCs.
8. Verify actual IP extraction.
9. Verify actual hash extraction.
10. Verify domain extraction.
11. Verify URL extraction.
12. Verify user association.
13. Verify process association.
14. Verify source/destination labels.
15. Verify IOC evidence source.
16. Click Lookup.
17. Verify Threat Intelligence.
18. Open Related Events.
19. Open MITRE.
20. Open Case.
21. Verify persistence after restart.
22. Test invalid/missing IOCs.
23. Test private IP.
24. Test IPv6.
25. Test provider failure.
26. Test multi-user authorization.
27. Check backend logs.
28. Check browser console.
29. Check network requests.
30. Confirm no mock/fake data.

DO NOT SAY "COMPLETE" UNTIL THESE TESTS ACTUALLY PASS.

FINAL REPORT MUST INCLUDE:

Files changed
Backend changes
Frontend changes
Database changes
IOC extraction coverage
Supported event IDs
Threat Intelligence integration
Tests performed
Tests passed
Tests failed
Errors found
Errors fixed
Remaining limitations

CORE PRINCIPLE:

SOCRA AI SHOULD NOT JUST SAY:

"No IP addresses found."

It should answer:

WHAT IOC WAS FOUND?
WHERE WAS IT FOUND?
WHAT EVENT PRODUCED IT?
WHO WAS ASSOCIATED WITH IT?
WHAT PROCESS WAS INVOLVED?
WHAT HOST WAS INVOLVED?
WHAT IS ITS THREAT INTELLIGENCE?
WHICH OTHER EVENTS CONTAIN IT?
WHICH ALERTS CONTAIN IT?
WHICH MITRE TECHNIQUES ARE ASSOCIATED?
CAN THE ANALYST INVESTIGATE IT?

Build this using REAL TELEMETRY and the EXISTING SOCRA AI
architecture.