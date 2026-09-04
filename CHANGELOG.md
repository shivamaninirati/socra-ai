# Changelog

All notable changes to SOCRA AI will be documented in this file.

## [0.1.0] - 2026-08-21

### Fixes

- **Collector vs Frontend Count Mismatch** — Fixed double-counting where the frontend accumulator incremented `totalEvents` and severity counts from WebSocket events that were already counted in the backend SQLite totals. The frontend now syncs all canonical counts exclusively from the backend `dashboard_stats` broadcast (every 2s). WS events only update the live stream, EPS, and hourly buckets.
- **Backend Broadcast Severity Fields** — Added individual `critical`, `medium`, `low`, `informational` severity counts to the WebSocket broadcast payload so the frontend can sync severity distribution correctly.
- **Host Count Sync** — Dashboard now displays the authoritative SQL-distinct host count from the backend instead of the live-stream approximation.
- **`.gitignore` Security** — Added `*.tmp` and `*_socra_token.tmp` patterns to prevent accidental credential commits.

### First Official Release

SOCRA AI v0.1.0 is the first production-ready release of the AI-Powered SOC Investigation Platform.

### Core Architecture

- **FastAPI backend** with SQLite persistence and single-writer thread architecture
- **React 19 frontend** with Vite, Tailwind CSS, and code-splitting via lazy routes
- **WebSocket live telemetry** with JWT authentication and sequence-based sync
- **JWT authentication** with PBKDF2-SHA256 password hashing and brute-force protection

### Telemetry Pipeline

- **Windows Event Log Collector** — native Python reader for Security, Sysmon, PowerShell, and Task Scheduler channels
- **Standalone Collector** — persistent out-of-process collector with resumability (installable as Windows scheduled task)
- **Live Forwarder** — forwards new events from SQLite into the live WebSocket store when standalone collector is active
- **Windows Event Parser** — parses raw Windows Event XML into structured event objects
- **Event Processor** — orchestrates parser → detection → severity → MITRE → IOC → storage pipeline
- **Event Deduplication** — SQLite unique index on (channel, computer, record_number, time_created) plus fingerprint-based trigger for events without record numbers

### Detection & Intelligence

- **Windows Detection Engine** — rule-based detection for authentication, process creation, and 100+ Windows/Sysmon event IDs
- **Severity Engine** — deterministic severity resolution from registry defaults and detection rules
- **MITRE ATT&CK Mapping** — maps detections to ATT&CK techniques, tactics, and procedure IDs with enterprise glossary
- **IOC Extraction** — extracts IPs, domains, URLs, hashes, registry keys, services, and scheduled tasks from event data
- **Process Intelligence** — per-process detection rules for suspicious tools (mimikatz, psexec, cobaltstrike, etc.)
- **Unified Event Registry** — single source of truth for event ID names, severities, MITRE mappings, and detection labels

### Dashboard & Analytics

- **Real-Time Dashboard** — total events, severity distribution, top hosts, hourly trends, events-per-second
- **Server-Side Analytics** — SQL-pushed-down aggregation over indexed denormalized columns (no full-dataset Python scan)
- **Alert Trend Chart** — hourly stacked bar chart of severity distribution
- **Severity Distribution Chart** — donut chart of severity breakdown
- **Top Hosts Card** — most active hosts with event counts
- **Collector Status Card** — live collector health and event throughput

### Alerts

- **Enterprise Alerts Table** — paginated, filterable alerts with SQL-pushdown queries
- **Multi-Dimensional Filtering** — time range, severity, host, MITRE, event ID, process, PID, user, status, source
- **Filter Cache Service** — incrementally-maintained in-memory counters for O(1) filter option lookups
- **Alert Triage Status** — persisted lifecycle (New → Investigating → Contained → Resolved → Closed) with analyst audit trail
- **Live Overlay** — real-time alert insertion via WebSocket with deduplication
- **Auto-Refresh Toggle** — Settings-driven live insertion control

### Investigation

- **Investigation Workspace** — persistent investigation records with status lifecycle management
- **Related Events** — time-window queries against historical telemetry for correlated activity
- **Process Tree** — hierarchical process execution visualization
- **IOC Extraction Panel** — categorized IOC display (IPs, domains, URLs, hashes, registry keys, services)
- **MITRE Mapping Display** — technique, tactic, and description visualization
- **Analyst Notes** — timestamped notes persisted to SQLite
- **Case Escalation** — promote investigations to persistent case management records
- **AI Investigation** — automated Tier-2 analysis via Ollama LLM

### Timeline

- **Server-Side Timeline** — paginated, filterable timeline over historical SQLite telemetry
- **Time Range Selection** — today, last 24h, last 7d, last 30d, all time, custom range
- **Event Detail Cards** — severity-coded timeline entries with event ID, host, process, and MITRE mapping

### Reports

- **SOC Report Generator** — generates reports from persisted telemetry with severity breakdown and MITRE mapping
- **Filterable Reports** — restrict by host, user, event ID, severity, process, MITRE, time range
- **AI-Enhanced Reports** — optional Ollama analysis attached to report with timeout protection

### AI Assistant

- **AI Chat** — conversational interface for security questions via Ollama
- **AI Investigation** — structured Tier-2 analysis with real event context, related events, IOCs, and process tree
- **AI Health Monitoring** — service availability and model installation status

### Enterprise Search

- **Global Search** — cross-platform keyword search across live and historical telemetry
- **SQL-Backed Search** — full-text search engine over SQLite with field-filter pushdown
- **Search-to-Alerts** — navigate search results directly into filtered Alerts view

### Threat Intelligence

- **IOC Lookup** — reputation checking against VirusTotal and AbuseIPDB (when configured)
- **Provider Status** — transparent "not configured" state for unconfigured providers
- **Configurable API Keys** — environment-driven provider configuration

### Case Management

- **Case Creation** — escalate investigations to persistent cases
- **Case Lifecycle** — status tracking with priority, assignment, and audit timestamps
- **Case Listing** — browse and manage all active cases

### Settings

- **System Status Dashboard** — real-time backend health (API, Collector, WebSocket, AI, Database)
- **Preference Toggles** — dark theme, notifications, auto-refresh with localStorage persistence
- **Version Display** — shows SOCRA AI version from backend

### Security

- **JWT Authentication** — token-based auth with configurable expiry
- **Password Hashing** — PBKDF2-SHA256 with 600K iterations
- **Brute-Force Protection** — sliding-window rate limiting on login (5 attempts per 5 minutes)
- **CORS Configuration** — environment-driven allowed origins
- **Security Headers** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Self-Hosted Swagger UI** — CSP-safe API documentation with vendored assets
- **Environment Variables** — all secrets via environment variables, no hardcoded credentials

### Infrastructure

- **SQLite WAL Mode** — Write-Ahead Logging for concurrent read/write
- **Single-Writer Thread** — eliminates lock contention with queued writes
- **Database Migrations** — automatic schema evolution for existing databases
- **Backfill System** — one-time denormalized column population for historical events
- **Process Name Cleanup** — strips enterprise metadata suffixes from stored process names

### Frontend

- **Code Splitting** — lazy-loaded route components for fast initial load
- **Responsive Design** — mobile-friendly layouts with Tailwind CSS
- **Dark/Light Theme** — toggle-able theme with CSS class switching
- **Event Details Drawer** — slide-out panel for full event inspection
- **Loading Skeletons** — smooth loading states for all major views
- **Error Handling** — graceful degradation with user-friendly error messages
