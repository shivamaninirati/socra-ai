<div align="center">

# 🛰️ SOCRA AI

### AI-Powered SOC Investigation Platform

<p>
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="platform"/>
  <img src="https://img.shields.io/badge/backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="backend"/>
  <img src="https://img.shields.io/badge/frontend-React%2019-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="frontend"/>
  <img src="https://img.shields.io/badge/AI-Ollama%20%2F%20Llama%203-black?style=for-the-badge&logo=meta&logoColor=white" alt="ai"/>
  <img src="https://img.shields.io/badge/database-SQLite%20WAL-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="database"/>
</p>

<p>
  <img src="https://github.com/shivamaninirati/socra-ai/actions/workflows/verify.yml/badge.svg" alt="SOCRA AI Verification"/>
</p>

<p>
  <b>🚀 Version:</b> v0.1.0 &nbsp; | &nbsp;
  <b>🟢 Status:</b> Actively Verified &nbsp; | &nbsp;
  <b>🛡️ Platform:</b> Windows
</p>

**Self-hosted. Real-time. MITRE ATT&CK aware.**  
Collect Windows telemetry, detect threats, investigate alerts, and let AI do the first pass.

</div>

<br/>

## 📑 Table of Contents

- [🚀 What It Does](#-what-it-does)
- [🏗️ Architecture](#️-architecture)
- [📋 Requirements](#-requirements)
- [⚙️ Installation](#️-installation)
- [🗄️ Database](#️-database)
- [🖥️ Windows Telemetry](#️-windows-telemetry)
- [🤖 AI / Ollama Setup](#-ai--ollama-setup)
- [🔌 Splunk (Optional)](#-splunk-optional)
- [▶️ Running the Application](#️-running-the-application)
- [🛠️ Development Usage](#️-development-usage)
- [⚠️ Known Limitations](#️-known-limitations)
- [📄 License](#-license)

---

## 🚀 What It Does

| | |
|---|---|
| 📡 **Collects** | Windows Event Logs in real time (Security, System, Application, and optional Sysmon) |
| 🔎 **Detects** | Suspicious activity using 100+ event rules and process intelligence |
| 🗂️ **Classifies** | Events by severity, mapped to MITRE ATT&CK techniques |
| 🕵️ **Investigates** | Alerts via an enterprise workspace — related events, process tree, IOCs, analyst notes |
| 🧠 **Analyzes** | Security events with AI (Ollama / Llama 3) |
| 📊 **Reports** | Filterable, exportable SOC activity reports |
| 📈 **Visualizes** | Threat trends on a live dashboard with real-time WebSocket updates |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React 19)                    │
│  Dashboard │ Alerts │ Investigation │ Timeline │ Reports  │
│  AI Chat │ Threat Hunting │ Settings │ Enterprise Search  │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API + WebSocket (JWT auth)
┌──────────────────────┴──────────────────────────────────┐
│                   Backend (FastAPI)                       │
│  Auth │ Analytics │ AI │ Cases │ Search │ Settings        │
│  Detection │ Severity │ MITRE │ IOC │ Event Processor     │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│              SQLite (WAL mode, single-writer)             │
│  events │ investigations │ cases │ collector_state        │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│         Windows Event Log Collector (Python)              │
│  Security │ System │ Application │ Sysmon (optional)     │
└─────────────────────────────────────────────────────────┘
```

---

## 📋 Requirements

<table>
<tr><th>🐍 Backend</th><th>🌐 Frontend</th></tr>
<tr valign="top">
<td>

- Python 3.10+
- Windows OS *(for Windows Event Log collection)*
- SQLite *(bundled with Python)*
- Ollama *(optional — AI features)*

</td>
<td>

- Node.js 18+
- npm or compatible package manager

</td>
</tr>
</table>

---

## ⚙️ Installation

<details open>
<summary><b>1️⃣ Clone the Repository</b></summary>

```bash
git clone https://github.com/shivamaninirati/socra-ai.git
cd socra-ai
```
</details>

<details open>
<summary><b>2️⃣ Backend Setup</b></summary>

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```
</details>

<details open>
<summary><b>3️⃣ Frontend Setup</b></summary>

```bash
cd frontend

# Install dependencies
npm install
```
</details>

---

## 🗄️ Database

SOCRA AI uses **SQLite with WAL** (Write-Ahead Logging) for concurrent read/write access. The database is created automatically at `backend/data/socra.db` on first run.

| Table | Purpose |
|---|---|
| `events` | All collected Windows security events with denormalized columns |
| `investigations` | Persistent investigation records |
| `cases` | Case management records |
| `collector_state` | Collector resumability state |

> Migrations run automatically on startup — no manual step required.

---

## 🖥️ Windows Telemetry

The native collector actively reads these Windows Event Log channels:

| Channel | Collected | Notes |
|---|---|---|
| 🔐 Security | ✅ (elevated only) | Needs Administrator; without elevation the channel is skipped and reported (`security_log_accessible: false`) — never a silent failure |
| 💻 System | ✅ | No elevation required |
| 📋 Application | ✅ | No elevation required |
| 🧬 Microsoft-Windows-Sysmon/Operational | ⚪ Optional | Collected only when Sysmon is installed; probed at startup and re-probed every ~5 minutes |

Every event keeps its source channel, provider, event ID, record number, exact
timestamp (ISO-8601) and raw message. Duplicate ingestion is prevented per
channel by a record-number watermark persisted in the `collector_state` table
(restarts do not re-ingest history); if a log's record numbering restarts
(log cleared/rotated) the watermark resets automatically instead of dropping
all future events.

### Sysmon Prerequisites (optional)

Sysmon is **not required**. When installed, its Operational channel is
detected and registered automatically as an extra source:

```powershell
# https://learn.microsoft.com/sysinternals/downloads/sysmon
sysmon64 -i sysmonconfig.xml
```

When the channel is missing, the collector records
`source_status.sysmon = {"available": false, ...}` and keeps collecting the
Windows channels — a missing source never stops the working ones. Installing
or removing Sysmon later needs no restart (the collector re-probes every
~5 minutes).

### Required Windows Permissions

| Channel | Permission |
|---|---|
| Security | Administrator — run elevated (admin shell or Task Scheduler "Run with highest privileges") |
| System / Application | Standard user |
| Sysmon/Operational | Standard user (read) |

### Collector Startup & Troubleshooting

```bash
cd backend
python main.py                     # in-process collector (development)
python install_collector.py task   # install standalone scheduled task
python run_collector.py            # run standalone manually
```

| Symptom | Cause / Fix |
|---|---|
| `Administrator privileges required for Security Event Log collection.` | Process not elevated — Security is skipped until it is; System/Application continue |
| `Sysmon optional source not available` | Sysmon not installed (normal) — auto-registered ~5 minutes after installation |
| No events at all | Check `source_status`, `last_error` and `channels` on `/live/status` or in Settings |
| `Refusing to start a duplicate collector` | Single-instance lock — only one collector runs at a time (by design) |

### Collector Modes

<table>
<tr><th>🧪 In-Process (Development)</th><th>🏭 Standalone (Production)</th></tr>
<tr valign="top">
<td>

```bash
cd backend
python main.py
```

</td>
<td>

```bash
cd backend
python install_collector.py task    # Install as scheduled task
python run_collector.py             # Or run manually
```

</td>
</tr>
</table>

> The standalone collector persists to SQLite independently. The API server detects it and forwards events to the live WebSocket pipeline without duplicating collection.

---

## 🤖 AI / Ollama Setup

SOCRA AI uses **Ollama** for AI-powered investigation and chat.

```bash
# 1. Install Ollama — download from https://ollama.ai

# 2. Pull a model
ollama pull llama3

# 3. Verify
ollama list
```

> 💡 **AI features are optional.** When Ollama isn't running, SOCRA AI operates normally — AI analysis simply shows "unavailable" instead of erroring out.

---

## 🔌 Splunk (Optional)

Splunk is **never required** for collection, storage, detection, or the UI —
the local pipeline runs entirely against SQLite, and the collection path does
not import the Splunk SDK. When `SPLUNK_HOST`, `SPLUNK_USERNAME` and
`SPLUNK_PASSWORD` are set in `backend/.env`, admins can verify connectivity
with `GET /splunk/test`. Legacy Splunk-only endpoints answer with an explicit
"Splunk integration required" message instead of failing, and the settings
default to empty values when unconfigured.

---

## ▶️ Running the Application

<table>
<tr><th>🔧 Backend</th><th>🎨 Frontend</th></tr>
<tr valign="top">
<td>

```bash
cd backend
python main.py
```
📍 `http://127.0.0.1:8000`

</td>
<td>

```bash
cd frontend
npm run dev
```
📍 `http://localhost:5173`

</td>
</tr>
</table>

### 🔑 Default Credentials

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | *your configured password* |
| Analyst | `analyst` | *your configured password* |

---

## 🛠️ Development Usage

**Build frontend for production**
```bash
cd frontend
npm run build
```
Output → `frontend/dist/`

**Run tests**
```bash
cd backend
python test_persistence.py
python test_event_registry.py
python test_analytics.py
python test_collector_reliability.py   # collector suite (all Windows access mocked, temp DB)
```

**API docs** — once the backend is running, visit `http://127.0.0.1:8000/docs` for Swagger UI.

---

## ⚠️ Known Limitations

| Limitation | Detail |
|---|---|
| 📡 Collected channels | Security, System, Application, and (when installed) Sysmon — PowerShell / Task Scheduler operational channels are **not** collected |
| 🪟 Windows Only | Collector requires Windows OS; the Security channel additionally requires Administrator privileges |
| 🖥️ Single Machine | Designed for single-machine deployment, not distributed |
| 🔓 No HTTPS | Use a reverse proxy (nginx, Caddy) for TLS in production |
| 🗄️ SQLite | Not suited for extremely high-volume environments (millions of events/day) |
| 🤖 Ollama Required | AI features need a running Ollama instance with a pulled model |
| 🔕 No Email/Slack Alerts | Notifications are in-app only, no external integrations |

---

## 📄 License

See repository for license details.

<div align="center">
<br/>
<sub>Built for defenders 🛡️ · Powered by FastAPI, React & Ollama</sub>
</div>
