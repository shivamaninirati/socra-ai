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
- [▶️ Running the Application](#️-running-the-application)
- [🛠️ Development Usage](#️-development-usage)
- [⚠️ Known Limitations](#️-known-limitations)
- [📄 License](#-license)

---

## 🚀 What It Does

| | |
|---|---|
| 📡 **Collects** | Windows Event Logs in real time (Security, Sysmon, PowerShell, Task Scheduler) |
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
│  Security │ Sysmon │ PowerShell │ Task Scheduler          │
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

SOCRA AI collects from four Windows Event Log channels:

| Channel | Provider | Event Types |
|---|---|---|
| 🔐 Security | Microsoft-Windows-Security-Auditing | Authentication (4624/4625), Privilege (4672), Account Mgmt |
| 🧬 Sysmon/Operational | Sysmon | Process Creation (1), Network (3), File Create (11), Registry (13) |
| 💻 PowerShell/Operational | PowerShell | Script Block Logging (4104), Module Logging (4103) |
| ⏱️ TaskScheduler/Operational | Task Scheduler | Task Created (106/141), Task Started (129/201) |

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
```

**API docs** — once the backend is running, visit `http://127.0.0.1:8000/docs` for Swagger UI.

---

## ⚠️ Known Limitations

| Limitation | Detail |
|---|---|
| 🪟 Windows Only | Collector requires Windows OS + admin privileges |
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
