# SOCRA AI

**AI-Powered SOC Investigation Platform**

SOCRA AI is a self-hosted Security Operations Center (SOC) platform that collects, analyzes, and investigates Windows security telemetry in real time. It combines a native Windows event collector, an enterprise detection engine, MITRE ATT&CK mapping, and AI-powered analysis through Ollama.

---

## What It Does

- **Collects** Windows Event Logs in real time (Security, Sysmon, PowerShell, Task Scheduler)
- **Detects** suspicious activity using 100+ event rules and process intelligence
- **Classifies** events by severity and maps them to MITRE ATT&CK techniques
- **Investigates** alerts with an enterprise workspace (related events, process tree, IOCs, analyst notes)
- **Analyzes** security events using AI (Ollama / Llama 3)
- **Reports** on SOC activity with filterable, exportable reports
- **Visualizes** threat trends on a real-time dashboard with live WebSocket updates

---

## Architecture

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

## Requirements

### Backend
- Python 3.10+
- Windows OS (for Windows Event Log collection)
- SQLite (included with Python)
- Ollama (optional, for AI features)

### Frontend
- Node.js 18+
- npm or compatible package manager

---

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd "SOCRA AI"
```

### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install
```

---

## Environment Variables

### Backend (.env)

Copy `backend/.env.example` to `backend/.env` and configure:

```bash
# Required: JWT Secret Key (generate with: python -c "import secrets; print(secrets.token_urlsafe(48))")
SECRET_KEY=your-random-secret-key-at-least-32-characters

# Required: Auth user password hashes (generate with: python -c "from app.auth.auth_service import hash_password; print(hash_password('your-password'))")
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=pbkdf2_sha256$600000$...
ANALYST_USERNAME=analyst
ANALYST_PASSWORD_HASH=pbkdf2_sha256$600000$...

# Optional: Splunk (legacy integration)
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your-splunk-password

# Optional: Gemini AI
GEMINI_API_KEY=your-gemini-api-key

# Optional: CORS origins (comma-separated)
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# Optional: Logging
LOG_LEVEL=INFO
LOG_FILE=socra.log
```

### Frontend (.env)

Copy `frontend/.env.example` to `frontend/.env` and configure (optional):

```bash
# Backend API base URL (defaults to http://127.0.0.1:8000)
# VITE_API_URL=http://127.0.0.1:8000

# WebSocket base URL (defaults to ws://127.0.0.1:8000)
# VITE_WS_URL=ws://127.0.0.1:8000
```

---

## Database

SOCRA AI uses SQLite with WAL (Write-Ahead Logging) mode for concurrent read/write access. The database file is created automatically at `backend/data/socra.db` on first run.

Tables:
- **events** — all collected Windows security events with denormalized columns
- **investigations** — persistent investigation records
- **cases** — case management records
- **collector_state** — collector resumability state

Migrations run automatically on startup.

---

## Windows Telemetry

SOCRA AI collects from four Windows Event Log channels:

| Channel | Provider | Event Types |
|---------|----------|-------------|
| Security | Microsoft-Windows-Security-Auditing | Authentication (4624/4625), Privilege (4672), Account Mgmt |
| Microsoft-Windows-Sysmon/Operational | Sysmon | Process Creation (1), Network (3), File Create (11), Registry (13) |
| Microsoft-Windows-PowerShell/Operational | PowerShell | Script Block Logging (4104), Module Logging (4103) |
| Microsoft-Windows-TaskScheduler/Operational | Task Scheduler | Task Created (106/141), Task Started (129/201) |

### Collector Modes

**In-Process Collector (Development)**
```bash
cd backend
python main.py
```

**Standalone Collector (Production)**
```bash
cd backend
python install_collector.py task    # Install as Windows scheduled task
python run_collector.py             # Or run manually
```

The standalone collector persists to SQLite independently. The API server detects it and forwards events to the live WebSocket pipeline without duplicating collection.

---

## AI / Ollama Setup

SOCRA AI uses Ollama for AI-powered investigation and chat.

### Install Ollama

Download from [ollama.ai](https://ollama.ai) and install.

### Pull a Model

```bash
ollama pull llama3
```

### Verify

```bash
ollama list
```

The AI features are optional. When Ollama is not running, SOCRA AI operates normally — AI analysis is replaced with "unavailable" indicators instead of errors.

---

## Running the Application

### Start Backend

```bash
cd backend
python main.py
```

The API starts at `http://127.0.0.1:8000`.

### Start Frontend

```bash
cd frontend
npm run dev
```

The UI starts at `http://localhost:5173`.

### Default Credentials

- **Admin:** `admin` / your configured password
- **Analyst:** `analyst` / your configured password

---

## Development Usage

### Build Frontend for Production

```bash
cd frontend
npm run build
```

Output is in `frontend/dist/`.

### Run Tests

```bash
cd backend
python test_persistence.py
python test_event_registry.py
python test_analytics.py
```

### API Documentation

Once the backend is running, visit `http://127.0.0.1:8000/docs` for Swagger UI documentation.

---

## Known Limitations

- **Windows Only** — The Windows Event Log collector requires Windows OS and admin privileges
- **Single Machine** — Designed for single-machine deployment (not distributed)
- **No HTTPS** — Production deployments should use a reverse proxy (nginx, Caddy) for TLS
- **SQLite** — Not suitable for extremely high-volume enterprise environments (millions of events/day)
- **Ollama Required** — AI features require a running Ollama instance with a pulled model
- **No Email/Slack Alerts** — Alert notifications are in-app only (no external integrations)

---

## License

See repository for license details.
