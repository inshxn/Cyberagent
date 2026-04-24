# CyberAgent + XPulse

CyberAgent + XPulse is a runnable cybersecurity agent system wrapped around a small microblogging demo app. CyberAgent is the main component: a FastAPI middleware layer that monitors every request, detects malicious behavior, scores risk, responds automatically, and stores forensic evidence in SQLite. XPulse exists only to generate realistic traffic and show the security system working.

## Architecture

```text
Client / Browser / Attack Script
        |
        v
FastAPI Middleware: CyberAgent
        |
        +--> Traffic Monitoring Agent
        |       IP, headers, query, body, route, timestamps, request frequency
        |
        +--> Detection Agents
        |       Signature: SQLi, XSS, command injection
        |       Behavior: rate spikes, brute force, large payloads
        |       Anomaly: running baseline with standard-deviation checks
        |
        +--> AI Decision Engine
        |       weighted explainable scoring, 0-100 risk, adaptive history
        |
        +--> Response Agent
        |       allow, flag, throttle, block, temporary IP ban
        |
        +--> Logging & Forensics
        |       SQLite security_events table and query APIs
        |
        v
XPulse Demo Backend
        |
        v
React Dashboard + Feed
```

## Project Layout

```text
CyberAgent/
├── core/                 CyberAgent detection, AI scoring, response, logging
├── plugin/               FastAPI middleware and config
├── api/                  ASGI app entrypoint
├── xpulse/               Demo microblog backend and React frontend
├── data/                 SQLite databases are created here
├── scripts/              Attack simulation script
├── tests/                Unit and integration tests
├── docker/               Dockerfiles
├── docker-compose.yml
├── requirements.txt
└── run.sh / run.bat
```

## Run Locally

```bash
cd CyberAgent
./run.sh
```

The app serves the built frontend from the backend at [http://localhost:8000](http://localhost:8000). If you prefer a separate Vite dev server:

```bash
cd CyberAgent/xpulse/frontend
npm install
VITE_API_URL=http://localhost:8000 npm run dev
```

## Docker

```bash
cd CyberAgent
docker compose up --build
```

Services:

- `backend`: FastAPI XPulse app wrapped by CyberAgent on port `8000`
- `frontend`: Vite React UI on port `5173`
- `database`: SQLite volume initializer for `logs.db` and `xpulse.db`

## CyberAgent Integration

CyberAgent is designed as middleware:

```python
from plugin import CyberAgent, CyberAgentConfig

config = CyberAgentConfig.from_file("plugin/config.yaml")
app.add_middleware(CyberAgent, config=config)
```

Modules and thresholds are controlled by [plugin/config.yaml](/Users/mhxain/Documents/New%20project/CyberAgent/plugin/config.yaml).

Risk mapping:

- `0-30`: allow
- `31-60`: flag and log
- `61-80`: throttle
- `81-100`: block and temporarily ban IP

## Demo Flow

1. Open the UI.
2. Sign up or log in.
3. Create normal XPulse posts.
4. Use the Attack Simulation panel for SQL injection, XSS, and rapid requests.
5. Watch the CyberAgent Events table update with attack type, risk score, and response action.

You can also run:

```bash
python scripts/simulate_attacks.py --base-url http://localhost:8000
```

Useful APIs:

- `GET /cyberagent/dashboard`
- `GET /cyberagent/events`
- `GET /cyberagent/blocked`
- `GET /simulate/sql-injection`
- `POST /simulate/xss`
- `GET /simulate/ping`

## Testing

```bash
cd CyberAgent
pytest
```

Tests cover signature/behavior/anomaly detection and middleware integration with the XPulse demo API.

## Notes

CyberAgent intentionally uses explainable detection and scoring instead of fake machine learning. The anomaly detector maintains a simple per-route and per-IP baseline, while adaptive learning increases risk for repeat offenders and decays that history over time.
