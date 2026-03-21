# AutoSec AI — Self-Responding SOC Platform

> A machine learning-powered Security Operations Center that detects threats in real time, scores them with a confidence engine, and automatically responds — blocking IPs, disabling compromised accounts, and alerting analysts — without human intervention.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5-F7931E?style=flat&logo=scikitlearn&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## What It Does

Most companies cannot afford a 24/7 security team watching every network event. AutoSec AI acts as that first line of defense — ingesting raw logs, running them through an ML pipeline, and autonomously responding to threats in milliseconds.

| Without AutoSec AI | With AutoSec AI |
|---|---|
| Analyst manually reviews thousands of alerts | ML engine filters and scores automatically |
| Hours to detect a brute-force attack | Detected after 3–5 failed logins |
| Manual IP blocking after investigation | Auto-blocked at 65%+ confidence |
| No audit trail for response decisions | Every action logged with reasoning |

---

## Demo

The dashboard updates in real time as attacks are detected and responded to.

**Simulator tab → Launch Attack → watch alerts populate with confidence scores, auto-response actions, and detection signal breakdowns.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Log Sources                          │
│          (network devices, servers, applications)           │
└──────────────────────────┬──────────────────────────────────┘
                           │ JSON logs via HTTP / TCP / Beats
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Logstash Pipeline                        │
│         Normalize → Enrich → Forward to ES + Backend       │
└──────────┬────────────────────────────┬────────────────────-┘
           │                            │
           ▼                            ▼
┌──────────────────┐        ┌───────────────────────────────┐
│  Elasticsearch   │        │      FastAPI Backend          │
│  (log storage,   │        │                               │
│   SIEM queries)  │        │  ┌─────────────────────────┐  │
└──────────────────┘        │  │   ML Detection Engine   │  │
           │                │  │                         │  │
           ▼                │  │  Isolation Forest       │  │
┌──────────────────┐        │  │  + Sequence Detector    │  │
│     Kibana       │        │  │  → Confidence Score     │  │
│  (historical     │        │  └──────────┬──────────────┘  │
│   dashboards)    │        │             │                  │
└──────────────────┘        │  ┌──────────▼──────────────┐  │
                            │  │  Auto-Response Engine   │  │
                            │  │                         │  │
                            │  │  ≥65% → Block IP        │  │
                            │  │  ≥80% → Block + Disable │  │
                            │  └──────────┬──────────────┘  │
                            │             │                  │
                            │  ┌──────────▼──────────────┐  │
                            │  │   WebSocket Broadcast   │  │
                            │  └──────────┬──────────────┘  │
                            └─────────────┼─────────────────┘
                                          │ Real-time push
                                          ▼
                            ┌─────────────────────────────┐
                            │      React Dashboard        │
                            │                             │
                            │  • Live alert feed          │
                            │  • Confidence score rings   │
                            │  • IF + LSTM score bars     │
                            │  • One-click unblock        │
                            │  • Attack simulator         │
                            └─────────────────────────────┘
```

---

## ML Pipeline

### Isolation Forest

An unsupervised anomaly detection algorithm from `scikit-learn`. Trained on normal traffic, it assigns anomaly scores to new log entries based on how few random splits are needed to isolate them — genuine anomalies are rare and easier to isolate, giving them higher scores.

**Features used:**
- Event type (encoded)
- Severity level
- Number of events from this IP (history)
- Failure rate (failed / total for this IP)
- Unique event types from this IP
- Events in last 60 seconds (burst detection)
- Total failure count

### Sequence Detector (LSTM Proxy)

Analyses the last 10 events from each source IP for known attack patterns using a sliding-window match:

| Pattern | Score Boost |
|---|---|
| `login_failed × 3` in sequence | +28 |
| `login_failed → login_failed → login_success` | +28 |
| `port_scan → login_failed` | +28 |
| `login_success → data_exfil` | +28 |
| 4+ events of same type in window | +7 per event |

### Confidence Score Formula

```
confidence = (0.55 × IsolationForest_score) + (0.45 × sequence_score)
```

**Semantic boosts applied on top:**

| Event Type | Boost |
|---|---|
| `malware` | +25 |
| `brute_force`, `data_exfil` | +22 |
| `privilege_escalation` | +15 |
| `port_scan`, `lateral_movement` | +10 |
| IP in known threat-actor range | +8 |

### Auto-Response Thresholds

| Confidence | Level | Action |
|---|---|---|
| ≥ 80% | CRITICAL | Block IP permanently + disable user account |
| 65–79% | HIGH | Temp-block IP for 60 minutes |
| 40–64% | MEDIUM | Raise alert, analyst review |
| < 40% | — | Log only, no action |

---

## File Structure

```
autosec-ai/
│
├── backend/                        # FastAPI server + ML pipeline
│   ├── main.py                     # Entry point — all routes, WebSocket, app init
│   ├── db.py                       # In-memory database (logs, alerts, blocked entities)
│   ├── log_collector.py            # SIEM-style ingestion pipeline
│   ├── response_engine.py          # Auto-response logic (block/disable/escalate)
│   ├── threat_simulator.py         # Generates realistic attack log sequences
│   ├── ml/
│   │   ├── __init__.py
│   │   └── detector.py             # Isolation Forest + Sequence anomaly detection
│   ├── requirements.txt            # Python dependencies
│   └── Dockerfile                  # Container definition for backend service
│
├── dashboard/                      # React 18 frontend
│   ├── public/
│   │   └── index.html              # HTML shell
│   ├── src/
│   │   ├── App.jsx                 # Full SPA — all tabs, components, WebSocket client
│   │   └── index.js                # React DOM entry point
│   └── package.json                # Node dependencies and scripts
│
├── simulator/                      # Standalone attack simulation scripts
│   ├── attack_sim.py               # CLI simulator — 4 attack scenarios via aiohttp
│   └── requirements.txt
│
├── config/
│   └── logstash.conf               # Logstash pipeline (TCP/Beats → ES + backend)
│
├── docs/                           # Documentation assets
│
├── .github/
│   └── workflows/
│       └── ci.yml                  # GitHub Actions — backend test + dashboard build
│
├── .env.example                    # Environment variable template
├── .gitignore
├── docker-compose.yml              # Full ELK stack + backend + dashboard
├── CONTRIBUTING.md
└── README.md
```

---

## Quick Start

### Option 1 — Local (no Docker)

**Requirements:** Python 3.10+, Node.js 18+

```bash
git clone https://github.com/YOUR_USERNAME/autosec-ai.git
cd autosec-ai
```

**Terminal 1 — Backend:**
```bash
cd backend
pip install -r requirements.txt        # Mac/Linux
py -m pip install -r requirements.txt  # Windows

python main.py        # Mac/Linux
py main.py            # Windows
```
Backend runs at `http://localhost:8000`

**Terminal 2 — Dashboard:**
```bash
cd dashboard
npm install
npm start
```
Dashboard opens at `http://localhost:3000`

**Terminal 3 — Run attack simulation (optional):**
```bash
cd simulator
pip install -r requirements.txt
python attack_sim.py        # Mac/Linux
py attack_sim.py            # Windows
```

---

### Option 2 — Full Stack with Docker (ELK included)

**Requirements:** Docker Desktop

```bash
git clone https://github.com/YOUR_USERNAME/autosec-ai.git
cd autosec-ai
docker-compose up -d
```

| Service | URL |
|---|---|
| React Dashboard | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/stats` | Aggregated statistics |
| `GET` | `/alerts?limit=N&status=X` | List alerts |
| `GET` | `/logs?limit=N&source_ip=X` | List ingested logs |
| `GET` | `/blocked` | All blocked IPs and disabled users |
| `POST` | `/ingest` | Submit a log entry for analysis |
| `POST` | `/simulate` | Trigger a simulated attack |
| `POST` | `/action` | Manually block/unblock/disable an entity |
| `POST` | `/response/{id}` | Approve / deny / escalate an alert |
| `DELETE` | `/blocked/{entity}` | Unblock an IP or re-enable a user |
| `POST` | `/train` | Retrain ML model on current log data |
| `WS` | `/ws` | Real-time event stream (WebSocket) |

### Example — Ingest a log

```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "185.220.101.47",
    "user": "admin",
    "event_type": "login_failed",
    "severity": 7,
    "details": { "service": "ssh", "attempt": 12 }
  }'
```

### Event types supported

`login_success` · `login_failed` · `port_scan` · `data_exfil` · `brute_force` · `privilege_escalation` · `lateral_movement` · `malware`

---

## Dashboard Tabs

| Tab | Description |
|---|---|
| **Dashboard** | Live stats overview, recent alerts, real-time log feed |
| **Alerts** | Full alert list filterable by ATTACK / SUSPICIOUS, with expandable signal breakdowns |
| **Log Stream** | Searchable terminal-style log viewer with anomaly highlighting |
| **Blocked** | All blocked IPs and disabled users with one-click unblock |
| **Simulator** | Built-in attack launcher — 5 scenarios, 3 intensity levels |

---

## Attack Scenarios (Simulator)

| Scenario | What it simulates | Expected response |
|---|---|---|
| SSH Brute Force | 18–30 rapid login failures from single IP | IP blocked at ~15 failures |
| Port Scan + Exploit | 256-port scan followed by exploit attempt | Alert raised, IP flagged |
| Data Exfiltration | Login then 500MB+ transfer to external IP | IP blocked + user disabled |
| Privilege Escalation | Sudo to root from internal IP | High-confidence alert |
| APT Mixed Campaign | All vectors simultaneously from multiple IPs | Multiple blocks triggered |

---

## Extending the Project

### Replace in-memory DB with PostgreSQL

In `db.py`, swap the `dict`-based store for SQLAlchemy:
```python
from sqlalchemy import create_engine
engine = create_engine("postgresql://user:pass@localhost/autosec")
```

### Add a real trained LSTM (PyTorch)

In `ml/detector.py`, replace `SequenceDetector.score()`:
```python
import torch
model = torch.load("ml/models/lstm.pt")

def score(self, events):
    tensor = encode_sequence(events)
    with torch.no_grad():
        return float(model(tensor).item() * 100)
```

### Real firewall integration

In `response_engine.py`, replace the dict-based block with:
```python
# Linux iptables
import subprocess
subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

# AWS Security Group
import boto3
ec2 = boto3.client("ec2")
ec2.revoke_security_group_ingress(GroupId="sg-xxx", IpPermissions=[...])
```

### Slack notifications

In `response_engine.py → _notify()`:
```python
import httpx
httpx.post(os.getenv("SLACK_WEBHOOK_URL"), json={
    "text": f":rotating_light: *{alert['threat_type']}* — {alert['source_ip']} — Confidence: {alert['confidence']}%"
})
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend | Python, FastAPI | REST API + WebSocket server |
| ML | scikit-learn (Isolation Forest) | Unsupervised anomaly scoring |
| ML | Custom Sequence Detector | Attack pattern recognition |
| Database | In-memory (dict) | Log + alert storage (swap for Postgres) |
| Frontend | React 18 | Real-time SOC dashboard |
| Log Pipeline | Logstash | Log normalization + forwarding |
| Log Storage | Elasticsearch | SIEM — long-term log retention + search |
| Visualization | Kibana | Historical dashboards + threat hunting |
| Containers | Docker Compose | One-command full-stack deployment |
| CI/CD | GitHub Actions | Automated test + build on every push |

---

## Roadmap

- [ ] PostgreSQL persistence layer
- [ ] Real PyTorch LSTM trained on CICIDS2017 dataset
- [ ] GeoIP enrichment on log ingestion
- [ ] Slack / PagerDuty / OpsGenie notification integrations
- [ ] JWT authentication on API endpoints
- [ ] Rate limiting on `/ingest`
- [ ] Kibana dashboard export (`.ndjson`)
- [ ] Unit test suite with pytest

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.

---

## Author

Built as a demonstration of an ML-powered autonomous SOC system combining unsupervised anomaly detection, real-time event streaming, and automated threat response.
