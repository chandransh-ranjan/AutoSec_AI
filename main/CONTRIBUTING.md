# Contributing to AutoSec AI

Thank you for your interest in contributing! Here's how to get started.

## Setting Up for Development

```bash
git clone https://github.com/YOUR_USERNAME/autosec-ai.git
cd autosec-ai

# Backend
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt

# Dashboard
cd ../dashboard
npm install
```

## Project Structure

```
autosec-ai/
├── backend/          # FastAPI server + ML pipeline
├── dashboard/        # React frontend
├── simulator/        # Attack simulation scripts
├── config/           # Logstash pipeline config
└── docs/             # Documentation and assets
```

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Test them (see below)
5. Commit: `git commit -m "feat: describe your change"`
6. Push: `git push origin feature/your-feature-name`
7. Open a Pull Request

## Testing Your Changes

```bash
# Backend pipeline test
cd backend
python -c "
import asyncio
from db import Database
from ml.detector import AnomalyDetector
from response_engine import AutoResponder
from log_collector import LogCollector
from threat_simulator import ThreatSimulator

db = Database()
det = AnomalyDetector()
resp = AutoResponder(db)
coll = LogCollector(db, det, resp)
coll.set_broadcast(lambda x: asyncio.sleep(0))

async def test():
    sim = ThreatSimulator(coll)
    await sim.run_simulation('brute_force', 'high')
    s = db.get_stats()
    print('Logs:', s['total_logs'], '| Alerts:', s['alerts_generated'])

asyncio.run(test())
"
```

## Commit Message Format

Use conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation update
- `refactor:` code refactor
- `test:` adding tests

## Ideas for Contributions

- Replace the in-memory database with SQLite or PostgreSQL
- Train and integrate a real PyTorch LSTM model
- Add unit tests with pytest
- Add real firewall/iptables integration in `response_engine.py`
- Add Slack / PagerDuty notification support
- Add GeoIP enrichment to log entries
- Improve the React dashboard with charts (Chart.js / Recharts)
