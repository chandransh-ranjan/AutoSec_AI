"""
AutoSec AI – Complete FastAPI Backend
All routes, WebSocket, ML pipeline, auto-response, simulator endpoint.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import uuid
import time
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from db import Database
from ml.detector import AnomalyDetector
from response_engine import AutoResponder
from log_collector import LogCollector
from threat_simulator import ThreatSimulator

app = FastAPI(title="AutoSec AI SOC", version="2.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ── Singletons ────────────────────────────────────────────────────────────────
db = Database()
detector = AnomalyDetector()
responder = AutoResponder(db)
collector = LogCollector(db, detector, responder)

# ── WebSocket Manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self): self.active: list[WebSocket] = []
    async def connect(self, ws: WebSocket):
        await ws.accept(); self.active.append(ws)
    def disconnect(self, ws: WebSocket):
        if ws in self.active: self.active.remove(ws)
    async def broadcast(self, msg: dict):
        dead = []
        for ws in self.active:
            try: await ws.send_json(msg)
            except: dead.append(ws)
        for ws in dead:
            if ws in self.active: self.active.remove(ws)

manager = ConnectionManager()
collector.set_broadcast(manager.broadcast)
simulator = ThreatSimulator(collector)

# ── Pydantic Models ───────────────────────────────────────────────────────────
class LogEntry(BaseModel):
    source_ip: str
    user: Optional[str] = None
    event_type: str          # login_failed|login_success|port_scan|data_exfil|brute_force|...
    severity: int = 5
    details: Optional[dict] = None

class ActionRequest(BaseModel):
    target_type: str         # ip | user
    target: str
    action: str              # block | unblock | disable | enable
    reason: str = ""

class SimRequest(BaseModel):
    attack_type: str         # brute_force|port_scan|data_exfil|privilege_escalation|mixed
    intensity: str = "medium"

class OverrideRequest(BaseModel):
    alert_id: str
    action: str              # approve | deny | escalate

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "operational", "version": "2.0.0", "timestamp": datetime.utcnow().isoformat()}

@app.get("/stats")
async def get_stats():
    s = db.get_stats()
    s["ml_ready"] = True
    s["model_info"] = detector.get_model_info() if hasattr(detector, "get_model_info") else {}
    return s

@app.get("/alerts")
async def get_alerts(limit: int = 100, status: Optional[str] = None):
    alerts = db.get_alerts(limit=limit, status=status)
    # Map to dashboard-expected shape
    out = []
    for a in alerts:
        out.append({
            **a,
            "label": _severity_to_label(a.get("confidence", 0)),
            "iforest_score": a.get("if_score", 0) / 100,
            "lstm_score": a.get("lstm_score", 0) / 100,
            "geo_risk_score": 0.4 if a.get("source_ip", "").startswith("185.") else 0.1,
            "port": a.get("details", {}).get("port"),
            "action": _level_to_action(a.get("response_level", "monitor")),
        })
    return {"alerts": out, "total": len(out)}

@app.get("/responses")
async def get_responses(limit: int = 50):
    responses = db.get_responses(limit=limit)
    return {"responses": responses}

@app.get("/logs")
async def get_logs(limit: int = 200, source_ip: Optional[str] = None):
    return db.get_logs(limit=limit, source_ip=source_ip)

@app.get("/blocked-ips")
async def get_blocked_ips():
    blocked = db.get_blocked_entities()
    return {"blocked_ips": {v["entity"]: v for v in blocked.get("blocked_ips", [])}}

@app.get("/blocked")
async def get_blocked():
    return db.get_blocked_entities()

@app.post("/ingest")
async def ingest_log(entry: LogEntry, background_tasks: BackgroundTasks):
    log = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": entry.source_ip,
        "user": entry.user or "unknown",
        "event_type": entry.event_type,
        "action": entry.event_type,          # alias for detector compat
        "status": "failed" if "fail" in entry.event_type else "success",
        "severity": entry.severity,
        "details": entry.details or {},
        "metadata": entry.details or {},
    }
    db.insert_log(log)
    background_tasks.add_task(collector.process_log, log)
    return {"log_id": log["id"], "status": "queued"}

@app.post("/action")
async def take_action(req: ActionRequest):
    if req.action == "block":
        db.block_ip(req.target, req.reason or "Manual block", "manual")
        resp = db.log_response("manual", "Manual IP block", req.target, 1.0)
    elif req.action == "unblock":
        db.unblock_entity(req.target)
        resp = {"action": "unblock", "result": f"Unblocked {req.target}"}
    elif req.action == "disable":
        db.disable_user(req.target, req.reason or "Manual disable", "manual")
        resp = db.log_response("manual", "Manual user disable", req.target, 1.0)
    else:
        resp = {"action": req.action, "result": "unknown action"}
    await manager.broadcast({"type": "response", "data": resp, "stats": db.get_stats()})
    return resp

@app.post("/response/{alert_id}")
async def manual_response(alert_id: str, override: OverrideRequest):
    alert = db.get_alert(alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    result = await responder.manual_override(alert, override.action)
    await manager.broadcast({"type": "response_update", "data": result, "stats": db.get_stats()})
    return result

@app.delete("/blocked/{entity}")
async def unblock(entity: str):
    db.unblock_entity(entity)
    await manager.broadcast({"type": "unblock", "data": {"entity": entity}, "stats": db.get_stats()})
    return {"status": "unblocked", "entity": entity}

@app.delete("/alerts/clear")
async def clear_alerts():
    db.clear_alerts()
    await manager.broadcast({"type": "cleared", "stats": db.get_stats()})
    return {"status": "cleared"}

@app.post("/simulate")
async def run_simulation(req: SimRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(simulator.run_simulation, req.attack_type, req.intensity)
    return {"status": "started", "attack_type": req.attack_type, "intensity": req.intensity}

@app.post("/train")
async def retrain():
    logs = db.get_logs(limit=10000)
    return detector.retrain(logs) if hasattr(detector, "retrain") else {"status": "not_supported"}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    await ws.send_json({"type": "init", "data": {"stats": db.get_stats()}})
    try:
        while True: await asyncio.wait_for(ws.receive_text(), timeout=30)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        manager.disconnect(ws)

# ── Helpers ───────────────────────────────────────────────────────────────────
def _severity_to_label(confidence):
    if isinstance(confidence, float) and confidence < 2:  # 0–1 scale
        confidence *= 100
    if confidence >= 80: return "ATTACK"
    if confidence >= 50: return "SUSPICIOUS"
    return "NORMAL"

def _level_to_action(level):
    mapping = {"critical": "AUTO_BLOCK", "high": "ALERT_AND_TEMP_BLOCK",
               "medium": "ALERT_SOC", "monitor": "LOG_ONLY", "monitoring": "LOG_ONLY"}
    return mapping.get(level, "LOG_ONLY")

if __name__ == "__main__":
    import uvicorn
    print("🛡️  AutoSec AI SOC Backend – starting on http://localhost:8000")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="warning")
