"""
In-memory database — swap for SQLite/Postgres in production.
"""
import threading
from datetime import datetime
from typing import Optional
import time, random


class Database:
    def __init__(self):
        self._lock = threading.Lock()
        self.logs: list[dict] = []
        self.alerts: list[dict] = []
        self.responses: list[dict] = []
        self.blocked: dict[str, dict] = {}
        self.disabled_users: dict[str, dict] = {}
        self.stats = dict(
            total_logs=0, alerts_generated=0, auto_responses=0,
            ips_blocked=0, users_disabled=0, threats_detected=0,
        )

    # ── Logs ──────────────────────────────────────────────────────────────────
    def insert_log(self, log: dict):
        with self._lock:
            self.logs.insert(0, log)
            if len(self.logs) > 50000: self.logs = self.logs[:50000]
            self.stats["total_logs"] += 1

    def get_logs(self, limit=200, source_ip: Optional[str] = None) -> list:
        with self._lock:
            src = self.logs
            if source_ip: src = [l for l in src if l.get("source_ip") == source_ip]
            return src[:limit]

    # ── Alerts ────────────────────────────────────────────────────────────────
    def insert_alert(self, alert: dict):
        with self._lock:
            self.alerts.insert(0, alert)
            if len(self.alerts) > 10000: self.alerts = self.alerts[:10000]
            self.stats["alerts_generated"] += 1
            self.stats["threats_detected"] += 1

    def get_alerts(self, limit=100, status: Optional[str] = None) -> list:
        with self._lock:
            src = self.alerts
            if status: src = [a for a in src if a.get("status") == status]
            return src[:limit]

    def get_alert(self, alert_id: str) -> Optional[dict]:
        with self._lock:
            for a in self.alerts:
                if a["id"] == alert_id: return a
        return None

    def update_alert(self, alert_id: str, updates: dict):
        with self._lock:
            for a in self.alerts:
                if a["id"] == alert_id:
                    a.update(updates); return a
        return None

    def clear_alerts(self):
        with self._lock:
            self.alerts.clear()

    # ── Responses ─────────────────────────────────────────────────────────────
    def log_response(self, action: str, result: str, triggered_by: str, confidence: float) -> dict:
        r = {
            "id": f"resp_{int(time.time()*1000)}",
            "timestamp": datetime.utcnow().isoformat(),
            "action": action, "result": result,
            "triggered_by": triggered_by, "confidence": confidence,
        }
        with self._lock:
            self.responses.insert(0, r)
            if len(self.responses) > 1000: self.responses = self.responses[:1000]
            self.stats["auto_responses"] += 1
        return r

    def get_responses(self, limit=50) -> list:
        with self._lock: return self.responses[:limit]

    # ── Blocking ──────────────────────────────────────────────────────────────
    def block_ip(self, ip: str, reason: str, alert_id: str, temp_minutes: Optional[int] = None):
        expires = None
        if temp_minutes:
            expires = datetime.utcfromtimestamp(time.time() + temp_minutes * 60).isoformat()
        with self._lock:
            self.blocked[ip] = dict(
                entity=ip, type="ip", reason=reason,
                blocked_at=datetime.utcnow().isoformat(),
                alert_id=alert_id, expires=expires,
            )
            self.stats["ips_blocked"] = len(self.blocked)
        return self.log_response("AUTO_BLOCK", f"Blocked IP {ip}", ip, 1.0)

    def disable_user(self, user: str, reason: str, alert_id: str):
        with self._lock:
            self.disabled_users[user] = dict(
                user=user, entity=user, type="user", reason=reason,
                disabled_at=datetime.utcnow().isoformat(), alert_id=alert_id,
            )
            self.stats["users_disabled"] = len(self.disabled_users)
        return self.log_response("DISABLE_USER", f"Disabled user {user}", user, 1.0)

    def is_blocked(self, ip: str) -> bool: return ip in self.blocked
    def is_disabled(self, user: str) -> bool: return user in self.disabled_users

    def unblock_entity(self, entity: str):
        with self._lock:
            self.blocked.pop(entity, None)
            self.disabled_users.pop(entity, None)
            self.stats["ips_blocked"] = len(self.blocked)
            self.stats["users_disabled"] = len(self.disabled_users)

    def get_blocked_entities(self) -> dict:
        with self._lock:
            return {
                "blocked_ips": list(self.blocked.values()),
                "disabled_users": list(self.disabled_users.values()),
            }

    # ── Stats ─────────────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        with self._lock: return dict(self.stats)
