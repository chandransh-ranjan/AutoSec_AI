"""AutoSec AI – Auto-Response Engine"""
import uuid
from datetime import datetime
from typing import Optional


class AutoResponder:
    HIGH = 80   # block IP + disable user
    MED  = 65   # block IP only
    LOW  = 40   # alert only

    def __init__(self, db):
        self.db = db
        self._broadcast = None

    def set_broadcast(self, fn): self._broadcast = fn

    async def respond(self, log: dict, analysis: dict) -> Optional[dict]:
        confidence = analysis.get("confidence", 0)
        if isinstance(confidence, float) and confidence <= 1:
            confidence *= 100  # normalise 0-1 → 0-100

        ip = log.get("source_ip", "")
        user = log.get("user") or log.get("username")
        if self.db.is_blocked(ip): return None

        alert_id = str(uuid.uuid4())
        actions = []
        level = "monitor"

        if confidence >= self.HIGH:
            level = "critical"
            self.db.block_ip(ip, analysis.get("attack_type", "threat"), alert_id)
            actions.append(f"Blocked IP {ip}")
            if user and user not in ("unknown", ""):
                self.db.disable_user(user, analysis.get("attack_type", "threat"), alert_id)
                actions.append(f"Disabled user {user}")
        elif confidence >= self.MED:
            level = "high"
            self.db.block_ip(ip, analysis.get("attack_type", "threat"), alert_id, temp_minutes=60)
            actions.append(f"Temp-blocked IP {ip} (60 min)")
        elif confidence >= self.LOW:
            level = "medium"
            actions.append("Alert raised – monitoring")

        threat_type = analysis.get("attack_type") or analysis.get("threat_type") or "Unknown"
        conf_norm = confidence if confidence > 1 else confidence * 100

        alert = {
            "id": alert_id,
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": ip,
            "user": user or "unknown",
            "event_type": log.get("event_type") or log.get("action", ""),
            "threat_type": threat_type,
            "confidence": round(conf_norm, 1),
            "if_score": round(analysis.get("iforest_score", analysis.get("if_score", conf_norm * 0.6)), 1),
            "lstm_score": round(analysis.get("lstm_score", conf_norm * 0.4), 1),
            "auto_respond": True,
            "response_level": level,
            "actions": actions,
            "signals": analysis.get("signals", []),
            "status": "auto_resolved" if actions else "monitoring",
        }
        self.db.insert_alert(alert)

        if self._broadcast:
            await self._broadcast({"type": "alert", "data": {
                **alert,
                "label": "ATTACK" if conf_norm >= 80 else "SUSPICIOUS" if conf_norm >= 50 else "NORMAL",
                "iforest_score": alert["if_score"] / 100,
                "lstm_score": alert["lstm_score"] / 100,
                "geo_risk_score": 0.4 if ip.startswith("185.") else 0.1,
                "action": {"critical": "AUTO_BLOCK", "high": "ALERT_AND_TEMP_BLOCK",
                           "medium": "ALERT_SOC", "monitor": "LOG_ONLY"}.get(level, "LOG_ONLY"),
            }, "stats": self.db.get_stats()})
        return alert

    async def manual_override(self, alert: dict, action: str) -> dict:
        updates = {"manual_action": action, "manual_at": datetime.utcnow().isoformat()}
        if action == "approve":
            updates["status"] = "approved"
        elif action == "deny":
            self.db.unblock_entity(alert.get("source_ip", ""))
            if alert.get("user"): self.db.unblock_entity(alert["user"])
            updates["status"] = "denied"
            updates["actions"] = (alert.get("actions") or []) + ["Reversed by analyst"]
        elif action == "escalate":
            updates["status"] = "escalated"
            updates["actions"] = (alert.get("actions") or []) + ["Escalated to Tier-2 SOC"]
        self.db.update_alert(alert["id"], updates)
        alert.update(updates)
        return alert
