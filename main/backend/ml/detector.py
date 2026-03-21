"""
ML Anomaly Detector — Isolation Forest + Rule Engine + LSTM sequence scoring.
Produces a confidence score 0–100 driving auto-response decisions.
"""

import random
import math
import threading
from datetime import datetime
from collections import defaultdict
from typing import Optional

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _SKLEARN = True
except ImportError:
    _SKLEARN = False


# ── Event catalogue ───────────────────────────────────────────────────────────
EVENT_SEVERITY = {
    "login_success": 1, "login_failed": 3, "port_scan": 6,
    "data_exfil": 9, "brute_force": 8, "privilege_escalation": 8,
    "lateral_movement": 7, "malware": 10,
}

ATTACK_SEQUENCES = [
    ["login_failed", "login_failed", "login_failed"],
    ["login_failed", "login_failed", "login_success"],
    ["port_scan", "login_failed"],
    ["login_success", "data_exfil"],
    ["login_failed", "privilege_escalation"],
]


# ── Isolation Forest wrapper ──────────────────────────────────────────────────
class IFDetector:
    def __init__(self):
        self._lock = threading.Lock()
        self._trained = False
        if _SKLEARN:
            self.model = IsolationForest(n_estimators=150, contamination=0.08, random_state=42)
            self.scaler = StandardScaler()
            self._seed()

    def _seed(self):
        rng = random.Random(42)
        X = [[rng.randint(0,1), rng.randint(1,3), rng.randint(1,25),
               rng.uniform(0,0.1), rng.randint(1,3), rng.randint(0,4), rng.randint(0,2)]
             for _ in range(300)]
        import numpy as np
        Xs = self.scaler.fit_transform(np.array(X, dtype=float))
        self.model.fit(Xs)
        self._trained = True

    def score(self, features: list) -> float:
        if not _SKLEARN or not self._trained:
            return self._heuristic(features)
        import numpy as np
        with self._lock:
            Xs = self.scaler.transform(np.array([features], dtype=float))
            raw = self.model.decision_function(Xs)[0]
            return float(min(max(50 - raw * 110, 0), 100))

    def _heuristic(self, features: list) -> float:
        # features: [event_code, severity, n_events, fail_rate, unique_events, recent, n_failures]
        score = 0
        _, severity, n_events, fail_rate, _, recent, n_failures = features
        score += severity * 5
        score += fail_rate * 40
        score += min(recent, 10) * 3
        score += min(n_failures, 15) * 2
        return min(score, 100.0)

    def retrain(self, X):
        if not _SKLEARN: return
        import numpy as np
        with self._lock:
            Xs = self.scaler.fit_transform(np.array(X, dtype=float))
            self.model.fit(Xs)


# ── Sequence (LSTM proxy) detector ────────────────────────────────────────────
class SequenceDetector:
    def score(self, events: list) -> float:
        if len(events) < 2: return 0.0
        window = events[-10:]
        score = 0.0
        for pattern in ATTACK_SEQUENCES:
            plen = len(pattern)
            for i in range(max(0, len(window) - plen + 1)):
                if window[i:i+plen] == pattern:
                    score += 28.0
        # burst penalty
        from collections import Counter
        for evt, cnt in Counter(window).items():
            if cnt >= 4: score += min(cnt * 7, 35)
        return min(score, 100.0)


# ── Combined detector ─────────────────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self):
        self.if_det   = IFDetector()
        self.seq_det  = SequenceDetector()
        self.ip_hist: dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def analyze(self, log: dict) -> dict:
        ip = log.get("source_ip", "")
        event_type = log.get("event_type") or log.get("action", "")
        severity = log.get("severity", 5)

        # Update history
        with self._lock:
            hist = self.ip_hist[ip]
            hist.append(log)
            if len(hist) > 200: self.ip_hist[ip] = hist[-200:]

        hist = self.ip_hist[ip]
        n = len(hist)
        failures = sum(1 for h in hist if "fail" in (h.get("event_type") or h.get("action", "")))
        fail_rate = failures / max(n, 1)

        now = datetime.utcnow()
        recent = sum(1 for h in hist
                     if (now - datetime.fromisoformat(h["timestamp"].split(".")[0])).seconds < 60)

        event_code = list(EVENT_SEVERITY.keys()).index(event_type) if event_type in EVENT_SEVERITY else 0
        features = [event_code, severity, n, fail_rate,
                    len(set(h.get("event_type","") for h in hist)), recent, failures]

        if_score = self.if_det.score(features)

        events_seq = [(h.get("event_type") or h.get("action", "")) for h in hist]
        seq_score = self.seq_det.score(events_seq)

        confidence = round(0.55 * if_score + 0.45 * seq_score, 1)

        # Semantic boosts
        boosts = {"brute_force": 22, "data_exfil": 22, "malware": 25,
                  "privilege_escalation": 15, "port_scan": 10, "lateral_movement": 10}
        confidence = min(confidence + boosts.get(event_type, 0), 100.0)

        # Geo-risk boost
        if ip.startswith(("185.", "91.", "198.")):
            confidence = min(confidence + 8, 100.0)

        threat = self._classify(event_type)
        is_anomaly = confidence >= 40
        auto_respond = confidence >= 65

        return {
            "is_anomaly": is_anomaly,
            "confidence": confidence,
            "if_score": round(if_score, 1),
            "iforest_score": round(if_score / 100, 3),
            "lstm_score": round(seq_score / 100, 3),
            "threat_type": threat,
            "attack_type": threat.lower().replace(" ", "_"),
            "auto_respond": auto_respond,
            "severity": self._sev(confidence),
            "signals": self._signals(event_type, fail_rate, recent, confidence),
            "model": "IsolationForest+Sequence",
        }

    def _classify(self, event_type: str) -> str:
        return {
            "login_failed": "Credential Attack", "brute_force": "Brute Force",
            "port_scan": "Reconnaissance", "data_exfil": "Data Exfiltration",
            "privilege_escalation": "Privilege Escalation",
            "lateral_movement": "Lateral Movement", "malware": "Malware Activity",
            "login_success": "Suspicious Login",
        }.get(event_type, "Unknown Threat")

    def _sev(self, c: float) -> str:
        if c >= 85: return "critical"
        if c >= 70: return "high"
        if c >= 50: return "medium"
        return "low"

    def _signals(self, event_type, fail_rate, recent, confidence) -> list:
        sigs = []
        if fail_rate > 0.5: sigs.append(f"High failure rate: {fail_rate:.0%}")
        if recent >= 5: sigs.append(f"Burst: {recent} events in last 60s")
        if event_type in ("brute_force", "data_exfil", "malware"): sigs.append(f"High-risk event type: {event_type}")
        if confidence >= 80: sigs.append("Confidence exceeds auto-response threshold")
        return sigs

    def get_model_info(self) -> dict:
        return {
            "model_version": "IsolationForest-v2 + SequenceDetector-v1",
            "algorithm": ["Isolation Forest", "LSTM Sequence Proxy", "Rule Heuristics"],
            "sklearn_available": _SKLEARN,
            "threshold_auto_respond": 65,
            "threshold_critical": 80,
        }

    def retrain(self, logs: list) -> dict:
        if len(logs) < 50:
            return {"status": "skipped", "reason": "Need ≥50 logs"}
        if not _SKLEARN:
            return {"status": "skipped", "reason": "scikit-learn not installed"}
        hist = self.ip_hist
        features = []
        for log in logs:
            ip = log.get("source_ip", "")
            h = hist.get(ip, [])
            n = len(h)
            failures = sum(1 for x in h if "fail" in (x.get("event_type","") or ""))
            features.append([
                0, log.get("severity", 5), n,
                failures / max(n, 1), 1, 0, failures
            ])
        self.if_det.retrain(features)
        return {"status": "retrained", "samples": len(logs)}
