"""SIEM-style log ingestion pipeline."""
import asyncio


class LogCollector:
    def __init__(self, db, detector, responder):
        self.db = db
        self.detector = detector
        self.responder = responder
        self._broadcast = None

    def set_broadcast(self, fn):
        self._broadcast = fn
        self.responder.set_broadcast(fn)

    async def process_log(self, log: dict):
        analysis = self.detector.analyze(log)
        if self._broadcast:
            await self._broadcast({
                "type": "new_log",
                "data": {**log, "analysis": analysis},
                "stats": self.db.get_stats(),
            })
        if analysis.get("is_anomaly"):
            await self.responder.respond(log, analysis)
