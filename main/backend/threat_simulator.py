"""
Threat Simulator – Generates realistic attack sequences
for testing the SOC detection pipeline.
"""

import asyncio
import random
import uuid
from datetime import datetime

ATTACK_IPS = [
    "185.220.101.47", "91.108.4.15", "198.51.100.22",
    "185.100.87.41",  "91.218.114.77", "198.50.200.15",
]
LEGIT_IPS  = ["10.0.1.10", "10.0.1.25", "192.168.1.100", "192.168.1.105"]
USERS      = ["alice", "bob", "charlie", "diana", "admin", "root", "svc_account"]


def _log(source_ip, event_type, severity, user=None, **details):
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": source_ip,
        "user": user or "unknown",
        "event_type": event_type,
        "action": event_type,
        "status": "failed" if "fail" in event_type else "success",
        "severity": severity,
        "details": details,
        "metadata": details,
    }


class ThreatSimulator:
    def __init__(self, collector):
        self.collector = collector

    async def run_simulation(self, attack_type: str, intensity: str = "medium"):
        delays = {"low": 0.6, "medium": 0.25, "high": 0.08}
        delay = delays.get(intensity, 0.25)

        if attack_type == "brute_force":
            await self._brute_force(delay)
        elif attack_type == "port_scan":
            await self._port_scan(delay)
        elif attack_type == "data_exfil":
            await self._data_exfil(delay)
        elif attack_type == "privilege_escalation":
            await self._privilege_escalation(delay)
        elif attack_type == "mixed":
            await asyncio.gather(
                self._brute_force(delay),
                self._port_scan(delay),
                self._data_exfil(delay),
            )

    async def _send(self, log: dict):
        self.collector.db.insert_log(log)
        await self.collector.process_log(log)

    async def _brute_force(self, delay: float):
        ip = random.choice(ATTACK_IPS)
        user = random.choice(USERS)
        n = random.randint(18, 35)
        for i in range(n):
            await self._send(_log(ip, "login_failed", min(4 + i // 4, 9), user=user,
                                  service="ssh", attempt=i + 1, fail_count=i + 1))
            await asyncio.sleep(delay)

    async def _port_scan(self, delay: float):
        ip = random.choice(ATTACK_IPS)
        ports = random.randint(80, 256)
        await self._send(_log(ip, "port_scan", 7, ports_scanned=ports, open_ports=[22, 80, 443]))
        await asyncio.sleep(delay * 4)
        # Follow-up exploit attempt
        await self._send(_log(ip, "login_failed", 8, user="admin",
                              service="http_admin", note="post-scan exploit"))

    async def _data_exfil(self, delay: float):
        ip = random.choice(ATTACK_IPS)
        user = random.choice(["alice", "bob", "svc_account"])
        # Legitimate-looking login first
        await self._send(_log(ip, "login_success", 2, user=user, service="web"))
        await asyncio.sleep(delay * 6)
        # Then massive exfil
        await self._send(_log(ip, "data_exfil", 9, user=user,
                              bytes=random.randint(200_000_000, 900_000_000),
                              destination="185.220.101.45", protocol="HTTPS"))

    async def _privilege_escalation(self, delay: float):
        ip = random.choice(LEGIT_IPS)
        user = random.choice(["charlie", "bob"])
        await self._send(_log(ip, "privilege_escalation", 8, user=user,
                              target_role="root", method="sudo"))
        await asyncio.sleep(delay * 3)
        await self._send(_log(ip, "login_success", 3, user="root",
                              source_user=user, note="post-escalation"))
