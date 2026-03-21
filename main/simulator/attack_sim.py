"""
AutoSec AI – Attack Simulator
Simulates realistic attack patterns:
- SSH brute force
- Port scan followed by exploit
- Credential stuffing
- Data exfiltration
"""

import asyncio
import aiohttp
import random
import uuid
from datetime import datetime

BASE_URL = "http://localhost:8000"

# ── Fake IP pools ──────────────────────────────────────────────────────────────

ATTACKER_IPS = [
    "185.220.101.45",   # Tor exit node
    "94.102.49.180",    # Known threat actor range
    "45.142.212.100",
    "198.98.54.220",
    "5.188.210.33",
]

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.15", "10.0.2.20",
    "192.168.1.100", "192.168.1.105",
]

USERS = ["alice", "bob", "charlie", "admin", "svc_account", "root"]

# ── Attack Scenarios ───────────────────────────────────────────────────────────

async def ssh_brute_force(session: aiohttp.ClientSession, ip: str, user: str, n: int = 20):
    """Simulate rapid SSH login failures → auto-block should trigger."""
    print(f"[SIM] SSH brute force: {ip} → {user}")
    for i in range(n):
        await send_log(session, {
            "source_ip": ip,
            "user": user,
            "event_type": "login_failed",
            "severity": 4 + (i // 5),
            "details": {"service": "ssh", "attempt": i + 1, "password_attempt": f"pass{i}"},
        })
        await asyncio.sleep(random.uniform(0.05, 0.3))

async def port_scan_then_exploit(session: aiohttp.ClientSession, ip: str):
    """Port scan followed by login attempt — reconnaissance pattern."""
    print(f"[SIM] Port scan + exploit attempt: {ip}")
    await send_log(session, {
        "source_ip": ip,
        "event_type": "port_scan",
        "severity": 6,
        "details": {"ports_scanned": list(range(20, 8090, 47)), "open": [22, 80, 443]},
    })
    await asyncio.sleep(2)
    await send_log(session, {
        "source_ip": ip,
        "user": "admin",
        "event_type": "login_failed",
        "severity": 8,
        "details": {"service": "http_admin", "note": "post-scan exploit"},
    })

async def credential_stuffing(session: aiohttp.ClientSession, ips: list[str]):
    """Distributed credential stuffing – many IPs, many users."""
    print("[SIM] Distributed credential stuffing")
    for ip in ips:
        user = random.choice(USERS)
        for _ in range(random.randint(3, 8)):
            await send_log(session, {
                "source_ip": ip,
                "user": user,
                "event_type": "login_failed",
                "severity": 5,
                "details": {"attack": "credential_stuffing"},
            })
            await asyncio.sleep(random.uniform(0.1, 0.5))

async def data_exfil_attack(session: aiohttp.ClientSession, ip: str, user: str):
    """Successful login followed by data exfiltration."""
    print(f"[SIM] Data exfil: {ip} as {user}")
    await send_log(session, {
        "source_ip": ip,
        "user": user,
        "event_type": "login_success",
        "severity": 2,
        "details": {"note": "insider threat – compromised account"},
    })
    await asyncio.sleep(1)
    await send_log(session, {
        "source_ip": ip,
        "user": user,
        "event_type": "data_exfil",
        "severity": 9,
        "details": {"bytes_sent": 847_000_000, "destination": "185.220.101.45", "protocol": "HTTPS"},
    })

async def normal_traffic(session: aiohttp.ClientSession, n: int = 30):
    """Simulate normal user activity for baseline."""
    for _ in range(n):
        await send_log(session, {
            "source_ip": random.choice(INTERNAL_IPS),
            "user": random.choice(USERS[:3]),
            "event_type": random.choice(["login_success", "login_success", "login_success", "login_failed"]),
            "severity": random.randint(1, 3),
        })
        await asyncio.sleep(random.uniform(0.1, 0.8))

# ── Helpers ────────────────────────────────────────────────────────────────────

async def send_log(session: aiohttp.ClientSession, log: dict):
    try:
        async with session.post(f"{BASE_URL}/ingest", json=log) as resp:
            return await resp.json()
    except Exception as e:
        print(f"[SIM] Error sending log: {e}")

async def main():
    print("=" * 60)
    print("  AutoSec AI – Attack Simulator")
    print("=" * 60)

    async with aiohttp.ClientSession() as session:
        # Phase 1: Normal baseline traffic
        print("\n[PHASE 1] Generating normal baseline traffic...")
        await normal_traffic(session, 20)

        # Phase 2: Brute force attack
        print("\n[PHASE 2] Launching SSH brute force...")
        await ssh_brute_force(session, ATTACKER_IPS[0], "admin", 25)

        # Phase 3: Port scan + exploit
        print("\n[PHASE 3] Port scan + exploit attempt...")
        await port_scan_then_exploit(session, ATTACKER_IPS[1])

        # Phase 4: Credential stuffing
        print("\n[PHASE 4] Credential stuffing from multiple IPs...")
        await credential_stuffing(session, ATTACKER_IPS[2:4])

        # Phase 5: Data exfiltration
        print("\n[PHASE 5] Data exfiltration simulation...")
        await data_exfil_attack(session, ATTACKER_IPS[0], "alice")

        print("\n[DONE] Simulation complete. Check dashboard for alerts.")

if __name__ == "__main__":
    asyncio.run(main())
