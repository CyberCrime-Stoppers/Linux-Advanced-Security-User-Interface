import asyncio, random
from .models import Finding, Severity

MOCK_FINDINGS = [
    dict(check="setuid_scan", severity=Severity.HIGH, title="Unexpected SUID binary",
         path="/usr/local/bin/legacy-helper",
         detail="SUID root binary outside package manager control",
         remediation="Verify provenance; run: dpkg -S /usr/local/bin/legacy-helper"),
    dict(check="world_writable", severity=Severity.MEDIUM, title="World-writable file in /etc",
         path="/etc/motd",
         detail="Mode 0666 allows any local user modification",
         remediation="chmod 0644 /etc/motd"),
    dict(check="sshd_config", severity=Severity.CRITICAL, title="SSH root login enabled",
         detail="PermitRootLogin is not set to 'no'",
         remediation="Add 'PermitRootLogin no' to /etc/ssh/sshd_config"),
    dict(check="pkg_updates", severity=Severity.LOW, title="Outstanding package updates",
         detail="14 packages pending security updates",
         remediation="apt upgrade or dnf update"),
]

async def mock_scanner(queue: asyncio.Queue):
    """Simulates audit runs. Replace with real agent invocation later."""
    while True:
        await asyncio.sleep(random.uniform(2, 5))
        spec = random.choice(MOCK_FINDINGS)
        await queue.put(Finding(host="localhost", **spec))
