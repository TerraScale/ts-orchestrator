import http.client
import json
import os
import select
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

binary = os.path.realpath(sys.argv[1])
now = datetime.now(UTC)
Path("/var/lib/ts-alerts/email-ledger.json").write_text(json.dumps([{
    "key": "daily-digest",
    "send_by": now.isoformat(),
    "until": (now + timedelta(days=1)).isoformat(),
}]))
process = subprocess.Popen([binary, "alert-delivery"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
lines = []
try:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stderr], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            raise RuntimeError("relay listener did not open")
        line = os.read(process.stderr.fileno(), 8192).decode()
        if not line:
            raise RuntimeError("relay exited before listener opened")
        lines.append(line)
        if "Alert delivery listener ready" in "".join(lines):
            break
    connection = http.client.HTTPConnection("127.0.0.1", 9094, timeout=10)
    connection.request("GET", "/metrics")
    response = connection.getresponse()
    body = response.read().decode()
    if response.status != 200 or "terrascale_production_journey_observed 0\n" not in body:
        raise RuntimeError(f"journey was not unknown: {response.status}: {body}")
    connection.request("POST", "/alerts/digest",
                       '{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"LaneDeliveryAccepted","severity":"warning"}}]}',
                       {"Content-Type": "application/json"})
    response = connection.getresponse()
    response.read()
    if response.status != 202:
        raise RuntimeError(f"real relay rejected notification: {response.status}")
    connection.close()
finally:
    process.terminate()
    try:
        _, remaining = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        _, remaining = process.communicate()
    lines.append(remaining.decode())
if "".join(lines).count("Production journey state unavailable; alert delivery continues") != 1:
    raise RuntimeError("malformed state was not logged exactly once")
print("monitoring: malformed journey state -> real relay accepts alert, observation unknown, one log line; passed")
