import http.client
import json
import os
import pwd
import queue
import secrets
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

binary = os.path.realpath(sys.argv[1])
budgets = [json.loads(path.read_text()) for path in Path(sys.argv[2]).glob("*/email-budget.json")]
assert len(budgets) == 3
assert sum(b["hourly"] for b in budgets) <= 12
assert sum(b["daily"] for b in budgets) <= 288
budget_path = Path("/etc/ts-monitoring/production/email-budget.json")
budget_path.write_text(json.dumps(budgets[0]))
now = datetime.now(UTC)
Path("/var/lib/ts-alerts/email-ledger.json").write_text(json.dumps([{
    "key": "daily-digest",
    "send_by": now.isoformat(),
    "until": (now + timedelta(days=1)).isoformat(),
}]))
directory = Path("/run/ts-alert-delivery")
directory.mkdir(mode=0o750, exist_ok=True)
directory.chmod(0o750)
gid = pwd.getpwnam("ts-alerts").pw_gid
os.chown(directory, 0, gid)
for key, value in {
    "cloudflare_account_id_file": secrets.token_hex(16),
    "cloudflare_email_token_file": secrets.token_urlsafe(32),
    "ts_alerts_ntfy_topic_file": secrets.token_urlsafe(32),
}.items():
    path = directory / key
    path.write_text(value)
    path.chmod(0o640)
    os.chown(path, 0, gid)
process = subprocess.Popen([binary, "alert-delivery"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
lines = []
events = queue.Queue()


def read_logs():
    for line in process.stderr:
        text = line.decode()
        lines.append(text)
        events.put(text)
    events.put(None)


reader = threading.Thread(target=read_logs)
reader.start()
try:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            line = events.get(timeout=max(0, deadline - time.monotonic()))
        except queue.Empty as error:
            raise RuntimeError("relay listener did not open") from error
        if line is None:
            raise RuntimeError("relay exited before listener opened: " + "".join(lines)[-2000:])
        if "Alert delivery listener ready" in line:
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
    ledger = Path("/var/lib/ts-alerts/email-ledger.json")

    def send_group(key):
        connection.request("POST", "/alerts", json.dumps({
            "status": "firing", "groupKey": key,
            "alerts": [{"status": "firing", "labels": {"alertname": "EmailBudgetJourney", "severity": "critical"}}],
        }), {"Content-Type": "application/json"})
        response = connection.getresponse()
        response.read()
        assert response.status == 202, response.status

    for index, budget in enumerate(budgets):
        budget_path.write_text(json.dumps(budget))
        ledger.write_text("[]")
        for attempt in range(budget["hourly"] + 2):
            send_group(f"region-{index}-attempt-{attempt}")
        entries = json.loads(ledger.read_text())
        assert len(entries) == budget["hourly"], entries
        send_group(f"region-{index}-attempt-0")
        assert json.loads(ledger.read_text()) == entries
        past = datetime.now(UTC) - timedelta(hours=2)
        ledger.write_text(json.dumps([{
            "key": f"spent-{attempt}", "send_by": past.isoformat(), "until": (past + timedelta(hours=4)).isoformat(),
        } for attempt in range(budget["daily"])]))
        before = ledger.read_bytes()
        send_group(f"region-{index}-daily-exhausted")
        assert ledger.read_bytes() == before
    budget_path.unlink()
    ledger.write_text("[]")
    send_group("missing-budget")
    assert ledger.read_text() == "[]"
    print("monitoring: real relay enforces rendered fleet caps <=12/hour, <=288/day across three budgets, duplicate suppression and missing-budget fail closed")
    connection.close()
finally:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    reader.join(timeout=10)
    assert not reader.is_alive()
if "".join(lines).count("Production journey state unavailable; alert delivery continues") != 1:
    raise RuntimeError("malformed state was not logged exactly once")
print("monitoring: malformed journey state -> real relay accepts alert, observation unknown, one log line; passed")
