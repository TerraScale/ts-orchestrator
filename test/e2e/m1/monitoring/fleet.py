import concurrent.futures
import http.client
import json
import os
import pwd
import queue
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

work, tools = map(Path, sys.argv[1:])
events = queue.Queue()
processes = []
servers = []
regions = ("sjc", "fra", "gru")
addresses = ("127.0.0.1", "127.0.0.2", "127.0.0.3")
state = {"readiness": 1, "burst": False}
emails = []
pushes = []
root = Path(__file__).resolve().parents[4]
counter_alerts = {"TerraBaseBackupFailed", "TerraBaseBackupHoles", "TerraBaseBackupDrillFailed", "TerraBaseReplicaDiverged", "AuthEmailProviderExhausted"}
budget_alerts = {"AlertDeliveryEmailBudgetExhausted", "AlertDeliveryEmailBudgetUnavailable"}
handled_line = re.compile(r'production alert notification handled status=(\w+) alerts=(\d+) group=(\w+) alertname=(\S+) region=(\S*) push=(\w+)')
email_line = re.compile(r'production alert email group=(\w+) sent=(\w+) reason="?([^"]*)"?$')


def request(address, port, path, body=None):
    connection = http.client.HTTPConnection(address, port, timeout=5)
    connection.request("GET" if body is None else "POST", path, body, {"Content-Type": "application/json"})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    if response.status not in (200, 202):
        raise RuntimeError(f"{address}:{port}{path}: {response.status}: {data[:200]!r}")
    return data


def query(index, expression):
    result = json.loads(request(addresses[index], 9090, "/api/v1/query?" + urlencode({"query": expression})))
    assert result["status"] == "success", result
    return result["data"]["result"]


def await_event(description, predicate, seconds=45):
    deadline = time.monotonic() + seconds
    while not predicate():
        for process in processes:
            if process.poll() is not None and process not in stopped:
                raise RuntimeError(f"{description}: process exited {process.args}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"{description}: deadline expired")
        try:
            events.get(timeout=remaining)
        except queue.Empty as error:
            raise RuntimeError(f"{description}: no event before deadline") from error


def launch(name, command, cwd=None, env=None):
    log = (work / f"{name}.log").open("w")
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    processes.append(process)
    lines = []
    process.lines = lines

    def consume():
        for line in process.stdout:
            log.write(line)
            log.flush()
            lines.append(line)
            if "ready to receive web requests" in line or "gossip settled; proceeding" in line or "Alert delivery listener ready" in line:
                ready.add(name)
            events.put(name)
        log.close()
        events.put(name)

    threading.Thread(target=consume, daemon=True).start()
    return process


def handled():
    return [(relay.address,) + match.groups() for relay in relays for line in list(relay.lines) for match in [handled_line.search(line)] if match]


def mailed():
    return [(relay.address,) + match.groups() for relay in relays for line in list(relay.lines) for match in [email_line.search(line)] if match]


def email_of(entry):
    return [mail for mail in mailed() if mail[1] == entry[3]]


def groups(status, names):
    return [entry for entry in handled() if entry[1] == status and entry[4] in names]


class Metrics(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/application":
            bump = int(state["burst"])
            text = (
                'terrabase_backup_failures_total{service="terrabase"} 38\n'
                f'terrabase_backup_holes_recorded_total{{service="terrabase"}} {2 + bump}\n'
                f'terrabase_backup_drills_total{{service="terrabase",result="failed"}} {1 + bump}\n'
                f'terrabase_replica_verifications_total{{service="terrabase",result="diverged"}} {2 + bump}\n'
                'ts_auth_emails_total{service="ts-auth",outcome="provider_exhausted"} 1\n'
            )
        else:
            text = f'terrascale_service_readiness{{service="ts-dashboard"}} {state["readiness"]}\nterrascale_production_journey_success 1\n'
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers()
        self.wfile.write(text.encode())
        events.put("scrape")


class Providers(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, value):
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        events.put("provider")

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.path == "/admission":
            self.reply({"status": "admitted", "sendBy": (datetime.now(UTC) + timedelta(seconds=5)).isoformat()})
        elif self.path.startswith("/accounts/") and self.path.endswith("/email/sending/send"):
            emails.append(json.loads(body))
            self.reply({"success": True, "result": {"delivered": ["mariogk@terrascale.tech"], "queued": [], "permanent_bounces": [], "suppressed_recipients": []}})
        elif self.path.startswith("/push/"):
            topic = self.path.removeprefix("/push/")
            pushes.append(body.decode())
            self.reply({"id": secrets.token_hex(6), "event": "message", "topic": topic})
        else:
            self.send_response(404)
            self.end_headers()


def post_alerts(alerts, ends=None):
    payload = json.dumps([{"labels": labels, **({"endsAt": ends} if ends else {})} for labels in alerts])
    for address in alive:
        request(address, 9093, "/api/v2/alerts", payload)


ready = set()
stopped = set()
alive = list(addresses)
relays = []
budget_servers = []
token = secrets.token_hex(32)
credentials = Path("/run/ts-alert-delivery")
gid = pwd.getpwnam("ts-alerts").pw_gid
os.chown(credentials, 0, gid)


def credential(key, value):
    (credentials / key).write_text(value)
    (credentials / key).chmod(0o640)
    os.chown(credentials / key, 0, gid)


for key, value in {"cloudflare_account_id_file": secrets.token_hex(16), "cloudflare_email_token_file": secrets.token_urlsafe(32), "ts_alerts_ntfy_topic_file": secrets.token_urlsafe(32)}.items():
    credential(key, value)


def relay_process(name, address, directory, layout):
    directory.mkdir(parents=True, exist_ok=True)
    process = launch(name, [str(work / "relay")], env={**os.environ, "JOURNEY_RELAY_ADDRESS": address, "JOURNEY_RELAY_STATE": str(directory), "JOURNEY_RELAY_LAYOUT": str(layout)})
    process.address = address
    return process


def post_relay(address, key, name):
    connection = http.client.HTTPConnection(address, 9094, timeout=60)
    connection.request("POST", "/alerts", json.dumps({"status": "firing", "groupKey": key, "alerts": [{"status": "firing", "labels": {"alertname": name, "severity": "critical", "region": "global"}}]}), {"Content-Type": "application/json"})
    response = connection.getresponse()
    response.read()
    connection.close()
    return response.status


try:
    providers = ThreadingHTTPServer(("127.0.0.9", 8025), Providers)
    servers.append(providers)
    threading.Thread(target=providers.serve_forever, daemon=True).start()
    launch("metrics", [str(work / "metrics"), str(work / "mesh-state")])
    for region, address in zip(regions, addresses):
        directory = work / region
        (directory / "budget").mkdir(parents=True)
        (directory / "budget" / "alerts.token").write_text(token)
        (directory / "relay").mkdir()
        (directory / "alertmanager.env").write_text(f"MONITOR_ADDRESS={address}\n")
        if region == "sjc":
            (directory / "relay" / "journey.json").write_text("{broken\n")
        budget_servers.append(launch("budget-" + region, [str(work / "metrics"), "budget", str(directory / "budget"), region, address] + [a for a in addresses if a != address]))
        relays.append(relay_process("relay-" + region, address, directory / "relay", directory / "alertmanager.env"))
        metrics = ThreadingHTTPServer((address, 9099), Metrics)
        servers.append(metrics)
        threading.Thread(target=metrics.serve_forever, daemon=True).start()
    prometheuses, alertmanagers = [], []
    for index, (region, address) in enumerate(zip(regions, addresses)):
        directory = work / region
        source = tools / "rendered" / f"ts-{region}-1"
        config = json.loads((source / "prometheus.yml").read_text())
        config["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"] = [a + ":9093" for a in addresses]
        config["global"].update(scrape_interval="5s", evaluation_interval="5s")
        config["scrape_configs"] = [
            {"job_name": "peer-topology", "metrics_path": "/orchestrator/metrics", "static_configs": [{"targets": ["127.0.0.1:9108"], "labels": {"region": "sjc"}}]},
        ]
        for job, port, path in (("monitoring-prometheus", 9090, "/metrics"), ("monitoring-alertmanager", 9093, "/metrics"), ("application-slo", 9099, "/application")):
            config["scrape_configs"].append({"job_name": job, "metrics_path": path, "static_configs": [
                {"targets": [a + f":{port}"], "labels": {"region": r, "host": f"ts-{r}-1"}} for a, r in zip(addresses, regions)
            ]})
        config["scrape_configs"].append({"job_name": "service-readiness", "metrics_path": "/metrics", "static_configs": [
            {"targets": [a + ":9099", a + ":9094"], "labels": {"region": r, "host": f"ts-{r}-1"}} for a, r in zip(addresses, regions)
        ], "metric_relabel_configs": [{"source_labels": ["__name__", "instance"], "regex": "terrascale_alert_delivery_email_withheld_total;.*:9094|.*;.*:9099", "action": "keep"}]})
        generated = json.loads((source / "rules.yml").read_text())
        allowed = counter_alerts | budget_alerts | {"ServiceReadinessFailed", "ProductionJourneyFailed"}
        generated["groups"] = [{"name": group["name"], "rules": [rule for rule in group["rules"] if rule.get("alert") in allowed]} for group in generated["groups"]]
        generated["groups"] = [group for group in generated["groups"] if group["rules"]]
        (directory / "prometheus.yml").write_text(json.dumps(config))
        (directory / "rules.yml").write_text(json.dumps(generated))
        (directory / "alertmanager.yml").write_text((root / "deploy/observability/production/alertmanager.yml").read_text().replace("127.0.0.1:9094", address + ":9094"))
        command = [str(tools / "alertmanager"), "--config.file=" + str(directory / "alertmanager.yml"), "--storage.path=" + str(directory / "alerts"), "--web.listen-address=" + address + ":9093", "--cluster.listen-address=" + address + ":9095", "--cluster.advertise-address=" + address + ":9095"]
        command.extend("--cluster.peer=" + a + ":9095" for a in addresses if a != address)
        alertmanagers.append(launch("alertmanager-" + region, command))
        prometheuses.append(launch("prometheus-" + region, [str(tools / "prometheus"), "--config.file=" + str(directory / "prometheus.yml"), "--storage.tsdb.path=" + str(directory / "data"), "--web.listen-address=" + address + ":9090"], directory))
    await_event("every backend and relay ready and gossip settled", lambda: len(ready) == 9)
    for address in addresses:
        cluster = json.loads(request(address, 9093, "/api/v2/status"))["cluster"]
        assert len(cluster["peers"]) == 3, cluster
    assert "".join(relays[0].lines).count("Production journey state unavailable; alert delivery continues") == 1, relays[0].lines
    await_event("every Prometheus scrapes actual mesh metrics through the 9108 proxy and every relay's budget counters at 0", lambda: all(query(i, 'ts_orch_mesh_store_observed{job="peer-topology"}') and len(query(i, 'terrascale_alert_delivery_email_withheld_total == 0')) == 6 for i in range(3)))
    await_event("old counters have repeated real scrapes", lambda: all(len(query(i, 'count_over_time(terrabase_backup_failures_total[1m]) >= 2')) == 3 for i in range(3)))
    for i in range(3):
        active = json.loads(request(addresses[i], 9090, "/api/v1/alerts"))["data"]["alerts"]
        assert not [a for a in active if a["labels"]["alertname"] in counter_alerts | budget_alerts], active
    assert not handled() and not pushes and not emails, (handled(), pushes, emails)
    state["readiness"] = 0
    await_event("relay perspectives aggregate one pending service outage", lambda: all(len(query(i, 'ALERTS{alertname="ServiceReadinessFailed",alertstate="pending",service="ts-dashboard",region="global"}')) == 1 for i in range(3)))
    for i in range(3):
        assert len(query(i, 'ALERTS{alertname="ServiceReadinessFailed"}')) == 1
    state["readiness"] = 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        replies = list(pool.map(lambda _: request("127.0.0.1", 9108, "/orchestrator/metrics"), range(24)))
    assert all(b"ts_orch_mesh_store_observed " in body for body in replies)
    digest = json.dumps({"status": "firing", "alerts": [{"status": "firing", "labels": {"alertname": "LaneDigest", "severity": "warning"}}]})
    request(addresses[1], 9094, "/alerts/digest", digest)
    await_event("before the mesh token exists a digest is withheld as budget unavailable", lambda: [m[2:] for m in mailed()] == [("false", 'budget unavailable')])
    credential("ts_alerts_nats_token_file", token)
    request(addresses[1], 9094, "/alerts/digest", digest)
    await_event("once the token appears the running relay emails the digest, without a restart, and never pushes", lambda: len(emails) == 1)
    assert emails[0]["subject"] == "TerraScale daily alert digest" and all(entry[6] == "false" for entry in groups("firing", {"LaneDigest"})), (emails, handled())
    await_event("the withheld email pages by push", lambda: len(groups("firing", {"AlertDeliveryEmailBudgetUnavailable"})) == 1, seconds=90)
    incident = {"alertname": "RuntimePeerTopologyMismatch", "service": "ts-orch", "region": "global", "severity": "critical"}
    post_alerts([incident])
    await_event("a firing topology incident reaches exactly one relay with production timings", lambda: len(groups("firing", {"RuntimePeerTopologyMismatch"})) == 1, seconds=40)
    post_alerts([incident], ends=datetime.now(UTC).isoformat())
    names = {f"JourneyBudget{index}" for index in range(12)}
    post_alerts([{**incident, "alertname": name, "service": "ts-dashboard"} for name in sorted(names)])
    await_event("its resolution reaches exactly one relay", lambda: len(groups("resolved", {"RuntimePeerTopologyMismatch"})) == 1, seconds=160)
    await_event("twelve more critical groups push once each", lambda: len(groups("firing", names)) == 12 and len([m for e in groups("firing", names) for m in email_of(e)]) == 12, seconds=60)
    assert len(emails) == 12 and any(m[3] == "hourly cap" for e in groups("firing", names) for m in email_of(e)), (emails, mailed())
    assert all(entry[6] == "true" for entry in handled() if entry[4] != "LaneDigest"), handled()
    await_event("the spent fleet budget pages by push", lambda: len(groups("firing", {"AlertDeliveryEmailBudgetExhausted"})) == 1, seconds=90)
    exhausted = groups("firing", {"AlertDeliveryEmailBudgetExhausted"})[0]
    assert exhausted[5] == "global" and exhausted[6] == "true", exhausted
    await_event("its email is withheld by the fleet cap", lambda: [m[3] for m in email_of(exhausted)] == ["hourly cap"])
    stopped.update((prometheuses[2], alertmanagers[2], relays[2], budget_servers[2]))
    for process in stopped:
        process.terminate()
        process.wait(timeout=10)
    servers[3].shutdown()
    servers[3].server_close()
    alive.remove(addresses[2])
    state["burst"] = True
    expected = {(name, region) for name in ("TerraBaseBackupHoles", "TerraBaseBackupDrillFailed", "TerraBaseReplicaDiverged") for region in ("sjc", "fra")}
    burst = lambda: [entry for entry in groups("firing", {name for name, _ in expected}) if (entry[4], entry[5]) in expected]
    await_event("the region-loss burst delivers every critical group once through the surviving relays", lambda: {(entry[4], entry[5]) for entry in burst()} == expected and all(email_of(entry) for entry in burst()), seconds=120)
    assert all(entry[0] != addresses[2] and entry[6] == "true" and [m[3] for m in email_of(entry)] == ["hourly cap"] for entry in burst()), (burst(), mailed())
    timestamp = 'timestamp(up{job="monitoring-prometheus",region="sjc"})'
    baseline = [float(query(i, timestamp)[0]["value"][1]) for i in range(2)]
    await_event("both surviving backends scrape through a full failover window without duplicates", lambda: all(float(query(i, timestamp)[0]["value"][1]) >= baseline[i] + 35 for i in range(2)), seconds=60)
    assert len(burst()) == len(expected) and len(emails) == 12, (burst(), emails)
    keys = [entry[3] for entry in handled() if entry[4] != "LaneDigest"]
    assert len(keys) == len(set(keys)), handled()
    assert len(pushes) == len([entry for entry in handled() if entry[6] == "true"]), (pushes, handled())
    labels = {"service": "ts-dashboard", "slo": "availability", "severity": "critical"}
    request(addresses[0], 9093, "/api/v2/alerts", json.dumps([{"labels": {**labels, "alertname": "ServiceSLOBurnFastGlobal", "region": "global"}}, {"labels": {**labels, "alertname": "ServiceSLOBurnFast", "region": "sjc"}}]))
    regional = lambda: json.loads(request(addresses[0], 9093, "/api/v2/alerts?" + urlencode({"filter": 'alertname="ServiceSLOBurnFast"'})))
    await_event("a global fast burn inhibits the same service's regional fast burn", lambda: [a["status"]["state"] for a in regional()] == ["suppressed"] and regional()[0]["status"]["inhibitedBy"])
    for process in budget_servers[:2]:
        process.terminate()
        process.wait(timeout=10)
        stopped.add(process)
    hung = socket.create_server((addresses[0], 4223))
    held = []
    threading.Thread(target=lambda: [held.append(hung.accept()) for _ in iter(int, 1)], daemon=True).start()
    withheld = len([m for m in mailed() if m[3] == "budget unavailable"])
    down = {f"BudgetDown{index}" for index in range(13)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=13) as pool:
        statuses = list(pool.map(lambda index: post_relay(addresses[0], f"unavailable-{index}", f"BudgetDown{index}"), range(13)))
    assert statuses == [202] * 13 and len(groups("firing", down)) == 13 and all(entry[6] == "true" for entry in groups("firing", down)), (statuses, groups("firing", down))
    await_event("a hung budget store withholds all thirteen emails", lambda: len([m for m in mailed() if m[3] == "budget unavailable"]) - withheld == 13, seconds=30)
    gru = relay_process("relay-gru-old-layout", "127.0.0.4", work / "gru-old" / "relay", work / "gru-old" / "alertmanager.env")
    relays.append(gru)
    await_event("an old-layout relay on the new binary starts", lambda: "relay-gru-old-layout" in ready)
    assert post_relay("127.0.0.4", "old-layout", "OldLayoutIncident") == 202
    await_event("the old-layout relay keeps emailing from its own ledger", lambda: len(emails) == 13)
    ledger = json.loads((work / "gru-old" / "relay" / "email-ledger.json").read_text())
    assert len(ledger) == 1 and emails[-1]["text"].startswith("firing: OldLayoutIncident"), (ledger, emails[-1])
    print(f"monitoring: production Alertmanager 0.34.1 timings x3 + real relay x3 + JetStream budget x3: malformed journey state logged once; a missing mesh token withholds email and pages, the token appearing later is used without a restart; topology incident firing then resolved -> one notification each; fleet email stops at 12 and the exhausted budget pages by push; GRU lost -> {len(expected)} groups once each, push only; hung budget store + 13 concurrent notifications -> 13 pushes and 13 withheld emails; old-layout relay still emails from its ledger; passed")
finally:
    for server in servers:
        server.shutdown()
        server.server_close()
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    if sys.exc_info()[0] is not None:
        for path in work.glob("*.log"):
            print(path.name, path.read_text()[-2000:], file=sys.stderr)
