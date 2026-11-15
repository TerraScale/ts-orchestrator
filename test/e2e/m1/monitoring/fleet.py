import concurrent.futures
import http.client
import json
import queue
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

work, tools = map(Path, sys.argv[1:])
events = queue.Queue()
notices = []
processes = []
servers = []
regions = ("sjc", "fra", "gru")
addresses = ("127.0.0.1", "127.0.0.2", "127.0.0.3")
state = {"readiness": 1, "burst": False}
accepted = {}
refused = []
root = Path(__file__).resolve().parents[4]
counter_alerts = {"TerraBaseBackupFailed", "TerraBaseBackupHoles", "TerraBaseBackupDrillFailed", "TerraBaseReplicaDiverged", "AuthEmailProviderExhausted"}


def request(address, port, path):
    connection = http.client.HTTPConnection(address, port, timeout=5)
    connection.request("GET", path)
    response = connection.getresponse()
    body = response.read()
    connection.close()
    if response.status != 200:
        raise RuntimeError(f"{address}:{port}{path}: {response.status}: {body[:200]!r}")
    return body


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


def launch(name, command, cwd=None):
    log = (work / f"{name}.log").open("w")
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    processes.append(process)

    def consume():
        for line in process.stdout:
            log.write(line)
            log.flush()
            if "ready to receive web requests" in line or "gossip settled; proceeding" in line:
                ready.add(name)
            events.put(name)
        log.close()
        events.put(name)

    threading.Thread(target=consume, daemon=True).start()
    return process


class Relay(BaseHTTPRequestHandler):
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

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        address = self.server.server_address[0]
        notices.append((address, body))
        group = (body["alerts"][0]["labels"]["alertname"], body["alerts"][0]["labels"].get("region"))
        status = 202
        if self.path == "/alerts" and body["status"] == "firing" and group not in accepted.get(address, {}):
            if len(accepted.setdefault(address, {})) >= budgets[address]:
                status = 503
                refused.append((address, group))
            else:
                accepted[address][group] = body
        self.send_response(status)
        self.end_headers()
        events.put("notification")


ready = set()
stopped = set()
budgets = {address: json.loads((tools / "rendered" / f"ts-{region}-1" / "email-budget.json").read_text())["hourly"] for region, address in zip(regions, addresses)}
try:
    launch("metrics", [str(work / "metrics"), str(work / "mesh-state")])
    prometheuses, alertmanagers = [], []
    for index, (region, address) in enumerate(zip(regions, addresses)):
        server = ThreadingHTTPServer((address, 9094), Relay)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        directory = work / region
        directory.mkdir()
        source = tools / "rendered" / f"ts-{region}-1"
        config = json.loads((source / "prometheus.yml").read_text())
        config["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"] = [a + ":9093" for a in addresses]
        config["global"].update(scrape_interval="5s", evaluation_interval="5s")
        config["scrape_configs"] = [
            {"job_name": "peer-topology", "metrics_path": "/orchestrator/metrics", "static_configs": [{"targets": ["127.0.0.1:9108"], "labels": {"region": "sjc"}}]},
        ]
        for job, port, path in (("monitoring-prometheus", 9090, "/metrics"), ("monitoring-alertmanager", 9093, "/metrics"), ("service-readiness", 9094, "/metrics"), ("application-slo", 9094, "/application")):
            config["scrape_configs"].append({"job_name": job, "metrics_path": path, "static_configs": [
                {"targets": [a + f":{port}"], "labels": {"region": r, "host": f"ts-{r}-1"}} for a, r in zip(addresses, regions)
            ]})
        generated = json.loads((source / "rules.yml").read_text())
        allowed = counter_alerts | {"MonitoringBackendDown", "ServiceReadinessFailed", "ProductionJourneyFailed"}
        generated["groups"] = [{"name": group["name"], "rules": [rule for rule in group["rules"] if rule.get("alert") in allowed]} for group in generated["groups"]]
        generated["groups"] = [group for group in generated["groups"] if group["rules"]]
        (directory / "prometheus.yml").write_text(json.dumps(config))
        (directory / "rules.yml").write_text(json.dumps(generated))
        (directory / "alertmanager.yml").write_text((root / "deploy/observability/production/alertmanager.yml").read_text().replace("127.0.0.1:9094", address + ":9094"))
        command = [str(tools / "alertmanager"), "--config.file=" + str(directory / "alertmanager.yml"), "--storage.path=" + str(directory / "alerts"), "--web.listen-address=" + address + ":9093", "--cluster.listen-address=" + address + ":9095", "--cluster.advertise-address=" + address + ":9095"]
        command.extend("--cluster.peer=" + a + ":9095" for a in addresses if a != address)
        alertmanagers.append(launch("alertmanager-" + region, command))
        prometheuses.append(launch("prometheus-" + region, [str(tools / "prometheus"), "--config.file=" + str(directory / "prometheus.yml"), "--storage.tsdb.path=" + str(directory / "data"), "--web.listen-address=" + address + ":9090"], directory))
    await_event("every backend ready and gossip settled", lambda: len(ready) == 6)
    for address in addresses:
        cluster = json.loads(request(address, 9093, "/api/v2/status"))["cluster"]
        assert len(cluster["peers"]) == 3, cluster
    await_event("every Prometheus scrapes actual mesh metrics through the 9108 proxy", lambda: all(query(i, 'ts_orch_mesh_store_observed{job="peer-topology"}') for i in range(3)))
    await_event("old counters have repeated real scrapes", lambda: all(len(query(i, 'count_over_time(terrabase_backup_failures_total[1m]) >= 2')) == 3 for i in range(3)))
    for i in range(3):
        active = json.loads(request(addresses[i], 9090, "/api/v1/alerts"))["data"]["alerts"]
        assert not [a for a in active if a["labels"]["alertname"] in counter_alerts], active
    assert not notices, notices
    state["readiness"] = 0
    await_event("relay perspectives aggregate one pending service outage", lambda: all(len(query(i, 'ALERTS{alertname="ServiceReadinessFailed",alertstate="pending",service="ts-dashboard",region="global"}')) == 1 for i in range(3)))
    for i in range(3):
        assert len(query(i, 'ALERTS{alertname="ServiceReadinessFailed"}')) == 1
    state["readiness"] = 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        replies = list(pool.map(lambda _: request("127.0.0.1", 9108, "/orchestrator/metrics"), range(24)))
    assert all(b"ts_orch_mesh_store_observed " in body for body in replies)
    await_event("readiness recovered before its hold", lambda: all(not query(i, 'ALERTS{alertname="ServiceReadinessFailed"}') for i in range(3)))
    stopped.update((prometheuses[2], alertmanagers[2]))
    for process in stopped:
        process.terminate()
        process.wait(timeout=10)
    servers[2].shutdown()
    servers[2].server_close()
    state["burst"] = True
    expected = {("MonitoringBackendDown", "gru")} | {(name, region) for name in ("TerraBaseBackupHoles", "TerraBaseBackupDrillFailed", "TerraBaseReplicaDiverged") for region in ("sjc", "fra")}
    delivered = lambda: {group for groups in accepted.values() for group in groups}
    await_event("the region-loss burst delivers every critical group through the surviving relays' shares", lambda: delivered() == expected, seconds=240)
    assert addresses[2] not in accepted, accepted
    assert all(len(groups) <= budgets[address] for address, groups in accepted.items()), accepted
    assert sum(len(groups) for groups in accepted.values()) == len(expected) <= sum(budgets[a] for a in addresses[:2]) <= 12, accepted
    assert refused and all(any(group in groups for address, groups in accepted.items() if address != refuser) for refuser, group in refused), (refused, accepted)
    down = next(body for groups in accepted.values() for group, body in groups.items() if group[0] == "MonitoringBackendDown")
    assert len(down["alerts"]) == 3, down
    timestamp = 'timestamp(up{job="monitoring-prometheus",region="sjc"})'
    baseline = [float(query(i, timestamp)[0]["value"][1]) for i in range(2)]
    await_event("both surviving backends scrape through a full failover window without duplicates", lambda: all(float(query(i, timestamp)[0]["value"][1]) >= baseline[i] + 45 for i in range(2)), seconds=65)
    assert delivered() == expected and sum(len(groups) for groups in accepted.values()) == len(expected), accepted
    labels = {"service": "ts-dashboard", "slo": "availability", "severity": "critical"}
    connection = http.client.HTTPConnection(addresses[0], 9093, timeout=5)
    connection.request("POST", "/api/v2/alerts", json.dumps([{"labels": {**labels, "alertname": "ServiceSLOBurnFastGlobal", "region": "global"}}, {"labels": {**labels, "alertname": "ServiceSLOBurnFast", "region": "sjc"}}]), {"Content-Type": "application/json"})
    response = connection.getresponse()
    response.read()
    connection.close()
    assert response.status == 200, response.status
    regional = lambda: json.loads(request(addresses[0], 9093, "/api/v2/alerts?" + urlencode({"filter": 'alertname="ServiceSLOBurnFast"'})))
    await_event("a global fast burn inhibits the same service's regional fast burn", lambda: [a["status"]["state"] for a in regional()] == ["suppressed"] and regional()[0]["status"]["inhibitedBy"])
    print("monitoring: real mesh exporter + 9108 proxy; old counters page nothing; 24 concurrent proxies; three Prometheus + gossip; GRU lost with a 7-group critical burst -> a capped relay answers 503, the next Alertmanager peer delivers through its own share, every group exactly once within the fleet budget; global burn inhibits the regional page")
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
