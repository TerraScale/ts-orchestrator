import concurrent.futures
import contextlib
import http.client
import ipaddress
import json
import math
import pathlib
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

from scenarios import Scenarios

ROOT = pathlib.Path(__file__).resolve().parents[3]
SCENARIOS = (
    ("http-one-source", "C18"),
    ("http-many-sources", "C18"),
    ("slow-headers", "C18"),
    ("slow-bodies", "C18"),
    ("idle-websocket", "C18"),
    ("idle-postgres", "C18"),
    ("tenant-isolation", "C20"),
    ("task-oom", "C14"),
    ("disk-full", "C14"),
    ("replica-scale", "C11"),
    ("node-scale", "C12"),
    ("node-loss", "C14"),
)


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def oci(region, *arguments, paginated=True):
    result = subprocess.run(
        ["oci", "--region", region, "--max-retries", "0", *arguments,
         *(["--all"] if paginated else []), "--output", "json"],
        capture_output=True, timeout=120, check=False,
    )
    require(result.returncode == 0, "OCI inventory failed; provider output withheld")
    data = json.loads(result.stdout)["data"]
    return data["items"] if isinstance(data, dict) and "items" in data else data


def fleet_scope():
    result = subprocess.run(["go", "run", "./test/e2e/abuse/control"], cwd=ROOT,
                            input=b'{"operation":"fleet"}', capture_output=True, timeout=120, check=False)
    require(result.returncode == 0, "internal/fleet authority validation failed; output withheld")
    return json.loads(result.stdout)


def staging():
    require(len(sys.argv) == 1, "no target or argument accepted; staging is discovered")
    scope = fleet_scope()
    fleet = scope["document"]
    target = dict(fleet["staging"])
    others = fleet["regions"]
    require(others, "production inventory missing; isolation cannot be checked")
    require(target["compartment_id"] and all(
        target["compartment_id"] != region["compartment_id"] for region in others
    ), "staging compartment overlaps production")
    require(1 <= target["nodes"]["min"] <= target["nodes"]["max"] <= 3,
            "staging node bounds must be within 1..3")
    for field in ("vcn_cidr", "public_subnet_cidr", "private_subnet_cidr"):
        network = ipaddress.ip_network(target[field])
        require(all(not network.overlaps(ipaddress.ip_network(region["vcn_cidr"]))
                    for region in others), "staging network overlaps production")
    host = scope["api_name"]
    require(host not in fleet["dns"]["steered_names"], "staging hostname is globally steered")
    require(not target.get("geo_continents"), "staging is assigned production GeoDNS continents")
    vault = oci(target["oci_region"], "kms", "management", "vault", "get",
                "--vault-id", target["vault_id"], paginated=False)
    require(vault["id"] == target["vault_id"] and vault["compartment-id"] == target["compartment_id"]
            and vault["lifecycle-state"] == "ACTIVE", "fleet staging Vault is not active in its own compartment")
    inventory = oci(target["oci_region"], "nlb", "network-load-balancer", "list",
                    "--compartment-id", target["compartment_id"])
    owned = [item for item in inventory
             if item["compartment-id"] == target["compartment_id"]
             and item["display-name"] == scope["nlb_name"]
             and item["lifecycle-state"] == "ACTIVE"
             and item["freeform-tags"].get("terrascale-managed-by") == "ts-orchestrator"
             and item["freeform-tags"].get("terrascale-owner") == "terrascale"
             and item["freeform-tags"].get("terrascale-resource-key") == scope["nlb_key"]]
    require(len(owned) == 1, "C16: exactly one owned, active staging NLB required")
    balancer = oci(target["oci_region"], "nlb", "network-load-balancer", "get",
                   "--network-load-balancer-id", owned[0]["id"], paginated=False)
    require(balancer["compartment-id"] == target["compartment_id"],
            "NLB detail outside staging compartment")
    addresses = {item["ip-address"] for item in balancer["ip-addresses"]
                 if item["is-public"] and ipaddress.ip_address(item["ip-address"]).version == 4}
    resolved = {item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET,
                                                        socket.SOCK_STREAM)}
    require(resolved and resolved == addresses, "staging DNS must resolve only to its owned NLB")
    policies = oci(target["oci_region"], "dns", "steering-policy", "list",
                   "--compartment-id", fleet["dns"]["compartment_id"])
    for policy in policies:
        detail = oci(target["oci_region"], "dns", "steering-policy", "get",
                     "--steering-policy-id", policy["id"], paginated=False)
        require(all(answer["rdata"].rstrip(".") not in addresses | {host}
                    for answer in detail.get("answers", [])), "staging NLB participates in production DNS steering")
    instances = oci(target["oci_region"], "compute", "instance", "list",
                    "--compartment-id", target["compartment_id"])
    running = [item for item in instances if item["lifecycle-state"] == "RUNNING"]
    require(target["nodes"]["min"] <= len(running) <= target["nodes"]["max"],
            "C16: live staging node count outside fleet bounds")
    node_ips = set()
    hosts = []
    for instance in running:
        require(instance["compartment-id"] == target["compartment_id"],
                "instance outside staging compartment")
        vnics = oci(target["oci_region"], "compute", "instance", "list-vnics",
                    "--compartment-id", target["compartment_id"], "--instance-id", instance["id"])
        for vnic in vnics:
            if vnic["is-primary"]:
                require(ipaddress.ip_address(vnic["private-ip"])
                        in ipaddress.ip_network(target["private_subnet_cidr"]),
                        "primary staging VNIC outside staging private subnet")
                node_ips.add(vnic["private-ip"])
                require(target["label"] in instance["display-name"]
                        and "desktop" not in instance["display-name"], "invalid staging host name")
                hosts.append({"id": instance["id"], "name": instance["display-name"],
                              "address": instance["display-name"] + ".nb.ts.internal"})
    require(len(node_ips) == len(running), "staging node addresses incomplete")
    expected = {f"tcp-{port}" for port in (80, 443, 5432)}
    require(set(balancer["listeners"]) == expected and set(balancer["backend-sets"]) == expected,
            "NLB has unknown listener or backend-set mappings")
    for port in (80, 443, 5432):
        name = f"tcp-{port}"
        listener = balancer["listeners"][name]
        require(listener["port"] == port and listener["protocol"] == "TCP"
                and listener["default-backend-set-name"] == name,
                "NLB listener does not target the staging TCP backend set")
        backends = balancer["backend-sets"][name]["backends"]
        require(backends and all(backend["ip-address"] in node_ips
                                and backend["port"] == port for backend in backends),
                "NLB backend outside staging nodes or expected port")
    target["_fleet"] = fleet
    target["_region_key"] = scope["region_key"]
    target["_nlb_key"] = scope["nlb_key"]
    target["_hosts"] = hosts
    return target, host, sorted(addresses)


def c18_integer(file, pattern):
    match = re.search(pattern, (ROOT / file).read_text())
    require(match is not None, "C18 source shape changed; review the budget reader")
    return int(match[1])


def duration(file, name):
    source = (ROOT / file).read_text()
    match = re.search(r"\b" + name + r"\s*=\s*(?:(\d+)\s*\*\s*)?time\.(Second|Minute)", source)
    require(match is not None, "deadline source changed: " + name)
    return int(match[1] or 1) * (60 if match[2] == "Minute" else 1)


def budgets(region):
    document = json.loads((ROOT / "deploy/observability/production/latency-budgets.json").read_text())
    peers = [item["label"] for item in region["_fleet"]["regions"]
             if item["oci_region"] == region["oci_region"] and item is not region]
    matches = [item for item in document if item["kind"] == "http"
               and any(item["name"].startswith(peer + ".api.") for peer in peers)]
    require(len(matches) == 1, "C22/X5: staging OCI region has no unique latency envelope")
    envelope = matches[0]
    policy = (ROOT / "internal/swarmruntime/autoscale.go").read_text()
    values = {name: int(re.search(name + r":\s*(\d+)", policy)[1])
              for name in ("UpStabilizationSeconds", "UpCooldownSeconds", "DownStabilizationSeconds", "DownCooldownSeconds")}
    rollout = duration("internal/swarmruntime/service.go", "serviceRollout") + 2 * duration("internal/swarmruntime/service.go", "DefaultReadyTimeout")
    require(all(len(envelope[key]) == 3 and all(math.isfinite(value) and value > 0 for value in envelope[key])
                for key in ("fresh", "kept")), "invalid X5 latency envelope")
    return {
        "p99": envelope["kept"][2],
        "fresh_p99": envelope["fresh"][2],
        "baseline": envelope["name"],
        "connections": c18_integer("internal/edge/limits.go", r"const maxSourceConnections = (\d+)"),
        "header": c18_integer("internal/edge/edge.go", r"public := &http.Server\{[\s\S]*?ReadHeaderTimeout:\s*(\d+) \* time.Second"),
        "workers": c18_integer("internal/edge/limits.go", r"const maxHTTPRefusals = (\d+)"),
        "body_bytes": c18_integer("internal/edge/limits.go", r"const bodyProgressBytes = (\d+) << 10") << 10,
        "max_body": c18_integer("internal/edge/edge.go", r"MaxBytesReader\(w, r.Body, (\d+)<<20\)") << 20,
        "header_bytes": c18_integer("internal/edge/edge.go", r"MaxHeaderBytes:\s*(\d+) << 10") << 10,
        "ws_source": c18_integer("internal/edge/regional.go", r"maxRegionalSocketsPerAddress\s*=\s*(\d+)"),
        "pg_source": (c18_integer("internal/edge/postgres.go", r"maxPostgresConns\s*=\s*(\d+)") //
                      c18_integer("internal/edge/postgres.go", r"maxPostgresSourceConns\s*=\s*maxPostgresConns / (\d+)")),
        "body": duration("internal/edge/limits.go", "bodyProgressWindow"),
        "idle": duration("internal/edge/edge.go", "clientIdleTimeout"),
        "pg_idle": duration("internal/edge/postgres.go", "postgresIdleTimeout"),
        "recovery": duration("internal/swarmruntime/liveness.go", "readinessWindow"),
        "deploy": duration("internal/swarmruntime/service.go", "serviceRollout")
                  + 2 * duration("internal/swarmruntime/service.go", "DefaultReadyTimeout"),
        "node_up": duration("internal/nodescale/decide.go", "UpWindow")
                   + duration("internal/nodescale/decide.go", "UpCooldown")
                   + duration("internal/nodescale/scaler.go", "LaunchTimeout"),
        "node_down": duration("internal/nodescale/decide.go", "DownWindow")
                     + duration("internal/nodescale/decide.go", "DownCooldown"),
        "replica_up": 60 + values["UpStabilizationSeconds"] + values["UpCooldownSeconds"] + rollout,
        "replica_down": 60 + values["DownStabilizationSeconds"] + values["DownCooldownSeconds"] + rollout,
    }


class TimedResponse(http.client.HTTPResponse):
    def begin(self):
        self.fp.peek(1)
        self.first_byte = time.monotonic()
        super().begin()


class Connection(http.client.HTTPConnection):
    response_class = TimedResponse
    def __init__(self, host, address, source, timeout, tls_context):
        super().__init__(host, port=443, timeout=timeout, source_address=(source, 0))
        self.address = address
        self.tls_context = tls_context

    def connect(self):
        raw = socket.create_connection((self.address, 443), self.timeout, self.source_address)
        try:
            self.sock = self.tls_context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def request(connection, method="GET", path="/edge/ready", body=None):
    started = time.monotonic()
    connection.request(method, path, body=body)
    response = connection.getresponse()
    connection.first_byte = response.first_byte - started
    connection.probe = response.getheader("X-Abuse-Process", "")
    response.read()
    return response.status


class Healthy:
    def __init__(self, connection, path="/edge/ready", outage=0, cadence=0):
        self.connection = connection
        self.samples = []
        self.errors = 0
        self.stop = threading.Event()
        self.path = path
        self.cadence = cadence
        self.outage = outage
        self.last_good = time.monotonic()
        self.worst_outage = 0
        self.terminal_error = False
        self.changed = threading.Condition()
        self.thread = threading.Thread(target=self.run)

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                if request(self.connection, path=self.path) != 200:
                    self.errors += 1
                else:
                    self.samples.append((started, self.connection.first_byte))
                    self.worst_outage = max(self.worst_outage, time.monotonic() - self.last_good)
                    self.last_good = time.monotonic()
            except (OSError, http.client.HTTPException):
                self.errors += 1
                self.connection.close()
                if not self.outage or time.monotonic() - self.last_good > self.outage:
                    self.terminal_error = True
                    self.stop.set()
            if not self.outage and self.errors:
                self.stop.set()
            with self.changed:
                self.changed.notify_all()
            if self.cadence:
                self.stop.wait(self.cadence)

    def wait_since(self, since, timeout):
        with self.changed:
            return self.changed.wait_for(lambda: sum(start >= since for start, _ in self.samples) >= 100
                                         or self.stop.is_set(), timeout)

    def finish(self, budget, since=0):
        self.stop.set()
        self.thread.join()
        self.connection.close()
        ordered = sorted(value for start, value in self.samples if start >= since)
        p99 = ordered[math.ceil(len(ordered) * .99) - 1] if ordered else math.inf
        self.worst_outage = max(self.worst_outage, time.monotonic() - self.last_good)
        numbers = f"samples={len(ordered)} errors={self.errors} p99_s={p99:.6f} budget_s={budget} outage_s={self.worst_outage:.6f} outage_budget_s={self.outage}"
        require(len(ordered) >= 100 and not self.terminal_error and p99 <= budget
                and ((self.outage and self.worst_outage <= self.outage) or self.errors == 0), numbers)
        return numbers


def sources():
    result = subprocess.run(["ip", "-j", "-4", "address", "show"],
                            capture_output=True, check=True, timeout=10)
    addresses = [item["local"] for interface in json.loads(result.stdout)
                 for item in interface.get("addr_info", [])
                 if ipaddress.ip_address(item["local"]).is_global]
    require(addresses, "public source address required; private/mesh clients bypass C18 quotas")
    return sorted(set(addresses))


class Lane:
    def __init__(self, region, host, addresses, limits):
        self.region = region
        self.host = host
        self.addresses = addresses
        self.limits = limits
        self.tls = ssl.create_default_context()
        self.tls.set_alpn_protocols(["http/1.1"])

    def guard(self):
        region, host, addresses = staging()
        require(region["label"] == self.region["label"] and region["compartment_id"] == self.region["compartment_id"]
                and region["vault_id"] == self.region["vault_id"] and region["key_id"] == self.region["key_id"]
                and region["_region_key"] == self.region["_region_key"] and region["_nlb_key"] == self.region["_nlb_key"]
                and host == self.host and addresses == self.addresses, "staging authority or NLB addresses changed")
        self.region["_hosts"] = region["_hosts"]

    def connection(self, source="", address=None, host=None):
        return Connection(host or self.host, address or self.addresses[0], source,
                          self.limits["header"] + self.limits["p99"], self.tls)

    def flood(self, many):
        clients = sources()
        require(not many or len(clients) >= 3,
                "many-source lane requires three distinct public source addresses")
        attackers = clients[1:3] if many else clients[:1]
        held = []
        opened = []
        lock = threading.Lock()
        healthy_connection = self.connection(clients[0])
        healthy = Healthy(healthy_connection)
        with contextlib.ExitStack() as cleanup:
            cleanup.callback(healthy_connection.close)
            require(request(healthy_connection) == 200, "healthy preflight failed")
            healthy.thread.start()
            cleanup.callback(healthy.thread.join)
            cleanup.callback(healthy.stop.set)
            cleanup.callback(lambda: [connection.close() for connection in opened])
            capacity = self.limits["connections"] * self.region["nodes"]["max"]
            jobs = [(source, self.addresses[index % len(self.addresses)])
                    for source in attackers for index in range(capacity + 1)]
            refused = {source: 0 for source in attackers}
            failed = 0

            def attack(job):
                source, address = job
                connection = self.connection(source, address)
                with lock:
                    opened.append(connection)
                try:
                    status = request(connection)
                except (OSError, http.client.HTTPException):
                    connection.close()
                    return source, None, None
                return source, status, connection

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.limits["workers"]) as pool:
                for source, status, connection in pool.map(attack, jobs):
                    if status == 200:
                        held.append(connection)
                    elif status == 429:
                        refused[source] += 1
                        connection.close()
                    else:
                        failed += 1
            def hammer(connection):
                completed = 0
                for _ in range(100):
                    try:
                        if request(connection) != 200:
                            return completed, 1
                    except (OSError, http.client.HTTPException):
                        return completed, 1
                    completed += 1
                return completed, 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.limits["workers"]) as pool:
                load = list(pool.map(hammer, held))
            numbers = healthy.finish(self.limits["p99"])
            completed = sum(count for count, _ in load)
            failed += sum(errors for _, errors in load)
            counts = f"sources={len(attackers)} accepted={len(held)} requests={completed} refused_429={sum(refused.values())} other_failures={failed}"
            require(all(count > 0 for count in refused.values()), counts + " missing per-source 429")
            require(len(held) > 0 and failed == 0, counts + " unclassified failures are not quota proof")
            return counts + " " + numbers

    def slow_headers(self):
        closed = []
        for address in self.addresses:
            connection = self.connection(sources()[0], address)
            with contextlib.closing(connection):
                connection.connect()
                started = time.monotonic()
                connection.sock.sendall(f"GET /edge/ready HTTP/1.1\r\nHost: {self.host}\r\nX-Slow: ".encode())
                connection.sock.settimeout(self.limits["header"] + self.limits["p99"])
                reply = bytearray()
                try:
                    while chunk := connection.sock.recv(4096):
                        reply.extend(chunk)
                        require(len(reply) <= 65536, "unexpected response to incomplete headers")
                except (ConnectionResetError, ssl.SSLEOFError):
                    pass
                elapsed = time.monotonic() - started
                require(self.limits["header"] - self.limits["p99"] <= elapsed
                        <= self.limits["header"] + self.limits["p99"],
                        f"closed_s={elapsed:.6f} expected_s={self.limits['header']}")
                closed.append(elapsed)
        return f"closed={len(closed)} max_closed_s={max(closed):.6f} deadline_s={self.limits['header']}"


def run():
    try:
        region, host, addresses = staging()
        print(f"PASS staging-guard label={region['label']} pinned_nlb_ips={len(addresses)} max_nodes={region['nodes']['max']}", flush=True)
        lane = Lane(region, host, addresses, budgets(region))
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, Refused) else type(error).__name__
        print(f"FAIL staging-preflight attempted=0 reason={message}", flush=True)
        for name, owner in SCENARIOS:
            print(f"FAIL {name} owner={owner} attempted=0 reason=preflight", flush=True)
        return 2
    scenarios = Scenarios(lane, ROOT, oci, require, request, Healthy, sources)
    operations = {
        "http-one-source": lambda: lane.flood(False),
        "http-many-sources": lambda: lane.flood(True),
        "slow-headers": scenarios.headers,
        "slow-bodies": scenarios.slow_bodies,
        "idle-websocket": scenarios.websocket,
        "idle-postgres": scenarios.postgres,
        "tenant-isolation": scenarios.tenants,
        "task-oom": scenarios.oom,
        "disk-full": scenarios.disk,
        "replica-scale": scenarios.replicas,
        "node-scale": scenarios.nodes,
        "node-loss": scenarios.node_loss,
    }
    failures = 0
    for name, owner in SCENARIOS:
        started = time.monotonic()
        try:
            lane.guard()
            numbers = operations[name]()
            print(f"PASS {name} owner={owner} elapsed_s={time.monotonic() - started:.6f} {numbers}", flush=True)
        except (Refused, OSError, ValueError, KeyError, TypeError, RuntimeError, StopIteration,
                subprocess.SubprocessError, http.client.HTTPException) as error:
            failures += 1
            message = str(error) if isinstance(error, Refused) else type(error).__name__
            print(f"FAIL {name} owner={owner} elapsed_s={time.monotonic() - started:.6f} reason={message}", flush=True)
    print(f"RESULT scenarios={len(SCENARIOS)} passed={len(SCENARIOS) - failures} failed={failures}", flush=True)
    return int(failures != 0)


def terminate(_signal, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, terminate)
    try:
        sys.exit(run())
    except KeyboardInterrupt:
        print("FAIL interrupted cleanup=closed-client-sockets", flush=True)
        sys.exit(130)
