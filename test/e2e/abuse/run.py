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


def staging():
    require(len(sys.argv) == 1, "no target or argument accepted; staging is discovered")
    fleet = json.loads((ROOT / "deploy/fleet/fleet.json").read_text())
    matches = [region for region in fleet["regions"] if region["label"] == "staging"]
    require(len(matches) == 1, "C16: fleet must contain exactly one label=staging entry")
    target = matches[0]
    others = [region for region in fleet["regions"] if region is not target]
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
    host = "staging.api." + fleet["dns"]["zone"]
    require(host not in fleet["dns"]["steered_names"], "staging hostname is globally steered")
    inventory = oci(target["oci_region"], "nlb", "network-load-balancer", "list",
                    "--compartment-id", target["compartment_id"])
    owned = [item for item in inventory
             if item["compartment-id"] == target["compartment_id"]
             and item["display-name"] == "staging-1-nlb"
             and item["lifecycle-state"] == "ACTIVE"
             and item["freeform-tags"].get("terrascale-managed-by") == "ts-orchestrator"
             and item["freeform-tags"].get("terrascale-owner") == "terrascale"
             and item["freeform-tags"].get("terrascale-resource-key")
             == "STAGING/network-load-balancer/nlb"]
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
    instances = oci(target["oci_region"], "compute", "instance", "list",
                    "--compartment-id", target["compartment_id"])
    running = [item for item in instances if item["lifecycle-state"] == "RUNNING"]
    require(target["nodes"]["min"] <= len(running) <= target["nodes"]["max"],
            "C16: live staging node count outside fleet bounds")
    node_ips = set()
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
    require(len(node_ips) == len(running), "staging node addresses incomplete")
    for port in (80, 443, 5432):
        backends = balancer["backend-sets"][f"tcp-{port}"]["backends"]
        require(backends and all(backend["ip-address"] in node_ips
                                and backend["port"] == port for backend in backends),
                "NLB backend outside staging nodes or expected port")
    return target, host, sorted(addresses)


def c18_integer(file, pattern):
    match = re.search(pattern, (ROOT / file).read_text())
    require(match is not None, "C18 source shape changed; review the budget reader")
    return int(match[1])


def budgets():
    table = (ROOT / "docs/staging-abuse.md").read_text()
    match = re.search(r"^\| healthy_p99_seconds \| ([0-9.]+) \| X5: ([^|]+) \|$", table, re.M)
    require(match is not None, "X5: measured healthy p99 budget and evidence path missing")
    evidence = (ROOT / match[2].strip()).resolve()
    require(evidence.is_relative_to(ROOT) and evidence.is_file(), "X5: evidence file missing")
    p99 = float(match[1])
    require(math.isfinite(p99) and p99 > 0, "X5: healthy p99 must be positive and finite")
    return {
        "p99": p99,
        "connections": c18_integer("internal/edge/limits.go", r"const maxSourceConnections = (\d+)"),
        "header": c18_integer("internal/edge/edge.go", r"public := &http.Server\{[\s\S]*?ReadHeaderTimeout:\s*(\d+) \* time.Second"),
        "workers": c18_integer("internal/edge/limits.go", r"const maxHTTPRefusals = (\d+)"),
    }


class Connection(http.client.HTTPConnection):
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


def request(connection):
    connection.request("GET", "/edge/ready")
    response = connection.getresponse()
    response.read()
    return response.status


class Healthy:
    def __init__(self, connection):
        self.connection = connection
        self.samples = []
        self.errors = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                if request(self.connection) != 200:
                    self.errors += 1
            except (OSError, http.client.HTTPException):
                self.errors += 1
                self.stop.set()
            self.samples.append(time.monotonic() - started)

    def finish(self, budget):
        self.stop.set()
        self.thread.join()
        self.connection.close()
        ordered = sorted(self.samples)
        p99 = ordered[math.ceil(len(ordered) * .99) - 1] if ordered else math.inf
        numbers = f"samples={len(ordered)} errors={self.errors} p99_s={p99:.6f} budget_s={budget}"
        require(len(ordered) >= 100 and self.errors == 0 and p99 <= budget, numbers)
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

    def connection(self, source, address=None):
        return Connection(self.host, address or self.addresses[0], source,
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


def pending(message):
    raise Refused(message)


def run():
    try:
        region, host, addresses = staging()
        print(f"PASS staging-guard label={region['label']} pinned_nlb_ips={len(addresses)} max_nodes={region['nodes']['max']}", flush=True)
        lane = Lane(region, host, addresses, budgets())
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, Refused) else type(error).__name__
        print(f"FAIL staging-preflight attempted=0 reason={message}", flush=True)
        for name, owner in SCENARIOS:
            print(f"FAIL {name} owner={owner} attempted=0 reason=preflight", flush=True)
        return 2
    operations = {
        "http-one-source": lambda: lane.flood(False),
        "http-many-sources": lambda: lane.flood(True),
        "slow-headers": lane.slow_headers,
        "slow-bodies": lambda: pending("body-consuming staging route and socket/memory observation required"),
        "idle-websocket": lambda: pending("staging echo route and C18 idle deadline evidence required"),
        "idle-postgres": lambda: pending("isolated staging database and private credential delivery required"),
        "tenant-isolation": lambda: pending("two isolated staging tenants and X5 workload required"),
        "task-oom": lambda: pending("region-scoped task fault operation and restart evidence required"),
        "disk-full": lambda: pending("staging node fault scope, alert evidence and recovery operation required"),
        "replica-scale": lambda: pending("isolated staging workload and C11 replica observation required"),
        "node-scale": lambda: pending("C12 node observation and staging scale policy required"),
        "node-loss": lambda: pending("C14 staging node fault and recovery operation required"),
    }
    failures = 0
    for name, owner in SCENARIOS:
        started = time.monotonic()
        try:
            numbers = operations[name]()
            print(f"PASS {name} owner={owner} elapsed_s={time.monotonic() - started:.6f} {numbers}", flush=True)
        except (Refused, OSError, ValueError, subprocess.SubprocessError, http.client.HTTPException) as error:
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
