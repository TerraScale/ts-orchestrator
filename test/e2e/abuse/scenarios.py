import base64
import concurrent.futures
import contextlib
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import threading
import time

import postgres
from workloads import Workloads, build


class Load:
    def __init__(self, owner, host, outage=0):
        self.owner = owner
        self.host = host
        self.stop = threading.Event()
        self.counts = []
        self.outage = outage
        self.changed = threading.Condition()
        self.seen = {}
        self.affected = set()
        self.recovered = set()
        self.phase = 0
        self.completed = 0
        self.post_completed = 0
        self.pre_errors = 0
        self.max_outage = 0
        self.failed = False
        self.victim = ""
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=32)
        self.jobs = [self.pool.submit(self.run, worker) for worker in range(32)]

    def run(self, worker):
        count, errors = 0, 0
        last_good = time.monotonic()
        with contextlib.closing(self.owner.lane.connection(host=self.host)) as connection:
            while not self.stop.is_set():
                with self.changed:
                    phase = self.phase
                success = False
                try:
                    success = self.owner.request(connection, path="/work") == 200
                except (OSError, http.client.HTTPException):
                    success = False
                now = time.monotonic()
                gap = now - last_good
                if success:
                    count += 1
                    last_good = now
                else:
                    errors += 1
                    connection.close()
                with self.changed:
                    self.completed += 1
                    self.pre_errors += int(phase == 0 and not success)
                    self.max_outage = max(self.max_outage, gap)
                    self.failed |= bool(self.outage and gap > self.outage)
                    if success:
                        self.seen.setdefault(connection.probe, set()).add(worker)
                        if phase == 2 and connection.probe and connection.probe != self.victim:
                            self.post_completed += 1
                            if worker in self.affected:
                                self.recovered.add(worker)
                    self.changed.notify_all()
                if self.failed or not success and not self.outage:
                    break
        return count, errors

    def begin_fault(self, victim, seconds):
        with self.changed:
            observed = self.changed.wait_for(lambda: self.completed >= 100 and self.seen.get(victim)
                                            or self.failed, seconds)
            self.owner.require(observed and not self.failed and not self.pre_errors and self.seen.get(victim),
                               "load did not reach the task on the victim node")
            self.victim = victim
            self.affected = set(self.seen[victim])
            self.phase = 1

    def observe_recovery(self, seconds):
        with self.changed:
            self.phase = 2
            observed = self.changed.wait_for(lambda: self.post_completed >= 100 and self.affected
                                            and self.affected <= self.recovered
                                            or self.failed, max(0, seconds))
            self.owner.require(observed and not self.failed and self.affected and self.affected <= self.recovered,
                               f"affected_clients={len(self.affected)} recovered_clients={len(self.recovered)} "
                               f"unrecovered_clients={len(self.affected - self.recovered)} post_fault_requests={self.post_completed}; "
                               "every affected workload client must recover within C14 deadline")

    def close(self):
        self.stop.set()
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.counts = [job.result() for job in self.jobs if not job.cancelled()]

    def proof(self):
        count = sum(item[0] for item in self.counts)
        errors = sum(item[1] for item in self.counts)
        numbers = f"load_requests={count} load_errors={errors} load_outage_s={self.max_outage:.6f} load_outage_budget_s={self.outage}"
        if self.outage:
            numbers += f" affected_clients={len(self.affected)} recovered_clients={len(self.recovered)} unrecovered_clients={len(self.affected - self.recovered)} post_fault_requests={self.post_completed}"
            self.owner.require(count >= 100 and self.post_completed >= 100 and self.affected
                               and self.affected <= self.recovered
                               and not self.failed and self.max_outage <= self.outage, numbers)
        else:
            self.owner.require(count >= 100 and errors == 0, numbers)
        return numbers


class Scenarios:
    def __init__(self, lane, root, oci, require, request, healthy, sources):
        self.lane = lane
        self.root = root
        self.oci = oci
        self.require = require
        self.request = request
        self.healthy = healthy
        self.sources = sources
        self.files = None

    def build(self):
        build(self)

    def effect(self, *arguments, timeout=120):
        result = subprocess.run(["oci", "--region", self.lane.region["oci_region"], "--max-retries", "0",
                                 *arguments, "--output", "json"], capture_output=True, timeout=timeout, check=False)
        self.require(result.returncode == 0, "staging OCI effect failed; provider output withheld")

    @contextlib.contextmanager
    def monitor(self, host, outage=0):
        self.lane.guard()
        connection = self.lane.connection(host=host)
        self.require(self.request(connection, path="/healthz") == 200, "healthy app preflight failed")
        healthy = self.healthy(connection, path="/healthz", outage=outage, cadence=self.lane.limits["p99"])
        healthy.thread.start()
        try:
            yield healthy
        finally:
            healthy.stop.set()
            healthy.thread.join()
            connection.close()

    def finish(self, healthy, since=0, seconds=None):
        self.require(healthy.wait_since(since, seconds if seconds is not None else self.lane.limits["deploy"]),
                     "healthy client has fewer than 100 phase samples")
        return healthy.finish(self.lane.limits["fresh_p99"] if healthy.outage else self.lane.limits["p99"], since)

    @contextlib.contextmanager
    def load(self, host, outage=0):
        self.lane.guard()
        load = Load(self, host, outage)
        try:
            yield load
        finally:
            load.close()

    def slow_bodies(self):
        with Workloads(self) as scope:
            _, host = scope.app("good")
            before = scope.snapshots()
            with self.monitor(host) as healthy:
                with contextlib.closing(self.lane.connection(host=host)) as connection:
                    connection.connect()
                    started = time.monotonic()
                    connection.sock.sendall(f"POST /read HTTP/1.1\r\nHost: {host}\r\nContent-Length: {self.lane.limits['body_bytes']}\r\n\r\nx".encode())
                    connection.sock.settimeout(self.lane.limits["body"] + self.lane.limits["p99"])
                    try:
                        while connection.sock.recv(65536):
                            pass
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                    elapsed = time.monotonic() - started
                    self.require(self.lane.limits["body"] - self.lane.limits["p99"] <= elapsed
                                 <= self.lane.limits["body"] + self.lane.limits["p99"],
                                 f"body_closed_s={elapsed:.6f} deadline_s={self.lane.limits['body']}")
                with contextlib.closing(self.lane.connection(host=host)) as connection:
                    maximum = self.lane.limits["max_body"]
                    try:
                        status = self.request(connection, "POST", "/read", b"x" * (maximum + 1))
                    except BrokenPipeError:
                        response = connection.getresponse()
                        status = response.status
                        response.read()
                    self.require(status in (400, 413), f"oversize_bytes={maximum + 1} status={status}")
                numbers = self.finish(healthy)
            return f"body_closed_s={elapsed:.6f} oversize_status={status} " + numbers + " " + scope.released(before)

    def open_websocket(self, host):
        connection = self.lane.connection(host=host)
        try:
            connection.connect()
            key = base64.b64encode(os.urandom(16)).decode()
            connection.sock.sendall(f"GET /echo HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n".encode())
            response = http.client.HTTPResponse(connection.sock)
            response.begin()
            status = response.status
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            if status == 101:
                self.require(response.getheader("Sec-WebSocket-Accept") == accept, "invalid WebSocket upgrade")
                payload, mask = b"abuse", os.urandom(4)
                connection.sock.sendall(bytes((129, 128 | len(payload))) + mask
                                        + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
                self.require(postgres.exact(connection.sock, len(payload) + 2) == bytes((129, len(payload))) + payload,
                             "WebSocket echo did not reach staging workload")
            response.close()
            return connection, status
        except BaseException:
            connection.close()
            raise

    def headers(self):
        with Workloads(self) as scope:
            before = scope.snapshots()
            return self.lane.slow_headers() + " " + scope.released(before)

    def websocket(self):
        with Workloads(self) as scope:
            _, host = scope.app("good", replicas=self.lane.region["nodes"]["min"])
            before = scope.snapshots()
            with self.monitor(host) as healthy:
                with contextlib.ExitStack() as cleanup:
                    sessions = []
                    accepted_at = []
                    refusals = 0
                    maximum = self.lane.limits["ws_source"]
                    for _ in range(maximum * self.lane.region["nodes"]["max"] + 1):
                        connection, status = self.open_websocket(host)
                        cleanup.callback(connection.close)
                        if status == 101:
                            sessions.append(connection)
                            accepted_at.append(time.monotonic())
                        else:
                            self.require(status == 429, f"websocket_refusal_status={status}")
                            refusals += 1
                    self.require(sessions and refusals, f"websocket_sessions={len(sessions)} refused_429={refusals}")
                    started = accepted_at[-1]
                    sessions[-1].sock.settimeout(self.lane.limits["idle"] + self.lane.limits["p99"])
                    try:
                        self.require(sessions[-1].sock.recv(1) == b"", "idle WebSocket unexpectedly sent data")
                    except (ConnectionResetError, ssl.SSLEOFError):
                        pass
                    except TimeoutError:
                        self.require(False, f"idle_websocket_cut=0 deadline_s={self.lane.limits['idle']} sessions={len(sessions)} refused_429={refusals}")
                    elapsed = time.monotonic() - started
                    self.require(self.lane.limits["idle"] - self.lane.limits["p99"] <= elapsed
                                 <= self.lane.limits["idle"] + self.lane.limits["p99"], "WebSocket idle cut outside deadline")
                numbers = self.finish(healthy)
            return f"websocket_sessions={len(sessions)} refused_429={refusals} idle_closed_s={elapsed:.6f} " + numbers + " " + scope.released(before)

    def postgres(self):
        with Workloads(self) as scope:
            _, host = scope.app("pg", mode="postgres", replicas=self.lane.region["nodes"]["min"])
            _, good = scope.app("good")
            before = scope.snapshots()
            with self.monitor(good) as healthy:
                with contextlib.ExitStack() as cleanup:
                    sessions = []
                    accepted_at = []
                    refused = 0
                    maximum = self.lane.limits["pg_source"]
                    for _ in range(maximum * self.lane.region["nodes"]["max"] + 1):
                        try:
                            stream = postgres.connect(host, self.lane.addresses[0], scope.password,
                                                      self.lane.limits["header"] + self.lane.limits["p99"], "")
                        except postgres.Rejected as error:
                            self.require(error.code == "53300", "unexpected Postgres admission failure")
                            refused += 1
                            continue
                        cleanup.callback(stream.close)
                        sessions.append(stream)
                        accepted_at.append(time.monotonic())
                    self.require(sessions and refused, f"pg_sessions={len(sessions)} refused_53300={refused}")
                    started = accepted_at[-1]
                    sessions[-1].settimeout(self.lane.limits["pg_idle"] + self.lane.limits["p99"])
                    try:
                        self.require(sessions[-1].recv(1) == b"", "idle Postgres session unexpectedly sent data")
                    except (ConnectionResetError, ssl.SSLEOFError):
                        pass
                    except TimeoutError:
                        self.require(False, f"pg_idle_cut=0 deadline_s={self.lane.limits['pg_idle']}")
                    elapsed = time.monotonic() - started
                    self.require(self.lane.limits["pg_idle"] - self.lane.limits["p99"] <= elapsed
                                 <= self.lane.limits["pg_idle"] + self.lane.limits["p99"], "Postgres idle cut outside deadline")
                numbers = self.finish(healthy)
            return f"pg_sessions={len(sessions)} refused_53300={refused} idle_closed_s={elapsed:.6f} " + numbers + " " + scope.released(before)

    def tenants(self):
        with Workloads(self) as scope:
            _, good = scope.app("good")
            _, noisy = scope.app("noisy", mode="noisy")
            with self.monitor(good) as healthy:
                with contextlib.closing(self.lane.connection(host=noisy)) as connection:
                    self.require(self.request(connection, "POST", "/noise") == 204, "noisy tenant did not start")
                numbers = self.finish(healthy)
                with contextlib.closing(self.lane.connection(host=noisy)) as connection:
                    connection.request("GET", "/noise")
                    response = connection.getresponse()
                    activity = json.loads(response.read())
                    self.require(response.status == 200 and activity["requests"] > 0 and activity["errors"] == 0,
                                 "self-hammering workload did not produce successful traffic")
            return f"noisy_requests={activity['requests']} noisy_errors={activity['errors']} " + numbers

    def oom(self):
        with Workloads(self) as scope:
            _, good = scope.app("good")
            name, leak = scope.app("leak", mode="leak")
            before = scope.control("snapshot")
            resources = scope.snapshots()
            initial = {task["ID"] for task in scope.service(before, name)["Tasks"]}
            with self.monitor(good) as healthy:
                with contextlib.closing(self.lane.connection(host=leak)) as connection:
                    self.require(self.request(connection, "POST", "/leak") == 202, "leak workload did not start")
                state = scope.wait(lambda state: any(task["ID"] not in initial and task["State"] == "RUNNING"
                                                    for task in scope.service(state, name)["Tasks"]), self.lane.limits["recovery"])
                tasks = scope.service(state, name)["Tasks"]
                self.require(any(task["OOM"] or task["Exit"] == 137 for task in tasks), "no killed leak-task evidence")
                after = scope.snapshots()
                kills = sum(after[key]["oom_kill"] - resources[key]["oom_kill"] for key in resources)
                self.require(kills >= 1, "no kernel OOM kill observed")
                self.require({task["ID"] for task in before["Neighbours"] or []}
                             <= {task["ID"] for task in state["Neighbours"] or []}, "OOM disturbed a neighbouring task")
                self.require(all(after[key]["pid"] == resources[key]["pid"] for key in resources), "OOM restarted an orchestrator node")
                numbers = self.finish(healthy)
            return f"kernel_oom_kills={kills} old_tasks={len(initial)} replacement_running=1 " + numbers

    def disk(self):
        with Workloads(self) as scope:
            _, good = scope.app("good", replicas=self.lane.region["nodes"]["min"])
            target = scope.hosts[-1]
            before = scope.remote(target, "snapshot")
            neighbours = scope.control("snapshot")["Neighbours"] or []
            with self.monitor(good) as healthy:
                with contextlib.ExitStack() as cleanup:
                    cleanup.callback(scope.remote, target, "disk-stop")
                    scope.remote(target, "disk-start", seconds=self.lane.limits["recovery"])
                    deadline = time.monotonic() + self.lane.limits["recovery"]
                    while True:
                        status = scope.remote(target, "disk-status")
                        if status["enospc"]:
                            confirmed_full = time.monotonic()
                            break
                        self.require(time.monotonic() < deadline, "disk fault never reached ENOSPC")
                        threading.Event().wait(self.lane.limits["body"])
                    during = scope.remote(target, "snapshot")
                    self.require(during["pid"] == before["pid"], "disk full stopped the orchestrator")
                    state = self.platform_health(scope)
                    self.require({task["ID"] for task in neighbours}
                                 <= {task["ID"] for task in state["Neighbours"] or []},
                                 "disk full disturbed a platform task")
                    numbers = self.finish(healthy, since=confirmed_full)
                    self.require(scope.remote(target, "disk-status")["enospc"],
                                 "disk fault ended before full-phase sampling completed")
                after = scope.remote(target, "snapshot")
                self.require(after["disk_free"] > during["disk_free"] and after["pid"], "disk space or orchestrator did not recover")
                self.platform_health(scope)
                with self.monitor(good) as recovered:
                    recovery_numbers = self.finish(recovered)
            return f"filled_bytes={status['filled']} enospc=1 free_before={before['disk_free']} free_full={during['disk_free']} free_after={after['disk_free']} full_phase=({numbers}) recovery_phase=({recovery_numbers})"

    def platform_health(self, scope):
        with contextlib.closing(self.lane.connection()) as connection:
            self.require(self.request(connection, path="/edge/ready") == 200, "staging platform readiness failed")
        state = scope.control("snapshot")
        self.require(all(node["State"] == "READY" for node in state["Nodes"]), "staging node not ready")
        return state

    def replicas(self):
        with Workloads(self) as scope:
            name, host = scope.app("scale", scalable=True)
            before = scope.control("snapshot")
            start = scope.service(before, name)["Replicas"]
            with self.monitor(host) as healthy:
                with self.load(host) as load:
                    grown = scope.wait(lambda state: scope.service(state, name)["Replicas"] > start
                                       and scope.running(state, name) == scope.service(state, name)["Replicas"],
                                       self.lane.limits["replica_up"])
                    peak = scope.service(grown, name)["Replicas"]
                shrunk = scope.wait(lambda state: scope.service(state, name)["Replicas"] == start
                                    and scope.running(state, name) == start, self.lane.limits["replica_down"])
                numbers = self.finish(healthy)
            return f"replicas_before={start} replicas_peak={peak} replicas_after={scope.service(shrunk, name)['Replicas']} " + load.proof() + " " + numbers

    def nodes(self):
        with Workloads(self) as scope:
            _, host = scope.app("scale", scalable=True)
            bounds = self.lane.region["nodes"]
            initial = scope.live_count()
            with self.monitor(host) as healthy:
                if bounds["min"] != bounds["max"] and initial > bounds["min"]:
                    scope.wait(lambda state: sum(node["State"] == "READY" for node in state["Nodes"]) == bounds["min"],
                               self.lane.limits["node_down"])
                    initial = scope.live_count()
                with self.load(host) as load:
                    if bounds["min"] == bounds["max"]:
                        scope.wait(lambda state: scope.running(state, scope.prefix + "-scale") >= 2,
                                   self.lane.limits["replica_up"])
                        self.require(scope.live_count() == initial == bounds["max"], "fixed staging node count changed")
                        peak = initial
                    else:
                        state = scope.wait(lambda state: sum(node["State"] == "READY" for node in state["Nodes"]) > initial,
                                           self.lane.limits["node_up"])
                        peak = sum(node["State"] == "READY" for node in state["Nodes"])
                if bounds["min"] != bounds["max"]:
                    scope.wait(lambda state: sum(node["State"] == "READY" for node in state["Nodes"]) == bounds["min"],
                               self.lane.limits["node_down"])
                final = scope.live_count()
                self.require(peak <= bounds["max"] <= 3 and final == bounds["min"], "staging node scale did not settle within bounds")
                numbers = self.finish(healthy)
            return f"nodes_before={initial} nodes_peak={peak} nodes_after={final} policy_min={bounds['min']} policy_max={bounds['max']} " + load.proof() + " " + numbers

    def terminate_instance(self, scope, target):
        self.lane.guard()
        inventory = self.oci(self.lane.region["oci_region"], "compute", "instance", "list",
                             "--compartment-id", self.lane.region["compartment_id"])
        matches = [item for item in inventory if item["id"] == target["id"]]
        self.require(len(matches) == 1 and matches[0]["compartment-id"] == self.lane.region["compartment_id"],
                     "fault target is outside staging compartment")
        scope.live_count()
        started = time.monotonic()
        self.effect("compute", "instance", "terminate", "--instance-id", target["id"],
                    "--preserve-boot-volume", "false", "--force")
        return started

    def restore_fleet(self, scope):
        scope.control("recover", seconds=self.lane.limits["node_up"])
        scope.wait(lambda state: sum(node["State"] == "READY" for node in state["Nodes"])
                   >= self.lane.region["nodes"]["min"], self.lane.limits["node_up"])

    def node_loss(self):
        with Workloads(self) as scope:
            name, host = scope.app("good", replicas=2)
            before = scope.control("snapshot")
            service = scope.service(before, name)
            nodes = {node["ID"]: node for node in before["Nodes"]}
            victim = next(node for node in nodes.values() if node["Instance"] != scope.manager["id"]
                          and any(task["Node"] == node["ID"] and task["State"] == "RUNNING" for task in service["Tasks"]))
            target = next(item for item in scope.hosts if item["id"] == victim["Instance"])
            identity = scope.remote(target, "probe-identity")["process"]
            with self.monitor(host, outage=self.lane.limits["recovery"]) as healthy:
                with contextlib.ExitStack() as cleanup:
                    cleanup.callback(self.restore_fleet, scope)
                    with self.load(host, outage=self.lane.limits["recovery"]) as load:
                        load.begin_fault(identity, self.lane.limits["deploy"])
                        started = self.terminate_instance(scope, target)
                        state = scope.wait(lambda state: scope.running(state, name) == 2
                                           and all(task["Node"] != victim["ID"] for task in scope.service(state, name)["Tasks"]
                                                   if task["State"] == "RUNNING"), self.lane.limits["recovery"])
                        moved = time.monotonic()
                        load.observe_recovery(self.lane.limits["recovery"] - (moved - started))
                        numbers = self.finish(healthy, since=moved,
                                              seconds=max(0, self.lane.limits["recovery"] - (time.monotonic() - started)))
                        recovered = time.monotonic() - started
                        self.require(recovered <= self.lane.limits["recovery"], "node-loss recovery exceeded C14 bound")
                    load_numbers = load.proof()
                scope.wait(lambda state: sum(node["State"] == "READY" for node in state["Nodes"])
                           >= self.lane.region["nodes"]["min"], self.lane.limits["node_up"])
            return f"node_terminated=1 moved_running={scope.running(state, name)} recovery_s={recovered:.6f} recovery_budget_s={self.lane.limits['recovery']} " + load_numbers + " " + numbers

    def integer(self, file, name):
        import re
        match = re.search(r"\b" + name + r"\s*=\s*(\d+)\b", (self.root / file).read_text())
        self.require(match is not None, "C18 constant source changed: " + name)
        return int(match[1])
