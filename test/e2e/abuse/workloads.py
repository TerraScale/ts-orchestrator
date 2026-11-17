import base64
import contextlib
import ipaddress
import json
import os
import pathlib
import secrets
import shlex
import subprocess
import tempfile
import threading
import time


class Workloads:
    def __init__(self, owner):
        self.owner = owner
        self.lane = owner.lane
        self.region = self.lane.region
        self.prefix = "abuse-" + secrets.token_hex(6)
        self.password = secrets.token_urlsafe(32)
        self.hosts = list(self.region["_hosts"])
        self.installed = set()
        self.manager = self.hosts[0]
        self.cleanup = contextlib.ExitStack()
        self.names = []
        self.image = None

    def __enter__(self):
        try:
            self.owner.build()
            self.image = {"tag": self.owner.image["tag"],
                          "ref": self.owner.image["ref"].replace("localhost/terrascale-abuse-probe@", "localhost/" + self.prefix + "/probe@")}
            self.refresh(install=False)
            self.manager = self.hosts[0]
            for host in self.hosts:
                self.cleanup.callback(self.remove_host, host)
                self.remote(host, "install", files=self.owner.files, image=self.image)
                self.installed.add(host["id"])
            self.control("snapshot")
            return self
        except BaseException:
            self.cleanup.close()
            raise

    def __exit__(self, *_):
        self.cleanup.close()

    def payload(self, host, operation, **fields):
        return dict(region=self.region["label"], compartment=self.region["compartment_id"],
                    instance=host["id"], prefix=self.prefix, operation=operation, **fields)

    def process(self, host, operation, **fields):
        self.owner.require(host in self.hosts and "desktop" not in host["address"], "host outside staging inventory")
        source = (self.owner.root / "test/e2e/abuse/host.py").read_text()
        command = "sudo -n python3 -c " + shlex.quote(source)
        process = subprocess.Popen(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                    "ubuntu@" + host["address"], command], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process, json.dumps(self.payload(host, operation, **fields)).encode()

    def remote(self, host, operation, **fields):
        process, payload = self.process(host, operation, **fields)
        seconds = fields.get("control", {}).get("seconds", self.lane.limits["deploy"])
        try:
            output, _ = process.communicate(payload, timeout=seconds + 30)
        except BaseException:
            process.kill()
            process.communicate()
            raise
        self.owner.require(process.returncode == 0, "staging host operation failed: " + operation + "; output withheld")
        return json.loads(output)

    def refresh(self, install=True):
        instances = self.owner.oci(self.region["oci_region"], "compute", "instance", "list",
                                   "--compartment-id", self.region["compartment_id"])
        active = [item for item in instances if item["lifecycle-state"] in ("PROVISIONING", "STARTING", "RUNNING", "STOPPING")]
        self.owner.require(all(item["compartment-id"] == self.region["compartment_id"] for item in instances)
                           and len(active) <= self.region["nodes"]["max"] <= 3,
                           "OCI staging node ceiling violated")
        hosts = []
        for item in instances:
            if item["lifecycle-state"] != "RUNNING":
                continue
            self.owner.require(self.region["label"] in item["display-name"]
                               and "desktop" not in item["display-name"], "invalid staging host name")
            vnics = self.owner.oci(self.region["oci_region"], "compute", "instance", "list-vnics",
                                   "--compartment-id", self.region["compartment_id"], "--instance-id", item["id"])
            primary = [vnic for vnic in vnics if vnic["is-primary"]]
            self.owner.require(len(primary) == 1 and ipaddress.ip_address(primary[0]["private-ip"])
                               in ipaddress.ip_network(self.region["private_subnet_cidr"]),
                               "autoscaled node is outside staging private subnet")
            host = {"id": item["id"], "name": item["display-name"], "address": item["display-name"] + ".nb.ts.internal"}
            hosts.append(host)
            if install and host["id"] not in self.installed:
                self.hosts.append(host)
                self.cleanup.callback(self.remove_host, host)
                self.remote(host, "install", files=self.owner.files, image=self.image)
                self.installed.add(host["id"])
        self.hosts = hosts
        self.region["_hosts"] = list(hosts)
        return [item["id"] for item in instances]

    def live_count(self):
        instances = self.owner.oci(self.region["oci_region"], "compute", "instance", "list",
                                   "--compartment-id", self.region["compartment_id"])
        count = sum(item["lifecycle-state"] in ("PROVISIONING", "STARTING", "RUNNING", "STOPPING") for item in instances)
        self.owner.require(count <= self.region["nodes"]["max"] <= 3, "staging compute ceiling violated")
        return count

    def remove_host(self, host):
        instances = self.owner.oci(self.region["oci_region"], "compute", "instance", "list",
                                   "--compartment-id", self.region["compartment_id"])
        matches = [item for item in instances if item["id"] == host["id"]]
        if not matches or matches[0]["lifecycle-state"] in ("TERMINATING", "TERMINATED"):
            return
        self.owner.require(matches[0]["compartment-id"] == self.region["compartment_id"], "cleanup outside staging")
        if host not in self.hosts:
            self.hosts.append(host)
        self.remote(host, "cleanup")

    def control(self, operation, seconds=None, **fields):
        request = dict(operation=operation, instances=self.refresh(),
                       seconds=seconds or self.lane.limits["deploy"], **fields)
        return self.remote(self.manager, "control", control=request)

    def wait(self, predicate, seconds):
        request = {"operation": "watch", "instances": self.refresh(), "seconds": seconds}
        process, payload = self.process(self.manager, "watch", control=request)
        try:
            process.stdin.write(payload)
            process.stdin.close()
            for line in process.stdout:
                state = json.loads(line)
                self.owner.require(sum(node["State"] == "READY" for node in state["Nodes"]) <= 3,
                                   "observed more than three staging nodes")
                if predicate(state):
                    self.refresh()
                    return state
            self.owner.require(False, "staging observation deadline expired")
        finally:
            process.terminate()
            process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()

    def dns(self, host, remove=False):
        self.owner.require(host.endswith("." + self.prefix + ".abuse." + self.lane.host),
                           "DNS name outside staging abuse namespace")
        zone = self.region["_fleet"]["dns"]["zone"]
        current = self.owner.oci(self.region["oci_region"], "dns", "record", "zone", "get",
                                 "--zone-name-or-id", zone, "--domain", host)
        records = [{"domain": host, "rdata": address, "rtype": "A",
                    "ttl": self.region["_fleet"]["dns"]["steering_ttl_seconds"],
                    "operation": "REMOVE" if remove else "ADD"} for address in self.lane.addresses]
        if remove:
            self.owner.require(all(item["domain"].rstrip(".") == host and item["rtype"] == "A"
                                   and item["rdata"] in self.lane.addresses for item in current),
                               "abuse DNS records changed ownership")
            if not current:
                return
        else:
            self.owner.require(not current, "abuse DNS name already exists")
            self.cleanup.callback(self.dns, host, True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf8") as body:
            json.dump(records, body)
            body.flush()
            self.owner.effect("dns", "record", "domain", "patch", "--zone-name-or-id", zone,
                              "--domain", host, "--items", "file://" + body.name)

    def app(self, role, mode="normal", replicas=1, scalable=False):
        ports = {"good": 18101, "noisy": 18102, "leak": 18103, "pg": 18104, "scale": 18106}
        name = self.prefix + "-" + role
        host = role + "." + self.prefix + ".abuse." + self.lane.host
        self.dns(host)
        architecture = "arm64" if ".A1." in self.region["nodes"]["shape"] else "amd64"
        tenant = self.prefix + ("-attacker" if role == "noisy" else "-victim")
        spec = {"name": name, "image": self.image["ref"],
                    "args": ["http", str(ports[role]), mode],
                    "port": ports[role], "readyPath": "/healthz", "hostnames": [host], "replicas": replicas,
                    "regions": [self.region["label"]], "dependencies": [], "memoryMiB": 64, "milliCPU": 50,
                    "env": {"ABUSE_TENANT": tenant, "PORT": "${PORT}"}}
        if scalable:
            spec["replicaBounds"] = {"min": 1, "max": 3}
        if mode == "postgres":
            manifest = json.loads((self.owner.root / "test/e2e/abuse/images.json").read_text())
            capacity = (self.lane.limits["pg_source"] * self.region["nodes"]["max"]
                        + self.owner.integer("internal/edge/postgres.go", "maxPostgresHandshakes") + 1)
            spec.update(image=manifest["postgres"][architecture], memoryMiB=256,
                        args=["sh", "-c", f"/tmp/probe http 18104 postgres & exec docker-entrypoint.sh postgres -p 18105 -c unix_socket_directories=/tmp -c max_connections={capacity} -c shared_buffers=16MB"],
                        postgres={"port": 18105, "hostname": host},
                        mounts=[{"source": "/var/lib/ts-data/" + self.prefix + "/postgres", "target": "/tmp"},
                                {"source": "/var/lib/ts-data/" + self.prefix + "/pgsocket", "target": "/var/run/postgresql"}],
                        env={"ABUSE_TENANT": tenant, "PGDATA": "/tmp/pgdata", "POSTGRES_PASSWORD": self.password})
        self.names.append(name)
        self.cleanup.callback(self.remove, name)
        placement = ""
        if replicas == 1 and role in ("good", "noisy", "leak"):
            placement = next(node["ID"] for node in self.control("snapshot")["Nodes"]
                             if node["Instance"] == self.manager["id"])
        self.control("apply", spec=spec, tenant=tenant, node=placement)
        self.wait(lambda state: self.running(state, name) == replicas, self.lane.limits["deploy"])
        self.ready(host)
        return name, host

    @staticmethod
    def service(state, name):
        return next((item for item in state["Services"] or [] if item["Name"] == name), None)

    @classmethod
    def running(cls, state, name):
        service = cls.service(state, name)
        return sum(task["State"] == "RUNNING" for task in service["Tasks"] or []) if service else 0

    def ready(self, host):
        deadline = time.monotonic() + self.lane.limits["deploy"]
        while True:
            with contextlib.closing(self.lane.connection(host=host)) as connection:
                try:
                    if self.owner.request(connection, path="/healthz") == 200:
                        return
                except (OSError, ValueError):
                    pass
            remaining = deadline - time.monotonic()
            self.owner.require(remaining > 0, "new staging app/DNS/certificate failed readiness")
            threading.Event().wait(min(self.lane.limits["body"], remaining))

    def remove(self, name):
        self.control("remove", name=name)
        self.wait(lambda state: self.service(state, name) is None and state["Orphans"] == 0,
                  self.lane.limits["deploy"])

    def snapshots(self):
        return {host["id"]: self.remote(host, "snapshot") for host in self.hosts}

    def released(self, before):
        deadline = time.monotonic() + self.lane.limits["idle"]
        while True:
            after = self.snapshots()
            if all(after[key]["sockets"] <= before[key]["sockets"] for key in before):
                break
            remaining = deadline - time.monotonic()
            self.owner.require(remaining > 0, "C18 sockets retained after client closure")
            threading.Event().wait(min(self.lane.limits["body"], remaining))
        self.owner.require(all(after[key]["pid"] and after[key]["available"] > 0 for key in before),
                           "staging node or memory unavailable after session cleanup")
        growth = max(after[key]["rss"] - before[key]["rss"] for key in before)
        self.owner.require(growth <= self.lane.limits["connections"] * self.lane.limits["header_bytes"],
                           f"C18 retained_rss_bytes={growth} exceeds source header-buffer envelope")
        return f"socket_before={sum(item['sockets'] for item in before.values())} socket_after={sum(item['sockets'] for item in after.values())} max_rss_growth_bytes={growth}"


def build(owner):
    if owner.files is not None:
        return
    architecture = "arm64" if ".A1." in owner.lane.region["nodes"]["shape"] else "amd64"
    with tempfile.TemporaryDirectory(prefix="ts-abuse-build-") as directory:
        files = {}
        for name in ("control", "probe"):
            target = pathlib.Path(directory) / name
            result = subprocess.run(["go", "build", "-trimpath", "-o", str(target),
                                     "./test/e2e/abuse/" + name], cwd=owner.root,
                                    env=dict(os.environ, GOOS="linux", GOARCH=architecture, CGO_ENABLED="0"),
                                    capture_output=True, check=False)
            owner.require(result.returncode == 0, "abuse helper build failed; output withheld")
            files[name] = base64.b64encode(target.read_bytes()).decode()
        archive = pathlib.Path(directory) / "image.tar"
        result = subprocess.run(["go", "run", "./test/e2e/abuse/image", str(pathlib.Path(directory) / "probe"), architecture, str(archive)],
                                cwd=owner.root, capture_output=True, check=False)
        owner.require(result.returncode == 0, "abuse OCI image packaging failed; output withheld")
        owner.image = json.loads(result.stdout)
        files["image.tar"] = base64.b64encode(archive.read_bytes()).decode()
        files["host.py"] = base64.b64encode((owner.root / "test/e2e/abuse/host.py").read_bytes()).decode()
        owner.files = files
