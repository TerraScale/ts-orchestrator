#!/usr/bin/env python3
"""Run the real regional controller/operator/host flow in four Firecracker VMs.

This script owns every bridge, TAP, VMM, mount, guest copy and credential it
creates. It never edits the supplied kernel or rootfs. Run on an isolated lab
host with passwordless sudo for ip, mount, umount, install and systemctl.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


REPO = Path(__file__).resolve().parents[2]
KERNEL_SHA = "e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2"
ROOTFS_SHA = "dd49aee1d9c28f8e781a627bec744db3a961ce4402950130ff9268504c551314"
ROLE = "terrabase"
CELL = "lab"
ENVIRONMENT = "test"
CONTROLLERS = ("c1", "c2", "c3")
GUESTS = (*CONTROLLERS, "host")
CONFIG_DIGEST = hashlib.sha256(b'{"args":[],"env":{}}').hexdigest()
BOOT_ARGS = "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw"
PRE_ACCEPTANCE_FENCED = "authority epoch was fenced before acceptance"


class TerminalReceipt(Exception):
    def __init__(self, receipt: dict[str, Any]):
        super().__init__(f"terminal delivery receipt: {receipt}")
        self.receipt = receipt


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def run(command: list[str], *, timeout: int = 120, cwd: Path = REPO,
        allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout,
                            check=False)
    if result.returncode and not allow_failure:
        raise RuntimeError(f"command {command!r} failed ({result.returncode}): "
                           f"{result.stdout[-2000:]} {result.stderr[-2000:]}")
    return result


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


def source_digest() -> str:
    value = hashlib.sha256()
    paths = [*REPO.rglob("*.go"), REPO / "go.mod", REPO / "go.sum"]
    for path in sorted(paths):
        if ".git" in path.parts or path.is_symlink():
            continue
        value.update(str(path.relative_to(REPO)).encode() + b"\0")
        value.update(bytes.fromhex(digest(path)))
    return value.hexdigest()


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: Path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class VM:
    def __init__(self, lab: "Lab", name: str, ip: str, tap: str, image: Path):
        self.lab, self.name, self.ip, self.tap, self.image = lab, name, ip, tap, image
        self.directory = lab.root / "vms" / name
        self.directory.mkdir(parents=True)
        self.socket = self.directory / "api.sock"
        self.process: subprocess.Popen[bytes] | None = None
        self.output = None
        self.boots = 0

    def api(self, path: str, payload: dict[str, Any]) -> None:
        connection = UnixHTTP(self.socket)
        try:
            connection.request("PUT", path, body=json.dumps(payload),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read().decode(errors="replace")
            if response.status not in (200, 204):
                raise RuntimeError(f"Firecracker {self.name} {path}: {response.status} {body}")
        finally:
            connection.close()

    def boot(self) -> None:
        if self.process is not None:
            raise RuntimeError(f"{self.name} is already running")
        self.boots += 1
        self.socket.unlink(missing_ok=True)
        serial = self.lab.logs / f"{self.name}-boot-{self.boots}-serial.log"
        self.output = serial.open("wb")
        command = [self.lab.firecracker, "--api-sock", str(self.socket),
                   "--log-path", str(self.lab.logs / f"{self.name}-boot-{self.boots}-vmm.log")]
        self.process = subprocess.Popen(command, stdout=self.output, stderr=subprocess.STDOUT,
                                        start_new_session=True)
        deadline = time.monotonic() + 20
        while not self.socket.exists():
            if self.process.poll() is not None:
                raise RuntimeError(f"Firecracker {self.name} exited before API socket; see {serial}")
            if time.monotonic() > deadline:
                raise TimeoutError(f"Firecracker {self.name} API socket never appeared")
            time.sleep(0.1)
        index = GUESTS.index(self.name) + 1
        self.api("/machine-config", {"vcpu_count": 1, "mem_size_mib": 512, "smt": False})
        self.api("/boot-source", {"kernel_image_path": str(self.lab.kernel), "boot_args": BOOT_ARGS})
        self.api("/drives/rootfs", {"drive_id": "rootfs", "path_on_host": str(self.image),
                                     "is_root_device": True, "is_read_only": False})
        self.api("/network-interfaces/eth0", {"iface_id": "eth0", "host_dev_name": self.tap,
                                                "guest_mac": f"02:fc:00:{self.lab.network_octet:02x}:00:{index:02x}"})
        self.api("/actions", {"action_type": "InstanceStart"})
        self.lab.note("vm_boot", name=self.name, pid=self.process.pid, serial=str(serial))

    def stop(self) -> None:
        if self.process is None:
            return
        process = self.process
        if process.poll() is None:
            try:
                self.api("/actions", {"action_type": "SendCtrlAltDel"})
                process.wait(timeout=25)
            except (OSError, TimeoutError, subprocess.TimeoutExpired, RuntimeError):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        self.lab.note("vm_stop", name=self.name, exit_code=process.returncode)
        self.process = None
        if self.output is not None:
            self.output.close()
            self.output = None
        self.socket.unlink(missing_ok=True)

    def crash(self) -> None:
        if self.process is None:
            return
        process = self.process
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        self.lab.note("vm_crash", name=self.name, pid=process.pid, exit_code=process.returncode)
        self.process = None
        if self.output is not None:
            self.output.close()
            self.output = None
        self.socket.unlink(missing_ok=True)


class Lab:
    def __init__(self, args: argparse.Namespace):
        self.kernel = args.kernel.resolve()
        self.rootfs = args.rootfs.resolve()
        self.firecracker = str(Path(args.firecracker).resolve())
        if args.run_dir:
            self.root = args.run_dir.resolve()
            self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            self.root = Path(tempfile.mkdtemp(prefix="ts-orch-fc-", dir="/tmp"))
        self.root.chmod(0o700)
        self.logs = self.root / "logs"
        self.secrets = self.root / "secrets"
        self.images = self.root / "images"
        self.stage = self.root / "stage"
        for directory in (self.logs, self.secrets, self.images, self.stage):
            directory.mkdir(mode=0o700)
        if len(str(self.root / "vms" / "host" / "api.sock")) >= 100:
            raise ValueError("run directory is too long for Firecracker Unix API sockets")
        self.events: list[dict[str, Any]] = []
        self.bridge = "tsf" + secrets.token_hex(3) + "b"
        self.taps = {name: "tsf" + self.bridge[3:9] + str(index) for index, name in enumerate(GUESTS, 1)}
        self.network_octet = self.choose_subnet()
        self.subnet = ipaddress.ip_network(f"198.19.{self.network_octet}.0/24")
        self.addresses = {name: str(self.subnet[index + 10]) for index, name in enumerate(GUESTS, 1)}
        self.created_links: list[str] = []
        self.mounted: list[Path] = []
        self.vms: dict[str, VM] = {}
        self.binary = self.root / "terrascale-orchestrator"
        self.natsdiag = self.root / "natsdiag"
        self.ssh_key = self.secrets / "lab_ssh"
        self.known_hosts = self.secrets / "known_hosts"
        self.operator_config = self.secrets / "operator.json"
        self.signing_public: dict[str, str] = {}
        self.nkeys: dict[str, str] = {}
        self.source = {"repository": "https://example.com/terrascale/firecracker-fixtures",
                       "commit": "f" * 40, "treeDigest": ""}
        self.failure_diagnostics_captured = False
        self.cluster_diagnostics_captured = False

    def note(self, event: str, **details: Any) -> None:
        entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "event": event, **details}
        self.events.append(entry)
        write_json(self.logs / "events.json", self.events)
        print(json.dumps(entry), flush=True)

    @staticmethod
    def choose_subnet() -> int:
        routes = run(["ip", "-j", "route", "show", "table", "all"]).stdout
        used = []
        for route in json.loads(routes):
            try:
                used.append(ipaddress.ip_network(route["dst"], strict=False))
            except (KeyError, ValueError):
                pass
        for _ in range(256):
            octet = secrets.randbelow(256)
            candidate = ipaddress.ip_network(f"198.19.{octet}.0/24")
            if not any(candidate.overlaps(network) for network in used):
                return octet
        raise RuntimeError("no isolated 198.19.x.0/24 subnet is free")

    def sudo(self, *args: str, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
        return run(["sudo", "-n", *args], allow_failure=allow_failure)

    def build(self) -> None:
        before = source_digest()
        revision = run(["git", "rev-parse", "HEAD"]).stdout.strip()
        result = run(["go", "version"])
        self.note("source", revision=revision, manifest_sha256=before, go=result.stdout.strip())
        environment = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH="amd64")
        command = ["go", "build", "-trimpath", "-o", str(self.binary), "./cmd/terrascale-orchestrator"]
        built = subprocess.run(command, cwd=REPO, env=environment, capture_output=True, text=True,
                               timeout=600, check=False)
        (self.logs / "build.log").write_text(built.stdout + built.stderr)
        if built.returncode:
            raise RuntimeError(f"Go build failed; see {self.logs / 'build.log'}")
        diagnostic = subprocess.run(["go", "build", "-trimpath", "-o", str(self.natsdiag),
                                     "tests/firecracker/natsdiag.go"], cwd=REPO,
                                    env=environment, capture_output=True, text=True,
                                    timeout=180, check=False)
        (self.logs / "natsdiag-build.log").write_text(diagnostic.stdout + diagnostic.stderr)
        if diagnostic.returncode:
            raise RuntimeError(f"NATS diagnostic build failed; see {self.logs / 'natsdiag-build.log'}")
        after = source_digest()
        if after != before:
            raise RuntimeError("Go source changed during build; rerun against a stable tree")
        self.note("binary", sha256=digest(self.binary), source_manifest_sha256=after)
        self.note("diagnostic_binary", sha256=digest(self.natsdiag))

    def identities(self) -> None:
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.ssh_key)])
        public_ssh = self.ssh_key.with_suffix(".pub")
        self.ssh_public = public_ssh.read_text().strip()
        for name in ("controller", "operator", "host"):
            key = self.secrets / f"{name}.key"
            generated = run([str(self.binary), "identity-new", "--key", str(key)])
            self.signing_public[name] = generated.stdout.strip()
            if not self.signing_public[name]:
                raise RuntimeError(f"identity-new returned no public key for {name}")
        generated = run(["go", "run", str(REPO / "tests/firecracker/nkeygen.go"),
                         "--dir", str(self.secrets), *CONTROLLERS, "operator", "host"], timeout=180)
        self.nkeys = json.loads(generated.stdout)
        self.note("identities", names=[*self.nkeys, *self.signing_public])

    def configs(self) -> None:
        grants = [{"public_key": self.nkeys[name], "role": "controller"} for name in CONTROLLERS]
        grants += [{"public_key": self.nkeys["operator"], "role": "operator"},
                   {"public_key": self.nkeys["host"], "role": "host", "node": "host-a"}]
        signer = {"actor": "ops", "public_key": self.signing_public["operator"],
                  "roles": [ROLE], "environments": [ENVIRONMENT],
                  "can_register_hosts": True, "repositories": [self.source["repository"]]}
        urls = ",".join(f"nats://{self.addresses[name]}:4222" for name in CONTROLLERS)
        for name in CONTROLLERS:
            other_routes = [f"nats-route://{self.addresses[peer]}:6222" for peer in CONTROLLERS if peer != name]
            config = {"nats": {"cell": CELL, "instance": name, "replicas": 3, "lab": True,
                               "nkey_seed_file": f"/etc/ts-orch/{name}.nk",
                               "embedded": {"host": self.addresses[name], "port": 4222,
                                            "route_host": self.addresses[name], "route_port": 6222,
                                            "routes": other_routes, "store_dir": "/var/lib/ts-orch/nats",
                                            "store_max_bytes": 2 << 30,
                                            "users": grants}},
                      "controller": {"response_key_file": "/etc/ts-orch/controller.key",
                                     "artifact_store_max_bytes": 64 << 20,
                                     "trusted_signers": [signer], "workloads": {
                                         ROLE: {"resources": {"cpu": 1, "memory_bytes": 67108864,
                                                              "disk_bytes": 134217728}}}}}
            write_json(self.secrets / f"{name}.json", config)
        host = {"nats": {"cell": CELL, "instance": "host-a", "replicas": 3, "lab": True,
                         "url": urls, "nkey_seed_file": "/etc/ts-orch/host.nk"},
                "host": {"node": "host-a", "environment": ENVIRONMENT, "roles": [ROLE],
                         "identity_key_file": "/etc/ts-orch/host.key",
                         "controller_public_key": self.signing_public["controller"],
                         "install_root": "/var/lib/ts-orch/install",
                         "state_root": "/var/lib/ts-orch/host", "poll_millis": 250}}
        write_json(self.secrets / "host.json", host)
        operator = {"nats": {"cell": CELL, "instance": "operator", "replicas": 3,
                             "lab": True, "url": urls,
                             "nkey_seed_file": str(self.secrets / "operator.nk")},
                    "controller": {"trusted_signers": [signer]},
                    "operator": {"actor": "ops", "signing_key_file": str(self.secrets / "operator.key")}}
        write_json(self.operator_config, operator)
        registration = {"cell": CELL, "node": "host-a", "environment": ENVIRONMENT,
                        "roles": [ROLE], "public_key": self.signing_public["host"],
                        "generation": 1, "capacity": {"cpu": 2, "memory_bytes": 268435456,
                                                     "disk_bytes": 536870912}}
        write_json(self.secrets / "registration.json", registration)

    def network(self) -> None:
        self.sudo("ip", "link", "add", "name", self.bridge, "type", "bridge")
        self.created_links.append(self.bridge)
        self.sudo("ip", "addr", "add", f"{self.subnet[1]}/24", "dev", self.bridge)
        self.sudo("ip", "link", "set", self.bridge, "up")
        for name, tap in self.taps.items():
            self.sudo("ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", str(os.getuid()))
            self.created_links.append(tap)
            self.sudo("ip", "link", "set", tap, "master", self.bridge)
            self.sudo("ip", "link", "set", tap, "up")
        self.note("network", bridge=self.bridge, subnet=str(self.subnet), taps=self.taps)

    def install(self, mount: Path, source: Path, destination: str, mode: str) -> None:
        if not destination.startswith("/") or ".." in Path(destination).parts:
            raise ValueError("invalid guest destination")
        self.sudo("install", "-D", "-o", "root", "-g", "root", "-m", mode,
                  str(source), str(mount / destination.lstrip("/")))

    def install_text(self, mount: Path, content: str, destination: str, mode: str = "0644") -> None:
        with tempfile.NamedTemporaryFile(mode="w", dir=self.stage, delete=False) as temporary:
            temporary.write(content)
            source = Path(temporary.name)
        try:
            self.install(mount, source, destination, mode)
        finally:
            source.unlink(missing_ok=True)

    def prepare_guest(self, name: str) -> None:
        image = self.images / f"{name}.ext4"
        run(["cp", "--reflink=auto", "--sparse=always", str(self.rootfs), str(image)], timeout=240)
        with image.open("r+b") as private_copy:
            private_copy.truncate(8 << 30)
        checked = run(["e2fsck", "-f", "-y", str(image)], timeout=240, allow_failure=True)
        if checked.returncode not in (0, 1):
            raise RuntimeError(f"private ext4 check failed for {name}: {checked.stdout[-1000:]} {checked.stderr[-1000:]}")
        run(["resize2fs", str(image)], timeout=240)
        mount = self.root / "mount" / name
        mount.mkdir(parents=True)
        self.sudo("mount", "-o", "loop", str(image), str(mount))
        self.mounted.append(mount)
        try:
            host_key = self.secrets / f"ssh-host-{name}"
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
            public_host_key = host_key.with_suffix(".pub")
            key_parts = public_host_key.read_text().split()
            if len(key_parts) < 2 or key_parts[0] != "ssh-ed25519":
                raise RuntimeError(f"invalid generated SSH host key for {name}")
            with self.known_hosts.open("a") as known_hosts:
                known_hosts.write(f"{self.addresses[name]} {key_parts[0]} {key_parts[1]}\n")
            self.known_hosts.chmod(0o600)
            self.install(mount, self.binary, "/usr/local/bin/terrascale-orchestrator", "0755")
            self.install_text(mount, self.ssh_public + "\n", "/root/.ssh/authorized_keys", "0600")
            self.install(mount, host_key, "/etc/ssh/ssh_host_ed25519_key", "0600")
            self.install(mount, public_host_key, "/etc/ssh/ssh_host_ed25519_key.pub", "0644")
            self.install_text(mount, "", "/etc/cloud/cloud-init.disabled")
            self.install_text(mount, "PermitRootLogin prohibit-password\nPasswordAuthentication no\n",
                              "/etc/ssh/sshd_config.d/99-ts-orch-fc.conf")
            self.install_text(mount, "[Match]\nName=e*\n\n[Network]\nAddress=" +
                              self.addresses[name] + "/24\n", "/etc/systemd/network/80-ts-orch-fc.network")
            role = "run" if name in CONTROLLERS else "host"
            config_name = name if name in CONTROLLERS else "host"
            self.install(mount, self.secrets / f"{config_name}.json", "/etc/ts-orch/config.json", "0600")
            self.install(mount, self.secrets / f"{config_name}.nk", f"/etc/ts-orch/{config_name}.nk", "0600")
            key_name = "controller" if name in CONTROLLERS else "host"
            self.install(mount, self.secrets / f"{key_name}.key", f"/etc/ts-orch/{key_name}.key", "0600")
            unit = ("[Unit]\nDescription=TerraScale Firecracker qualification " + name +
                    "\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n" +
                    f"ExecStart=/usr/local/bin/terrascale-orchestrator {role} --config /etc/ts-orch/config.json\n" +
                    "Restart=on-failure\nRestartSec=2\nStandardOutput=journal+console\n" +
                    "StandardError=journal+console\n\n[Install]\nWantedBy=multi-user.target\n")
            self.install_text(mount, unit, "/etc/systemd/system/ts-orch.service")
            self.sudo("systemctl", f"--root={mount}", "enable", "systemd-networkd.service")
            self.sudo("systemctl", f"--root={mount}", "enable", "ssh.service")
            self.sudo("systemctl", f"--root={mount}", "enable", "ts-orch.service")
        finally:
            self.sudo("umount", str(mount))
            self.mounted.remove(mount)
        self.vms[name] = VM(self, name, self.addresses[name], self.taps[name], image)
        self.note("guest_prepared", name=name, image=str(image), virtual_disk_bytes=image.stat().st_size)

    def ssh(self, name: str, command: str, *, timeout: int = 15,
            allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
        address = self.addresses[name]
        return run(["ssh", "-i", str(self.ssh_key), "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=3",
                    "-o", f"UserKnownHostsFile={self.known_hosts}",
                    f"root@{address}", "sh", "-lc", shlex.quote(command)],
                   timeout=timeout, allow_failure=allow_failure)

    def wait(self, label: str, probe: Any, *, timeout: int = 120, period: float = 2) -> Any:
        deadline = time.monotonic() + timeout
        last: BaseException | None = None
        while time.monotonic() < deadline:
            try:
                value = probe()
                if value:
                    self.note("ready", label=label)
                    return value
            except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as error:
                last = error
            time.sleep(period)
        raise TimeoutError(f"{label} did not become ready: {last}")

    def wait_ssh(self, name: str) -> None:
        command = "systemctl is-active ts-orch.service" if name in CONTROLLERS else "true"
        self.wait(f"ssh-{name}", lambda: self.ssh(name, command,
                                                  allow_failure=True).returncode == 0, timeout=150)

    def operator(self, operation: str, *arguments: str, timeout: int = 35,
                 allow_failure: bool = False) -> dict[str, Any] | None:
        command = [str(self.binary), "operator", operation, "--config", str(self.operator_config),
                   *arguments]
        outcome = run(command, timeout=timeout, allow_failure=allow_failure)
        self.note("operator", operation=operation, exit_code=outcome.returncode,
                  stdout=outcome.stdout.strip()[-3000:], stderr=outcome.stderr.strip()[-1000:])
        if outcome.returncode:
            return None
        return json.loads(outcome.stdout)

    def check_cluster(self) -> bool:
        config = self.operator_config
        outcome = run([str(self.binary), "check", "--config", str(config)],
                      timeout=20, allow_failure=True)
        return outcome.returncode == 0

    def wait_cluster(self) -> None:
        self.wait("jetstream-quorum", self.check_cluster, timeout=100)

    def wait_host(self, version: str | None = None) -> None:
        def probe() -> bool:
            statuses = self.operator("hosts")
            if not isinstance(statuses, list) or len(statuses) != 1:
                return False
            status = statuses[0]
            if not status.get("session_expires_at"):
                return False
            if version is None:
                return True
            reports = status.get("reports", [])
            if any(report.get("role") == ROLE and report.get("state") == "failed"
                   for report in reports):
                self.capture_failure_diagnostics()
            if not any(report.get("role") == ROLE and report.get("state") == "running"
                       for report in reports):
                return False
            result = self.ssh("host", "test \"$(cat /run/ts-orch-workload.marker)\" = " +
                              shlex.quote(version) + " && kill -0 \"$(cat /run/ts-orch-workload.pid)\"",
                              allow_failure=True)
            return result.returncode == 0
        self.wait("host-session" if version is None else f"workload-{version}", probe, timeout=150)

    def fixture(self, version: str) -> Path:
        script = ("#!/bin/sh\nset -eu\nprintf '%s\\n' " + shlex.quote(version) +
                  " > /run/ts-orch-workload.marker\nprintf '%s\\n' \"$$\" > /run/ts-orch-workload.pid\n" +
                  "while :; do sleep 1; done\n")
        path = self.stage / f"workload-{version}.sh"
        path.write_text(script)
        path.chmod(0o755)
        return path

    def artifact(self, version: str) -> dict[str, Any]:
        path = self.fixture(version)
        self.source["treeDigest"] = digest(path)
        record = self.operator("artifact-push", "--file", str(path),
                               "--repository", self.source["repository"],
                               "--commit", self.source["commit"],
                               "--tree-digest", self.source["treeDigest"],
                               "--role", ROLE, "--environment", ENVIRONMENT)
        if not isinstance(record, dict) or record.get("digest") != digest(path):
            raise RuntimeError(f"artifact {version} did not return its exact content digest")
        return record

    def intent(self, record: dict[str, Any], generation: int, name: str) -> Path:
        request = {"schemaVersion": 1, "operationId": f"fc-{name}-{generation}",
                   "source": record["source"], "artifactDigest": record["digest"],
                   "manifestDigest": record["manifestDigest"], "cell": CELL,
                   "role": ROLE, "environment": ENVIRONMENT, "generation": generation,
                   "desiredReplicas": 1, "configDigest": CONFIG_DIGEST}
        path = self.stage / f"intent-{name}-{generation}.json"
        write_json(path, request)
        return path

    def deploy(self, record: dict[str, Any], generation: int, name: str,
               operation: str = "deploy") -> None:
        deadline = time.monotonic() + 200

        def remaining() -> int:
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise TimeoutError(f"{operation} {name} exhausted its 200-second wait budget")
            return min(100, math.ceil(seconds))

        attempts = (name, f"{name}-epoch-retry") if name == "one-node-loss" else (name,)
        for attempt, attempt_name in enumerate(attempts):
            path = self.intent(record, generation, attempt_name)
            submitted = self.wait(f"submit-{attempt_name}",
                                  lambda: self.operator(operation, "--intent", str(path),
                                                        timeout=min(35, remaining())),
                                  timeout=remaining())
            if not isinstance(submitted, dict) or submitted.get("status") != "submitted":
                raise RuntimeError(f"{operation} {attempt_name} did not submit")
            submitted_at = time.monotonic()

            def accepted() -> bool:
                receipt = self.operator("status", "--operation-id", submitted["operationId"],
                                        "--fingerprint", submitted["fingerprint"],
                                        timeout=min(35, remaining()))
                if name == "one-node-loss" and time.monotonic() - submitted_at >= 20:
                    self.capture_cluster_diagnostics()
                if not isinstance(receipt, dict):
                    return False
                if receipt.get("status") in ("rejected", "held"):
                    raise TerminalReceipt(receipt)
                return receipt.get("status") == "accepted"

            try:
                self.wait(f"accepted-{attempt_name}", accepted, timeout=remaining())
                return
            except TerminalReceipt as terminal:
                receipt = terminal.receipt
                self.note("terminal_receipt", name=attempt_name,
                          operation_id=submitted["operationId"],
                          fingerprint=submitted["fingerprint"],
                          status=receipt.get("status"), error=receipt.get("error"),
                          authority_epoch=receipt.get("authorityEpoch"))
                if (attempt == 0 and name == "one-node-loss" and
                        receipt.get("status") == "rejected" and
                        receipt.get("error") == PRE_ACCEPTANCE_FENCED):
                    self.note("retry_fenced_intent", rejected_operation_id=submitted["operationId"],
                              new_operation_id=f"fc-{attempts[1]}-{generation}")
                    continue
                raise RuntimeError(f"{operation} {attempt_name} became terminal {receipt}") from terminal

    def capture_cluster_diagnostics(self) -> None:
        if self.cluster_diagnostics_captured:
            return
        self.cluster_diagnostics_captured = True
        for name in CONTROLLERS:
            vm = self.vms.get(name)
            if vm is None or vm.process is None or vm.process.poll() is not None:
                continue
            path = self.logs / f"{name}-live-diagnostics.txt"
            command = ("systemctl status ts-orch.service --no-pager --full; "
                       "journalctl -u ts-orch.service -b --no-pager -n 300 -o short-iso-precise; "
                       "ps -eo pid,ppid,stat,etime,cmd | grep '[t]errascale-orchestrator'")
            try:
                result = self.ssh(name, command, timeout=12, allow_failure=True)
                path.write_text(result.stdout + result.stderr)
                path.chmod(0o600)
                self.note("cluster_diagnostics", name=name, path=str(path),
                          exit_code=result.returncode)
            except Exception as error:
                path.write_text(f"controller diagnostics unavailable: {error!r}\n")
                path.chmod(0o600)
                self.note("cluster_diagnostics", name=name, path=str(path), error=repr(error))
        if self.natsdiag.exists() and (self.secrets / "c1.nk").exists():
            urls = ",".join(f"nats://{self.addresses[name]}:4222" for name in CONTROLLERS)
            path = self.logs / "nats-live-diagnostics.jsonl"
            try:
                result = run([str(self.natsdiag), "--seed", str(self.secrets / "c1.nk"),
                              "--operator-seed", str(self.secrets / "operator.nk"),
                              "--cell", CELL, "--urls", urls], timeout=35, allow_failure=True)
                path.write_text(result.stdout + result.stderr)
                path.chmod(0o600)
                self.note("cluster_diagnostics", name="nats", path=str(path),
                          exit_code=result.returncode)
            except Exception as error:
                path.write_text(f"NATS diagnostics unavailable: {error!r}\n")
                path.chmod(0o600)
                self.note("cluster_diagnostics", name="nats", path=str(path), error=repr(error))

    def scenario(self) -> None:
        self.network()
        for name in GUESTS:
            self.prepare_guest(name)
        for name in GUESTS:
            self.vms[name].boot()
        for name in GUESTS:
            self.wait_ssh(name)
        self.wait_cluster()
        registration = self.wait("signed-host-registration",
                                 lambda: self.operator("host-register", "--registration",
                                                       str(self.secrets / "registration.json")),
                                 timeout=100)
        if not isinstance(registration, dict) or registration.get("generation") != 1:
            raise RuntimeError(f"host registration failed: {registration}")
        self.wait_host()
        original = self.artifact("v1")
        self.deploy(original, 1, "initial")
        self.wait_host("v1")
        self.note("milestone", name="initial-native-workload")

        self.vms["host"].stop()
        self.vms["host"].boot()
        self.wait_ssh("host")
        self.wait_host("v1")
        self.note("milestone", name="host-restart-recovery")

        replacement = self.artifact("v2")
        self.vms["c3"].crash()
        self.wait_cluster()
        self.deploy(replacement, 2, "one-node-loss")
        self.wait_host("v2")
        self.note("milestone", name="one-controller-nats-node-loss")
        self.vms["c3"].boot()
        self.wait_ssh("c3")
        self.wait_cluster()

        rollback = self.intent(original, 3, "rollback")
        self.vms["c2"].crash()
        self.vms["c3"].crash()
        denied = self.operator("rollback", "--intent", str(rollback),
                               timeout=25, allow_failure=True)
        if denied is not None:
            raise RuntimeError("rollback submitted without JetStream quorum")
        marker = self.ssh("host", "test \"$(cat /run/ts-orch-workload.marker)\" = v2 && "
                          "kill -0 \"$(cat /run/ts-orch-workload.pid)\"", allow_failure=True)
        if marker.returncode:
            raise RuntimeError("native v2 workload changed during quorum loss")
        self.note("milestone", name="quorum-loss-rejected-new-intent")
        self.vms["c2"].boot()
        self.wait_ssh("c2")
        self.wait_cluster()
        self.deploy(original, 3, "rollback", operation="rollback")
        self.wait_host("v1")
        self.vms["c3"].boot()
        self.wait_ssh("c3")
        self.note("milestone", name="rollback-after-quorum-recovery")

    def capture_failure_diagnostics(self) -> None:
        if self.failure_diagnostics_captured:
            return
        host_vm = self.vms.get("host")
        if host_vm is None or host_vm.process is None or host_vm.process.poll() is not None:
            return
        self.failure_diagnostics_captured = True
        path = self.logs / "host-failure-diagnostics.txt"
        command = r"""
set +e
printf '\n=== host service ===\n'
systemctl status ts-orch.service --no-pager --full
printf '\n=== host service journal ===\n'
journalctl -u ts-orch.service -b --no-pager -o short-iso-precise
printf '\n=== native process inventory ===\n'
ps -eo pid,ppid,stat,etime,cmd,cgroup
printf '\n=== runner inventory ===\n'
inventory=/var/lib/ts-orch/host/lab/host-a/inventory.json
if [ -f "$inventory" ]; then cat "$inventory"; else echo 'inventory missing'; fi
printf '\n=== cgroup mount and state ===\n'
findmnt -T /sys/fs/cgroup
for root in /sys/fs/cgroup/terrascale-host-*; do
    [ -d "$root" ] || continue
    for group in "$root" "$root"/*; do
        [ -d "$group" ] || continue
        printf '\n%s\n' "$group"
        for item in cgroup.events cgroup.procs memory.events; do
            if [ -f "$group/$item" ]; then
                printf '%s: ' "$item"
                cat "$group/$item"
            fi
        done
    done
done
printf '\n=== workload marker and process ===\n'
ls -l /run/ts-orch-workload.*
for item in /run/ts-orch-workload.marker /run/ts-orch-workload.pid; do
    if [ -f "$item" ]; then printf '%s: ' "$item"; cat "$item"; fi
done
marker_pid=$(cat /run/ts-orch-workload.pid 2>/dev/null)
inventory_pid=$(sed -n 's/.*"pid":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$inventory" 2>/dev/null | head -n 1)
for pid in "$marker_pid" "$inventory_pid"; do
    case "$pid" in ''|*[!0-9]*) continue ;; esac
    printf '\n/proc/%s\n' "$pid"
    for item in stat status cgroup; do
        if [ -f "/proc/$pid/$item" ]; then
            printf '%s: ' "$item"
            cat "/proc/$pid/$item"
        fi
    done
done
printf '\n=== installed workload artifacts ===\n'
find /var/lib/ts-orch/install -type f -print -exec stat -c '%a %u:%g %s %n' {} \; -exec sha256sum {} \;
"""
        try:
            result = self.ssh("host", command, timeout=35, allow_failure=True)
            path.write_text(result.stdout + result.stderr)
            path.chmod(0o600)
            self.note("failure_diagnostics", name="host", path=str(path), exit_code=result.returncode)
        except Exception as error:
            path.write_text(f"host diagnostics unavailable: {error!r}\n")
            path.chmod(0o600)
            self.note("failure_diagnostics", name="host", path=str(path), error=repr(error))

    def cleanup(self) -> list[str]:
        errors: list[str] = []
        images_safe = True
        for vm in reversed(list(self.vms.values())):
            try:
                vm.stop()
            except Exception as error:  # cleanup must continue for all owned resources
                images_safe = False
                errors.append(f"stop {vm.name}: {error}")
        for mount in reversed(self.mounted):
            try:
                result = self.sudo("umount", str(mount), allow_failure=True)
                if result.returncode:
                    errors.append(f"unmount {mount}: {result.stderr.strip()}")
                else:
                    self.mounted.remove(mount)
            except Exception as error:
                errors.append(f"unmount {mount}: {error}")
        for link in reversed(self.created_links):
            try:
                result = self.sudo("ip", "link", "del", link, allow_failure=True)
                if result.returncode:
                    errors.append(f"delete link {link}: {result.stderr.strip()}")
            except Exception as error:
                errors.append(f"delete link {link}: {error}")
        if images_safe and not self.mounted:
            shutil.rmtree(self.images, ignore_errors=True)
        else:
            errors.append(f"guest images retained for manual cleanup: {self.images}")
        shutil.rmtree(self.secrets, ignore_errors=True)
        shutil.rmtree(self.stage, ignore_errors=True)
        return errors


def preflight(args: argparse.Namespace) -> None:
    for path, expected in ((args.kernel, KERNEL_SHA), (args.rootfs, ROOTFS_SHA)):
        if not path.is_file() or digest(path) != expected:
            raise RuntimeError(f"asset missing or SHA-256 mismatch: {path}")
    for command in ("go", "git", "ssh", "ssh-keygen", "cp", "ip", "sudo", "mount", "umount", "e2fsck", "resize2fs"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required command missing: {command}")
    if not Path(args.firecracker).is_file():
        raise RuntimeError(f"Firecracker executable missing: {args.firecracker}")
    if not Path("/dev/kvm").exists() or not Path("/dev/net/tun").exists():
        raise RuntimeError("Firecracker requires /dev/kvm and /dev/net/tun")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--kernel", type=Path, default=Path("/tmp/vm-inputs/vmlinux"))
    parser.add_argument("--rootfs", type=Path, default=Path("/tmp/vm-inputs/rootfs.ext4"))
    parser.add_argument("--firecracker", default=shutil.which("firecracker") or "firecracker")
    parser.add_argument("--run-dir", type=Path, help="new, private evidence directory")
    args = parser.parse_args()
    preflight(args)
    if args.action == "check":
        print("Firecracker assets and host prerequisites verified; no resources created")
        return 0
    run(["sudo", "-n", "true"])
    lab = Lab(args)
    signal.signal(signal.SIGTERM, lambda _signal, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    outcome = "FAILED"
    failure = ""
    cleanup_errors: list[str] = []
    try:
        lab.build()
        lab.identities()
        lab.configs()
        lab.scenario()
        outcome = "PASS"
    except BaseException as error:
        failure = repr(error)
        print(f"qualification failed: {failure}", file=sys.stderr, flush=True)
        try:
            lab.capture_cluster_diagnostics()
        except Exception as diagnostic_error:
            print(f"cluster diagnostics failed: {diagnostic_error!r}", file=sys.stderr, flush=True)
        try:
            lab.capture_failure_diagnostics()
        except Exception as diagnostic_error:
            print(f"host diagnostics failed: {diagnostic_error!r}", file=sys.stderr, flush=True)
    finally:
        cleanup_errors = lab.cleanup()
        summary = {"result": outcome if not cleanup_errors else "CLEANUP_FAILED",
                   "failure": failure, "cleanup_errors": cleanup_errors,
                   "revision": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
                   "binary_sha256": digest(lab.binary) if lab.binary.exists() else None,
                   "events": lab.events}
        write_json(lab.root / "summary.json", summary)
        print(f"evidence: {lab.root / 'summary.json'}", flush=True)
    return 0 if outcome == "PASS" and not cleanup_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
