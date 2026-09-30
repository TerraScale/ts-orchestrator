#!/usr/bin/env python3
"""Run the real regional controller/operator/host flow in four Firecracker VMs.

This script owns every bridge, TAP, VMM, mount, guest copy and credential it
creates. It never edits the supplied kernel or rootfs. Run on an isolated lab
host with passwordless sudo for ip, mount, umount, install and systemctl.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


REPO = Path(__file__).resolve().parents[2]
KERNEL_SHA = "586a02db8ea1fd331d45efa6ebf502fff21ceddfedf010ef70ba389b8e095523"
ROOTFS_SHA = "a6c1cb9c712d8bb9e67b05dd8f46b7e88827250b445e76015e6bb536a15e1af6"
MAX_UNIX_SOCKET_PATH_BYTES = 107
ROLE = "terrabase"
CELL = "lab"
ENVIRONMENT = "test"
CONTROLLERS = ("c1", "c2", "c3")
GUESTS = (*CONTROLLERS, "host")
CONFIG_DIGEST = hashlib.sha256(b'{"args":[],"env":{}}').hexdigest()
BOOT_ARGS = "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw"
PRE_ACCEPTANCE_FENCED = "authority epoch was fenced before acceptance"
SESSION_EXECUTION_RESERVE_SECONDS = 5
WORKLOAD_UID = 2000
WORKLOAD_GID = 2000
WORKLOAD_RUN_DIR = "/run/ts-orch-workload"
CLOCK_READY = "/run/ts-orch-clock-ready"
CLOCK_BOUND_NS = 1_000_000_000
CHRONYD = Path("/nix/store/zinbanwvmabvr9lk7x5qaac0al3v18ml-chrony-4.8/bin/chronyd")
CHRONYC = CHRONYD.with_name("chronyc")
CHRONYD_SHA = "bcfa87ddfc6b61c079ed764b541c82de7e1f279c56ad50b6757c679d6c3b05dd"
CHRONYC_SHA = "10fbfd50c1efe52f56e2a1f1643ab8855b41a6954b5f93242bba1404d8fc7875"
NTP_DIAGNOSTIC_BYTES = 32 << 10


def _default_slog_attributes(message: str, event: str,
                             required_fields: set[str]) -> dict[str, str] | None:
    prefix = re.fullmatch(
        rf"(?P<timestamp>\d{{4}}/\d{{2}}/\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}) "
        rf"INFO {re.escape(event)}(?: (?P<attributes>.*))?",
        message,
    )
    if prefix is None:
        return None
    try:
        datetime.strptime(prefix.group("timestamp"), "%Y/%m/%d %H:%M:%S")
        parts = shlex.split(prefix.group("attributes") or "")
    except ValueError:
        return None

    fields: dict[str, str] = {}
    for part in parts:
        key, separator, value = part.partition("=")
        if not separator or not key or key in fields:
            return None
        fields[key] = value
    if not required_fields.issubset(fields):
        return None
    return fields


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


def firecracker_socket_path(directory: Path, name: str) -> Path:
    path = directory / f"{name}.sock"
    if len(os.fsencode(path)) > MAX_UNIX_SOCKET_PATH_BYTES:
        raise ValueError(f"Firecracker API socket path is too long: {path}")
    return path


def create_private_socket_directory() -> Path:
    directory = Path(tempfile.mkdtemp(prefix="tsfc-", dir="/tmp"))
    try:
        directory.chmod(0o700)
    except BaseException:
        directory.rmdir()
        raise
    return directory


def child_exited_without_reaping(process: subprocess.Popen[Any]) -> bool:
    if process.returncode is not None:
        return True
    try:
        result = os.waitid(os.P_PID, process.pid,
                           os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        raise RuntimeError(f"owned process {process.pid} was reaped before cleanup") from error
    return result is not None and result.si_pid == process.pid


def wait_child_without_reaping(process: subprocess.Popen[Any], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while not child_exited_without_reaping(process):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def owned_process_group(process: subprocess.Popen[Any]) -> int:
    if process.returncode is not None:
        raise RuntimeError(f"owned process {process.pid} was reaped before group cleanup")
    try:
        pgid = os.getpgid(process.pid)
    except ProcessLookupError as error:
        raise RuntimeError(f"owned process {process.pid} disappeared before group cleanup") from error
    if pgid != process.pid:
        raise RuntimeError(f"owned process {process.pid} is no longer its process-group leader")
    return pgid


def live_process_group_members(pgid: int) -> list[int]:
    members = []
    try:
        entries = list(Path("/proc").iterdir())
    except OSError as error:
        raise RuntimeError(f"cannot inspect owned process group {pgid}: {error}") from error
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RuntimeError(f"cannot inspect process {entry.name} in group {pgid}: {error}") from error
        if len(fields) < 3:
            raise RuntimeError(f"invalid process status for {entry.name} in group {pgid}")
        state, _, process_group = fields[:3]
        try:
            observed_pgid = int(process_group)
        except ValueError as error:
            raise RuntimeError(f"invalid process group for process {entry.name}") from error
        if observed_pgid == pgid and state not in ("Z", "X", "x"):
            members.append(int(entry.name))
    return members


def wait_for_process_group_quiescence(pgid: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        members = live_process_group_members(pgid)
        if not members:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(f"owned process group {pgid} still has live members: {members}")
        time.sleep(0.05)


def stop_process_group(process: subprocess.Popen[Any], *, timeout: float = 5) -> None:
    pgid = owned_process_group(process)
    os.killpg(pgid, signal.SIGTERM)
    wait_child_without_reaping(process, timeout)
    # Keep the group leader unreaped until the final signal; its zombie reserves the PGID.
    if owned_process_group(process) != pgid:
        raise RuntimeError(f"owned process group {pgid} changed before forced cleanup")
    os.killpg(pgid, signal.SIGKILL)
    wait_for_process_group_quiescence(pgid, timeout)
    process.wait(timeout=timeout)


def kill_process_group(process: subprocess.Popen[Any], *, timeout: float = 5) -> None:
    pgid = owned_process_group(process)
    os.killpg(pgid, signal.SIGKILL)
    wait_for_process_group_quiescence(pgid, timeout)
    process.wait(timeout=timeout)


def cleanup_owned_sockets(vms: dict[str, "VM"], directory: Path) -> list[str]:
    for vm in vms.values():
        if vm.process is not None:
            return [f"keep Firecracker API sockets until {vm.name} is confirmed stopped"]

    errors: list[str] = []
    for vm in vms.values():
        try:
            vm.socket.unlink(missing_ok=True)
        except OSError as error:
            errors.append(f"remove owned Firecracker API socket {vm.socket}: {error}")
    if errors:
        return errors
    try:
        directory.rmdir()
    except FileNotFoundError:
        pass
    except OSError as error:
        errors.append(f"remove empty Firecracker API socket directory {directory}: {error}")
    return errors


def validate_native_cgroup_path(path: str, service_cgroup: str) -> None:
    def components(value: str) -> list[str]:
        if not isinstance(value, str) or not value.startswith("/") or value.endswith("/"):
            raise ValueError("invalid native workload cgroup path")
        parts = value[1:].split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise ValueError("invalid native workload cgroup path")
        return parts

    service_parts = components(service_cgroup)
    workload_parts = components(path)
    if (len(service_parts) < 2 or service_parts[-1] != "ts-orch.service" or
            any(re.fullmatch(r"[A-Za-z0-9_-]+\.slice", part) is None
                for part in service_parts[:-1]) or
            workload_parts[:len(service_parts)] != service_parts or
            len(workload_parts) != len(service_parts) + 2 or
            re.fullmatch(r"terrascale-host-[0-9a-f]{16}", workload_parts[-2]) is None or
            workload_parts[-1] != ROLE):
        raise ValueError("invalid native workload cgroup path")


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


def curated_host_statuses(statuses: Any, captured_at: datetime) -> list[dict[str, Any]]:
    if not isinstance(statuses, list):
        raise ValueError("operator hosts did not return a list")
    result = []
    for status in statuses:
        if not isinstance(status, dict) or not isinstance(status.get("registration"), dict):
            raise ValueError("operator hosts returned an invalid status")
        registration = status["registration"]
        expiry = status.get("session_expires_at")
        try:
            current = (datetime.fromisoformat(expiry.replace("Z", "+00:00")) > captured_at
                       if isinstance(expiry, str) else False)
        except ValueError:
            current = False
        capacity = registration.get("capacity") or {}
        reports = status.get("reports") or []
        result.append({
            "node": registration.get("node"),
            "environment": registration.get("environment"),
            "roles": registration.get("roles"),
            "registration_generation": registration.get("generation"),
            "capacity": {key: capacity.get(key) for key in ("cpu", "memory_bytes", "disk_bytes")},
            "session_expires_at": expiry,
            "session_current": current,
            "verified": status.get("verified"),
            "reports": [{"role": report.get("role"), "generation": report.get("generation"),
                         "state": report.get("state"), "digest_prefix": str(report.get("digest", ""))[:12],
                         "epoch": report.get("epoch"), "observed_at": report.get("observed_at"),
                         "session_id_hash": (hashlib.sha256(report["session_id"].encode()).hexdigest()[:32]
                                             if isinstance(report.get("session_id"), str) else None)}
                        for report in reports if isinstance(report, dict)],
        })
    return result


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
        self.socket = firecracker_socket_path(lab.socket_dir, name)
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
            if child_exited_without_reaping(self.process):
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
        try:
            self.api("/actions", {"action_type": "SendCtrlAltDel"})
        except Exception:
            pass
        else:
            wait_child_without_reaping(process, 25)
        stop_process_group(process)
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
        kill_process_group(process)
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
        self.events: list[dict[str, Any]] = []
        self.bridge = "tsf" + secrets.token_hex(3) + "b"
        self.taps = {name: "tsf" + self.bridge[3:9] + str(index) for index, name in enumerate(GUESTS, 1)}
        self.network_octet = self.choose_subnet()
        self.subnet = ipaddress.ip_network(f"198.19.{self.network_octet}.0/24")
        self.addresses = {name: str(self.subnet[index + 10]) for index, name in enumerate(GUESTS, 1)}
        self.created_links: list[str] = []
        self.created_nft_tables: list[str] = []
        self.ntp_rule_comment: str | None = None
        self.ntp_rule_handle: int | None = None
        self.clock_diagnostics_captured: set[str] = set()
        self.clock_host_diagnostics: dict[str, Any] | None = None
        self.mounted: list[Path] = []
        self.vms: dict[str, VM] = {}
        self.binary = self.root / "terrascale-orchestrator"
        self.natsdiag = self.root / "natsdiag"
        self.jwtsetup = self.root / "jwtsetup"
        self.clockprobe = self.root / "clockprobe"
        self.chrony_process: subprocess.Popen[str] | None = None
        self.chrony_control_dir: Path | None = None
        self.session_probe_process: subprocess.Popen[str] | None = None
        self.ssh_key = self.secrets / "lab_ssh"
        self.known_hosts = self.secrets / "known_hosts"
        self.operator_config = self.secrets / "operator.json"
        self.signing_public: dict[str, str] = {}
        self.jwt_manifest: dict[str, Any] = {}
        self.source = {"repository": "https://example.com/terrascale/firecracker-fixtures",
                       "commit": "f" * 40, "treeDigest": ""}
        self.failure_diagnostics_captured = False
        self.cluster_diagnostics_captured = False
        self.host_status_diagnostics_captured: set[str] = set()
        self.active_operation_id = ""
        self.go_source_sha256 = ""
        self.harness_sha256 = ""
        self.guest_clock_upper_ns: dict[str, int] = {}
        self.socket_dir = create_private_socket_directory()
        for name in GUESTS:
            firecracker_socket_path(self.socket_dir, name)

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
        self.go_source_sha256 = before
        self.harness_sha256 = self.harness_digest()
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
        for label, target, source in (("jwtsetup", self.jwtsetup, "tests/firecracker/jwtsetup/main.go"),
                                      ("clockprobe", self.clockprobe, "tests/firecracker/clockprobe/main.go")):
            result = subprocess.run(["go", "build", "-trimpath", "-o", str(target), source],
                                    cwd=REPO, env=environment, capture_output=True, text=True,
                                    timeout=180, check=False)
            (self.logs / f"{label}-build.log").write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(f"{label} build failed; see {self.logs / f'{label}-build.log'}")
        after = source_digest()
        if after != before:
            raise RuntimeError("Go source changed during build; rerun against a stable tree")
        if self.harness_digest() != self.harness_sha256:
            raise RuntimeError("Firecracker harness changed during build; rerun against a stable tree")
        self.note("binary", sha256=digest(self.binary), source_manifest_sha256=after)
        self.note("diagnostic_binary", sha256=digest(self.natsdiag))
        self.note("jwtsetup_binary", sha256=digest(self.jwtsetup))
        self.note("clockprobe_binary", sha256=digest(self.clockprobe))

    @staticmethod
    def harness_digest() -> str:
        value = hashlib.sha256()
        for name in ("qualify.py", "test_qualify.py", "natsdiag.go", "natsdiag_test.go",
                     "jwtsetup/main.go", "clockprobe/main.go", "README.md"):
            path = REPO / "tests" / "firecracker" / name
            value.update(name.encode() + b"\0" + bytes.fromhex(digest(path)))
        return value.hexdigest()

    def tls_files(self, name: str, *, guest: bool) -> dict[str, str]:
        directory = Path("/etc/ts-orch") if guest else self.secrets
        return {"ca_file": str(directory / "nats-ca.pem"),
                "cert_file": str(directory / f"nats-{name}.pem"),
                "key_file": str(directory / f"nats-{name}.key")}

    def create_tls_material(self) -> None:
        ca_key = self.secrets / "nats-ca.key"
        ca_cert = self.secrets / "nats-ca.pem"
        run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
             "ec_paramgen_curve:P-256", "-out", str(ca_key)])
        ca_key.chmod(0o600)
        run(["openssl", "req", "-new", "-x509", "-key", str(ca_key), "-sha256",
             "-days", "2", "-subj", f"/CN=ts-fc-{self.bridge}",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", str(ca_cert)])
        ca_cert.chmod(0o600)
        fingerprints = {}
        for serial, name in enumerate((*GUESTS, "operator"), 2):
            private_key = self.secrets / f"nats-{name}.key"
            request = self.secrets / f"nats-{name}.csr"
            extension = self.secrets / f"nats-{name}.ext"
            certificate = self.secrets / f"nats-{name}.pem"
            run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                 "ec_paramgen_curve:P-256", "-out", str(private_key)])
            private_key.chmod(0o600)
            run(["openssl", "req", "-new", "-key", str(private_key), "-out",
                 str(request), "-subj", f"/CN={name}.{CELL}.fc"])
            san = f"IP:{self.addresses[name]},DNS:{name}.{CELL}.fc" if name in GUESTS else "DNS:operator.lab.fc"
            extension.write_text("[leaf]\nbasicConstraints=critical,CA:FALSE\n"
                                 "keyUsage=critical,digitalSignature\n"
                                 "extendedKeyUsage=serverAuth,clientAuth\n"
                                 f"subjectAltName={san}\n")
            extension.chmod(0o600)
            run(["openssl", "x509", "-req", "-in", str(request), "-CA", str(ca_cert),
                 "-CAkey", str(ca_key), "-set_serial", str(serial), "-days", "2",
                 "-sha256", "-extfile", str(extension), "-extensions", "leaf",
                 "-out", str(certificate)])
            certificate.chmod(0o600)
            fingerprints[name] = digest(certificate)
            request.unlink()
            extension.unlink()
        route_password = self.secrets / "route-password"
        route_password.write_text(secrets.token_urlsafe(32) + "\n")
        route_password.chmod(0o600)
        self.note("tls_material", minimum_version="TLS1.3", client_auth="require_and_verify",
                  ca_sha256=digest(ca_cert), certificate_sha256=fingerprints,
                  distinct_certificates=len(set(fingerprints.values())) == len(fingerprints))
        if len(set(fingerprints.values())) != len(fingerprints):
            raise RuntimeError("TLS leaf certificates were not distinct")

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
        generated = run([str(self.jwtsetup), "--dir", str(self.secrets), "--cell", CELL,
                         "--brokers", ",".join(CONTROLLERS), "--host-node", "host-a"])
        self.jwt_manifest = json.loads(generated.stdout)
        if set(self.jwt_manifest.get("users", {})) != {*CONTROLLERS, "operator", "host", "system"}:
            raise RuntimeError("JWT fixture returned incomplete public user identities")
        self.create_tls_material()
        self.note("identities", names=[*self.jwt_manifest["users"], *self.signing_public],
                  operator_account=self.jwt_manifest["operator_account"],
                  cell_account=self.jwt_manifest["cell_account"])

    def configs(self) -> None:
        signer = {"actor": "ops", "public_key": self.signing_public["operator"],
                  "roles": [ROLE], "environments": [ENVIRONMENT],
                  "can_register_hosts": True, "repositories": [self.source["repository"]]}
        urls = ",".join(f"tls://{self.addresses[name]}:4222" for name in CONTROLLERS)
        for name in CONTROLLERS:
            other_routes = [f"nats-route://{self.addresses[peer]}:6222" for peer in CONTROLLERS if peer != name]
            config = {"nats": {"cell": CELL, "instance": name, "replicas": 3, "lab": False,
                               "client_role": "controller", "tls": self.tls_files(name, guest=True),
                               "credentials_file": f"/etc/ts-orch/{name}.creds",
                               "embedded": {"host": self.addresses[name], "port": 4222,
                                            "route_host": self.addresses[name], "route_port": 6222,
                                            "routes": other_routes, "store_dir": "/var/lib/ts-orch/nats",
                                            "store_max_bytes": 2 << 30,
                                            "tls": self.tls_files(name, guest=True),
                                            "route_tls": self.tls_files(name, guest=True),
                                            "route_user": "ts-fc-route",
                                            "route_password_file": "/etc/ts-orch/route-password",
                                            "operator_jwt_file": "/etc/ts-orch/operator.jwt",
                                            "system_jwt_file": "/etc/ts-orch/system.jwt",
                                            "cell_jwt_file": "/etc/ts-orch/cell.jwt",
                                            "system_credentials_file": "/etc/ts-orch/system.creds",
                                            "ticket_public_key_file": "/etc/ts-orch/broker-ticket.pub",
                                            "broker_ids": list(CONTROLLERS)}},
                      "controller": {"response_key_file": "/etc/ts-orch/controller.key",
                                     "broker_ticket_key_file": "/etc/ts-orch/broker-ticket.key",
                                     "artifact_store_max_bytes": 64 << 20,
                                     "trusted_signers": [signer], "workloads": {
                                         ROLE: {"resources": {"cpu": 1, "memory_bytes": 67108864,
                                                              "disk_bytes": 134217728}}}}}
            write_json(self.secrets / f"{name}.json", config)
        host = {"nats": {"cell": CELL, "instance": "host-a", "replicas": 3, "lab": False,
                         "client_role": "host", "url": urls,
                         "tls": self.tls_files("host", guest=True),
                         "credentials_file": "/etc/ts-orch/host.creds"},
                "host": {"node": "host-a", "environment": ENVIRONMENT, "roles": [ROLE],
                         "session_trace": True,
                         "workload_uid": WORKLOAD_UID, "workload_gid": WORKLOAD_GID,
                         "identity_key_file": "/etc/ts-orch/host.key",
                         "controller_public_key": self.signing_public["controller"],
                         "install_root": "/var/lib/ts-orch-install",
                         "state_root": "/var/lib/ts-orch/host", "poll_millis": 250}}
        write_json(self.secrets / "host.json", host)
        operator = {"nats": {"cell": CELL, "instance": "operator", "replicas": 3,
                             "lab": False, "client_role": "operator", "url": urls,
                             "tls": self.tls_files("operator", guest=False),
                             "credentials_file": str(self.secrets / "operator.creds")},
                    "controller": {"trusted_signers": [signer]},
                    "operator": {"actor": "ops", "signing_key_file": str(self.secrets / "operator.key"),
                                 "broker_ticket_public_key_file": str(self.secrets / "broker-ticket.pub")}}
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

    def _input_firewall_rules(self) -> list[dict[str, Any]]:
        """Read the active IPv4 INPUT chain, including handles and counters."""
        output = self.sudo("nft", "-j", "-a", "list", "chain", "ip", "filter", "INPUT")
        entries = json.loads(output.stdout)["nftables"]
        chains = [item["chain"] for item in entries if "chain" in item]
        if (len(chains) != 1 or chains[0].get("family") != "ip" or
                chains[0].get("table") != "filter" or chains[0].get("name") != "INPUT" or
                chains[0].get("type") != "filter" or chains[0].get("hook") != "input"):
            raise RuntimeError("host IPv4 filter INPUT is not the active input hook")
        return [item["rule"] for item in entries if "rule" in item]

    def _owned_ntp_rules(self) -> list[dict[str, Any]]:
        comment = self.ntp_rule_comment
        if comment is None:
            return []
        return [rule for rule in self._input_firewall_rules()
                if rule.get("family") == "ip" and rule.get("table") == "filter" and
                rule.get("chain") == "INPUT" and rule.get("comment") == comment]

    def _exact_ntp_rule(self, rule: dict[str, Any]) -> bool:
        """Do not treat a reused comment on a different rule as our resource."""
        expected = [
            ("meta", "iifname", self.bridge),
            ("payload", "ip", "saddr", {
                "prefix": {"addr": str(self.subnet.network_address), "len": 24}}),
            ("payload", "ip", "daddr", str(self.subnet[1])),
            ("payload", "udp", "dport", 123),
        ]
        expressions = rule.get("expr")
        if not isinstance(expressions, list) or len(expressions) != 6:
            return False
        for expression, wanted in zip(expressions[:4], expected, strict=True):
            match = expression.get("match", {})
            if match.get("op") != "==" or match.get("right") != wanted[-1]:
                return False
            left = match.get("left", {})
            if wanted[0] == "meta":
                if left != {"meta": {"key": wanted[1]}}:
                    return False
            elif left != {"payload": {"protocol": wanted[1], "field": wanted[2]}}:
                return False
        return "counter" in expressions[4] and len(expressions[4]) == 1 and \
            "accept" in expressions[5] and len(expressions[5]) == 1

    def install_ntp_firewall_rule(self) -> None:
        """Admit only the owned guests' NTP requests before NixOS's INPUT drop."""
        if self.ntp_rule_comment is not None:
            raise RuntimeError("private NTP firewall rule was already attempted")
        if (re.fullmatch(r"tsf[0-9a-f]{6}b", self.bridge) is None or
                self.subnet.prefixlen != 24 or
                not self.subnet.subnet_of(ipaddress.ip_network("198.19.0.0/16"))):
            raise RuntimeError("private NTP firewall rule requires the owned bridge and /24")
        rules = self._input_firewall_rules()
        if not any(any(expr.get("jump", {}).get("target") == "nixos-fw"
                       for expr in rule.get("expr", [])) for rule in rules):
            raise RuntimeError("host INPUT does not route through the expected NixOS firewall")
        comment = "ts-orch-fc-ntp-" + secrets.token_hex(12)
        self.ntp_rule_comment = comment  # retain ownership even if insertion partly succeeds
        self.sudo("nft", "insert", "rule", "ip", "filter", "INPUT",
                  "iifname", self.bridge,
                  "ip", "saddr", str(self.subnet),
                  "ip", "daddr", str(self.subnet[1]),
                  "udp", "dport", "123", "counter", "accept", "comment", comment)
        owned = self._owned_ntp_rules()
        if (len(owned) != 1 or not self._exact_ntp_rule(owned[0]) or
                not isinstance(owned[0].get("handle"), int)):
            raise RuntimeError("cannot identify the private NTP firewall rule after insertion")
        self.ntp_rule_handle = owned[0]["handle"]
        self.note("ntp_firewall_rule", bridge=self.bridge, source=str(self.subnet),
                  destination=str(self.subnet[1]), protocol="udp", port=123,
                  comment=comment, handle=self.ntp_rule_handle)

    def remove_ntp_firewall_rule(self) -> None:
        """Delete only the uniquely tagged rule, including after partial setup."""
        if getattr(self, "ntp_rule_comment", None) is None:
            return
        owned = self._owned_ntp_rules()
        if len(owned) > 1:
            raise RuntimeError("private NTP firewall comment matched multiple rules")
        if not owned:
            self.ntp_rule_comment = None
            self.ntp_rule_handle = None
            return
        if not self._exact_ntp_rule(owned[0]):
            raise RuntimeError("private NTP firewall rule scope changed")
        handle = owned[0].get("handle")
        if (not isinstance(handle, int) or handle < 1 or
                (self.ntp_rule_handle is not None and handle != self.ntp_rule_handle)):
            raise RuntimeError("private NTP firewall handle changed")
        self.sudo("nft", "delete", "rule", "ip", "filter", "INPUT", "handle", str(handle))
        if self._owned_ntp_rules():
            raise RuntimeError("private NTP firewall rule remains after deletion")
        self.note("ntp_firewall_rule_removed", comment=self.ntp_rule_comment, handle=handle)
        self.ntp_rule_comment = None
        self.ntp_rule_handle = None

    def chrony_socket_path(self) -> Path:
        created = self.sudo("mktemp", "-d", "-p", "/run", "ts-orch-fc-chrony.XXXXXXXX")
        directory = Path(created.stdout.strip())
        if (directory.parent != Path("/run") or
                re.fullmatch(r"ts-orch-fc-chrony\.[A-Za-z0-9]{8}", directory.name) is None):
            raise RuntimeError("invalid private Chrony control directory")
        self.chrony_control_dir = directory
        details = directory.lstat()
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or
                stat.S_IMODE(details.st_mode) != 0o700):
            raise RuntimeError("private Chrony control directory must be root-owned mode 0700")
        return directory / "chronyd.sock"

    def start_chrony(self) -> None:
        config = self.stage / "chrony.conf"
        socket_path = self.chrony_socket_path()
        config.write_text(
            "pool 2.nixos.pool.ntp.org iburst maxsources 4\n"
            f"bindaddress {self.subnet[1]}\nallow {self.subnet}\nport 123\n"
            f"bindcmdaddress {socket_path}\ncmdport 0\n"
            f"pidfile {self.root / 'chronyd.pid'}\n"
            f"driftfile {self.root / 'chronyd.drift'}\n")
        config.chmod(0o600)
        run([str(CHRONYD), "-p", "-f", str(config)])
        log = (self.logs / "chronyd.log").open("w")
        try:
            self.chrony_process = subprocess.Popen(
                ["sudo", "-n", str(CHRONYD), "-x", "-d", "-4", "-f", str(config)],
                stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        finally:
            log.close()

        def selected() -> bool:
            if self.chrony_process.poll() is not None:
                raise RuntimeError(f"private chronyd exited; see {self.logs / 'chronyd.log'}")
            sources = run(["sudo", "-n", str(CHRONYC), "-n", "-h", str(socket_path), "sources"],
                          timeout=10, allow_failure=True)
            if sources.returncode:
                return False
            # ^* denotes a selected real upstream; the config contains no local clock.
            if not any(line.lstrip().startswith("^*") for line in sources.stdout.splitlines()):
                return False
            listeners = run(["sudo", "-n", "ss", "-H", "-lun"], timeout=10)
            return any(f"{self.subnet[1]}:123" in line for line in listeners.stdout.splitlines())

        self.wait("private-chrony-upstream-and-listener", selected, timeout=150, period=2)
        self.note("chrony_ready", pid=self.chrony_process.pid, upstream="selected_remote",
                  bind_address=str(self.subnet[1]), chronyd_sha256=digest(CHRONYD))

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

    @staticmethod
    def guest_unit(name: str, role: str) -> str:
        host_service = ""
        if name == "host":
            host_service = (
                "NoNewPrivileges=yes\n"
                "CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP\n"
                "AmbientCapabilities=\nDelegate=yes\nDelegateSubgroup=supervisor\n"
                f"ExecStartPre=/usr/bin/install -d -o {WORKLOAD_UID} -g {WORKLOAD_GID} "
                f"-m 0700 {WORKLOAD_RUN_DIR}\n")
        return ("[Unit]\nDescription=TerraScale Firecracker qualification " + name +
                "\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n" +
                host_service +
                "TimeoutStartSec=180\n" +
                f"ExecStartPre=/bin/sh -c 'while ! test -f {CLOCK_READY}; do sleep 0.1; done'\n" +
                f"ExecStart=/usr/local/bin/terrascale-orchestrator {role} --config /etc/ts-orch/config.json\n" +
                "Restart=on-failure\nRestartSec=2\nStandardOutput=journal+console\n" +
                "StandardError=journal+console\n\n[Install]\nWantedBy=multi-user.target\n")

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
            self.install(mount, self.clockprobe, "/usr/local/bin/ts-orch-clockprobe", "0755")
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
            self.install(mount, self.secrets / f"{config_name}.creds",
                         f"/etc/ts-orch/{config_name}.creds", "0600")
            for file_name in ("nats-ca.pem", f"nats-{name}.pem", f"nats-{name}.key"):
                self.install(mount, self.secrets / file_name, f"/etc/ts-orch/{file_name}", "0600")
            if name in CONTROLLERS:
                self.install(mount, self.secrets / "route-password", "/etc/ts-orch/route-password", "0600")
                for file_name in ("operator.jwt", "system.jwt", "cell.jwt", "system.creds",
                                  "broker-ticket.key", "broker-ticket.pub"):
                    self.install(mount, self.secrets / file_name, f"/etc/ts-orch/{file_name}", "0600")
            self.install_text(mount, "[Time]\nNTP=" + str(self.subnet[1]) +
                              "\nFallbackNTP=\nRootDistanceMaxSec=1\n",
                              "/etc/systemd/timesyncd.conf.d/ts-orch-fc.conf")
            key_name = "controller" if name in CONTROLLERS else "host"
            self.install(mount, self.secrets / f"{key_name}.key", f"/etc/ts-orch/{key_name}.key", "0600")
            unit = self.guest_unit(name, role)
            self.install_text(mount, unit, "/etc/systemd/system/ts-orch.service")
            self.sudo("systemctl", f"--root={mount}", "enable", "systemd-networkd.service")
            self.sudo("systemctl", f"--root={mount}", "enable", "ssh.service")
            self.sudo("systemctl", f"--root={mount}", "enable", "systemd-timesyncd.service")
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

    def wait(self, label: str, probe: Any, *, timeout: int = 120, period: float = 2,
             deadline: float | None = None) -> Any:
        if deadline is None:
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
        self.wait(f"ssh-{name}", lambda: self.ssh(name, "true",
                                                  allow_failure=True).returncode == 0, timeout=150)
        self.release_synchronized_guest_clock(name)
        self.wait(f"service-{name}", lambda: self.ssh(name, "systemctl is-active ts-orch.service",
                                                      allow_failure=True).returncode == 0,
                  timeout=150)

    def operator(self, operation: str, *arguments: str, timeout: float = 35,
                 allow_failure: bool = False, stage: str = "") -> dict[str, Any] | None:
        command = [str(self.binary), "operator", operation, "--config", str(self.operator_config),
                   *arguments]
        started = time.monotonic()
        try:
            outcome = run(command, timeout=timeout, allow_failure=True)
        except subprocess.TimeoutExpired as error:
            stderr = error.stderr or ""
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            self.note("operator", operation=operation, stage=stage or operation,
                      exit_code=None, elapsed_seconds=round(time.monotonic() - started, 3),
                      timeout_seconds=timeout, stdout="", stderr=stderr[-1000:],
                      failure="subprocess_timeout")
            raise
        except OSError as error:
            self.note("operator", operation=operation, stage=stage or operation,
                      exit_code=None, elapsed_seconds=round(time.monotonic() - started, 3),
                      timeout_seconds=timeout, stdout="", stderr=str(error)[-1000:],
                      failure="launch_error")
            raise
        logged_stdout = ("" if operation == "hosts" and outcome.returncode else
                         outcome.stdout.strip()[-3000:])
        if operation == "hosts" and outcome.returncode == 0:
            try:
                logged_stdout = json.dumps(curated_host_statuses(json.loads(outcome.stdout),
                                                                 datetime.now(timezone.utc)))[-3000:]
            except (ValueError, TypeError):
                logged_stdout = "<invalid host-status output>"
        self.note("operator", operation=operation, stage=stage or operation,
                  exit_code=outcome.returncode,
                  elapsed_seconds=round(time.monotonic() - started, 3),
                  timeout_seconds=timeout, stdout=logged_stdout,
                  stderr=outcome.stderr.strip()[-1000:],
                  failure="exit_nonzero" if outcome.returncode else None)
        if outcome.returncode:
            if not allow_failure:
                failure_stdout = "" if operation == "hosts" else outcome.stdout[-2000:]
                raise RuntimeError(f"command {command!r} failed ({outcome.returncode}): "
                                   f"{failure_stdout} {outcome.stderr[-2000:]}")
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
            observed = self.native_observation()
            return (observed["marker"] == version and observed["workload_alive"] and
                    bool(observed["workload_cgroup"]) and
                    not self.cgroup_empty(observed["workload_cgroup"], observed["service_cgroup"]))
        self.wait("host-session" if version is None else f"workload-{version}", probe, timeout=150)

    def host_session(self, version: str, *, timeout: float = 35,
                     stage: str = "") -> dict[str, Any]:
        statuses = self.operator("hosts", timeout=timeout, stage=stage)
        if not isinstance(statuses, list) or len(statuses) != 1:
            raise RuntimeError("expected exactly one host status")
        status = statuses[0]
        expiry_raw = status.get("session_expires_at")
        if not isinstance(expiry_raw, str):
            raise RuntimeError("host status lacks a session expiry")
        expiry = datetime.fromisoformat(expiry_raw.replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise RuntimeError("host session is not current")
        reports = [report for report in status.get("reports", [])
                   if report.get("role") == ROLE and report.get("state") == "running"
                   and report.get("generation") == (1 if version == "v1" else 2)]
        if len(reports) != 1 or not reports[0].get("session_id"):
            raise RuntimeError("host lacks a unique running report bound to a session")
        return {"expires_at": expiry, "session_id": reports[0]["session_id"],
                "report": reports[0], "reader_verified": status.get("verified")}

    def native_observation(self, *, timeout: float = 15) -> dict[str, Any]:
        command = """set -eu
agent=$(systemctl show ts-orch.service -p MainPID --value)
invocation=$(systemctl show ts-orch.service -p InvocationID --value)
service_cgroup=$(systemctl show ts-orch.service -p ControlGroup --value)
agent_cgroup=''
case "$agent" in ''|0|*[!0-9]*) ;; *)
    if [ -r "/proc/$agent/cgroup" ]; then
        agent_cgroup=$(awk -F: '$1 == "0" {print $3}' "/proc/$agent/cgroup")
    fi ;;
esac
workload=$(cat /run/ts-orch-workload/pid 2>/dev/null || true)
marker=$(cat /run/ts-orch-workload/marker 2>/dev/null || true)
proc_state() {
    case "$1" in ''|0|*[!0-9]*) printf 'missing'; return ;; esac
    if [ -r "/proc/$1/stat" ]; then awk '{print $3 ":" $22}' "/proc/$1/stat"; else printf 'missing'; fi
}
workload_state_before=$(proc_state "$workload")
workload_cgroup=''
case "$workload" in ''|0|*[!0-9]*) ;; *)
    if [ -r "/proc/$workload/cgroup" ]; then
        workload_cgroup=$(awk -F: '$1 == "0" {print $3}' "/proc/$workload/cgroup")
    fi ;;
esac
printf 'agent_pid=%s\nagent_state=%s\nagent_cgroup=%s\nservice_cgroup=%s\ninvocation=%s\nworkload_pid=%s\nworkload_state_before=%s\nworkload_state=%s\nworkload_cgroup=%s\nmarker=%s\n' \
    "$agent" "$(proc_state "$agent")" "$agent_cgroup" "$service_cgroup" "$invocation" "$workload" "$workload_state_before" "$(proc_state "$workload")" "$workload_cgroup" "$marker"
"""
        output = self.ssh("host", command, timeout=timeout).stdout
        observed = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        expected = {"agent_pid", "agent_state", "agent_cgroup", "service_cgroup", "invocation",
                    "workload_pid", "workload_state_before", "workload_state", "workload_cgroup", "marker"}
        if not expected.issubset(observed):
            raise RuntimeError("incomplete native process observation")
        if (not observed["service_cgroup"] or
                observed["agent_cgroup"] != observed["service_cgroup"] + "/supervisor"):
            raise RuntimeError("host agent is not in its systemd supervisor subgroup")
        before_start = observed["workload_state_before"].split(":")[-1]
        after_start = observed["workload_state"].split(":")[-1]
        if ((before_start == "missing" and after_start != "missing") or
                (after_start != "missing" and before_start != after_start)):
            raise RuntimeError("native workload PID changed during cgroup observation")
        if after_start == "missing":
            observed["workload_cgroup"] = ""
        observed["workload_alive"] = observed["workload_state"].split(":", 1)[0] not in ("missing", "Z", "X")
        if observed["workload_alive"]:
            validate_native_cgroup_path(observed["workload_cgroup"], observed["service_cgroup"])
        return observed

    def cgroup_empty(self, path: str, service_cgroup: str) -> bool:
        validate_native_cgroup_path(path, service_cgroup)
        role_path = "/sys/fs/cgroup" + path
        service_path = "/sys/fs/cgroup" + service_cgroup
        runner_path = "/sys/fs/cgroup" + path.rsplit("/", 1)[0]
        events = role_path + "/cgroup.events"
        prefixes = ["/sys", "/sys/fs", "/sys/fs/cgroup"]
        for component in path[1:].split("/"):
            prefixes.append(prefixes[-1] + "/" + component)
        command = (
            "set -eu\n" +
            "test \"$(systemctl show ts-orch.service -p ControlGroup --value)\" = " +
            shlex.quote(service_cgroup) + "\n" +
            "for entry in " + " ".join(shlex.quote(prefix) for prefix in prefixes) +
            "; do test ! -L \"$entry\" || exit 4; done\n" +
            "test -d " + shlex.quote(service_path) + "\n" +
            "grep -qw memory " + shlex.quote(service_path + "/cgroup.controllers") + "\n" +
            "for parent in " + " ".join(shlex.quote(parent) for parent in
                                         (service_path, runner_path)) + "; do\n" +
            "    test -f \"$parent/cgroup.procs\"\n" +
            "    test ! -s \"$parent/cgroup.procs\"\n" +
            "    grep -qw memory \"$parent/cgroup.subtree_control\"\n" +
            "done\n" +
            "if test -f " + shlex.quote(events) + "; then\n" +
            "    test ! -L " + shlex.quote(events) + "\n" +
            "    cat " + shlex.quote(events) + "\n" +
            "elif test -e " + shlex.quote(role_path) + "; then exit 5\n" +
            "else printf 'populated 0\\n'; fi")
        output = self.ssh("host", command).stdout
        populated = [line for line in output.splitlines() if line.startswith("populated ")]
        if populated == ["populated 0"]:
            return True
        if populated == ["populated 1"]:
            return False
        raise RuntimeError("native workload cgroup has no populated state")

    def measure_guest_clock(self, name: str) -> tuple[int, int]:
        start_outer = time.monotonic_ns()
        before = time.time_ns()
        start_inner = time.monotonic_ns()
        output = self.ssh(name, "date +%s%N", timeout=10).stdout.strip()
        end_inner = time.monotonic_ns()
        after = time.time_ns()
        end_outer = time.monotonic_ns()
        if not start_outer <= start_inner <= end_inner <= end_outer:
            raise RuntimeError("lab host monotonic clock changed during guest clock measurement")
        lower_elapsed = end_inner - start_inner
        upper_elapsed = end_outer - start_outer
        realtime_elapsed = after - before
        # The paired monotonic reads bound sampling delay; allow a small slew.
        allowance = max(1_000_000, upper_elapsed // 1_000)
        if (realtime_elapsed < 0 or
                realtime_elapsed < lower_elapsed - allowance or
                realtime_elapsed > upper_elapsed + allowance):
            raise RuntimeError("lab host clock changed during guest clock measurement")
        guest = int(output)
        offset = guest - (before + after) // 2
        uncertainty = upper_elapsed // 2 + allowance
        self.guest_clock_upper_ns[name] = offset + uncertainty
        self.note("guest_clock", name=name, offset_ns=offset, uncertainty_ns=uncertainty)
        return offset, uncertainty

    def wait_synchronized_guest_clock(self, name: str) -> None:
        def synchronized() -> bool:
            result = self.ssh(name,
                              "systemctl is-active --quiet systemd-timesyncd.service && "
                              "test \"$(timedatectl show -p NTPSynchronized --value)\" = yes && "
                              "/usr/local/bin/ts-orch-clockprobe",
                              timeout=10, allow_failure=True)
            try:
                evidence = json.loads(result.stdout.strip())
            except ValueError:
                return False
            if result.returncode or evidence.get("healthy") is not True:
                return False
            self.note("guest_kernel_clock", name=name, **evidence)
            return True

        try:
            self.wait(f"ntp-clock-{name}", synchronized, timeout=180, period=2)
            offset, uncertainty = self.measure_guest_clock(name)
            if abs(offset) + uncertainty > CLOCK_BOUND_NS:
                raise RuntimeError(f"{name} NTP clock differs from lab host by over one second")
        except (RuntimeError, TimeoutError):
            try:
                self.capture_clock_diagnostics(name)
            except Exception as error:
                self.note("clock_diagnostics", guest=name, status="capture_failed",
                          error_type=type(error).__name__)
            raise

    def release_synchronized_guest_clock(self, name: str) -> None:
        guard = (f"test ! -e {CLOCK_READY} && "
                 'test "$(systemctl show -p MainPID --value ts-orch.service)" = 0')
        if self.ssh(name, guard, timeout=10, allow_failure=True).returncode:
            raise RuntimeError(f"{name} service began before NTP clock readiness")
        self.wait_synchronized_guest_clock(name)
        offset, uncertainty = self.measure_guest_clock(name)
        self.ssh(name, f"/usr/bin/install -m 0600 /dev/null {CLOCK_READY}", timeout=10)
        self.note("guest_clock_released", name=name, offset_ns=offset,
                  uncertainty_ns=uncertainty)

    def check_guest_clocks(self) -> None:
        for name in GUESTS:
            offset, uncertainty = self.measure_guest_clock(name)
            if abs(offset) + uncertainty > CLOCK_BOUND_NS:
                raise RuntimeError(f"{name} clock differs from lab host by over one second")

    def verify_broker_clock_gate(self) -> None:
        endpoint = f"tls://{self.addresses['c1']}:4222"
        command = [str(self.natsdiag), "--creds", str(self.secrets / "c1.creds"),
                   "--cell", CELL, "--urls", endpoint,
                   "--ca", str(self.secrets / "nats-ca.pem"),
                   "--cert", str(self.secrets / "nats-c1.pem"),
                   "--key", str(self.secrets / "nats-c1.key")]
        log_path = self.logs / "c1-clock-gate-session.jsonl"
        error_path = self.logs / "c1-clock-gate-session.stderr.log"
        with log_path.open("w") as output, error_path.open("w") as errors:
            self.session_probe_process = subprocess.Popen(
                [*command, "--session-probe", "hold"], stdout=output, stderr=errors, text=True)

        def state(expected: str) -> bool:
            records = [json.loads(line) for line in log_path.read_text().splitlines() if line]
            if any(record.get("state") == expected for record in records):
                return True
            if self.session_probe_process.poll() is not None:
                raise RuntimeError(f"pinned c1 session exited before {expected}; see {error_path}")
            return False

        self.wait("c1-authenticated-session", lambda: state("ready"), timeout=20, period=0.1)
        fault_started = time.monotonic()
        fault_deadline = fault_started + 20

        def remaining(cap: float) -> float:
            seconds = fault_deadline - time.monotonic()
            if seconds <= 0:
                raise TimeoutError("c1 session closure exceeded the 20-second fault budget")
            return min(cap, seconds)

        self.ssh("c1", "systemctl stop systemd-timesyncd.service && "
                 "date -u --set=\"$(date -u -d '+90 seconds' '+%Y-%m-%d %H:%M:%S')\" >/dev/null",
                 timeout=remaining(12))
        unhealthy = self.ssh("c1", "/usr/local/bin/ts-orch-clockprobe", timeout=remaining(10),
                             allow_failure=True)
        evidence = json.loads(unhealthy.stdout.strip())
        if unhealthy.returncode == 0 or evidence.get("healthy") is not False:
            raise RuntimeError("c1 clock jump did not make the production kernel predicate unhealthy")
        self.note("broker_clock_unhealthy", name="c1", **evidence)
        remaining(20)
        self.wait("c1-session-closed", lambda: state("closed"),
                  deadline=fault_deadline, period=0.1)
        elapsed = time.monotonic() - fault_started
        if elapsed > 20:
            raise RuntimeError(f"c1 session closure exceeded polling and ticket bound: {elapsed:.3f}s")
        refused = run([*command, "--session-probe", "once"], timeout=8, allow_failure=True)
        if refused.returncode == 0 or '"state":"ready"' in refused.stdout:
            raise RuntimeError("c1 broker admitted a new authenticated session while clock was unhealthy")
        self.note("broker_clock_fenced", name="c1", closure_elapsed_seconds=elapsed,
                  new_admission_exit_code=refused.returncode)
        self.ssh("c1", "systemctl start systemd-timesyncd.service", timeout=12)
        self.wait_synchronized_guest_clock("c1")
        self.wait("c1-readmitted-after-ntp", lambda: run(
            [*command, "--session-probe", "once"], timeout=8, allow_failure=True).returncode == 0,
            timeout=75, period=2)
        self.note("broker_clock_recovered", name="c1")

    def host_renewal_failure_evidence(self, since: datetime, session_hash: str,
                                      epoch: int, expiry: datetime) -> None:
        command = ("journalctl -u ts-orch.service --since " +
                   shlex.quote("@" + str(int(since.timestamp()))) +
                   " -n 500 -o json --no-pager")
        result = self.ssh("host", command, timeout=15, allow_failure=True)
        if result.returncode:
            raise RuntimeError("host renewal journal query failed")
        first_failure: str | None = None
        fence_completion: str | None = None
        fence_started: datetime | None = None
        fence_cause: str | None = None
        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
                message = entry.get("MESSAGE", "")
                instant = datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000,
                                                 timezone.utc).isoformat()
            except (ValueError, KeyError, TypeError):
                continue
            if "host session exchange deferred" in message and first_failure is None:
                first_failure = instant
            if "host session execution reserve exhausted" in message and fence_completion is None:
                fence_completion = instant
            try:
                fields = _default_slog_attributes(
                    message, "host session fenced", {"session_id_hash", "epoch", "expires_at"})
                if (fields is not None and fields.get("session_id_hash") == session_hash and
                        int(fields.get("epoch", "0")) == epoch and
                        datetime.fromisoformat(fields["expires_at"].replace("Z", "+00:00")) == expiry):
                    fence_started = datetime.fromisoformat(instant)
                    fence_cause = fields.get("cause_class")
            except (ValueError, KeyError, TypeError):
                continue
        self.note("host_renewal_failure_timing", first_failed_exchange_at=first_failure,
                  actual_fence_started_at=fence_started.isoformat() if fence_started else None,
                  fence_cause_class=fence_cause,
                  agent_failure_reported_at=fence_completion,
                  journal_clock="guest_realtime", since=since.isoformat())
        if first_failure is None:
            raise RuntimeError("host logged no failed session renewal after quorum loss")
        if fence_started is None:
            raise RuntimeError("host did not record a matching fence for the native workload")
        if fence_started > expiry - timedelta(seconds=SESSION_EXECUTION_RESERVE_SECONDS - 1.25):
            raise RuntimeError("host began fencing too late for its one-second reserve ticker")

    def verified_lease_events(self, since: datetime, *, timeout: float = 15) -> list[dict[str, Any]]:
        command = ("journalctl -u ts-orch.service --since " +
                   shlex.quote("@" + str(int(since.timestamp()))) +
                   " -n 500 -o json --no-pager")
        result = self.ssh("host", command, timeout=timeout)
        events = []
        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
                fields = _default_slog_attributes(
                    entry.get("MESSAGE", ""), "host session accepted",
                    {"phase", "session_id_hash", "epoch", "expires_at"})
                if fields is None:
                    continue
                at = datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000,
                                            timezone.utc)
                expiry = datetime.fromisoformat(fields["expires_at"].replace("Z", "+00:00"))
                session_hash = fields["session_id_hash"]
                epoch = int(fields["epoch"])
                if (at < since or expiry.tzinfo is None or epoch <= 0 or
                        len(session_hash) != 32 or any(c not in "0123456789abcdef" for c in session_hash)):
                    continue
                events.append({"at": at, "expires_at": expiry,
                               "session_id_hash": session_hash, "epoch": epoch,
                               "phase": fields.get("phase")})
            except (ValueError, KeyError, TypeError):
                continue
        return events

    def wait_same_process_renewal(self, first_session: dict[str, Any],
                                  first_native: dict[str, Any], connected: str,
                                  first_fault_at: datetime) -> None:
        deadline = time.monotonic() + 25

        def remaining(cap: float) -> float:
            return min(cap, max(0.0, deadline - time.monotonic()))

        def renewed_on_same_process() -> bool:
            timeout = remaining(5)
            if timeout <= 0:
                return False
            session = self.host_session("v1", timeout=timeout,
                                        stage="same-process-host-session-renewal")
            timeout = remaining(15)
            if timeout <= 0:
                return False
            observed = self.native_observation(timeout=timeout)
            same_agent = (observed["agent_pid"] == first_native["agent_pid"] and
                          observed["agent_state"].split(":")[-1] == first_native["agent_state"].split(":")[-1] and
                          observed["invocation"] == first_native["invocation"])
            same_workload = (observed["workload_pid"] == first_native["workload_pid"] and
                             observed["workload_state"].split(":")[-1] == first_native["workload_state"].split(":")[-1] and
                             observed["workload_alive"] and observed["marker"] == "v1")
            if session["session_id"] != first_session["session_id"] or not same_agent or not same_workload:
                raise RuntimeError("host agent, signed session or native workload restarted during 2/3 renewal")
            if session["expires_at"] <= first_session["expires_at"]:
                return False
            timeout = remaining(15)
            if timeout <= 0:
                return False
            session_hash = hashlib.sha256(session["session_id"].encode()).hexdigest()[:32]
            matching = [event for event in self.verified_lease_events(first_fault_at, timeout=timeout)
                        if event["phase"] == "renew" and event["session_id_hash"] == session_hash
                        and event["epoch"] == session["report"]["epoch"]
                        and event["expires_at"] == session["expires_at"]]
            if not matching or time.monotonic() >= deadline:
                return False
            self.note("host_session_renewed_on_surviving_quorum",
                      connected_controller=connected,
                      session_id_hash=session_hash,
                      signed_renewal_at=matching[-1]["at"].isoformat(),
                      previous_expiry=first_session["expires_at"].isoformat(),
                      renewed_expiry=session["expires_at"].isoformat(),
                      native=observed)
            return True

        try:
            self.wait("same-process-host-session-renewal", renewed_on_same_process,
                      deadline=deadline, period=0.5)
        except TimeoutError:
            try:
                events = self.verified_lease_events(first_fault_at, timeout=5)
                self.note("host_renewal_timeout_diagnostics", status="ok", renewals=[{
                    "accepted_at": event["at"].isoformat(),
                    "expires_at": event["expires_at"].isoformat(),
                    "session_id_hash": event["session_id_hash"],
                    "epoch": event["epoch"],
                } for event in events if event["phase"] == "renew"])
            except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as error:
                self.note("host_renewal_timeout_diagnostics", status="unavailable",
                          error_type=type(error).__name__)
            raise

    def connected_controller(self) -> str:
        output = self.ssh("host", "ss -Hnt state established", timeout=10).stdout
        connected = set()
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            local, local_separator, _ = fields[-2].rpartition(":")
            if not local_separator or local.strip("[]") != self.addresses["host"]:
                continue
            peer, separator, port = fields[-1].rpartition(":")
            if separator and port == "4222":
                connected.update(name for name in CONTROLLERS if self.addresses[name] == peer.strip("[]"))
        if len(connected) != 1:
            raise RuntimeError(f"expected one established host NATS controller socket, found {sorted(connected)}")
        return connected.pop()

    def blackhole_host_controller(self, controller: str) -> str:
        table = "tsfc" + secrets.token_hex(5)
        host_ip, controller_ip = self.addresses["host"], self.addresses[controller]
        self.sudo("nft", "add", "table", "bridge", table)
        self.created_nft_tables.append(table)
        self.sudo("nft", "add", "chain", "bridge", table, "forward",
                  "{", "type", "filter", "hook", "forward", "priority", "-300", ";",
                  "policy", "accept", ";", "}")
        for source, destination, port_kind in ((host_ip, controller_ip, "dport"),
                                               (controller_ip, host_ip, "sport")):
            self.sudo("nft", "add", "rule", "bridge", table, "forward", "ether", "type", "ip",
                      "ip", "saddr", source, "ip", "daddr", destination,
                      "tcp", port_kind, "4222", "drop")
        self.note("host_controller_blackhole", table=table, host_ip=host_ip,
                  controller=controller, controller_ip=controller_ip, port=4222)
        return table

    def remove_blackhole(self, table: str) -> None:
        self.sudo("nft", "delete", "table", "bridge", table)
        self.created_nft_tables.remove(table)
        self.note("host_controller_blackhole_removed", table=table)

    def fixture(self, version: str) -> Path:
        script = ("#!/bin/sh\nset -eu\nprintf '%s\\n' " + shlex.quote(version) +
                  " > /run/ts-orch-workload/marker\nprintf '%s\\n' \"$$\" > /run/ts-orch-workload/pid\n" +
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
            self.active_operation_id = submitted["operationId"]
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
        self.capture_host_status("early-pending")
        for name in CONTROLLERS:
            vm = self.vms.get(name)
            if vm is None or vm.process is None or child_exited_without_reaping(vm.process):
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
        if self.natsdiag.exists() and (self.secrets / "c1.creds").exists():
            urls = ",".join(f"tls://{self.addresses[name]}:4222" for name in CONTROLLERS)
            path = self.logs / "nats-live-diagnostics.jsonl"
            try:
                command = [str(self.natsdiag), "--creds", str(self.secrets / "c1.creds"),
                           "--operator-creds", str(self.secrets / "natsdiag.creds"),
                           "--cell", CELL, "--urls", urls,
                           "--ca", str(self.secrets / "nats-ca.pem"),
                           "--cert", str(self.secrets / "nats-c1.pem"),
                           "--key", str(self.secrets / "nats-c1.key"),
                           "--operator-cert", str(self.secrets / "nats-operator.pem"),
                           "--operator-key", str(self.secrets / "nats-operator.key")]
                if self.active_operation_id:
                    command.extend(("--operation-id", self.active_operation_id))
                result = run(command, timeout=35, allow_failure=True)
                path.write_text(result.stdout + result.stderr)
                path.chmod(0o600)
                self.note("cluster_diagnostics", name="nats", path=str(path),
                          exit_code=result.returncode)
            except Exception as error:
                path.write_text(f"NATS diagnostics unavailable: {error!r}\n")
                path.chmod(0o600)
                self.note("cluster_diagnostics", name="nats", path=str(path), error=repr(error))

    def capture_host_status(self, label: str) -> None:
        if label in self.host_status_diagnostics_captured:
            return
        self.host_status_diagnostics_captured.add(label)
        captured_at = datetime.now(timezone.utc)
        path = self.logs / f"host-status-{label}.json"
        snapshot: dict[str, Any] = {"captured_at": captured_at.isoformat(), "label": label}
        try:
            outcome = run([str(self.binary), "operator", "hosts", "--config",
                           str(self.operator_config)], timeout=10, allow_failure=True)
            if outcome.returncode:
                snapshot.update(status="operator_failed", exit_code=outcome.returncode)
            else:
                snapshot.update(status="ok", hosts=curated_host_statuses(
                    json.loads(outcome.stdout), captured_at))
        except subprocess.TimeoutExpired:
            snapshot["status"] = "timeout"
        except Exception as error:  # diagnostics must not fail the qualification
            snapshot.update(status="error", error_type=type(error).__name__)
        try:
            write_json(path, snapshot)
        except OSError as error:
            self.note("host_status_diagnostics", label=label, status="write_failed",
                      error_type=type(error).__name__)
            return
        self.note("host_status_diagnostics", label=label, path=str(path), status=snapshot["status"])

    def capture_clock_diagnostics(self, name: str) -> None:
        """Keep bounded guest, Chrony, and effective firewall evidence before cleanup."""
        captured = getattr(self, "clock_diagnostics_captured", set())
        if name in captured:
            return
        captured.add(name)
        self.clock_diagnostics_captured = captured
        path = self.logs / f"{name}-clock-diagnostics.json"
        snapshot: dict[str, Any] = {"captured_at": datetime.now(timezone.utc).isoformat(),
                                    "guest": name}

        def record(label: str, command: list[str] | None = None, *,
                   guest_command: str | None = None) -> None:
            try:
                result = (self.ssh(name, guest_command, timeout=12, allow_failure=True)
                          if guest_command is not None else
                          run(command or [], timeout=10, allow_failure=True))
                stdout = result.stdout or ""
                stderr = result.stderr or ""
                snapshot[label] = {"exit_code": result.returncode,
                                   "stdout": stdout[:NTP_DIAGNOSTIC_BYTES],
                                   "stderr": stderr[:2048],
                                   "truncated": len(stdout) > NTP_DIAGNOSTIC_BYTES or
                                   len(stderr) > 2048}
            except Exception as error:
                snapshot[label] = {"error_type": type(error).__name__,
                                   "error": str(error)[:512]}

        guest_command = """set +e
printf '\\n=== timesyncd status ===\\n'
systemctl status systemd-timesyncd.service --no-pager --full
printf '\\n=== timedatectl ===\\n'
timedatectl show -p NTPSynchronized -p NTP
timedatectl timesync-status --no-pager
printf '\\n=== timesyncd journal ===\\n'
journalctl -u systemd-timesyncd.service -b -n 80 --no-pager -o short-iso-precise
printf '\\n=== private NTP config and route ===\\n'
cat /etc/systemd/timesyncd.conf.d/ts-orch-fc.conf
ip -4 route show
printf '\\n=== kernel clock predicate ===\\n'
/usr/local/bin/ts-orch-clockprobe
"""
        record("guest_time", guest_command=guest_command)
        host_evidence = getattr(self, "clock_host_diagnostics", None)
        if host_evidence is None:
            snapshot["host_clock_captured_at"] = datetime.now(timezone.utc).isoformat()
            control_dir = getattr(self, "chrony_control_dir", None)
            if control_dir is not None:
                socket_path = str(control_dir / "chronyd.sock")
                for suffix in ("sources", "tracking", "clients"):
                    record(f"chrony_{suffix}",
                           ["sudo", "-n", str(CHRONYC), "-n", "-h", socket_path, suffix])
            try:
                snapshot["chrony_config"] = (self.stage / "chrony.conf").read_text()[:4096]
            except OSError as error:
                snapshot["chrony_config"] = {"error_type": type(error).__name__}
            record("chrony_listener", ["sudo", "-n", "ss", "-H", "-lun"])
            record("host_input_rules", ["sudo", "-n", "nft", "-j", "-a", "list", "chain",
                                        "ip", "filter", "INPUT"])
            record("host_nixos_firewall", ["sudo", "-n", "nft", "-j", "-a", "list", "chain",
                                           "ip", "filter", "nixos-fw"])
            snapshot["ntp_rule_comment"] = getattr(self, "ntp_rule_comment", None)
            snapshot["ntp_rule_handle"] = getattr(self, "ntp_rule_handle", None)
            host_evidence = {key: value for key, value in snapshot.items()
                             if key not in ("captured_at", "guest", "guest_time")}
            self.clock_host_diagnostics = host_evidence
        else:
            snapshot.update(host_evidence)
        try:
            write_json(path, snapshot)
            self.note("clock_diagnostics", guest=name, path=str(path))
        except OSError as error:
            self.note("clock_diagnostics", guest=name, status="write_failed",
                      error_type=type(error).__name__)

    def scenario(self) -> None:
        self.network()
        self.install_ntp_firewall_rule()
        self.start_chrony()
        for name in GUESTS:
            self.prepare_guest(name)
        for name in GUESTS:
            self.vms[name].boot()
        for name in GUESTS:
            self.wait_ssh(name)
        self.check_guest_clocks()
        self.wait_cluster()
        self.verify_broker_clock_gate()
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
        first_session = self.host_session("v1")
        first_native = self.native_observation()
        if (not first_native["workload_alive"] or first_native["marker"] != "v1" or
                not first_native["workload_cgroup"] or
                self.cgroup_empty(first_native["workload_cgroup"], first_native["service_cgroup"])):
            raise RuntimeError("native v1 workload is not running before controller loss")
        connected = self.connected_controller()
        fault_table = self.blackhole_host_controller(connected)
        if self.connected_controller() != connected:
            raise RuntimeError("host changed NATS peer before connected-controller crash")
        self.vms[connected].crash()
        first_fault_at = datetime.now(timezone.utc)
        self.wait_cluster()
        self.wait_same_process_renewal(first_session, first_native, connected, first_fault_at)
        self.deploy(replacement, 2, "one-node-loss")
        self.wait_host("v2")
        self.note("milestone", name="one-controller-nats-node-loss")
        self.remove_blackhole(fault_table)
        self.vms[connected].boot()
        self.wait_ssh(connected)
        self.wait_cluster()

        self.check_guest_clocks()
        rollback = self.intent(original, 3, "rollback")
        last_native = self.native_observation()
        if (not last_native["workload_alive"] or last_native["marker"] != "v2" or
                not last_native["workload_cgroup"] or
                self.cgroup_empty(last_native["workload_cgroup"], last_native["service_cgroup"])):
            raise RuntimeError("native v2 workload is not running before quorum loss")
        matching = []
        for attempt in range(3):
            connected = self.connected_controller()
            second = next(name for name in CONTROLLERS if name != connected)
            second_fault_table = self.blackhole_host_controller(connected)
            blackhole_at = datetime.now(timezone.utc)
            last_session = self.host_session("v2")
            recent_renewals = self.verified_lease_events(datetime.now(timezone.utc) - timedelta(seconds=8))
            session_hash = hashlib.sha256(last_session["session_id"].encode()).hexdigest()[:32]
            matching = [event for event in recent_renewals
                        if event["phase"] == "renew" and event["session_id_hash"] == session_hash
                        and event["epoch"] == last_session["report"]["epoch"]
                        and event["expires_at"] == last_session["expires_at"]]
            if matching and (matching[-1]["expires_at"] - datetime.now(timezone.utc)).total_seconds() < 15:
                matching = []
            if matching:
                try:
                    still_connected = self.connected_controller()
                except RuntimeError:
                    still_connected = None
                if still_connected != connected:
                    matching = []
            if matching:
                break
            self.remove_blackhole(second_fault_table)
            self.note("lease_capture_retry", attempt=attempt + 1,
                      reason="durable_expiry_not_equal_to_verified_renewal")
            time.sleep(1)
        if not matching:
            raise RuntimeError("latest durable host expiry lacks a matching verified signed renewal")
        signed_lease = matching[-1]
        before_crash = self.native_observation()
        if (not before_crash["workload_alive"] or before_crash["marker"] != "v2" or
                before_crash["agent_pid"] != last_native["agent_pid"] or
                before_crash["agent_state"].split(":")[-1] != last_native["agent_state"].split(":")[-1] or
                before_crash["workload_pid"] != last_native["workload_pid"] or
                before_crash["workload_state"].split(":")[-1] != last_native["workload_state"].split(":")[-1]):
            raise RuntimeError("host agent or native v2 workload changed during lease capture")
        self.vms[connected].crash()
        self.vms[second].crash()
        fault_at = datetime.now(timezone.utc)
        time.sleep(1)
        after_fault = [event for event in self.verified_lease_events(signed_lease["at"])
                       if event["session_id_hash"] == session_hash and
                       event["epoch"] == signed_lease["epoch"]]
        if after_fault:
            signed_lease = max(after_fault, key=lambda event: event["expires_at"])
        clock_allowance_ns = max(0, self.guest_clock_upper_ns["host"]) + 250_000_000
        stop_deadline = signed_lease["expires_at"] - timedelta(
            microseconds=math.ceil(clock_allowance_ns / 1000))
        self.note("quorum_loss", crashed=[connected, second],
                  blackhole_table=second_fault_table,
                  session_id_hash=session_hash,
                  signed_renewal_at=signed_lease["at"].isoformat(),
                  signed_expiry=signed_lease["expires_at"].isoformat(),
                  conservative_stop_deadline=stop_deadline.isoformat(),
                  host_clock_upper_ns=self.guest_clock_upper_ns["host"],
                  expected_fence_at=(signed_lease["expires_at"] -
                                     timedelta(seconds=SESSION_EXECUTION_RESERVE_SECONDS)).isoformat(),
                  blackhole_at=blackhole_at.isoformat(), fault_at=fault_at.isoformat(), native=last_native)
        stop_observation = None
        while datetime.now(timezone.utc) < stop_deadline:
            observed = self.native_observation()
            if (not observed["workload_alive"] and
                    self.cgroup_empty(last_native["workload_cgroup"], last_native["service_cgroup"])):
                stop_observation = observed
                break
            time.sleep(0.25)
        if stop_observation is None:
            raise RuntimeError("native v2 workload survived the conservative signed-session stop deadline")
        stopped_at = datetime.now(timezone.utc)
        if stopped_at >= stop_deadline:
            raise RuntimeError("native v2 workload stopped after the conservative signed-session deadline")
        self.note("native_stopped_on_quorum_loss", stopped_at=stopped_at.isoformat(),
                  seconds_before_expiry=(signed_lease["expires_at"] - stopped_at).total_seconds(),
                  execution_reserve_seconds=SESSION_EXECUTION_RESERVE_SECONDS,
                  original_cgroup_empty=True, native=stop_observation)
        self.host_renewal_failure_evidence(blackhole_at, session_hash,
                                           signed_lease["epoch"], signed_lease["expires_at"])
        denied = self.operator("rollback", "--intent", str(rollback),
                               timeout=25, allow_failure=True)
        if denied is not None:
            raise RuntimeError("rollback submitted without JetStream quorum")
        time.sleep(2)
        stopped_again = self.native_observation()
        if (stopped_again["workload_alive"] or
                not self.cgroup_empty(last_native["workload_cgroup"], last_native["service_cgroup"])):
            raise RuntimeError("native v2 workload resumed before quorum restoration")
        self.note("milestone", name="quorum-loss-rejected-new-intent")
        self.vms[connected].boot()
        self.wait_ssh(connected)
        self.wait_cluster()
        self.deploy(original, 3, "rollback", operation="rollback")
        self.wait_host("v1")
        self.vms[second].boot()
        self.wait_ssh(second)
        self.note("milestone", name="rollback-after-quorum-recovery")

    def capture_failure_diagnostics(self) -> None:
        if self.failure_diagnostics_captured:
            return
        self.capture_host_status("failure")
        host_vm = self.vms.get("host")
        if (host_vm is None or host_vm.process is None or
                child_exited_without_reaping(host_vm.process)):
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
service_cgroup=$(systemctl show ts-orch.service -p ControlGroup --value)
for root in /sys/fs/cgroup"$service_cgroup"/terrascale-host-*; do
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
ls -l /run/ts-orch-workload/
for item in /run/ts-orch-workload/marker /run/ts-orch-workload/pid; do
    if [ -f "$item" ]; then printf '%s: ' "$item"; cat "$item"; fi
done
marker_pid=$(cat /run/ts-orch-workload/pid 2>/dev/null)
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
find /var/lib/ts-orch-install -type f -print -exec stat -c '%a %u:%g %s %n' {} \; -exec sha256sum {} \;
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

    def cleanup(self, *, preserve_images: bool = False) -> list[str]:
        errors: list[str] = []
        images_safe = True
        if getattr(self, "session_probe_process", None) is not None:
            process = self.session_probe_process
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            self.session_probe_process = None
        try:
            self.remove_ntp_firewall_rule()
        except Exception as error:
            errors.append(f"remove owned private NTP firewall rule: {error}")
        for table in reversed(self.created_nft_tables.copy()):
            try:
                result = self.sudo("nft", "delete", "table", "bridge", table, allow_failure=True)
                if result.returncode:
                    errors.append(f"delete owned nft table {table}: {result.stderr.strip()}")
                else:
                    self.created_nft_tables.remove(table)
            except Exception as error:
                errors.append(f"delete owned nft table {table}: {error}")
        for vm in reversed(list(self.vms.values())):
            try:
                vm.stop()
            except Exception as error:  # cleanup must continue for all owned resources
                images_safe = False
                errors.append(f"stop {vm.name}: {error}")
        if getattr(self, "socket_dir", None) is not None:
            errors.extend(cleanup_owned_sockets(self.vms, self.socket_dir))
        for mount in reversed(self.mounted):
            try:
                result = self.sudo("umount", str(mount), allow_failure=True)
                if result.returncode:
                    errors.append(f"unmount {mount}: {result.stderr.strip()}")
                else:
                    self.mounted.remove(mount)
            except Exception as error:
                errors.append(f"unmount {mount}: {error}")
        if getattr(self, "chrony_process", None) is not None:
            process = self.chrony_process
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            self.note("chrony_stop", pid=process.pid, exit_code=process.returncode)
            self.chrony_process = None
        if getattr(self, "chrony_control_dir", None) is not None:
            directory = self.chrony_control_dir
            try:
                removed = self.sudo("rm", "-f", "--", str(directory / "chronyd.sock"),
                                    allow_failure=True)
                if removed.returncode:
                    errors.append(f"remove owned Chrony socket {directory}: {removed.stderr.strip()}")
                else:
                    removed = self.sudo("rmdir", "--", str(directory), allow_failure=True)
                    if removed.returncode:
                        errors.append(f"remove owned Chrony directory {directory}: {removed.stderr.strip()}")
                    else:
                        self.chrony_control_dir = None
            except Exception as error:
                errors.append(f"remove owned Chrony control directory {directory}: {error}")
        for link in reversed(self.created_links):
            try:
                result = self.sudo("ip", "link", "del", link, allow_failure=True)
                if result.returncode:
                    errors.append(f"delete link {link}: {result.stderr.strip()}")
            except Exception as error:
                errors.append(f"delete link {link}: {error}")
        if preserve_images or errors:
            reason = "qualification_failed" if preserve_images else "cleanup_failed"
            self.note("guest_images_retained", path=str(self.images), reason=reason)
        elif images_safe and not self.mounted:
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
    for command in ("go", "git", "ssh", "ssh-keygen", "cp", "ip", "nft", "openssl",
                    "sudo", "mount", "umount", "e2fsck", "resize2fs", "ss"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required command missing: {command}")
    if not Path(args.firecracker).is_file():
        raise RuntimeError(f"Firecracker executable missing: {args.firecracker}")
    if (not CHRONYD.is_file() or digest(CHRONYD) != CHRONYD_SHA or
            not CHRONYC.is_file() or digest(CHRONYC) != CHRONYC_SHA):
        raise RuntimeError("pinned Chrony 4.8 binaries are unavailable or changed")
    if not Path("/dev/kvm").exists() or not Path("/dev/net/tun").exists():
        raise RuntimeError("Firecracker requires /dev/kvm and /dev/net/tun")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
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
        if source_digest() != lab.go_source_sha256 or lab.harness_digest() != lab.harness_sha256:
            raise RuntimeError("source changed during qualification; run cannot certify a moving tree")
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
        cleanup_errors = lab.cleanup(preserve_images=outcome != "PASS")
        summary = {"result": outcome if not cleanup_errors else "CLEANUP_FAILED",
                   "failure": failure, "cleanup_errors": cleanup_errors,
                   "revision": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
                   "go_source_sha256": lab.go_source_sha256,
                   "harness_sha256": lab.harness_sha256,
                   "final_go_source_sha256": source_digest(),
                   "final_harness_sha256": lab.harness_digest(),
                   "binary_sha256": digest(lab.binary) if lab.binary.exists() else None,
                   "events": lab.events}
        write_json(lab.root / "summary.json", summary)
        print(f"evidence: {lab.root / 'summary.json'}", flush=True)
    return 0 if outcome == "PASS" and not cleanup_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
