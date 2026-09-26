#!/usr/bin/env python3
"""Two-VM managed member launch and signed-v2 HTTPS qualification.

This driver consumes an immutable, separately generated fixture. It does not
generate an authority signer, build binaries, or mutate source inputs.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
import uuid


REPO = Path(__file__).resolve().parents[3]
PROFILE = "managed-member-serving-v1"
GO_TEST = "TestManagedMemberFirecrackerSignedServing"
COMMON_INPUTS = {"kernel", "rootfs", "firecracker", "go_host_test", "tb_server"}
MEMBER_INPUTS = {
    "volume_ext4", "authority_tbca", "trusted_public_key", "server_crt",
    "server_key", "client_ca_pem", "server_ca_pem", "client_managed_manifest",
    "client_config", "client_chain", "client_private_key", "client_api_keys",
    "client_api_token", "client_https_ca_pem",
}
MATERIAL = {
    "authority_tbca": "authority.tbca",
    "trusted_public_key": "trusted-public-key",
    "server_crt": "server.crt",
    "server_key": "server.key",
    "client_ca_pem": "client-ca.pem",
    "server_ca_pem": "server-ca.pem",
    "client_managed_manifest": "client-managed-manifest.json",
    "client_config": "client-config.json",
    "client_chain": "client-chain.pem",
    "client_private_key": "client-private-key.pem",
    "client_api_keys": "client-api-keys.json",
}
SUBNET = ipaddress.ip_network("10.77.39.0/24")
HOST_IP = "10.77.39.1"
GUEST_IPS = {"a": "10.77.39.11", "b": "10.77.39.12"}
GUEST_MACS = {"a": "02:fc:77:39:00:01", "b": "02:fc:77:39:00:02"}
VOLUME_UUIDS = {
    "a": "76f1b43d-7d79-4f41-9a6e-cc1f4aaab102",
    "b": "76f1b43d-7d79-4f41-9a6e-cc1f4aaab103",
}
MEMBER_IDS = {
    "a": "018f0000-0000-7000-8000-000000000001",
    "b": "018f0000-0000-7000-8000-000000000002",
}
MEMBER_DIRS = {
    "a": Path("/srv/ts-managed/6efe9447512debbf02bcd921c78d666c"),
    "b": Path("/srv/ts-managed/948d999055329358cc417bcc96edb470"),
}
CONTROL_PORT = 9540
REPLICATION_PORT = 7000
VOLUME_BYTES = 256 << 20
RAM_MIB = 9216
SERVICE_SECONDS = 480
VM_SECONDS = 540
LOG_BOUND = 32 << 20
EVIDENCE_BOUND = 64 << 10
BOOT_ARGS = "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw systemd.unit=multi-user.target"
RESULT_PREFIX = "TS_MANAGED_MEMBER_QUALIFICATION_RESULT="
RESULT_FAIL = re.compile(r"^TS_MANAGED_MEMBER_QUALIFICATION_RESULT=FAILED status=([1-9][0-9]{0,2})$")
TEST_PHASE_PASS = re.compile(r"^TS_MANAGED_MEMBER_PHASE=PASS node=node-[ab]$")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40,64}\Z")
_FIRECRACKER_ID = re.compile(r"[A-Za-z0-9_]+\Z")


class QualificationError(RuntimeError):
    pass


def firecracker_drive_request(identifier: str, path: Path, root: bool) -> tuple[str, dict[str, Any]]:
    if not _FIRECRACKER_ID.fullmatch(identifier):
        raise QualificationError(f"invalid Firecracker drive resource ID: {identifier}")
    return f"/drives/{identifier}", {"drive_id": identifier, "path_on_host": str(path),
                                      "is_root_device": root, "is_read_only": False}


def firecracker_network_request(identifier: str, tap: str, mac: str) -> tuple[str, dict[str, Any]]:
    if not _FIRECRACKER_ID.fullmatch(identifier):
        raise QualificationError(f"invalid Firecracker network resource ID: {identifier}")
    return f"/network-interfaces/{identifier}", {"iface_id": identifier,
                                                   "host_dev_name": tap, "guest_mac": mac}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    before_path = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before_path.st_dev, before_path.st_ino) != (opened.st_dev, opened.st_ino):
            raise QualificationError(f"file changed type or inode before hashing: {path}")
        for chunk in iter(lambda: stream.read(4 << 20), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    after_path = path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(opened) != identity(after) or identity(after) != identity(after_path):
        raise QualificationError(f"file changed while hashing: {path}")
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_input(name: str, record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise QualificationError(f"{name}: input must have exactly path and sha256")
    supplied = record["path"]
    digest = record["sha256"]
    if not isinstance(supplied, str) or not Path(supplied).is_absolute() or not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise QualificationError(f"{name}: invalid absolute path or lowercase SHA-256")
    path = Path(supplied)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise QualificationError(f"{name}: input is not a regular, direct file")
    actual = sha256_file(path)
    if actual != digest:
        raise QualificationError(f"{name}: input SHA-256 mismatch: {path}")
    return {"path": path, "sha256": digest, "size": info.st_size}


def canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.int != 0 and str(parsed) == value


def member_directory(scope: dict[str, Any], host_attempt: int) -> Path:
    identity = (f"{scope['cluster_id']}/{scope['tenant_id']}/{scope['database_id']}/"
                f"{scope['shard_id']}/{scope['member_id']}/{scope['incarnation']}/{host_attempt}")
    return Path("/srv/ts-managed") / hashlib.sha256(identity.encode("ascii")).hexdigest()[:32]


def _valid_config(member: str, config: Any, inputs: dict[str, dict[str, Any]]) -> None:
    required = {
        "version", "node", "failure_domain", "member", "authority", "runtime",
        "volume_id", "attachment_id", "attachment_etag", "source_digest",
        "collection_id", "schema_generation", "schema_digest", "document_id",
    }
    if not isinstance(config, dict) or set(config) != required:
        raise QualificationError(f"{member}: guest_config has unexpected or missing fields")
    if config["version"] != 1 or config["node"] != "node-" + member or config["failure_domain"] != ("FAULT-DOMAIN-1" if member == "a" else "FAULT-DOMAIN-2"):
        raise QualificationError(f"{member}: node or failure-domain mismatch")
    binding = config["member"]
    if (not isinstance(binding, dict) or set(binding) != {"scope", "host_attempt"} or
            type(binding["host_attempt"]) is not int or binding["host_attempt"] != 1):
        raise QualificationError(f"{member}: member binding is malformed")
    scope = binding["scope"]
    if (not isinstance(scope, dict) or
            set(scope) != {"cluster_id", "tenant_id", "database_id", "shard_id", "member_id", "incarnation"} or
            not isinstance(scope["cluster_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", scope["cluster_id"]) or
            not canonical_uuid(scope["tenant_id"]) or not canonical_uuid(scope["database_id"]) or
            not canonical_uuid(scope["member_id"]) or scope["member_id"] != MEMBER_IDS[member] or
            type(scope["shard_id"]) is not int or not 0 < scope["shard_id"] <= (1 << 64) - 1 or
            not isinstance(scope["incarnation"], str) or
            not re.fullmatch(r"[0-9a-f]{32}", scope["incarnation"])):
        raise QualificationError(f"{member}: member scope is malformed")
    if scope["incarnation"] != ("bb" if member == "a" else "cc") * 16:
        raise QualificationError(f"{member}: member incarnation mismatch")
    if member_directory(scope, binding["host_attempt"]) != MEMBER_DIRS[member]:
        raise QualificationError(f"{member}: member scope derives an unexpected runtime directory")
    authority = config["authority"]
    if not isinstance(authority, dict) or set(authority) != {"epoch", "configuration_id", "certificate_sha256", "tls_leaf_sha256"} or authority["epoch"] != 1 or authority["certificate_sha256"] != inputs["authority_tbca"]["sha256"]:
        raise QualificationError(f"{member}: signed authority hash mismatch")
    for key in ("configuration_id", "tls_leaf_sha256"):
        if not isinstance(authority[key], str) or not _SHA.fullmatch(authority[key]):
            raise QualificationError(f"{member}: invalid authority {key}")
    runtime = config["runtime"]
    runtime_keys = {
        "device_path", "mount_path", "filesystem_uuid", "filesystem_type",
        "trusted_key_sha256", "server_certificate_sha256", "server_private_key_sha256",
        "client_ca_roots_sha256", "client_managed_material_manifest_sha256",
        "replication_listen_address", "replication_peer_member_id",
        "replication_peer_address", "replication_server_ca_sha256",
    }
    if not isinstance(runtime, dict) or set(runtime) != runtime_keys:
        raise QualificationError(f"{member}: runtime pins are malformed")
    other = "b" if member == "a" else "a"
    expected = {
        "device_path": "/dev/oracleoci/oraclevdb",
        "mount_path": str(MEMBER_DIRS[member] / "volume"),
        "filesystem_uuid": VOLUME_UUIDS[member],
        "filesystem_type": "ext4",
        "trusted_key_sha256": inputs["trusted_public_key"]["sha256"],
        "server_certificate_sha256": inputs["server_crt"]["sha256"],
        "server_private_key_sha256": inputs["server_key"]["sha256"],
        "client_ca_roots_sha256": inputs["client_ca_pem"]["sha256"],
        "client_managed_material_manifest_sha256": inputs["client_managed_manifest"]["sha256"],
        "replication_listen_address": f"{GUEST_IPS[member]}:{REPLICATION_PORT}",
        "replication_peer_member_id": MEMBER_IDS[other],
        "replication_peer_address": f"{GUEST_IPS[other]}:{REPLICATION_PORT}",
        "replication_server_ca_sha256": inputs["server_ca_pem"]["sha256"],
    }
    if runtime != expected:
        raise QualificationError(f"{member}: runtime pins differ from immutable inputs or peer layout")
    if config["volume_id"] != f"ocid1.volume.fixture-{member}" or config["attachment_id"] != f"ocid1.volumeattachment.fixture-{member}" or config["attachment_etag"] != f"fixture-attachment-{member}":
        raise QualificationError(f"{member}: fixture volume/attachment identity mismatch")
    if not isinstance(config["source_digest"], str) or not _SHA.fullmatch(config["source_digest"]):
        raise QualificationError(f"{member}: source digest invalid")
    if config["collection_id"] != "21212121-2121-2121-2121-212121212121" or config["document_id"] != "018f0000-0000-7000-8000-000000000021" or config["schema_generation"] != 1 or not isinstance(config["schema_digest"], str) or not _SHA.fullmatch(config["schema_digest"]):
        raise QualificationError(f"{member}: active document binding mismatch")


def load_manifest(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > 64 << 10:
        raise QualificationError("manifest exceeds 64 KiB")
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or set(manifest) != {"profile", "source_commits", "inputs", "members"} or manifest["profile"] != PROFILE:
        raise QualificationError("unsupported or malformed qualification manifest")
    commits = manifest["source_commits"]
    if not isinstance(commits, dict) or set(commits) != {"orchestrator", "terrabase"} or any(not isinstance(value, str) or not _COMMIT.fullmatch(value) for value in commits.values()):
        raise QualificationError("source commits must be full hexadecimal IDs")
    common = manifest["inputs"]
    members = manifest["members"]
    if not isinstance(common, dict) or set(common) != COMMON_INPUTS or not isinstance(members, dict) or set(members) != {"a", "b"}:
        raise QualificationError("manifest has missing or extra common/member inputs")
    verified = {name: exact_input(name, record) for name, record in common.items()}
    for name in ("firecracker", "go_host_test", "tb_server"):
        if not os.access(verified[name]["path"], os.X_OK):
            raise QualificationError(f"{name}: input must be executable")
    parsed_members: dict[str, Any] = {}
    for member, record in members.items():
        if not isinstance(record, dict) or set(record) != {"inputs", "guest_config"} or not isinstance(record["inputs"], dict) or set(record["inputs"]) != MEMBER_INPUTS:
            raise QualificationError(f"{member}: input names are incomplete")
        inputs = {name: exact_input(f"{member}.{name}", value) for name, value in record["inputs"].items()}
        if inputs["volume_ext4"]["size"] != VOLUME_BYTES:
            raise QualificationError(f"{member}: volume image must be exactly 256 MiB")
        _valid_config(member, record["guest_config"], inputs)
        parsed_members[member] = {"inputs": inputs, "guest_config": record["guest_config"]}
    left, right = parsed_members["a"]["guest_config"], parsed_members["b"]["guest_config"]
    for field in ("cluster_id", "tenant_id", "database_id", "shard_id"):
        if left["member"]["scope"][field] != right["member"]["scope"][field]:
            raise QualificationError("members are not in one signed shard")
    for field in ("epoch", "configuration_id", "certificate_sha256"):
        if left["authority"][field] != right["authority"][field]:
            raise QualificationError("members disagree on signed authority")
    for field in ("source_digest", "collection_id", "schema_generation", "schema_digest", "document_id"):
        if left[field] != right[field]:
            raise QualificationError("members disagree on transaction fixture")
    return {"raw": raw, "sha256": sha256_bytes(raw), "source_commits": commits,
            "inputs": verified, "members": parsed_members}


def check_subnet_collision() -> None:
    result = subprocess.run(["ip", "-j", "route", "show", "table", "all"], capture_output=True, text=True, timeout=10, check=True)
    for route in json.loads(result.stdout):
        destination = route.get("dst")
        if not destination or destination == "default":
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.version == 4 and network.overlaps(SUBNET):
            raise QualificationError(f"fixture subnet collides with host route {destination}")
    result = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=10, check=True)
    for interface in json.loads(result.stdout):
        for address in interface.get("addr_info", []):
            if address.get("family") != "inet":
                continue
            network = ipaddress.ip_network(f"{address['local']}/{address['prefixlen']}", strict=False)
            if network.overlaps(SUBNET):
                raise QualificationError(f"fixture subnet collides with host address {network}")


def prerequisites() -> None:
    required = ("sudo", "ip", "mount", "umount", "install", "ln", "cp", "e2fsck", "resize2fs", "blkid", "sha256sum", "stat")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise QualificationError(f"host commands missing: {missing}")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/dev/net/tun").exists():
        raise QualificationError("Firecracker requires /dev/kvm and /dev/net/tun")
    check_subnet_collision()


class CommandLog:
    def __init__(self, root: Path):
        self.root = root
        self.number = 0

    def run(self, label: str, argv: list[str], *, sudo: bool = False,
            timeout: int = 120, allowed: tuple[int, ...] = (0,)) -> str:
        self.number += 1
        path = self.root / f"{self.number:03d}-{label}.log"
        command = (["sudo", "-n"] if sudo else []) + argv
        with path.open("wb") as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                status = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                raise QualificationError(f"{label}: timed out; see {path}") from error
        if path.stat().st_size > LOG_BOUND:
            raise QualificationError(f"{label}: command log exceeded {LOG_BOUND} bytes")
        content = path.read_text(errors="replace")
        if status not in allowed:
            raise QualificationError(f"{label}: exit {status}; see {path}: {content[-1500:]}")
        return content


def guest_path(mount: Path, destination: Path) -> Path:
    if not destination.is_absolute() or ".." in destination.parts:
        raise QualificationError(f"unsafe guest path {destination}")
    current = mount
    for part in destination.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise QualificationError(f"guest path traverses symlink {current}")
    return current


def check_guest_tools(mount: Path) -> None:
    required = (Path("/usr/lib/systemd/systemd"), Path("/usr/sbin/blkid"),
                *(Path("/usr/bin") / command for command in
                  ("mount", "findmnt", "mountpoint", "readlink", "systemctl", "ip")))
    for destination in required:
        if not guest_path(mount, destination).is_file():
            raise QualificationError(f"guest rootfs lacks {destination}")


def managed_directories(member: str) -> tuple[tuple[Path, int], ...]:
    member_dir = MEMBER_DIRS[member]
    return ((Path("/srv/ts-managed"), 0o750), (member_dir, 0o750),
            (member_dir / "material", 0o750), (member_dir / "control", 0o730),
            (member_dir / "volume", 0o750))


def volume_setup_script(member: str) -> str:
    mount = MEMBER_DIRS[member] / "volume"
    uuid = VOLUME_UUIDS[member]
    material = MEMBER_DIRS[member] / "material"
    return f"""#!/bin/sh
set -eu
DEVICE=/dev/vdb
ALIAS=/dev/oracleoci/oraclevdb
MOUNT={mount}
UUID={uuid}
attempt=0
while [ "$attempt" -lt 120 ]; do
  if [ -b "$DEVICE" ] && [ -e "/dev/disk/by-uuid/$UUID" ] &&
     [ "$(readlink -f "/dev/disk/by-uuid/$UUID")" = "$DEVICE" ]; then break; fi
  attempt=$((attempt + 1)); sleep 0.5
done
[ "$attempt" -lt 120 ] || exit 1
[ "$(/usr/sbin/blkid -s UUID -o value "$DEVICE")" = "$UUID" ] || exit 1
for directory in /srv/ts-managed {MEMBER_DIRS[member]} {material} {MEMBER_DIRS[member] / 'control'} "$MOUNT"; do
  [ ! -L "$directory" ] && [ -d "$directory" ] || exit 1
done
[ ! -e /dev/oracleoci ] || [ -d /dev/oracleoci ] || exit 1
mkdir -p /dev/oracleoci
[ ! -e "$ALIAS" ] && [ ! -L "$ALIAS" ] || exit 1
ln -s ../vdb "$ALIAS"
if findmnt -rn -S "$DEVICE" >/dev/null 2>&1 || mountpoint -q "$MOUNT"; then exit 1; fi
mount -t ext4 -o rw "$ALIAS" "$MOUNT"
[ "$(findmnt -n -o TARGET --source "$DEVICE")" = "$MOUNT" ] || exit 1
[ "$(findmnt -n -o FSTYPE --target "$MOUNT")" = ext4 ] || exit 1
chown 0:65534 "$MOUNT"; chmod 0750 "$MOUNT"
[ ! -e "$MOUNT/.terrascale-member-claim" ] || exit 1
mkdir -m 0700 "$MOUNT/data" "$MOUNT/replication"
chown 65534:65534 "$MOUNT/data" "$MOUNT/replication"
"""


def runner_script(member: str) -> str:
    node = "node-" + member
    return f"""#!/bin/sh
set -u
LOG=/var/log/ts-managed-member/go-host-test.log
mkdir -p /var/log/ts-managed-member
attempt=0
while [ "$attempt" -lt 120 ]; do
  if ip -4 -o addr show | grep -Fq '{GUEST_IPS[member]}/24'; then break; fi
  attempt=$((attempt + 1)); sleep 0.5
done
if [ "$attempt" -ge 120 ]; then
  echo '{RESULT_PREFIX}FAILED status=90'
  systemctl --no-block reboot || true
  exit 90
fi
TS_FC_MANAGED_MEMBER_CONFIG=/etc/ts-managed-member/guest-config.json \\
  /opt/ts-managed-member/host.test -test.run='^{GO_TEST}$' -test.v -test.timeout={SERVICE_SECONDS}s > "$LOG" 2>&1
status=$?
cat "$LOG"
if [ "$status" -eq 0 ]; then
  echo '{RESULT_PREFIX}PASS node={node}'
else
  echo '{RESULT_PREFIX}FAILED status='"$status"
fi
sync
systemctl --no-block reboot || true
exit "$status"
"""


def setup_unit() -> str:
    return """[Unit]
Description=Prepare pinned managed member volume
After=local-fs.target
Before=ts-managed-member-test.service

[Service]
Type=oneshot
User=root
TimeoutStartSec=90s
ExecStart=/usr/local/sbin/ts-managed-member-volume-setup
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""


def test_unit() -> str:
    return """[Unit]
Description=Two-VM managed member qualification
After=network-online.target ts-managed-member-volume-setup.service
Requires=ts-managed-member-volume-setup.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
Delegate=yes
DelegateSubgroup=supervisor
MemoryMax=8G
NoNewPrivileges=yes
AmbientCapabilities=
CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_READ_SEARCH
TimeoutStartSec=510s
KillMode=control-group
StandardOutput=journal+console
StandardError=journal+console
ExecStart=/usr/local/sbin/ts-managed-member-runner

[Install]
WantedBy=multi-user.target
"""


class BoundedCapture:
    def __init__(self, source: Any, destination: Path):
        self.source = source
        self.destination = destination
        self.total = 0
        self.truncated = False
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _pump(self) -> None:
        with self.destination.open("wb") as target:
            while chunk := self.source.read(64 << 10):
                self.total += len(chunk)
                remaining = max(0, LOG_BOUND - target.tell())
                if remaining:
                    target.write(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True

    def finish(self) -> None:
        self.thread.join(timeout=10)
        if self.thread.is_alive() or self.truncated:
            raise QualificationError(f"VM output truncated or not drained: {self.destination}")


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: Path):
        super().__init__("localhost", timeout=5)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(str(self.path))


class VM:
    def __init__(self, lab: "Lab", member: str):
        self.lab = lab
        self.member = member
        self.socket = lab.socket_dir / f"{member}.sock"
        self.process: subprocess.Popen[bytes] | None = None
        self.serial: BoundedCapture | None = None
        self.vmm: BoundedCapture | None = None
        self.stopped = False

    def api(self, method: str, endpoint: str, payload: dict[str, Any] | None = None) -> None:
        connection = UnixHTTP(self.socket)
        try:
            body = None if payload is None else json.dumps(payload)
            connection.request(method, endpoint, body=body,
                               headers={"Content-Type": "application/json"} if body else {})
            response = connection.getresponse()
            detail = response.read(1 << 20).decode(errors="replace")
            if response.status not in (200, 204):
                raise QualificationError(f"Firecracker {self.member} {endpoint}: HTTP {response.status}: {detail}")
        finally:
            connection.close()

    def resource_requests(self) -> tuple[tuple[str, dict[str, Any]], ...]:
        return (
            firecracker_drive_request("rootfs", self.lab.images / f"{self.member}-rootfs.ext4", True),
            firecracker_drive_request("managed_volume", self.lab.images / f"{self.member}-volume.ext4", False),
            firecracker_network_request("eth0", self.lab.taps[self.member], GUEST_MACS[self.member]),
        )

    def start(self) -> None:
        if len(os.fsencode(self.socket)) >= 100:
            raise QualificationError("Firecracker API socket path is too long")
        resource_requests = self.resource_requests()
        command = [str(self.lab.manifest["inputs"]["firecracker"]["path"]),
                   "--api-sock", str(self.socket), "--log-path", "/dev/stderr"]
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True, bufsize=0)
        assert self.process.stdout is not None and self.process.stderr is not None
        self.serial = BoundedCapture(self.process.stdout, self.lab.logs / f"{self.member}-serial.log")
        self.vmm = BoundedCapture(self.process.stderr, self.lab.logs / f"{self.member}-vmm.log")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise QualificationError(f"Firecracker {self.member} exited before API socket")
            if self.socket.exists():
                try:
                    self.api("GET", "/version")
                    break
                except (OSError, http.client.HTTPException):
                    pass
            time.sleep(0.1)
        else:
            raise QualificationError(f"Firecracker {self.member} API socket timeout")
        self.api("PUT", "/machine-config", {"vcpu_count": 2, "mem_size_mib": RAM_MIB, "smt": False})
        self.api("PUT", "/boot-source", {"kernel_image_path": str(self.lab.manifest["inputs"]["kernel"]["path"]),
                                          "boot_args": BOOT_ARGS})
        for route, body in resource_requests:
            self.api("PUT", route, body)
        self.api("PUT", "/actions", {"action_type": "InstanceStart"})
        self.lab.note("vm_started", member=self.member, pid=self.process.pid)

    def natural_exit(self) -> None:
        if self.process is None:
            raise QualificationError("VM was not started")
        try:
            status = self.process.wait(timeout=VM_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise QualificationError(f"VM {self.member} did not exit naturally") from error
        self.stopped = True
        assert self.serial is not None and self.vmm is not None
        self.serial.finish()
        self.vmm.finish()
        if status != 0:
            raise QualificationError(f"VM {self.member} exit {status}")
        self.lab.note("vm_natural_exit", member=self.member, status=status)

    def stop(self) -> list[str]:
        errors: list[str] = []
        if self.process is None:
            return errors
        if self.process.poll() is None:
            try:
                self.api("PUT", "/actions", {"action_type": "SendCtrlAltDel"})
                self.process.wait(timeout=15)
            except Exception:
                pass
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=5)
            except Exception:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        self.stopped = self.process.poll() is not None
        if not self.stopped:
            errors.append(f"VM {self.member} process group not confirmed stopped")
        for capture in (self.serial, self.vmm):
            if capture is not None:
                try:
                    capture.finish()
                except Exception as error:
                    errors.append(str(error))
        return errors


class Lab:
    def __init__(self, manifest: dict[str, Any], run_dir: Path):
        self.manifest = manifest
        self.root = run_dir
        self.logs = run_dir / "logs"
        self.commands = run_dir / "commands"
        self.images = run_dir / "images"
        self.mounts = run_dir / "mounts"
        self.stage = run_dir / "stage"
        self.socket_dir: Path | None = None
        suffix = secrets.token_hex(3)
        self.bridge = "tsm" + suffix + "b"
        self.taps = {"a": "tsm" + suffix + "1", "b": "tsm" + suffix + "2"}
        self.created_links: list[str] = []
        self.mounted: set[str] = set()
        self.vms: dict[str, VM] = {}
        self.events: list[dict[str, Any]] = []
        self.cleanup_errors: list[str] = []
        self.failure = ""
        self.outcome = "FAILED"
        self.command_log: CommandLog | None = None
        self.tokens = {member: secrets.token_hex(32) for member in ("a", "b")}
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.source_paths = {
            "driver": Path(__file__).resolve(),
            "driver_tests": Path(__file__).with_name("test_qualify.py").resolve(),
            "readme": Path(__file__).with_name("README.md").resolve(),
            "guest_test": REPO / "internal/host/managed_member_firecracker_test.go",
        }
        self.source_hashes = {name: sha256_file(path) for name, path in self.source_paths.items()}

    def note(self, kind: str, **fields: Any) -> None:
        self.events.append({"at": datetime.now(timezone.utc).isoformat(), "kind": kind, **fields})

    def run_cmd(self, label: str, argv: list[str], *, sudo: bool = False,
                timeout: int = 120, allowed: tuple[int, ...] = (0,)) -> str:
        assert self.command_log is not None
        result = self.command_log.run(label, argv, sudo=sudo, timeout=timeout, allowed=allowed)
        self.note("command", label=label, argv=argv, sudo=sudo)
        return result

    def prepare_dirs(self) -> None:
        if os.path.lexists(self.root):
            raise QualificationError("run directory must not exist before qualification")
        self.root.mkdir(mode=0o700)
        for directory in (self.logs, self.commands, self.images, self.mounts, self.stage):
            directory.mkdir(mode=0o700)
        (self.root / "manifest.json").write_bytes(self.manifest["raw"])
        (self.root / "manifest.json").chmod(0o600)
        self.command_log = CommandLog(self.commands)
        self.note("start", profile=PROFILE, manifest_sha256=self.manifest["sha256"],
                  source_commits=self.manifest["source_commits"], source_hashes=self.source_hashes)

    def recheck_inputs(self) -> None:
        records = list(self.manifest["inputs"].values())
        for member in ("a", "b"):
            records.extend(self.manifest["members"][member]["inputs"].values())
        for record in records:
            if sha256_file(record["path"]) != record["sha256"]:
                raise QualificationError(f"immutable input changed: {record['path']}")
        self.note("inputs_rechecked", count=len(records))

    def copy_images(self) -> None:
        for member in ("a", "b"):
            rootfs = self.images / f"{member}-rootfs.ext4"
            volume = self.images / f"{member}-volume.ext4"
            source_root = self.manifest["inputs"]["rootfs"]
            source_volume = self.manifest["members"][member]["inputs"]["volume_ext4"]
            for name, source, target in (("rootfs", source_root, rootfs), ("volume", source_volume, volume)):
                self.run_cmd(f"copy-{member}-{name}", ["cp", "--reflink=auto", "--sparse=always", str(source["path"]), str(target)], timeout=240)
                target.chmod(0o600)
                if sha256_file(target) != source["sha256"]:
                    raise QualificationError(f"private {member} {name} differs from pinned input")
                self.note("private_image_verified", member=member, image=name, sha256=source["sha256"])
            with rootfs.open("r+b") as stream:
                stream.truncate(max(rootfs.stat().st_size, 8 << 30))
            self.run_cmd(f"e2fsck-{member}-rootfs", ["e2fsck", "-f", "-y", str(rootfs)], timeout=240, allowed=(0, 1))
            self.run_cmd(f"resize-{member}-rootfs", ["resize2fs", str(rootfs)], timeout=240)
            self.run_cmd(f"e2fsck-{member}-volume", ["e2fsck", "-fn", str(volume)], timeout=120)
            uuid = self.run_cmd(f"uuid-{member}-volume", ["blkid", "-s", "UUID", "-o", "value", str(volume)], timeout=30).strip()
            kind = self.run_cmd(f"type-{member}-volume", ["blkid", "-s", "TYPE", "-o", "value", str(volume)], timeout=30).strip()
            if uuid != VOLUME_UUIDS[member] or kind != "ext4":
                raise QualificationError(f"{member}: attached private volume UUID/type mismatch")

    def mount_root(self, member: str, *, read_only: bool = False) -> Path:
        target = self.mounts / member
        if target.exists():
            raise QualificationError(f"{member}: root mount path already exists")
        target.mkdir(mode=0o700)
        option = "loop,ro,noload" if read_only else "loop"
        try:
            self.run_cmd(f"mount-{member}-{'ro' if read_only else 'rw'}", ["mount", "-o", option,
                           str(self.images / f"{member}-rootfs.ext4"), str(target)], sudo=True)
        except Exception:
            if os.path.ismount(target):
                self.mounted.add(member)
            else:
                target.rmdir()
            raise
        if not os.path.ismount(target):
            raise QualificationError(f"{member}: mount returned without mounting")
        self.mounted.add(member)
        return target

    def unmount_root(self, member: str) -> None:
        target = self.mounts / member
        if not os.path.ismount(target):
            self.mounted.discard(member)
            if target.exists():
                target.rmdir()
            return
        if member not in self.mounted:
            raise QualificationError(f"{member}: refusing to unmount unowned image")
        self.run_cmd(f"umount-{member}", ["umount", str(target)], sudo=True)
        if os.path.ismount(target):
            raise QualificationError(f"{member}: owned image remains mounted")
        self.mounted.discard(member)
        target.rmdir()

    def stage_text(self, name: str, text: str, mode: int = 0o600) -> Path:
        path = self.stage / name
        path.write_text(text)
        path.chmod(mode)
        return path

    def install(self, mount: Path, source: Path, destination: Path, mode: str,
                group: str = "root") -> None:
        target = guest_path(mount, destination)
        self.run_cmd("install-" + destination.name, ["install", "-D", "-o", "root", "-g", group,
                      "-m", mode, str(source), str(target)], sudo=True, timeout=60)

    def staged_sha256(self, mount: Path, destination: Path) -> str:
        target = guest_path(mount, destination)
        output = self.run_cmd("hash-" + destination.name, ["sha256sum", str(target)], sudo=True, timeout=60)
        fields = output.split()
        if len(fields) != 2 or fields[1] != str(target) or not _SHA.fullmatch(fields[0]):
            raise QualificationError(f"staged guest hash output is malformed for {destination}")
        return fields[0]

    def install_dir(self, mount: Path, destination: Path, mode: str, group: str = "root") -> None:
        target = guest_path(mount, destination)
        self.run_cmd("install-dir-" + destination.name, ["install", "-d", "-o", "root", "-g", group,
                      "-m", mode, str(target)], sudo=True, timeout=30)

    def stage_managed_material(self, mount: Path, member: str, inputs: dict[str, dict[str, Any]]) -> None:
        directories = managed_directories(member)
        # The mount is a private image beneath a 0700 run directory. Keep only
        # traversal open during staging so the unprivileged host can reject
        # symlinks in every component before privileged installs and hashes.
        for destination, _ in directories:
            self.install_dir(mount, destination, "0755", "65534")
        for key, filename in MATERIAL.items():
            destination = MEMBER_DIRS[member] / "material" / filename
            self.install(mount, inputs[key]["path"], destination, "0440", "65534")
            if self.staged_sha256(mount, destination) != inputs[key]["sha256"]:
                raise QualificationError(f"{member}: staged {key} changed")
        self.lock_managed_layout(mount, member, directories)

    def lock_managed_layout(self, mount: Path, member: str,
                            directories: tuple[tuple[Path, int], ...]) -> None:
        # Resolve and inspect all paths while they remain traversable. No
        # unprivileged path walk occurs after the protected parent is locked.
        expected = [(guest_path(mount, destination), mode, True) for destination, mode in directories]
        expected.extend((guest_path(mount, MEMBER_DIRS[member] / "material" / filename), 0o440, False)
                        for filename in MATERIAL.values())
        for destination, mode in reversed(directories):
            self.install_dir(mount, destination, f"{mode:04o}", "65534")
        output = self.run_cmd(f"verify-{member}-managed-layout",
                              ["stat", "-c", "%u:%g:%f", "--", *(str(path) for path, _, _ in expected)],
                              sudo=True, timeout=30)
        lines = output.splitlines()
        if len(lines) != len(expected):
            raise QualificationError(f"{member}: managed layout stat count mismatch")
        for (path, mode, directory), line in zip(expected, lines, strict=True):
            try:
                uid, gid, bits = line.split(":")
                observed = int(bits, 16)
            except ValueError as error:
                raise QualificationError(f"{member}: malformed managed layout stat for {path}") from error
            if (uid != "0" or gid != "65534" or stat.S_IMODE(observed) != mode or
                    (not stat.S_ISDIR(observed) if directory else not stat.S_ISREG(observed))):
                raise QualificationError(f"{member}: unsafe final managed layout at {path}")

    def enable_unit(self, mount: Path, name: str) -> None:
        wants = guest_path(mount, Path("/etc/systemd/system/multi-user.target.wants"))
        self.run_cmd("wants-dir", ["install", "-d", "-o", "root", "-g", "root", "-m", "0755", str(wants)], sudo=True)
        link = wants / name
        if os.path.lexists(link):
            raise QualificationError(f"guest unit link already exists: {link}")
        self.run_cmd("enable-" + name, ["ln", "-s", "../" + name, str(link)], sudo=True)

    def stage_guest(self, member: str) -> None:
        mount = self.mount_root(member)
        try:
            check_guest_tools(mount)
            self.install(mount, self.manifest["inputs"]["go_host_test"]["path"],
                         Path("/opt/ts-managed-member/host.test"), "0755")
            self.install(mount, self.manifest["inputs"]["tb_server"]["path"],
                         Path("/opt/ts-managed-member/tb-server"), "0755")
            for key, destination in (("go_host_test", Path("/opt/ts-managed-member/host.test")),
                                     ("tb_server", Path("/opt/ts-managed-member/tb-server"))):
                if self.staged_sha256(mount, destination) != self.manifest["inputs"][key]["sha256"]:
                    raise QualificationError(f"{member}: staged {key} changed")
            inputs = self.manifest["members"][member]["inputs"]
            self.stage_managed_material(mount, member, inputs)
            for key, filename in (("client_api_token", "client-api-token"),
                                  ("client_https_ca_pem", "client-https-ca.pem")):
                destination = Path("/opt/ts-managed-member") / filename
                self.install(mount, inputs[key]["path"], destination, "0600")
                if self.staged_sha256(mount, destination) != inputs[key]["sha256"]:
                    raise QualificationError(f"{member}: staged {key} changed")
            config = dict(self.manifest["members"][member]["guest_config"])
            config.update(artifact_path="/opt/ts-managed-member/tb-server",
                          artifact_sha256=self.manifest["inputs"]["tb_server"]["sha256"],
                          control_address=f"{GUEST_IPS[member]}:{CONTROL_PORT}",
                          control_host_ip=HOST_IP, control_token=self.tokens[member],
                          client_root_path="/opt/ts-managed-member/client-https-ca.pem",
                          client_root_sha256=inputs["client_https_ca_pem"]["sha256"],
                          client_token_path="/opt/ts-managed-member/client-api-token",
                          client_token_sha256=inputs["client_api_token"]["sha256"])
            config_file = self.stage_text(f"{member}-guest-config.json", json.dumps(config, sort_keys=True) + "\n")
            self.install(mount, config_file, Path("/etc/ts-managed-member/guest-config.json"), "0600")
            self.install(mount, self.stage_text(f"{member}-volume-setup.sh", volume_setup_script(member), 0o700),
                         Path("/usr/local/sbin/ts-managed-member-volume-setup"), "0755")
            self.install(mount, self.stage_text(f"{member}-runner.sh", runner_script(member), 0o700),
                         Path("/usr/local/sbin/ts-managed-member-runner"), "0755")
            self.install(mount, self.stage_text(f"{member}-volume-setup.service", setup_unit(), 0o644),
                         Path("/etc/systemd/system/ts-managed-member-volume-setup.service"), "0644")
            self.install(mount, self.stage_text(f"{member}-test.service", test_unit(), 0o644),
                         Path("/etc/systemd/system/ts-managed-member-test.service"), "0644")
            network = f"[Match]\nMACAddress={GUEST_MACS[member]}\n\n[Network]\nAddress={GUEST_IPS[member]}/24\n"
            self.install(mount, self.stage_text(f"{member}-network.conf", network, 0o644),
                         Path("/etc/systemd/network/80-ts-managed-member.network"), "0644")
            self.install(mount, self.stage_text(f"{member}-cloud-init.disabled", "", 0o644),
                         Path("/etc/cloud/cloud-init.disabled"), "0644")
            self.enable_unit(mount, "ts-managed-member-volume-setup.service")
            self.enable_unit(mount, "ts-managed-member-test.service")
            self.note("guest_staged", member=member, guest_config_sha256=sha256_file(config_file),
                      artifact_sha256=self.manifest["inputs"]["tb_server"]["sha256"])
        finally:
            self.unmount_root(member)

    def network(self) -> None:
        check_subnet_collision()
        self.run_cmd("bridge-add", ["ip", "link", "add", "name", self.bridge, "type", "bridge"], sudo=True)
        self.created_links.append(self.bridge)
        self.run_cmd("bridge-address", ["ip", "addr", "add", f"{HOST_IP}/24", "dev", self.bridge], sudo=True)
        self.run_cmd("bridge-up", ["ip", "link", "set", self.bridge, "up"], sudo=True)
        for member in ("a", "b"):
            tap = self.taps[member]
            self.run_cmd(f"tap-{member}-add", ["ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", str(os.getuid())], sudo=True)
            self.created_links.append(tap)
            self.run_cmd(f"tap-{member}-master", ["ip", "link", "set", tap, "master", self.bridge], sudo=True)
            self.run_cmd(f"tap-{member}-up", ["ip", "link", "set", tap, "up"], sudo=True)
        self.note("private_network", bridge=self.bridge, taps=self.taps, subnet=str(SUBNET))

    def start_vms(self) -> None:
        self.recheck_inputs()
        self.socket_dir = Path(tempfile.mkdtemp(prefix="tsmm-", dir="/tmp"))
        self.socket_dir.chmod(0o700)
        if len(os.fsencode(self.socket_dir / "a.sock")) >= 100:
            raise QualificationError("private Firecracker socket directory is too long")
        for member in ("a", "b"):
            vm = VM(self, member)
            self.vms[member] = vm
            vm.start()

    def request(self, member: str, method: str, path: str) -> tuple[int, dict[str, Any]]:
        connection = http.client.HTTPConnection(GUEST_IPS[member], CONTROL_PORT, timeout=5)
        try:
            connection.request(method, path, headers={"X-TS-Test-Token": self.tokens[member]})
            response = connection.getresponse()
            body = response.read(EVIDENCE_BOUND + 1)
            if len(body) > EVIDENCE_BOUND:
                raise QualificationError(f"{member} {path}: evidence response exceeded bound")
            if response.status == 204:
                if body:
                    raise QualificationError(f"{member} {path}: unexpected no-content body")
                return response.status, {}
            if response.status != 200:
                return response.status, {"error": body.decode(errors="replace")[:1024]}
            decoded = json.loads(body)
            if not isinstance(decoded, dict):
                raise QualificationError(f"{member} {path}: response is not an object")
            return response.status, decoded
        finally:
            connection.close()

    def wait_evidence(self, member: str, timeout: int = 180) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last = "no response"
        while time.monotonic() < deadline:
            vm = self.vms[member]
            if vm.process is not None and vm.process.poll() is not None:
                raise QualificationError(f"{member}: VM exited before guest evidence was ready")
            try:
                status, evidence = self.request(member, "GET", "/evidence")
                if status == 200:
                    self.validate_evidence(member, evidence)
                    return evidence
                last = f"HTTP {status}: {evidence}"
            except (OSError, http.client.HTTPException, TimeoutError) as error:
                last = str(error)
            time.sleep(0.25)
        raise QualificationError(f"{member}: native evidence timeout: {last}")

    def validate_evidence(self, member: str, evidence: dict[str, Any]) -> None:
        fields = {"version", "node", "member_id", "process_pid", "process_uid", "process_gid",
                  "process_cgroup", "memory_max_bytes", "filesystem_uuid", "mount_id",
                  "claim_sha256", "storage_recovered", "listener_ready", "metrics"}
        if (set(evidence) != fields or evidence["version"] != 1 or evidence["node"] != "node-" + member or
                evidence["member_id"] != MEMBER_IDS[member] or evidence["filesystem_uuid"] != VOLUME_UUIDS[member] or
                evidence["process_uid"] != 65534 or evidence["process_gid"] != 65534 or
                evidence["memory_max_bytes"] != 6 << 30 or evidence["process_pid"] < 2 or
                evidence["mount_id"] < 1 or not evidence["storage_recovered"] or not evidence["listener_ready"] or
                not isinstance(evidence["claim_sha256"], str) or not _SHA.fullmatch(evidence["claim_sha256"]) or
                not isinstance(evidence["process_cgroup"], str) or not evidence["process_cgroup"].endswith("/terrabase") or
                not isinstance(evidence["metrics"], dict)):
            raise QualificationError(f"{member}: native process/volume evidence is incomplete or inconsistent")

    @staticmethod
    def metric(metrics: dict[str, Any], name: str, *, required: bool = False) -> float:
        if name not in metrics:
            if required:
                raise QualificationError(f"native metric missing: {name}")
            return 0.0
        value = metrics[name]
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0 or value != value:
            raise QualificationError(f"native metric invalid: {name}={value!r}")
        return float(value)

    def exercise(self) -> None:
        binding = self.manifest["members"]["a"]["guest_config"]
        a_before = self.wait_evidence("a")
        b_before = self.wait_evidence("b")
        self.note("members_ready", a=a_before, b=b_before)
        durable_key = 'terrabase_replication_acks_total{stage="durable"}'
        applied_key = 'terrabase_replication_acks_total{stage="applied"}'
        durable_before = self.metric(b_before["metrics"], durable_key)
        applied_before = self.metric(b_before["metrics"], applied_key)
        status, absent = self.request("b", "GET", "/read")
        absent_body = absent.get("body") if isinstance(absent, dict) else None
        if (status != 200 or set(absent) != {"status", "body"} or absent["status"] != 200 or
                not isinstance(absent_body, dict) or absent_body.get("version") != 1 or
                absent_body.get("state") != "absent" or absent_body.get("context") != [] or
                absent_body.get("siblings") != []):
            raise QualificationError(f"B's pinned document was not absent before A wrote it: {absent}")
        self.note("https_peer_absent_before_write", member="b", status=200, point=absent_body,
                  document_id=binding["document_id"])
        status, write = self.request("a", "POST", "/write")
        if status != 200 or set(write) != {"status", "body"} or write["status"] != 200 or not isinstance(write["body"], dict) or write["body"].get("durability") != "local_durable":
            raise QualificationError(f"A local HTTPS write did not return local_durable: {write}")
        if any(key in write["body"] for key in ("received", "applied", "remote_ack")):
            raise QualificationError("local durable receipt incorrectly claimed peer durability")
        self.note("https_write", member="a", status=200, receipt=write["body"])
        deadline = time.monotonic() + 90
        last = "no read"
        while time.monotonic() < deadline:
            status, read = self.request("b", "GET", "/read")
            body = read.get("body") if isinstance(read, dict) else None
            siblings = body.get("siblings") if isinstance(body, dict) else None
            if (status == 200 and set(read) == {"status", "body"} and read["status"] == 200 and
                    isinstance(body, dict) and body.get("version") == 1 and body.get("state") == "value" and
                    isinstance(siblings, list) and len(siblings) == 1 and isinstance(siblings[0], dict) and
                    siblings[0].get("kind") == "live" and siblings[0].get("fields") == [] and
                    siblings[0].get("schema_generation") == str(binding["schema_generation"]) and
                    siblings[0].get("schema_digest") == binding["schema_digest"]):
                self.note("https_peer_read", member="b", status=200, point=read["body"],
                          document_id=binding["document_id"])
                break
            last = f"HTTP {status}: {read}"
            time.sleep(0.25)
        else:
            raise QualificationError(f"B did not read A's committed document: {last}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            a_after = self.wait_evidence("a", 10)
            b_after = self.wait_evidence("b", 10)
            b_durable = self.metric(b_after["metrics"], durable_key)
            b_applied = self.metric(b_after["metrics"], applied_key)
            connected = self.metric(a_after["metrics"], "terrabase_replication_sender_connected", required=True)
            durable_lag = self.metric(a_after["metrics"], "terrabase_replication_sender_durable_lag_events", required=True)
            applied_lag = self.metric(a_after["metrics"], "terrabase_replication_sender_applied_lag_events", required=True)
            if b_durable > durable_before and b_applied > applied_before and connected == 1 and durable_lag == 0 and applied_lag == 0:
                self.note("peer_acks_observed", receiver_before={"durable": durable_before, "applied": applied_before},
                          receiver_after={"durable": b_durable, "applied": b_applied},
                          source={"connected": connected, "durable_lag": durable_lag, "applied_lag": applied_lag},
                          a=a_after, b=b_after)
                return
            time.sleep(0.25)
        raise QualificationError("peer read succeeded but durable/applied ACK delta or source lag evidence was absent")

    def finish_guests(self) -> None:
        for member in ("a", "b"):
            status, _ = self.request(member, "POST", "/finish")
            if status != 204:
                raise QualificationError(f"{member}: guest refused finish signal")
        for member in ("a", "b"):
            self.vms[member].natural_exit()

    def collect_results(self) -> None:
        for member in ("a", "b"):
            mount = self.mount_root(member, read_only=True)
            try:
                source = guest_path(mount, Path("/var/log/ts-managed-member/go-host-test.log"))
                info = source.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or info.st_size > LOG_BOUND:
                    raise QualificationError(f"{member}: guest test log missing or oversized")
                target = self.logs / f"{member}-go-host-test.log"
                self.run_cmd(f"copy-{member}-guest-log", ["install", "-o", str(os.getuid()),
                             "-g", str(os.getgid()), "-m", "0600", str(source), str(target)], sudo=True)
                output = target.read_bytes()
                if len(output) != info.st_size:
                    raise QualificationError(f"{member}: copied guest log length changed")
                self.parse_test_result(member, output.decode(errors="replace"),
                                       (self.logs / f"{member}-serial.log").read_text(errors="replace"))
                self.note("guest_result", member=member, log_sha256=sha256_bytes(output), status="PASS")
            finally:
                self.unmount_root(member)

    @staticmethod
    def parse_test_result(member: str, output: str, serial: str) -> None:
        lines = [line.strip() for line in output.splitlines()]
        runs = [line for line in lines if line.startswith("=== RUN   ")]
        passes = [line for line in lines if line.startswith("--- PASS: ")]
        if (runs != ["=== RUN   " + GO_TEST] or len(passes) != 1 or not passes[0].startswith("--- PASS: " + GO_TEST + " ") or
                any(line.startswith(("--- FAIL:", "--- SKIP:")) for line in lines) or lines[-1:] != ["PASS"] or
                [line for line in lines if TEST_PHASE_PASS.fullmatch(line)] != [f"TS_MANAGED_MEMBER_PHASE=PASS node=node-{member}"]):
            raise QualificationError(f"{member}: focused Go test did not pass exactly once without skip")
        markers = [line.split(RESULT_PREFIX, 1)[1].strip() for line in serial.splitlines() if RESULT_PREFIX in line]
        if markers != [f"PASS node=node-{member}"] or RESULT_FAIL.search(serial):
            raise QualificationError(f"{member}: terminal guest runner result is absent or ambiguous: {markers}")

    def cleanup(self) -> None:
        for vm in self.vms.values():
            self.cleanup_errors.extend(vm.stop())
        for member in tuple(self.mounted):
            try:
                self.unmount_root(member)
            except Exception as error:
                self.cleanup_errors.append(f"unmount {member}: {error}")
        if any(not vm.stopped for vm in self.vms.values()):
            self.cleanup_errors.append("private network retained while a VM may still be live")
        else:
            for link in reversed(self.created_links):
                try:
                    self.run_cmd("remove-" + link, ["ip", "link", "del", "dev", link], sudo=True)
                except Exception as error:
                    self.cleanup_errors.append(f"remove owned link {link}: {error}")
        if self.socket_dir is not None:
            if any(not vm.stopped for vm in self.vms.values()):
                self.cleanup_errors.append("private API sockets retained while a VM may still be live")
            else:
                try:
                    for entry in self.socket_dir.iterdir():
                        if not entry.is_socket() or entry.name not in {"a.sock", "b.sock"}:
                            raise QualificationError(f"unexpected API socket entry {entry}")
                        entry.unlink()
                    self.socket_dir.rmdir()
                except Exception as error:
                    self.cleanup_errors.append(f"remove private API socket directory: {error}")
        if not self.failure and not self.cleanup_errors and not self.mounted and all(vm.stopped for vm in self.vms.values()):
            for path in self.images.glob("*.ext4"):
                path.unlink()
            self.note("private_images_removed")
        else:
            self.note("private_images_retained", failure=self.failure, cleanup_errors=self.cleanup_errors)

    def run(self) -> dict[str, Any]:
        self.prepare_dirs()
        try:
            self.recheck_inputs()
            self.copy_images()
            for member in ("a", "b"):
                self.stage_guest(member)
            self.network()
            self.start_vms()
            self.exercise()
            self.finish_guests()
            self.collect_results()
        except BaseException as error:
            self.failure = f"{type(error).__name__}: {error}"
            self.note("failure", detail=self.failure)
        finally:
            changed = {}
            for name, path in self.source_paths.items():
                try:
                    current = sha256_file(path)
                except OSError:
                    current = "missing"
                if current != self.source_hashes[name]:
                    changed[name] = {"initial": self.source_hashes[name], "observed": current}
            if changed:
                self.failure = "; ".join(part for part in (self.failure, "local qualification source changed") if part)
                self.note("source_changed", files=changed)
            self.cleanup()
        self.outcome = "CLEANUP_FAILED" if self.cleanup_errors else "FAILED" if self.failure else "PASS"
        summary = {
            "schema_version": 1, "profile": PROFILE, "outcome": self.outcome,
            "failure": self.failure, "cleanup_errors": self.cleanup_errors,
            "manifest_sha256": self.manifest["sha256"], "source_commits": self.manifest["source_commits"],
            "local_source_hashes": self.source_hashes,
            "started_at": self.started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "run_dir": str(self.root), "events": self.events,
            "logs": {member: {"serial": str(self.logs / f"{member}-serial.log"),
                               "vmm": str(self.logs / f"{member}-vmm.log"),
                               "go_test": str(self.logs / f"{member}-go-host-test.log")}
                     for member in ("a", "b")},
        }
        target = self.root / "summary.json"
        temporary = self.root / "summary.json.tmp"
        temporary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        temporary.chmod(0o600)
        os.replace(temporary, target)
        print(json.dumps({"outcome": self.outcome, "summary": str(target), "failure": self.failure}, sort_keys=True), flush=True)
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--run-dir", type=Path)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        prerequisites()
        if args.command == "check":
            print(json.dumps({"profile": PROFILE, "manifest_sha256": manifest["sha256"], "status": "CHECK_PASS"}, sort_keys=True))
            return 0
        if args.run_dir is None or not args.run_dir.is_absolute() or not args.run_dir.parent.is_dir():
            raise QualificationError("run requires an absolute new --run-dir under an existing parent")
        return 0 if Lab(manifest, args.run_dir).run()["outcome"] == "PASS" else 1
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError, QualificationError) as error:
        print(f"managed-member qualification: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
