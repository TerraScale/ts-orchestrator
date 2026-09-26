#!/usr/bin/env python3
"""Three-VM, packet-backed production restart qualification.

The script only runs with --run. Its default invocation validates inputs and
prepares disposable images; it never changes the supplied base image.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


SLOTS = ("controller-a", "controller-b", "seed-a")
ADDRESSES = {"controller-a": "10.44.0.11", "controller-b": "10.44.0.12", "seed-a": "10.44.0.10"}
IMDS_PATHS = frozenset(("/opc/v2/instance/id", "/opc/v2/instance/metadata/terrascale-bootstrap",
                        "/opc/v2/instance/region", "/opc/v2/identity/cert.pem",
                        "/opc/v2/identity/key.pem", "/opc/v2/identity/intermediate.pem"))
BRIDGE_IP = "10.44.0.1"
LAB_SUBNET = ipaddress.ip_network("10.44.0.0/24")
BOOT_ARGS = "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw"
UNITS = ("systemd-networkd.service", "systemd-timesyncd.service",
         "systemd-time-wait-sync.service", "terrascale-orchestrator-controller.service", "ssh.service")


def command(*args: str, timeout: int = 60, input_text: str | None = None,
            check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr[-1200:]}")
    return result


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def require_pinned_file(path: Path, expected: str) -> Path:
    path = path.resolve(strict=True)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError(f"invalid pinned regular input {path}")
    observed = digest(path)
    if observed != expected:
        raise ValueError(f"input hash mismatch for {path}: {observed}")
    return path


def check_network_collision() -> None:
    routes = json.loads(command("ip", "-j", "route", "show", "table", "all").stdout)
    for row in routes:
        destination = row.get("dst")
        if not isinstance(destination, str) or destination == "default":
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network) and network.overlaps(LAB_SUBNET):
            raise RuntimeError(f"host route collides with isolated fixture subnet: {destination}")
    links = json.loads(command("ip", "-j", "address", "show").stdout)
    for link in links:
        for address in link.get("addr_info", []):
            if address.get("family") != "inet":
                continue
            local = ipaddress.ip_address(address["local"])
            if local in LAB_SUBNET or str(local) == "169.254.169.254":
                raise RuntimeError(f"host address collides with isolated fixture: {local}")


def ensure_run_network_namespace(run: bool) -> None:
    if not run or not os.path.samefile("/proc/self/ns/net", "/proc/1/ns/net"):
        return
    if os.geteuid() != 0:
        raise RuntimeError("production Firecracker qualification requires root")
    # These checks must see the host before unshare hides its interfaces.
    check_network_collision()
    if command("timedatectl", "show", "-p", "NTPSynchronized", "--value").stdout.strip() != "yes":
        raise RuntimeError("host clock is not NTP synchronized")
    unshare = shutil.which("unshare")
    if unshare is None:
        raise RuntimeError("unshare is required for isolated production qualification")
    # The bridge, taps, nft rules, NTP server, OCI simulator, VMMs and SSH
    # client all inherit this namespace. Host INPUT firewall chains cannot
    # later discard packets accepted by the fixture's own nft chains.
    os.execv(unshare, [unshare, "--net", "--", sys.executable,
                       str(Path(__file__).resolve()), *sys.argv[1:]])
    raise AssertionError("unshare returned without executing the driver")


def ntp_timestamp(moment: float) -> bytes:
    seconds = moment + 2208988800
    whole = int(seconds)
    fraction = int((seconds - whole) * (1 << 32))
    return struct.pack("!II", whole, fraction)


def ntp_response(request: bytes, moment: float) -> bytes:
    if len(request) < 48 or request[0] & 7 != 3:
        raise ValueError("not an NTP client request")
    answer = bytearray(48)
    answer[0] = 0x24  # leap=0, version=4, server mode=4
    answer[1] = 2      # synchronized host-backed stratum
    answer[2] = request[2]
    answer[3] = 0xEC   # signed precision -20
    answer[12:16] = b"TSFC"
    answer[16:24] = ntp_timestamp(moment - 1)
    answer[24:32] = request[40:48]
    answer[32:40] = ntp_timestamp(moment)
    answer[40:48] = ntp_timestamp(time.time())
    return bytes(answer)


class NTPServer:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((BRIDGE_IP, 123))
        self.socket.settimeout(0.5)
        self.stop_event = threading.Event()
        self.requests = {slot: 0 for slot in SLOTS}
        self.counts = {slot: 0 for slot in SLOTS}
        self.send_errors = {slot: 0 for slot in SLOTS}
        self.unknown = 0
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        by_address = {address: slot for slot, address in ADDRESSES.items()}
        while not self.stop_event.is_set():
            try:
                request, peer = self.socket.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            slot = by_address.get(peer[0])
            if slot is None:
                self.unknown += 1
                continue
            self.requests[slot] += 1
            try:
                self.socket.sendto(ntp_response(request, time.time()), peer)
            except ValueError:
                self.unknown += 1
            except OSError:
                self.send_errors[slot] += 1
            else:
                self.counts[slot] += 1

    def close(self) -> None:
        self.stop_event.set()
        self.socket.close()
        self.thread.join(timeout=2)


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: Path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class VM:
    def __init__(self, slot: str, tap: str, image: Path, kernel: Path, firecracker: Path,
                 work: Path, ssh_key: Path, known_hosts: Path):
        self.slot, self.tap, self.image = slot, tap, image
        self.kernel, self.firecracker, self.work = kernel, firecracker, work
        self.ssh_key, self.known_hosts = ssh_key, known_hosts
        self.socket = work / f"{slot}.sock"
        if len(os.fsencode(self.socket)) >= 108:
            raise ValueError("Firecracker socket path exceeds Unix limit")
        self.process: subprocess.Popen[bytes] | None = None
        self.serial = None

    def api(self, path: str, payload: dict[str, Any]) -> None:
        connection = UnixHTTPConnection(self.socket)
        try:
            connection.request("PUT", path, body=json.dumps(payload),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read()
            if response.status not in (200, 204):
                raise RuntimeError(f"Firecracker {self.slot} {path}: {response.status} {body[:500]!r}")
        finally:
            connection.close()

    def boot(self) -> None:
        self.serial = (self.work / f"{self.slot}-serial.log").open("wb")
        self.process = subprocess.Popen(
            [str(self.firecracker), "--api-sock", str(self.socket)],
            stdout=self.serial, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 20
        while not self.socket.exists():
            if self.process.poll() is not None:
                raise RuntimeError(f"Firecracker {self.slot} exited before API socket")
            if time.monotonic() > deadline:
                raise TimeoutError(f"Firecracker {self.slot} API socket did not appear")
            time.sleep(0.1)
        self.api("/machine-config", {"vcpu_count": 2, "mem_size_mib": 4096, "smt": False})
        self.api("/boot-source", {"kernel_image_path": str(self.kernel), "boot_args": BOOT_ARGS})
        self.api("/drives/rootfs", {"drive_id": "rootfs", "path_on_host": str(self.image),
                                     "is_root_device": True, "is_read_only": False})
        self.api("/network-interfaces/eth0", {"iface_id": "eth0", "host_dev_name": self.tap,
                                                "guest_mac": f"02:fc:44:00:00:{SLOTS.index(self.slot)+1:02x}"})
        self.api("/actions", {"action_type": "InstanceStart"})

    def ssh(self, script: str, *, timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess[str]:
        return command("ssh", "-i", str(self.ssh_key), "-o", "BatchMode=yes",
                       "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                       "-o", f"UserKnownHostsFile={self.known_hosts}",
                       "-o", "ConnectTimeout=3", f"root@{ADDRESSES[self.slot]}",
                       "sh", "-lc", shlex.quote(script), timeout=timeout, check=check)

    def wait_ssh(self, *, different_boot_id: str | None = None, timeout: int = 240) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process is None or self.process.poll() is not None:
                raise RuntimeError(f"Firecracker {self.slot} stopped while waiting for SSH")
            try:
                result = self.ssh("cat /proc/sys/kernel/random/boot_id", timeout=8, check=False)
            except subprocess.TimeoutExpired:
                time.sleep(2)
                continue
            boot_id = result.stdout.strip()
            if result.returncode == 0 and boot_id and boot_id != different_boot_id:
                return boot_id
            time.sleep(2)
        raise TimeoutError(f"{self.slot} SSH did not reach a new boot")

    def health(self, expected_uid: int, expected_gid: int) -> dict[str, Any]:
        script = (
            "set -eu; "
            "fail() { printf 'failed-stage=%s\\n' \"$1\" >&2; exit 1; }; "
            "test \"$(timedatectl show -p NTPSynchronized --value)\" = yes || fail ntp-synchronized; "
            "timedatectl timesync-status --no-pager | grep -F '10.44.0.1' || fail ntp-server; "
            "test \"$(systemctl show -p Result --value terrascale-orchestrator-bootstrap.service)\" = success || fail bootstrap-result; "
            "test \"$(systemctl show -p ExecMainStatus --value terrascale-orchestrator-bootstrap.service)\" = 0 || fail bootstrap-exit; "
            "test \"$(systemctl show -p ActiveState --value terrascale-orchestrator-controller.service)\" = active || fail controller-active; "
            "pid=$(systemctl show -p MainPID --value terrascale-orchestrator-controller.service); "
            "test \"$pid\" -gt 1 || fail controller-pid; "
            "awk '/^Uid:|^Gid:/ {print $1, $2, $3, $4, $5}' /proc/$pid/status; "
            "systemctl show -p InvocationID --value terrascale-orchestrator-controller.service; "
            "cat /proc/sys/kernel/random/boot_id"
        )
        deadline = time.monotonic() + 300
        last = ""
        while time.monotonic() < deadline:
            try:
                result = self.ssh(script, timeout=15, check=False)
            except subprocess.TimeoutExpired:
                time.sleep(3)
                continue
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                uids = [line.split()[1:] for line in lines if line.startswith("Uid:")]
                gids = [line.split()[1:] for line in lines if line.startswith("Gid:")]
                if (len(uids) == len(gids) == 1 and
                        uids[0] == [str(expected_uid)] * 4 and
                        gids[0] == [str(expected_gid)] * 4):
                    return {"bootId": lines[-1], "controllerInvocation": lines[-2],
                            "uid": expected_uid, "gid": expected_gid,
                            "ntp": "synchronized", "bootstrap": "success", "controller": "active"}
                last = "failed-stage=service-identity\n" + result.stdout[-500:]
            else:
                last = result.stderr[-500:] + result.stdout[-500:]
            time.sleep(3)
        raise TimeoutError(f"{self.slot} did not reach production health: {last}\n"
                           f"guest diagnostics:\n{self.health_diagnostics()}")

    def health_diagnostics(self) -> str:
        # Limit journal output to systemd-authored unit events; application
        # messages can contain credentials and are intentionally excluded.
        script = (
            "printf '%s\\n' '[clock]'; "
            "timedatectl show -p NTPSynchronized --value 2>&1 || true; "
            "timedatectl timesync-status --no-pager 2>&1 || true; "
            "printf '%s\\n' '[network]'; "
            "networkctl status eth0 --no-pager 2>&1 || true; "
            "printf '%s\\n' '[units]'; "
            "for unit in systemd-timesyncd.service systemd-time-wait-sync.service "
            "terrascale-orchestrator-bootstrap.service terrascale-orchestrator-controller.service; do "
            "printf '%s\\n' \"$unit\"; "
            "systemctl show \"$unit\" -p ActiveState -p SubState -p Result "
            "-p ExecMainStatus --no-pager 2>&1 || true; "
            "done; "
            "printf '%s\\n' '[systemd unit journal]'; "
            "journalctl -b -n 40 --no-pager -o cat SYSLOG_IDENTIFIER=systemd "
            "-u systemd-timesyncd.service -u systemd-time-wait-sync.service "
            "-u terrascale-orchestrator-bootstrap.service "
            "-u terrascale-orchestrator-controller.service 2>&1 || true"
        )
        try:
            result = self.ssh(script, timeout=20, check=False)
        except subprocess.TimeoutExpired:
            return "diagnostic SSH timed out"
        return (result.stdout + result.stderr)[-8000:]

    def stop(self) -> None:
        process = self.process
        try:
            if process is not None:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=10)
        finally:
            if process is None or process.poll() is not None:
                self.process = None
                if self.serial is not None:
                    self.serial.close()
                    self.serial = None
                self.socket.unlink(missing_ok=True)


def check_audit(audit: dict[str, Any]) -> dict[str, int]:
    if audit.get("unknownSources") != 0 or set(audit.get("slots", {})) != set(SLOTS):
        raise RuntimeError("OCI simulator saw unknown sources or incomplete slots")
    counts: dict[str, int] = {}
    for slot in SLOTS:
        entry = audit["slots"][slot]
        requests = entry.get("requests", [])
        if entry.get("overflow") != 0 or not requests:
            raise RuntimeError(f"{slot} OCI audit is empty or overflowed")
        for request in requests:
            if not request.get("listed") or request.get("method") not in ("GET", "POST") or \
                    request.get("status") not in (200, 404):
                raise RuntimeError(f"{slot} made a failed, write, or unlisted OCI request: {request}")
            if request["status"] == 404 and request["host"] != "objectstorage.sa-saopaulo-1.oraclecloud.com":
                raise RuntimeError(f"{slot} received an unexpected non-ledger 404: {request}")
        imds = {request["requestUri"] for request in requests
                if request["host"] == "169.254.169.254"}
        auth = sum(request["host"] == "auth.sa-saopaulo-1.oraclecloud.com" for request in requests)
        compute = {request["requestUri"] for request in requests
                   if request["host"] == "iaas.sa-saopaulo-1.oraclecloud.com"}
        storage = sum(request["host"] == "objectstorage.sa-saopaulo-1.oraclecloud.com" for request in requests)
        if not IMDS_PATHS.issubset(imds) or auth < 1 or len(compute) < 3 or storage < 1:
            raise RuntimeError(f"{slot} did not exercise IMDS, federation, Compute, and ledger reads")
        counts[slot] = len(requests)
    return counts


def nft_drop_packets(table: str, family: str) -> int:
    output = command("nft", "list", "table", family, table).stdout
    return sum(int(value) for value in re.findall(r"counter packets (\d+) bytes \d+ drop", output))


class Qualification:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="tspr-", dir="/tmp"))
        self.root.chmod(0o700)
        self.bridge = "tspr" + self.root.name[-4:]
        self.taps = {slot: "tsp" + self.root.name[-4:] + str(index)
                     for index, slot in enumerate(SLOTS, 1)}
        self.table = "tspr_" + self.root.name[-4:]
        self.created_links: list[str] = []
        self.created_tables: list[tuple[str, str]] = []
        self.mounted: list[Path] = []
        self.vms: dict[str, VM] = {}
        self.simulator: subprocess.Popen[str] | None = None
        self.simulator_output = None
        self.ntp: NTPServer | None = None
        self.audit_path = self.root / "oci-audit.json"
        self.report: dict[str, Any] = {"result": "incomplete", "artifacts": {}}

    def fixturegen(self, *extra: str) -> subprocess.CompletedProcess[str]:
        if digest(self.args.fixturegen) != self.args.fixturegen_sha256 or \
                digest(self.args.root_cert) != self.args.root_cert_sha256:
            raise RuntimeError("packet verifier or trusted root changed after pinning")
        return command(str(self.args.fixturegen), *extra, "-packet", str(self.args.packet),
                       "-root-cert", str(self.args.root_cert), "-source-root", str(self.args.source_root),
                       "-image-ocid", self.args.image_ocid, timeout=120)

    def preflight(self) -> dict[str, Any]:
        if os.geteuid() != 0:
            raise RuntimeError("production Firecracker qualification requires root")
        for name in ("rootfs", "kernel", "firecracker", "fixturegen", "ssh_key", "known_hosts"):
            path = require_pinned_file(getattr(self.args, name), getattr(self.args, name + "_sha256"))
            setattr(self.args, name, path)
            self.report["artifacts"][name] = digest(path)
        self.args.root_cert = require_pinned_file(self.args.root_cert, self.args.root_cert_sha256)
        self.report["artifacts"]["root_cert"] = digest(self.args.root_cert)
        self.fixturegen("production-preflight")
        manifest = json.loads((self.args.packet / "manifest.json").read_text())
        if [row["slot"] for row in manifest["controllers"]] != list(SLOTS):
            raise RuntimeError("packet controller slots differ from fixed topology")
        check_network_collision()
        if self.args.run and command("timedatectl", "show", "-p", "NTPSynchronized", "--value").stdout.strip() != "yes":
            raise RuntimeError("host clock is not NTP synchronized")
        return manifest

    def prepare_images(self, manifest: dict[str, Any]) -> None:
        identities: dict[str, dict[str, int]] = {}
        plan = json.loads((self.args.packet / "simulator/guest-directories.json").read_text())
        if len(plan) != 6:
            raise RuntimeError("signed service directory plan is incomplete")
        for slot in SLOTS:
            owner = [row for row in plan if row["controllerSlot"] == slot]
            if len(owner) != 2 or owner[0]["uid"] != owner[1]["uid"] or owner[0]["gid"] != owner[1]["gid"]:
                raise RuntimeError(f"{slot} has incomplete service ownership")
            identities[slot] = {"uid": owner[0]["uid"], "gid": owner[0]["gid"]}
            image = self.root / f"{slot}.ext4"
            command("cp", "--reflink=never", "--sparse=always", str(self.args.rootfs), str(image), timeout=240)
            if digest(image) != self.args.rootfs_sha256 or image.samefile(self.args.rootfs):
                raise RuntimeError("disposable image copy differs from pinned base")
            with image.open("r+b") as stream:
                stream.truncate(max(image.stat().st_size, 8 << 30))
            checked = command("e2fsck", "-f", "-y", str(image), timeout=240, check=False)
            if checked.returncode not in (0, 1):
                raise RuntimeError(f"disposable image check failed: {checked.stderr[-500:]}")
            command("resize2fs", str(image), timeout=240)
            mount = self.root / f"mount-{slot}"
            mount.mkdir(mode=0o700)
            command("mount", "-o", "loop", str(image), str(mount))
            self.mounted.append(mount)
            try:
                self.fixturegen("stage", "-guest-root", str(mount), "-slot", slot)
                for unit in UNITS:
                    enabled = command("systemctl", f"--root={mount}", "is-enabled", unit).stdout.strip()
                    if enabled != "enabled":
                        raise RuntimeError(f"{slot} image has disabled {unit}: {enabled}")
            finally:
                command("umount", str(mount))
                self.mounted.remove(mount)
            self.vms[slot] = VM(slot, self.taps[slot], image, self.args.kernel, self.args.firecracker,
                                 self.root, self.args.ssh_key, self.args.known_hosts)
        self.report["serviceIdentity"] = identities

    def network(self) -> None:
        if os.path.samefile("/proc/self/ns/net", "/proc/1/ns/net"):
            raise RuntimeError("production fixture network requires a private namespace")
        command("ip", "link", "set", "lo", "up")
        command("ip", "link", "add", self.bridge, "type", "bridge")
        self.created_links.append(self.bridge)
        command("ip", "address", "add", "10.44.0.1/24", "dev", self.bridge)
        command("ip", "address", "add", "169.254.169.254/32", "dev", self.bridge)
        command("ip", "link", "set", self.bridge, "up")
        for slot in SLOTS:
            tap = self.taps[slot]
            command("ip", "tuntap", "add", "dev", tap, "mode", "tap")
            self.created_links.append(tap)
            command("ip", "link", "set", tap, "master", self.bridge)
            command("ip", "link", "set", tap, "up")
        self.firewall()

    def firewall(self) -> None:
        for family in ("inet", "bridge"):
            if command("nft", "list", "table", family, self.table, check=False).returncode == 0:
                raise RuntimeError(f"refusing to replace existing {family} firewall table")
        taps = ", ".join(f'"{self.taps[slot]}"' for slot in SLOTS)
        inet = [f"table inet {self.table} {{",
                "chain vm_input { type filter hook input priority -100; policy accept;"]
        for slot in SLOTS:
            inet.append(f'iifname "{self.taps[slot]}" ip saddr != {ADDRESSES[slot]} counter drop')
        inet += [f"iifname {{ {taps} }} ct state established,related accept",
                 f"iifname {{ {taps} }} ip daddr {BRIDGE_IP} tcp dport 443 counter accept",
                 f"iifname {{ {taps} }} ip daddr {BRIDGE_IP} udp dport 123 counter accept",
                 f"iifname {{ {taps} }} ip daddr 169.254.169.254 tcp dport 80 counter accept",
                 f"iifname {{ {taps} }} counter drop", "}",
                 "chain vm_forward { type filter hook forward priority -100; policy accept;"]
        for slot in SLOTS:
            inet.append(f'iifname "{self.taps[slot]}" ip saddr != {ADDRESSES[slot]} counter drop')
        inet.append(f'iifname {{ {taps}, "{self.bridge}" }} ct state established,related accept')
        for source in SLOTS:
            for target in SLOTS:
                if source != target:
                    inet.append(f'iifname {{ {taps}, "{self.bridge}" }} '
                                f'ip saddr {ADDRESSES[source]} ip daddr {ADDRESSES[target]} '
                                'tcp dport { 4222, 6222 } accept')
        inet += [f"iifname {{ {taps}, \"{self.bridge}\" }} counter drop", "}", "}"]
        command("nft", "-f", "-", input_text="\n".join(inet))
        self.created_tables.append(("inet", self.table))
        bridge = [f"table bridge {self.table} {{",
                  "chain vm_input { type filter hook input priority 0; policy accept;",
                  f"iifname {{ {taps} }} ether type arp accept",
                  f"iifname {{ {taps} }} ether type ip6 drop"]
        for slot in SLOTS:
            bridge.append(f'iifname "{self.taps[slot]}" ip saddr != {ADDRESSES[slot]} counter drop')
        bridge += [f"iifname {{ {taps} }} ct state established,related accept",
                   f"iifname {{ {taps} }} ip daddr {BRIDGE_IP} tcp dport 443 counter accept",
                   f"iifname {{ {taps} }} ip daddr {BRIDGE_IP} udp dport 123 counter accept",
                   f"iifname {{ {taps} }} ip daddr 169.254.169.254 tcp dport 80 counter accept",
                   f"iifname {{ {taps} }} counter drop", "}",
                   "chain vm_forward { type filter hook forward priority 0; policy accept;",
                   f"iifname {{ {taps} }} ether type arp accept",
                   f"iifname {{ {taps} }} ether type ip6 drop"]
        for slot in SLOTS:
            bridge.append(f'iifname "{self.taps[slot]}" ip saddr != {ADDRESSES[slot]} counter drop')
        bridge.append(f"iifname {{ {taps} }} ct state established,related accept")
        for source in SLOTS:
            for target in SLOTS:
                if source != target:
                    bridge.append(f'iifname "{self.taps[source]}" oifname "{self.taps[target]}" '
                                  f'ip saddr {ADDRESSES[source]} ip daddr {ADDRESSES[target]} '
                                  'tcp dport { 4222, 6222 } accept')
        bridge += [f"iifname {{ {taps} }} counter drop", "}", "}"]
        command("nft", "-f", "-", input_text="\n".join(bridge))
        self.created_tables.append(("bridge", self.table))

    def start_services(self) -> None:
        if digest(self.args.fixturegen) != self.args.fixturegen_sha256 or \
                digest(self.args.root_cert) != self.args.root_cert_sha256:
            raise RuntimeError("packet verifier or trusted root changed before simulator launch")
        self.ntp = NTPServer()
        self.simulator_output = (self.root / "simulator.log").open("w")
        self.simulator = subprocess.Popen(
            [str(self.args.fixturegen), "serve", "-packet", str(self.args.packet),
             "-root-cert", str(self.args.root_cert), "-source-root", str(self.args.source_root),
             "-image-ocid", self.args.image_ocid, "-audit", str(self.audit_path)],
            stdout=self.simulator_output, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if self.simulator.poll() is not None:
                raise RuntimeError("OCI simulator exited before VM boot")
            if "simulators ready" in (self.root / "simulator.log").read_text():
                return
            time.sleep(0.2)
        raise TimeoutError("OCI simulator did not become ready")

    def run_vms(self) -> None:
        for slot in SLOTS:
            self.vms[slot].boot()
        evidence = {slot: {} for slot in SLOTS}
        for slot in SLOTS:
            vm = self.vms[slot]
            boot_id = vm.wait_ssh()
            first = vm.health(self.report["serviceIdentity"][slot]["uid"],
                              self.report["serviceIdentity"][slot]["gid"])
            if first["bootId"] != boot_id:
                raise RuntimeError(f"{slot} boot identity changed during health check")
            evidence[slot]["first"] = first
        for slot in SLOTS:
            vm = self.vms[slot]
            previous = evidence[slot]["first"]["bootId"]
            try:
                vm.ssh("systemctl reboot", timeout=10, check=False)
            except subprocess.TimeoutExpired:
                # SSH may outlive the command while the guest closes its network.
                # The new boot ID below is the evidence that reboot completed.
                pass
            vm.wait_ssh(different_boot_id=previous)
            restarted = vm.health(self.report["serviceIdentity"][slot]["uid"],
                                  self.report["serviceIdentity"][slot]["gid"])
            if restarted["bootId"] == previous or \
                    restarted["controllerInvocation"] == evidence[slot]["first"]["controllerInvocation"]:
                raise RuntimeError(f"{slot} did not complete a new production controller invocation")
            evidence[slot]["restart"] = restarted
        self.report["guests"] = evidence

    def finish_audit(self) -> None:
        for vm in self.vms.values():
            vm.stop()
        if self.simulator is None:
            raise RuntimeError("OCI simulator did not start")
        if self.simulator.poll() is not None:
            raise RuntimeError("OCI simulator exited before audit collection")
        os.killpg(self.simulator.pid, signal.SIGTERM)
        if self.simulator.wait(timeout=20) != 0:
            raise RuntimeError("OCI simulator did not exit cleanly")
        self.simulator = None
        audit = json.loads(self.audit_path.read_text())
        self.report["ociRequests"] = check_audit(audit)
        if self.ntp is None or self.ntp.unknown != 0 or \
                any(self.ntp.send_errors.values()) or \
                any(self.ntp.counts[slot] == 0 for slot in SLOTS):
            raise RuntimeError("NTP server did not serve only the three expected guests")
        self.report["ntpRequests"] = self.ntp.requests.copy()
        self.report["ntpReplies"] = self.ntp.counts.copy()
        drops = sum(nft_drop_packets(name, family) for family, name in self.created_tables)
        if drops:
            raise RuntimeError(f"isolated bridge dropped {drops} unexpected packets")
        self.report["firewallDrops"] = drops

    def cleanup(self) -> list[str]:
        failures: list[str] = []
        for vm in self.vms.values():
            try:
                vm.stop()
            except Exception as error:
                failures.append(f"stop {vm.slot}: {error}")
        if self.simulator is not None:
            try:
                if self.simulator.poll() is None:
                    try:
                        os.killpg(self.simulator.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                try:
                    self.simulator.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(self.simulator.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.simulator.wait(timeout=10)
                    failures.append("simulator required SIGKILL during cleanup")
            except Exception as error:
                failures.append(f"stop simulator: {error}")
        if self.simulator_output is not None:
            self.simulator_output.close()
        if self.ntp is not None:
            self.ntp.close()
            self.report["ntpRequests"] = self.ntp.requests.copy()
            self.report["ntpReplies"] = self.ntp.counts.copy()
            self.report["ntpUnknownRequests"] = self.ntp.unknown
            self.report["ntpSendErrors"] = self.ntp.send_errors.copy()
        for mount in reversed(self.mounted):
            try:
                command("umount", str(mount))
            except Exception as error:
                failures.append(f"unmount {mount}: {error}")
        for family, name in reversed(self.created_tables):
            try:
                rules = command("nft", "list", "table", family, name).stdout
                filename = f"firewall-{family}.txt"
                (self.root / filename).write_text(rules)
                self.report.setdefault("firewallCounterFiles", {})[family] = filename
                self.report["firewallDrops"] = self.report.get("firewallDrops", 0) + sum(
                    int(value) for value in re.findall(r"counter packets (\d+) bytes \d+ drop", rules))
            except Exception as error:
                failures.append(f"capture {family} firewall counters: {error}")
            try:
                command("nft", "delete", "table", family, name)
            except Exception as error:
                failures.append(f"delete {family} {name}: {error}")
        for link in reversed(self.created_links):
            try:
                command("ip", "link", "delete", link)
            except Exception as error:
                failures.append(f"delete {link}: {error}")
        for slot in SLOTS:
            image = self.root / f"{slot}.ext4"
            if image.exists() and self.args.run and all(vm.process is None for vm in self.vms.values()) and not self.mounted:
                try:
                    image.unlink()
                except Exception as error:
                    failures.append(f"remove {image}: {error}")
        return failures


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("rootfs", "kernel", "firecracker", "fixturegen", "ssh-key", "known-hosts"):
        token = name.replace("-", "_")
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", dest=token + "_sha256", required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--root-cert", type=Path, required=True)
    parser.add_argument("--root-cert-sha256", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--image-ocid", required=True)
    parser.add_argument("--run", action="store_true", help="launch three VMs after image preparation")
    return parser.parse_args()


def main() -> int:
    args = arguments()
    args.packet = args.packet.resolve(strict=True)
    args.root_cert = args.root_cert.resolve(strict=True)
    args.source_root = args.source_root.resolve(strict=True)
    ensure_run_network_namespace(args.run)
    qualification = Qualification(args)
    error = None
    try:
        manifest = qualification.preflight()
        qualification.prepare_images(manifest)
        if args.run:
            qualification.network()
            qualification.start_services()
            qualification.run_vms()
            qualification.finish_audit()
        qualification.report["result"] = "passed" if args.run else "prepared-only"
    except Exception as failure:
        error = str(failure)
        qualification.report["result"] = "failed"
        qualification.report["error"] = error
    finally:
        cleanup = qualification.cleanup()
        qualification.report["cleanupErrors"] = cleanup
        if cleanup:
            qualification.report["result"] = "failed"
        (qualification.root / "report.json").write_text(json.dumps(qualification.report, indent=2) + "\n")
        print(f"qualification artifacts: {qualification.root}")
    if error or cleanup:
        raise RuntimeError(error or "; ".join(cleanup))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
