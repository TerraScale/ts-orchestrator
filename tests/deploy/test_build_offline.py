import base64
import binascii
import json
import hashlib
import importlib.util
import os
import re
import secrets
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "deploy/image/build-offline.sh"
OFFLINE_HELPER = ROOT / "deploy/image/offline-guestfs.py"
BOOTSTRAP_DIRECTORY = "/etc/terrascale-orchestrator/bootstrap"
MARKER_DIRECTORY = "/var/lib/terrascale-orchestrator-bootstrap"
SECRETS_DIRECTORY = "/var/lib/terrascale-orchestrator-secrets"
CONTROLLER_DIRECTORY = "/var/lib/terrascale-orchestrator-controller"
MANAGED_DIRECTORY = "/srv/ts-managed"
TIMESYNCD_CONFIG_GUEST = "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf"
TIME_WAIT_SYNC_DROPIN = "/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf"
RUNTIME_PRIORITY_PROFILE_GUEST = "/etc/terrascale-orchestrator/runtime-priority.json"
RUNTIME_PRIORITY_HELPER_GUEST = "/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py"
NATIVE_VERIFIER_GUEST = "/usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server"
HOST_ENROLLMENT_GUEST = "/etc/terrascale-orchestrator/host-enrollment-public.json"
RUNTIME_PRIORITY_DROPINS = (
    "/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf",
    "/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf",
    "/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf",
)
RUNTIME_PRIORITY_PROFILE_ID = "preview-1ocpu-6gib-v1"
RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES = 1 << 30
BAKED_LOADER = ROOT / "internal/bootstrapstart/baked.go"
RUNTIME_PRIORITY_QUALIFIER = ROOT / "tests/runtime_priority/qualify.py"
RUNTIME_PRIORITY_QUALIFIER_SPEC = importlib.util.spec_from_file_location(
    "runtime_priority_qualifier", RUNTIME_PRIORITY_QUALIFIER
)
RUNTIME_PRIORITY_QUALIFIER_MODULE = importlib.util.module_from_spec(RUNTIME_PRIORITY_QUALIFIER_SPEC)
RUNTIME_PRIORITY_QUALIFIER_SPEC.loader.exec_module(RUNTIME_PRIORITY_QUALIFIER_MODULE)


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


class BuildOfflineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="offline image inputs ")
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.inputs = self.root / "inputs with spaces"
        self.inputs.mkdir()
        self.base = self.write_file(self.inputs / "base image.qcow2", b"mock qcow2 bytes")
        self.binary = self.write_file(self.inputs / "orchestrator binary", b"mock verified binary")
        native_header = bytearray(64)
        native_header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", native_header, 16, 3)
        struct.pack_into("<H", native_header, 18, 183)
        struct.pack_into("<I", native_header, 20, 1)
        struct.pack_into("<H", native_header, 52, 64)
        self.native_verifier = self.write_file(
            self.inputs / "tb-server-linux-arm64", bytes(native_header) + b"mock native verifier"
        )
        self.native_verifier_sha256 = hashlib.sha256(self.native_verifier.read_bytes()).hexdigest()
        self.receipt = self.write_file(self.inputs / "release receipt.json", b"mock receipt")
        self.qualification = self.write_file(self.inputs / "qualification.json", b"mock qualification")
        self.delegation = self.write_file(self.inputs / "release delegation.json", b"mock delegation")
        self.release_root = self.write_file(self.inputs / "release root.pem", b"release public key")
        self.bootstrap_root_a = self.write_file(self.inputs / "bootstrap root a.pem", b"bootstrap public key a")
        self.bootstrap_root_b = self.write_file(self.inputs / "bootstrap root b.pem", b"bootstrap public key b")
        self.anchor = self.write_file(self.inputs / "signed anchor v2.json", b"mock signed anchor v2")
        self.identity = self.write_file(
            self.inputs / "bootstrap identity.json",
            b'{"schemaVersion":1,"deploymentId":"deployment-a","environment":"canary","cell":"GRU"}',
        )
        self.timesyncd_config = self.write_file(
            self.inputs / "timesyncd config.conf",
            b"[Time]\nNTP=ntp.deployment.example\n",
        )
        self.shims = self.root / "tool shims"
        self.shims.mkdir()
        self.base_image_temporary_directory = tempfile.TemporaryDirectory(prefix="ntp-base-image-")
        self.addCleanup(self.base_image_temporary_directory.cleanup)
        self.base_image_root = Path(self.base_image_temporary_directory.name)
        self.events = self.root / "events.log"
        self.bootstrap_arguments = self.root / "bootstrap-arguments.bin"
        self.release_arguments = self.root / "release-arguments.bin"
        account_raw = bytes([0]) + bytes(range(32))
        account_raw += binascii.crc_hqx(account_raw, 0).to_bytes(2, "little")
        # The builder checks PEM framing; the guest verifies X.509 CA semantics.
        bundle = {
            "schema_version": 1, "cell": "gru", "region": "GRU", "environment": "canary",
            "controller_endpoints": [f"10.251.0.{number}:8443" for number in (11, 12, 13)],
            "nats_urls": [f"tls://10.251.0.{number}:4222" for number in (11, 12, 13)],
            "ca_pem": "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
            "controller_response_public_key": base64.b64encode(bytes(range(32))).decode(),
            "cell_account_nkey": base64.b32encode(account_raw).decode(),
            "workload_uid": 2000, "workload_gid": 2000,
            "install_root": "/var/lib/terrascale-orchestrator-host/install",
            "state_root": "/var/lib/terrascale-orchestrator-host/state",
            "managed_runtime_root": MANAGED_DIRECTORY,
        }
        self.host_bundle = self.write_file(
            self.inputs / "host enrollment public.json", json.dumps(bundle, separators=(",", ":")).encode()
        )
        self.host_bundle_sha256 = hashlib.sha256(self.host_bundle.read_bytes()).hexdigest()
        self.priority_inputs = {
            "--runtime-priority-profile-id": RUNTIME_PRIORITY_PROFILE_ID,
            "--runtime-priority-system-reserve-bytes": str(RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES),
            "--host-memory-min-bytes": str(64 << 20),
            "--host-memory-low-bytes": str(128 << 20),
            "--controller-memory-min-bytes": str(64 << 20),
            "--controller-memory-low-bytes": str(128 << 20),
            "--system-slice-memory-min-bytes": str(128 << 20),
            "--system-slice-memory-low-bytes": str(256 << 20),
        }
        self.output = self.root / "candidate image.qcow2"

        write_executable(
            self.shims / "qemu-img",
            """#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  check) printf 'qemu-check\\n' >> "$EVENTS_PATH" ;;
  info)
    printf 'qemu-info\\n' >> "$EVENTS_PATH"
    printf '{"format":"qcow2","backing-filename":""}\\n'
    ;;
  *) exit 2 ;;
esac
""",
        )
        for directory in (
            "/etc/systemd/system", "/usr/lib/systemd/system", "/usr/local/lib/terrascale-orchestrator",
            "/etc/sysusers.d", "/usr/local/bin", "/var/lib", "/srv",
        ):
            (self.base_image_root / directory.lstrip("/")).mkdir(parents=True, exist_ok=True)
        (self.base_image_root / "srv").chmod(0o755)
        (self.base_image_root / "var/lib/dpkg").mkdir(parents=True)
        (self.base_image_root / "var/lib/dpkg/status").write_text(
            "Package: systemd\nStatus: install ok installed\nVersion: 255.4-1ubuntu8.12\n\n",
            encoding="utf-8",
        )
        for name, contents, mode in (
            ("passwd", "root:x:0:0:root:/root:/bin/bash\n", 0o644),
            ("group", "root:x:0:\n", 0o644),
            ("shadow", "root:*:0:0:99999:7:::\n", 0o640),
            ("gshadow", "root:*::\n", 0o640),
        ):
            file = self.base_image_root / "etc" / name
            file.write_text(contents, encoding="utf-8")
            file.chmod(mode)
        for name in ("systemd-timesyncd.service", "systemd-time-wait-sync.service"):
            (self.base_image_root / "usr/lib/systemd/system" / name).write_text(
                f"[Unit]\nDescription={name}\n[Install]\nWantedBy=sysinit.target\n", encoding="utf-8"
            )
        self.fs_metadata = self.root / "fs-metadata.json"
        write_executable(
            self.shims / "guestfish",
            r"""#!/usr/bin/env python3
import json, os, shutil, stat, sys
from pathlib import Path
root = Path(os.environ["BASE_IMAGE_ROOT_PATH"])
metadata_path = Path(os.environ["FS_METADATA_PATH"])
arguments = sys.argv[1:]
if "--listen" in arguments:
    with open(os.environ["EVENTS_PATH"], "a", encoding="utf-8") as stream:
        stream.write("guestfish-listen\n")
    print("GUESTFISH_PID=1; export GUESTFISH_PID")
    raise SystemExit(0)
assert arguments[0] == "--remote", arguments
command, *args = arguments[1:]
path = lambda guest: root / guest.lstrip("/")
dead_marker = Path(os.environ["GUESTFISH_DEAD_MARKER_PATH"])
if dead_marker.exists():
    raise SystemExit("guestfish: remote: looks like the server is not running")
metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
if command in ("is-symlink", "is-dir", "is-file", "exists"):
    target = path(args[0])
    result = {
        "is-symlink": target.is_symlink,
        "is-dir": target.is_dir,
        "is-file": target.is_file,
        "exists": target.exists,
    }[command]()
    print("true" if result else "false")
elif command == "lstatns":
    target = path(args[0])
    if os.environ.get("VIRT_FAIL_MISSING_LSTAT") == "1" and not target.exists() and not target.is_symlink():
        dead_marker.touch()
        raise SystemExit(f"libguestfs: error: lstatns: {args[0]}: No such file or directory")
    info = target.lstat()
    owner = metadata.get(args[0], [0, 0])
    for key, value in (
        ("st_mode", info.st_mode), ("st_uid", owner[0]), ("st_gid", owner[1]),
        ("st_nlink", info.st_nlink),
    ):
        print(f"{key}: {value}")
elif command == "ls":
    print("\n".join(sorted(child.name for child in path(args[0]).iterdir())))
elif command == "readlink":
    print(os.readlink(path(args[0])))
elif command == "download":
    shutil.copyfile(path(args[0]), args[1])
elif command == "copy-out":
    target = path(args[0])
    shutil.copytree(target, Path(args[1]) / target.name, symlinks=True)
elif command == "mkdir-p":
    path(args[0]).mkdir(parents=True, exist_ok=True)
elif command == "chown":
    metadata[args[2]] = [int(args[0]), int(args[1])]
elif command == "chmod":
    path(args[1]).chmod(int(args[0], 8))
elif command == "upload":
    target = path(args[1])
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args[0], target)
elif command == "ln-s":
    path(args[1]).symlink_to(args[0])
elif command != "exit":
    raise SystemExit(f"unsupported fake guestfish command: {command}")
metadata_path.write_text(json.dumps(metadata))
""",
        )
        write_executable(
            self.shims / "systemd-sysusers",
            r"""#!/usr/bin/env python3
import sys
from pathlib import Path
root = Path(sys.argv[1].split("=", 1)[1])
etc = root / "etc"
config = etc / "sysusers.d/terrascale-orchestrator.conf"
if len(sys.argv) != 3 or Path(sys.argv[2]) != config or not config.is_file():
    raise SystemExit("sysusers configuration must be passed as its staged host path")
with (etc / "passwd").open("a") as stream:
    stream.write("terrascale-workload:x:2000:2000:TerraScale Managed Workload:/var/empty:/usr/sbin/nologin\n")
    stream.write("terrascale-orchestrator:x:999:999:TerraScale Orchestrator:/var/lib/terrascale-orchestrator-controller:/usr/sbin/nologin\n")
with (etc / "group").open("a") as stream:
    stream.write("terrascale-workload:x:2000:\nterrascale-orchestrator:x:999:\n")
with (etc / "shadow").open("a") as stream:
    stream.write("terrascale-workload:!*:::::::\nterrascale-orchestrator:!*:::::::\n")
with (etc / "gshadow").open("a") as stream:
    stream.write("terrascale-workload:!*::\nterrascale-orchestrator:!*::\n")
""",
        )
        write_executable(
            self.shims / "systemctl",
            r"""#!/usr/bin/env python3
import os, sys
from pathlib import Path
if sys.argv[1] == "--version":
    print("systemd 260 (fake test tool)")
    raise SystemExit(0)
root = Path(sys.argv[1].split("=", 1)[1])
command = sys.argv[2]
names = sys.argv[3:]
if command == "enable":
    for name in names:
        source = root / "etc/systemd/system" / name
        if not source.exists():
            source = root / "usr/lib/systemd/system" / name
        if os.environ.get("VIRT_FAIL_TIME_UNITS") == "1" and name == "systemd-timesyncd.service":
            raise SystemExit("mock base image is missing a required systemd time unit")
        if not source.is_file():
            raise SystemExit("missing a required systemd time unit: " + name)
        section = None
        for raw in source.read_text().splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if section != "Install" or "=" not in line:
                continue
            key, value = line.split("=", 1)
            for item in value.split():
                if key == "WantedBy":
                    link = root / "etc/systemd/system" / (item + ".wants") / name
                elif key == "Alias":
                    link = root / "etc/systemd/system" / item
                else:
                    continue
                link.parent.mkdir(parents=True, exist_ok=True)
                if not link.is_symlink():
                    link.symlink_to(os.path.relpath(source, link.parent))
elif command == "is-enabled":
    if os.environ.get("VIRT_FAIL_TIME_UNITS") == "1" and names[0] == "systemd-timesyncd.service":
        raise SystemExit("missing a required systemd time unit")
    print("enabled")
else:
    raise SystemExit("unexpected systemctl operation")
""",
        )
        write_executable(
            self.shims / "virt-cat",
            """#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 && $1 == -a ]]
case "$3" in
  "$VIRT_NATIVE_VERIFIER_GUEST_PATH")
    if [[ ${VIRT_CORRUPT_NATIVE:-0} == 1 ]]; then
      printf 'corrupt guest bytes'
    else
      cat "$BASE_IMAGE_ROOT_PATH/$3"
    fi
    ;;
  "$VIRT_HOST_ENROLLMENT_GUEST_PATH") cat "$BASE_IMAGE_ROOT_PATH/$3" ;;
  *) exit 2 ;;
esac
""",
        )
        self.release_tool = self.root / "release tool"
        write_executable(
            self.release_tool,
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\0' "$@" > "$RELEASE_ARGUMENTS_PATH"
""",
        )
        self.bootstrap_tool = self.root / "bootstrap tool"
        write_executable(
            self.bootstrap_tool,
            """#!/usr/bin/env bash
set -euo pipefail
printf 'bootstrap-verify\\n' >> "$EVENTS_PATH"
printf '%s\\0' "$@" > "$BOOTSTRAP_ARGUMENTS_PATH"
if [[ "${BOOTSTRAP_VERIFY_FAIL:-0}" == 1 ]]; then
  echo 'mock anchor verification rejected' >&2
  exit 1
fi
printf '{}\\n'
""",
        )

    def write_file(self, path: Path, data: bytes) -> Path:
        path.write_bytes(data)
        return path

    def set_sfo_host_bundle(self) -> dict:
        self.identity.write_bytes(json.dumps({
            "schemaVersion": 1, "deploymentId": "deployment-sfo",
            "environment": "canary", "cell": "SFO",
        }, separators=(",", ":")).encode())
        bundle = json.loads(self.host_bundle.read_bytes())
        bundle["cell"] = "sfo"
        bundle["region"] = "SFO"
        bundle["controller_endpoints"] = [f"10.52.8.{number}:8443" for number in (101, 102, 103)]
        bundle["nats_urls"] = [f"tls://10.52.8.{number}:4222" for number in (101, 102, 103)]
        self.host_bundle.write_bytes(json.dumps(bundle, separators=(",", ":")).encode())
        return bundle

    def assert_baked_loader_accepts_roots(self, filenames: list[str]) -> None:
        source = BAKED_LOADER.read_text(encoding="utf-8")
        pattern_match = re.search(r"rootFilenameRE\s*=\s*regexp\.MustCompile\(`([^`]+)`\)", source)
        rejected_match = re.search(
            r'!rootFilenameRE\.MatchString\(name\)\s*\|\|\s*name\s*==\s*"([^"]+)"', source
        )
        count_match = re.search(r"MaxRootFiles\s*=\s*(\d+)", source)
        self.assertIsNotNone(pattern_match, "could not find baked loader root filename expression")
        self.assertIsNotNone(rejected_match, "could not find baked loader reserved root filename")
        self.assertIsNotNone(count_match, "could not find baked loader root file limit")
        pattern = pattern_match.group(1)
        reserved_name = rejected_match.group(1)
        self.assertLessEqual(len(filenames), int(count_match.group(1)))
        for filename in filenames:
            self.assertRegex(filename, pattern)
            self.assertNotEqual(filename, reserved_name)

    def test_builder_limits_match_baked_loader_contract(self) -> None:
        builder_source = BUILDER.read_text(encoding="utf-8")
        helper_source = OFFLINE_HELPER.read_text(encoding="utf-8")
        loader_source = BAKED_LOADER.read_text(encoding="utf-8")
        anchor_source = (ROOT / "internal/bootstrap/anchor.go").read_text(encoding="utf-8")
        baked_directory = re.search(r'BakedDirectory\s*=\s*"([^"]+)"', loader_source)
        builder_directory = re.search(r'^BOOTSTRAP = "([^"]+)"$', helper_source, re.MULTILINE)
        self.assertIsNotNone(baked_directory, "could not find baked loader directory")
        self.assertIsNotNone(builder_directory, "could not find builder baked directory")
        self.assertEqual(builder_directory.group(1), baked_directory.group(1))

        def bash_limit(name: str) -> int:
            match = re.search(rf"^{name}=(\d+)$", builder_source, re.MULTILINE)
            self.assertIsNotNone(match, f"could not find builder limit {name}")
            return int(match.group(1))

        def go_limit(source: str, name: str) -> int:
            match = re.search(rf"\b{name}\s*=\s*(\d+)(?:\s*<<\s*(\d+))?", source)
            self.assertIsNotNone(match, f"could not find runtime limit {name}")
            return int(match.group(1)) << int(match.group(2) or "0")

        self.assertEqual(bash_limit("bootstrap_root_limit"), go_limit(loader_source, "MaxRootFiles"))
        self.assertEqual(bash_limit("bootstrap_root_max_bytes"), go_limit(loader_source, "MaxRootBytes"))
        self.assertEqual(
            bash_limit("bootstrap_roots_max_total_bytes"), go_limit(loader_source, "MaxRootsTotal")
        )
        self.assertEqual(bash_limit("bootstrap_identity_max_bytes"), go_limit(loader_source, "maxIdentity"))
        self.assertEqual(
            bash_limit("bootstrap_anchor_max_bytes"), go_limit(anchor_source, "MaxBootstrapAnchorBytes")
        )

    def builder_environment(self, **overrides: str) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.shims}{os.pathsep}{Path(sys.executable).parent}:/run/current-system/sw/bin:/usr/bin:/bin",
                "EVENTS_PATH": str(self.events),
                "BOOTSTRAP_ARGUMENTS_PATH": str(self.bootstrap_arguments),
                "RELEASE_ARGUMENTS_PATH": str(self.release_arguments),
                "VIRT_NATIVE_VERIFIER_GUEST_PATH": NATIVE_VERIFIER_GUEST,
                "VIRT_HOST_ENROLLMENT_GUEST_PATH": HOST_ENROLLMENT_GUEST,
                "BASE_IMAGE_ROOT_PATH": str(self.base_image_root),
                "FS_METADATA_PATH": str(self.fs_metadata),
                "GUESTFISH_DEAD_MARKER_PATH": str(self.root / "guestfish-dead"),
            }
        )
        environment.update(overrides)
        return environment

    def run_builder(self, *, host_enrollment_public: Path | None = None,
                    host_enrollment_public_sha256: str | None = None,
                    native_verifier_binary: Path | None = None,
                    native_verifier_sha256: str | None = None,
                    **environment_overrides: str) -> subprocess.CompletedProcess[str]:
        return self.run_builder_with_roots(
            [self.bootstrap_root_a, self.bootstrap_root_b],
            host_enrollment_public=host_enrollment_public,
            host_enrollment_public_sha256=host_enrollment_public_sha256,
            native_verifier_binary=native_verifier_binary,
            native_verifier_sha256=native_verifier_sha256,
            **environment_overrides
        )

    def run_builder_with_roots(
        self, bootstrap_roots: list[Path], *, host_enrollment_public: Path | None = None,
        host_enrollment_public_sha256: str | None = None,
        native_verifier_binary: Path | None = None,
        native_verifier_sha256: str | None = None,
        **environment_overrides: str
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            str(BUILDER),
            "--base",
            str(self.base),
            "--binary",
            str(self.binary),
            "--native-verifier-binary",
            str(native_verifier_binary or self.native_verifier),
            "--native-verifier-sha256",
            native_verifier_sha256 or self.native_verifier_sha256,
            "--receipt",
            str(self.receipt),
            "--qualification",
            str(self.qualification),
            "--delegation",
            str(self.delegation),
            "--root-key",
            str(self.release_root),
            "--environment",
            "canary",
            "--release-tool",
            str(self.release_tool),
            "--bootstrap-tool",
            str(self.bootstrap_tool),
            "--bootstrap-anchor",
            str(self.anchor),
            "--bootstrap-identity",
            str(self.identity),
            "--timesyncd-config",
            str(self.timesyncd_config),
        ]
        for flag, value in self.priority_inputs.items():
            arguments.extend((flag, value))
        for bootstrap_root in bootstrap_roots:
            arguments.extend(("--bootstrap-root", str(bootstrap_root)))
        if host_enrollment_public is not None:
            arguments.extend(("--host-enrollment-public", str(host_enrollment_public)))
        if host_enrollment_public_sha256 is not None:
            arguments.extend(("--host-enrollment-public-sha256", host_enrollment_public_sha256))
        arguments.extend(("--out", str(self.output)))
        return subprocess.run(
            arguments,
            cwd=ROOT,
            env=self.builder_environment(**environment_overrides),
            capture_output=True,
            check=False,
            text=True,
        )

    def test_verified_public_inputs_and_directories_are_installed_offline(self) -> None:
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), self.base.read_bytes())
        events = self.events.read_text(encoding="utf-8").splitlines()
        self.assertLess(events.index("bootstrap-verify"), events.index("guestfish-listen"))
        self.assertEqual(events.count("qemu-check"), 2)

        bootstrap_arguments = self.bootstrap_arguments.read_bytes().split(b"\0")[:-1]
        self.assertEqual([part.decode() for part in bootstrap_arguments], [
            "verify-anchor", "--anchor", str(self.anchor), "--identity", str(self.identity),
            "--root-key", str(self.bootstrap_root_a), "--root-key", str(self.bootstrap_root_b),
        ])
        release_arguments = [part.decode() for part in self.release_arguments.read_bytes().split(b"\0")[:-1]]
        self.assertEqual(release_arguments[release_arguments.index("--root-key") + 1], str(self.release_root))
        self.assertEqual(release_arguments[release_arguments.index("--qualification") + 1], str(self.qualification))
        self.assertNotIn(str(self.bootstrap_root_a), release_arguments)

        root = self.base_image_root
        metadata = json.loads(self.fs_metadata.read_text())
        def installed(path: str, contents: bytes, mode: int = 0o644,
                      owner: tuple[int, int] = (0, 0)) -> None:
            file = root / path.lstrip("/")
            self.assertTrue(file.is_file() and not file.is_symlink(), path)
            self.assertEqual(file.read_bytes(), contents, path)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), mode, path)
            self.assertEqual(tuple(metadata[path]), owner, path)
            self.assertEqual(file.stat().st_nlink, 1, path)

        installed(f"{BOOTSTRAP_DIRECTORY}/anchor.json", self.anchor.read_bytes(), 0o444)
        installed(f"{BOOTSTRAP_DIRECTORY}/identity.json", self.identity.read_bytes(), 0o444)
        for index, source in enumerate((self.bootstrap_root_a, self.bootstrap_root_b), 1):
            installed(f"{BOOTSTRAP_DIRECTORY}/trust-roots/{index:03d}.pem", source.read_bytes(), 0o444)
        self.assert_baked_loader_accepts_roots(["001.pem", "002.pem"])
        installed(NATIVE_VERIFIER_GUEST, self.native_verifier.read_bytes(), 0o755)
        self.assertIn(f"native verifier image sha256={self.native_verifier_sha256}", result.stdout)
        installed("/usr/local/bin/terrascale-orchestrator", self.binary.read_bytes(), 0o755)
        installed(RUNTIME_PRIORITY_HELPER_GUEST, RUNTIME_PRIORITY_QUALIFIER.read_bytes(), 0o755)
        installed(TIME_WAIT_SYNC_DROPIN, b"[Service]\nTimeoutStartSec=300s\n")
        normalized_time = b"[Time]\nNTP=\nNTP=ntp.deployment.example\nFallbackNTP=\n"
        installed(TIMESYNCD_CONFIG_GUEST, normalized_time)
        self.assertIn(hashlib.sha256(normalized_time).hexdigest(), result.stdout)
        profile = json.dumps({
            "version": 1, "profile_id": RUNTIME_PRIORITY_PROFILE_ID,
            "system_reserve_bytes": RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES,
        }, separators=(",", ":")).encode()
        installed(RUNTIME_PRIORITY_PROFILE_GUEST, profile)
        for guest_path, section, minimum, low in (
            (RUNTIME_PRIORITY_DROPINS[0], "[Slice]", 128 << 20, 256 << 20),
            (RUNTIME_PRIORITY_DROPINS[1], "[Service]", 64 << 20, 128 << 20),
            (RUNTIME_PRIORITY_DROPINS[2], "[Service]", 64 << 20, 128 << 20),
        ):
            content = (root / guest_path.lstrip("/")).read_text()
            self.assertIn(section, content)
            self.assertIn(f"MemoryMin={minimum}\n", content)
            self.assertIn(f"MemoryLow={low}\n", content)
            self.assertIn(hashlib.sha256(content.encode()).hexdigest(), result.stdout)
        self.assertEqual(tuple(metadata[SECRETS_DIRECTORY]), (999, 999))
        self.assertEqual(tuple(metadata[CONTROLLER_DIRECTORY]), (999, 999))
        self.assertEqual(stat.S_IMODE((root / SECRETS_DIRECTORY.lstrip("/")).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((root / CONTROLLER_DIRECTORY.lstrip("/")).stat().st_mode), 0o700)
        self.assertEqual(tuple(metadata[MARKER_DIRECTORY]), (0, 0))
        passwd = (root / "etc/passwd").read_text()
        group = (root / "etc/group").read_text()
        self.assertIn("terrascale-workload:x:2000:2000:", passwd)
        self.assertIn("terrascale-workload:x:2000:", group)
        self.assertIn("terrascale-orchestrator:x:999:999:", passwd)
        for unit in ("systemd-timesyncd.service", "systemd-time-wait-sync.service"):
            link = root / "etc/systemd/system/sysinit.target.wants" / unit
            self.assertTrue(link.is_symlink(), unit)
        for unit in ("terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service"):
            link = root / "etc/systemd/system/multi-user.target.wants" / unit
            self.assertTrue(link.is_symlink(), unit)
        self.assertFalse((root / "etc/systemd/system/multi-user.target.wants/terrascale-orchestrator-bootstrap.service").exists())
        self.assertNotIn("--run-command", BUILDER.read_text())
        for private_input in (self.receipt, self.release_root, self.delegation):
            self.assertFalse((root / private_input.name).exists())

    def test_native_verifier_rejects_wrong_digest_and_architecture_before_image_copy(self) -> None:
        wrong_digest = "0" * 64
        result = self.run_builder(native_verifier_sha256=wrong_digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native verifier bytes do not match", result.stderr)
        self.assertNotIn("guestfish-listen", self.events.read_text())
        self.assertFalse(self.output.exists())

        native_bytes = bytearray(self.native_verifier.read_bytes())
        struct.pack_into("<H", native_bytes, 18, 62)
        self.native_verifier.write_bytes(native_bytes)
        result = self.run_builder(
            native_verifier_sha256=hashlib.sha256(native_bytes).hexdigest()
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ELF64 little-endian AArch64", result.stderr)
        self.assertNotIn("guestfish-listen", self.events.read_text())
        self.assertFalse(self.output.exists())

    def test_native_verifier_guest_readback_mismatch_discards_candidate(self) -> None:
        result = self.run_builder(VIRT_CORRUPT_NATIVE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed native verifier bytes do not match", result.stderr)
        self.assertFalse(self.output.exists())

    def test_missing_application_lib_parent_is_created_from_pristine_base(self) -> None:
        parent = self.base_image_root / "usr/local/lib/terrascale-orchestrator"
        parent.rmdir()
        result = self.run_builder(VIRT_FAIL_MISSING_LSTAT="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(parent.is_dir() and not parent.is_symlink())
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
        self.assertEqual(tuple(json.loads(self.fs_metadata.read_text())["/usr/local/lib/terrascale-orchestrator"]),
                         (0, 0))
        self.assertTrue(self.output.exists())
        self.assertFalse((self.root / "guestfish-dead").exists())

    def test_missing_upload_directories_are_created_before_install(self) -> None:
        paths = (
            "/etc/sysusers.d", "/etc/systemd/system", "/etc/systemd", "/usr/local/bin",
        )
        for path in paths:
            (self.base_image_root / path.lstrip("/")).rmdir()
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads(self.fs_metadata.read_text())
        for path in paths:
            directory = self.base_image_root / path.lstrip("/")
            self.assertTrue(directory.is_dir() and not directory.is_symlink(), path)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755, path)
            self.assertEqual(tuple(metadata[path]), (0, 0), path)
        self.assertTrue((self.base_image_root / "etc/sysusers.d/terrascale-orchestrator.conf").is_file())
        self.assertTrue(self.output.exists())

    def test_unsafe_existing_native_verifier_parents_fail_closed(self) -> None:
        parent = self.base_image_root / "usr/local/lib/terrascale-orchestrator"
        parent.rmdir()
        parent.symlink_to("/tmp")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native verifier parent must be a root-owned nonwritable directory", result.stderr)
        self.assertIn("(kind=symlink)", result.stderr)
        self.assertFalse(self.output.exists())

        parent.unlink()
        parent.symlink_to("missing-target")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(kind=symlink)", result.stderr)
        self.assertFalse(self.output.exists())

        parent.unlink()
        os.mkfifo(parent)
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(kind=other)", result.stderr)
        self.assertFalse(self.output.exists())

        parent.unlink()
        parent.mkdir(mode=0o755)
        parent.chmod(0o777)
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native verifier parent must be a root-owned nonwritable directory", result.stderr)
        self.assertIn("mode=0777", result.stderr)
        self.assertFalse(self.output.exists())

        parent.chmod(0o755)
        ancestor = self.base_image_root / "usr/local/lib"
        ancestor.chmod(0o777)
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native verifier parent must be a root-owned nonwritable directory: /usr/local/lib",
                      result.stderr)
        self.assertIn("mode=0777", result.stderr)
        self.assertFalse(self.output.exists())

    def test_runtime_priority_artifacts_must_be_absent_in_base_image(self) -> None:
        for guest_path in (
            RUNTIME_PRIORITY_PROFILE_GUEST,
            *RUNTIME_PRIORITY_DROPINS,
            RUNTIME_PRIORITY_HELPER_GUEST,
        ):
            with self.subTest(path=guest_path):
                existing = self.base_image_root / guest_path.lstrip("/")
                existing.parent.mkdir(parents=True, exist_ok=True)
                existing.write_text("conflicting image file\n", encoding="utf-8")

                result = self.run_builder()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "base image has a conflicting runtime-priority profile artifact",
                    result.stderr,
                )
                self.assertFalse(self.output.exists())
                self.assertFalse(self.output.exists())

                existing.unlink()

        self.assertIn("guestfish-listen", self.events.read_text(encoding="utf-8"))

    def test_reserved_workload_identity_collision_fails_before_installation(self) -> None:
        with (self.base_image_root / "etc/passwd").open("a") as stream:
            stream.write("base-user:x:2000:2000:Existing:/var/empty:/usr/sbin/nologin\n")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved managed workload UID, GID, or name", result.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse((self.base_image_root / NATIVE_VERIFIER_GUEST.lstrip("/")).exists())

    def test_symlinked_upload_parent_fails_closed(self) -> None:
        sysusers = self.base_image_root / "etc/sysusers.d"
        sysusers.rmdir()
        sysusers.symlink_to("/tmp")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guest directory is not a direct directory: /etc/sysusers.d", result.stderr)
        self.assertFalse(self.output.exists())

        sysusers.unlink()
        sysusers.mkdir()
        binary = self.base_image_root / "usr/local/bin"
        binary.rmdir()
        binary.symlink_to("/tmp")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guest directory is not a direct directory: /usr/local/bin", result.stderr)
        self.assertFalse(self.output.exists())

    def test_guest_systemd_version_must_match_audited_noble_semantics(self) -> None:
        (self.base_image_root / "var/lib/dpkg/status").write_text(
            "Package: systemd\nStatus: install ok installed\nVersion: 256.1\n\n",
            encoding="utf-8",
        )
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("audited Noble systemd 255", result.stderr)
        self.assertFalse(self.output.exists())

    def test_unsupported_unit_install_directive_fails_before_enablement(self) -> None:
        unit = self.base_image_root / "usr/lib/systemd/system/systemd-timesyncd.service"
        unit.write_text("[Install]\nWantedBy=sysinit.target\nFoo=bar\n", encoding="utf-8")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported systemd [Install] entry", result.stderr)
        self.assertFalse(self.output.exists())

    def test_runtime_priority_profile_rejects_slice_floor_below_child_aggregate(self) -> None:
        self.priority_inputs["--system-slice-memory-min-bytes"] = str(64 << 20)
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("system.slice floors must cover aggregate", result.stderr)
        self.assertFalse(self.events.exists())
        self.assertFalse(self.events.exists())
        self.assertFalse(self.output.exists())

    def test_target_probe_fails_closed_when_baked_reserve_differs_from_placement(self) -> None:
        profile_path = self.root / "runtime-priority.json"
        wire = json.dumps(
            {
                "version": 1,
                "profile_id": RUNTIME_PRIORITY_PROFILE_ID,
                "system_reserve_bytes": RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES,
            },
            separators=(",", ":"),
        ).encode()
        profile_path.write_bytes(wire)
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
        )
        args = SimpleNamespace(
            profile_id=RUNTIME_PRIORITY_PROFILE_ID,
            system_reserve_bytes=RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES + 4096,
        )
        with (
            patch.object(
                RUNTIME_PRIORITY_QUALIFIER_MODULE,
                "RUNTIME_PRIORITY_PROFILE",
                profile_path,
            ),
            patch.object(Path, "lstat", return_value=metadata),
        ):
            probe = RUNTIME_PRIORITY_QUALIFIER_MODULE.Probe(args)
            with self.assertRaisesRegex(
                RUNTIME_PRIORITY_QUALIFIER_MODULE.QualificationError,
                "profile ID/reserve differs",
            ):
                probe.verify_baked_profile()

    def test_target_probe_accepts_only_canonical_matching_baked_reserve(self) -> None:
        profile_path = self.root / "runtime-priority.json"
        wire = json.dumps(
            {
                "version": 1,
                "profile_id": RUNTIME_PRIORITY_PROFILE_ID,
                "system_reserve_bytes": RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES,
            },
            separators=(",", ":"),
        ).encode()
        profile_path.write_bytes(wire)
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
        )
        args = SimpleNamespace(
            profile_id=RUNTIME_PRIORITY_PROFILE_ID,
            system_reserve_bytes=RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES,
        )
        with (
            patch.object(
                RUNTIME_PRIORITY_QUALIFIER_MODULE,
                "RUNTIME_PRIORITY_PROFILE",
                profile_path,
            ),
            patch.object(Path, "lstat", return_value=metadata),
        ):
            result = RUNTIME_PRIORITY_QUALIFIER_MODULE.Probe(args).verify_baked_profile()
        self.assertEqual(result["sha256"], hashlib.sha256(wire).hexdigest())
        self.assertEqual(result["profile_id"], RUNTIME_PRIORITY_PROFILE_ID)
        self.assertEqual(result["system_reserve_bytes"], RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES)

    def test_packaged_probe_does_not_require_a_git_checkout(self) -> None:
        packaged = self.root / "usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py"
        packaged.parent.mkdir(parents=True)
        packaged.write_text("# packaged helper\n", encoding="utf-8")
        with patch.object(RUNTIME_PRIORITY_QUALIFIER_MODULE, "__file__", str(packaged)):
            revision, unit_directory = RUNTIME_PRIORITY_QUALIFIER_MODULE.Probe(
                SimpleNamespace()
            ).source_identity()
        self.assertIsNone(revision)
        self.assertEqual(unit_directory, Path("/etc/systemd/system"))

    def test_host_bundle_provisions_fixed_managed_root_and_setup_units(self) -> None:
        host_unit = (ROOT / "deploy/systemd/terrascale-orchestrator-host.service").read_text()
        self.assertIn("ProtectSystem=strict\n", host_unit)
        self.assertIn(f"ReadWritePaths=-{MANAGED_DIRECTORY}\n", host_unit)
        result = self.run_builder(host_enrollment_public=self.host_bundle,
                                  host_enrollment_public_sha256=self.host_bundle_sha256)
        self.assertEqual(result.returncode, 0, result.stderr)
        root = self.base_image_root
        self.assertEqual((root / HOST_ENROLLMENT_GUEST.lstrip("/")).read_bytes(), self.host_bundle.read_bytes())
        self.assertEqual(stat.S_IMODE((root / HOST_ENROLLMENT_GUEST.lstrip("/")).stat().st_mode), 0o444)
        self.assertIn(f"host enrollment image sha256={self.host_bundle_sha256}", result.stdout)
        managed = root / MANAGED_DIRECTORY.lstrip("/")
        self.assertTrue(managed.is_dir() and not managed.is_symlink())
        self.assertEqual(stat.S_IMODE(managed.stat().st_mode), 0o750)
        metadata = json.loads(self.fs_metadata.read_text())
        self.assertEqual(tuple(metadata[MANAGED_DIRECTORY]), (0, 2000))
        for unit, target in (("terrascale-orchestrator-host-setup.service", "multi-user.target"),
                             ("terrascale-orchestrator-host-setup.timer", "timers.target")):
            self.assertTrue((root / "etc/systemd/system" / (target + ".wants") / unit).is_symlink())

    def test_sfo_host_bundle_matches_baked_identity_and_is_installed(self) -> None:
        self.set_sfo_host_bundle()
        digest = hashlib.sha256(self.host_bundle.read_bytes()).hexdigest()
        result = self.run_builder(host_enrollment_public=self.host_bundle,
                                  host_enrollment_public_sha256=digest)
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = self.base_image_root / HOST_ENROLLMENT_GUEST.lstrip("/")
        self.assertEqual(installed.read_bytes(), self.host_bundle.read_bytes())
        self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o444)
        self.assertIn(f"host enrollment image sha256={digest}", result.stdout)

    def test_sfo_host_bundle_mismatches_fail_before_image_effects(self) -> None:
        bundle = self.set_sfo_host_bundle()
        cases = (
            ("cell region mapping", {"region": "FRA"}, None, "cell and region differ"),
            ("baked identity cell", {}, "FRA", "region differs from bootstrap identity"),
            ("release environment", {"environment": "production"}, None,
             "environment differs from release environment"),
            ("reviewed digest", {}, None, "differs from its reviewed SHA-256"),
        )
        original_identity = self.identity.read_bytes()
        for name, changes, identity_cell, expected_error in cases:
            with self.subTest(name=name):
                candidate = {**bundle, **changes}
                self.host_bundle.write_bytes(json.dumps(candidate, separators=(",", ":")).encode())
                identity = json.loads(original_identity)
                if identity_cell is not None:
                    identity["cell"] = identity_cell
                self.identity.write_bytes(json.dumps(identity, separators=(",", ":")).encode())
                digest = hashlib.sha256(self.host_bundle.read_bytes()).hexdigest()
                if name == "reviewed digest":
                    digest = "0" * 64
                result = self.run_builder(host_enrollment_public=self.host_bundle,
                                          host_enrollment_public_sha256=digest)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse(self.output.exists())

    def test_host_bundle_requires_paired_digest_before_image_effects(self) -> None:
        for inputs in (
            {"host_enrollment_public": self.host_bundle},
            {"host_enrollment_public_sha256": self.host_bundle_sha256},
            {"host_enrollment_public": self.host_bundle,
             "host_enrollment_public_sha256": "0" * 64},
        ):
            with self.subTest(inputs=inputs):
                result = self.run_builder(**inputs)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.events.exists())
                self.assertFalse(self.output.exists())

    def test_shipped_host_sandbox_allows_only_its_writable_managed_path(self) -> None:
        if os.geteuid() == 0 or any(shutil.which(command) is None for command in
                                    ("sudo", "systemctl", "systemd-run", "install", "touch", "sh")):
            self.skipTest("requires a nonroot host user, systemd and passwordless sudo")
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
            self.skipTest("passwordless sudo is unavailable")
        if subprocess.run(["systemctl", "show", "--property=Version", "--value"],
                          capture_output=True).returncode != 0:
            self.skipTest("systemd system manager is unavailable")

        unit = (ROOT / "deploy/systemd/terrascale-orchestrator-host.service").read_text(encoding="utf-8")
        directives = dict(line.split("=", 1) for line in unit.splitlines()
                          if "=" in line and not line.startswith("#"))
        self.assertEqual(directives["ProtectSystem"], "strict")
        self.assertEqual(directives["ReadWritePaths"], "-" + MANAGED_DIRECTORY)
        with tempfile.TemporaryDirectory(prefix="ts-managed-sandbox-") as name:
            base = Path(name)
            base.chmod(0o755)
            allowed, denied = base / "allowed", base / "denied"
            for path in (allowed, denied):
                subprocess.run(["sudo", "-n", "install", "-d", "-o", "root", "-g", "root",
                                "-m", "0755", str(path)], check=True, timeout=10)
            try:
                script = '"$3" "$1/created" || exit 21; if "$3" "$2/created"; then exit 22; fi; exit 0'
                properties = ["User", "Group", "ProtectSystem", "NoNewPrivileges",
                              "CapabilityBoundingSet", "AmbientCapabilities"]
                result = subprocess.run(
                    ["sudo", "-n", "systemd-run", "--wait", "--collect",
                     "--unit=ts-managed-sandbox-" + secrets.token_hex(5),
                     *("--property=" + key + "=" + directives[key] for key in properties),
                     "--property=ReadWritePaths=-" + str(allowed), shutil.which("sh"),
                     "-c", script, "probe", str(allowed), str(denied), shutil.which("touch")],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((allowed / "created").exists())
                self.assertFalse((denied / "created").exists())
            finally:
                subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(allowed), str(denied)],
                               check=True, timeout=10)

    def test_timesyncd_configuration_is_required_explicit_and_excludes_lab_range(self) -> None:
        self.timesyncd_config.unlink()
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())
        self.assertFalse(self.events.exists())
        self.assertFalse(self.output.exists())

        for label, invalid_config in (
            ("empty NTP list", b"[Time]\nNTP=\n"),
            ("lab endpoint", b"[Time]\nNTP=198.19.8.1\n"),
            (
                "lab endpoint accumulates without reset",
                b"[Time]\nNTP=198.19.8.1\nNTP=ntp.deployment.example\n",
            ),
            (
                "empty reset removes all endpoints",
                b"[Time]\nNTP=ntp.deployment.example\nNTP=\n",
            ),
            ("oversize config", b"[Time]\nNTP=ntp.example\n" + b"#" * (16 * 1024)),
            ("unsupported continuation", b"[Time]\nNTP=ntp.example \\\nntp2.example\n"),
        ):
            with self.subTest(config=label):
                self.timesyncd_config.write_bytes(invalid_config)
                result = self.run_builder()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.events.exists(), result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse(self.output.exists())

        self.timesyncd_config.write_bytes(
            b"# Systemd empty assignments reset earlier list members.\n"
            b"[Time]\nPollIntervalSec=32\nNTP=198.19.8.1\nNTP=\nNTP=ntp.deployment.example\n"
            b"FallbackNTP=198.19.3.5\nFallbackNTP=\nFallbackNTP=fallback.deployment.example\n"
        )
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        generated_timesyncd_config = (
            b"# Systemd empty assignments reset earlier list members.\n"
            b"[Time]\nPollIntervalSec=32\nNTP=\nNTP=ntp.deployment.example\n"
            b"FallbackNTP=\nFallbackNTP=fallback.deployment.example\n"
        )
        self.assertEqual((self.base_image_root / TIMESYNCD_CONFIG_GUEST.lstrip("/")).read_bytes(), generated_timesyncd_config)
        self.assertNotIn(b"198.19.", (self.base_image_root / TIMESYNCD_CONFIG_GUEST.lstrip("/")).read_bytes())
        self.assertIn(hashlib.sha256(generated_timesyncd_config).hexdigest(), result.stdout)

    def test_competing_base_timesyncd_configuration_fails_closed(self) -> None:
        competing_config = self.base_image_root / "etc/systemd/timesyncd.conf.d/20-base.conf"
        competing_config.parent.mkdir(parents=True)
        competing_config.write_text("[Time]\nNTP=base.example\n", encoding="utf-8")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("base image has active NTP/FallbackNTP configuration", result.stderr)
        self.assertIn("/etc/systemd/timesyncd.conf.d/20-base.conf", result.stderr)
        self.assertFalse(self.output.exists())
        self.assertIn("guestfish-listen", self.events.read_text(encoding="utf-8"))

    def test_base_time_config_section_and_dropin_mask_precedence_are_respected(self) -> None:
        masked_name = "20-base.conf"
        lower_config = self.base_image_root / "usr/lib/systemd/timesyncd.conf.d" / masked_name
        lower_config.parent.mkdir(parents=True)
        lower_config.write_text("[Time]\nNTP=hidden.example\n", encoding="utf-8")
        mask = self.base_image_root / "etc/systemd/timesyncd.conf.d" / masked_name
        mask.parent.mkdir(parents=True)
        mask.symlink_to("/dev/null")
        unrelated_section = self.base_image_root / "etc/systemd/timesyncd.conf.d/30-other.conf"
        unrelated_section.write_text("[Other]\nNTP=not-timesyncd.example\n", encoding="utf-8")

        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.exists())

    def test_missing_time_sync_units_abort_image_creation(self) -> None:
        result = self.run_builder(VIRT_FAIL_TIME_UNITS="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing a required systemd time unit", result.stderr)
        self.assertFalse(self.output.exists())
        self.assertIn("guestfish-listen", self.events.read_text(encoding="utf-8"))

    def test_controller_waits_for_bounded_systemd_clock_sync_before_bootstrap(self) -> None:
        bootstrap_unit = (ROOT / "deploy/systemd/terrascale-orchestrator-bootstrap.service").read_text(encoding="utf-8")
        controller_unit = (ROOT / "deploy/systemd/terrascale-orchestrator-controller.service").read_text(encoding="utf-8")
        self.assertIn(
            "Requires=systemd-timesyncd.service systemd-time-wait-sync.service",
            bootstrap_unit,
        )
        self.assertIn(
            "After=systemd-timesyncd.service systemd-time-wait-sync.service",
            bootstrap_unit,
        )
        self.assertIn("TimeoutStartSec=300s", bootstrap_unit)
        self.assertIn("Type=oneshot", bootstrap_unit)
        self.assertIn("Restart=on-failure", bootstrap_unit)
        self.assertIn("RestartSec=10s", bootstrap_unit)
        self.assertIn("OnSuccess=terrascale-orchestrator-controller.service", bootstrap_unit)
        self.assertIn(
            "CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID CAP_DAC_OVERRIDE CAP_KILL",
            bootstrap_unit,
        )
        self.assertIn(
            f"ReadWritePaths={MARKER_DIRECTORY} {SECRETS_DIRECTORY} {CONTROLLER_DIRECTORY} /run/terrascale-orchestrator-bootstrap",
            bootstrap_unit,
        )
        self.assertIn(
            "Requires=terrascale-orchestrator-bootstrap.service",
            controller_unit,
        )
        self.assertIn("After=terrascale-orchestrator-bootstrap.service", controller_unit)

    def test_rejected_anchor_prevents_guest_copy_and_output_creation(self) -> None:
        result = self.run_builder(BOOTSTRAP_VERIFY_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.events.read_text(encoding="utf-8").splitlines(), ["bootstrap-verify"])
        self.assertEqual(list(self.root.glob(".ts-orchestrator-image.*")), [])

    def test_bootstrap_environment_must_match_release_environment_before_verification(self) -> None:
        self.identity.write_bytes(
            b'{"schemaVersion":1,"deploymentId":"deployment-a","environment":"production","cell":"GRU"}'
        )
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bootstrap identity environment must match", result.stderr)
        self.assertFalse(self.bootstrap_arguments.exists())
        self.assertFalse(self.events.exists())
        self.assertFalse(self.output.exists())

    def test_bootstrap_identity_must_match_baked_schema_and_canonical_field_order(self) -> None:
        self.identity.write_bytes(
            b'{"deploymentId":"deployment-a","environment":"canary","cell":"GRU"}'
        )
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schemaVersion, deploymentId, environment, and cell", result.stderr)
        self.assertFalse(self.bootstrap_arguments.exists())
        self.assertFalse(self.events.exists())

        self.identity.write_bytes(
            b'{"deploymentId":"deployment-a","schemaVersion":1,"environment":"canary","cell":"GRU"}'
        )
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical schema-version-1 JSON", result.stderr)
        self.assertFalse(self.bootstrap_arguments.exists())
        self.assertFalse(self.events.exists())

    def test_baked_input_sizes_and_root_set_bounds_are_enforced_before_verification(self) -> None:
        loader_source = BAKED_LOADER.read_text(encoding="utf-8")
        max_roots_match = re.search(r"MaxRootFiles\s*=\s*(\d+)", loader_source)
        self.assertIsNotNone(max_roots_match)
        too_many_roots = [
            self.write_file(self.inputs / f"root-{index:02d}.pem", b"root")
            for index in range(int(max_roots_match.group(1)) + 1)
        ]
        too_large_root = self.write_file(self.inputs / "oversize root.pem", b"r" * (16 * 1024 + 1))
        too_many_root_bytes = [
            self.write_file(self.inputs / f"large-root-{index}.pem", b"r" * (16 * 1024))
            for index in range(5)
        ]

        cases = (
            ("too many roots", too_many_roots, None, None),
            ("per-root byte limit", [too_large_root], None, None),
            ("total root byte limit", too_many_root_bytes, None, None),
            ("identity byte limit", [self.bootstrap_root_a], b"x" * (4 * 1024 + 1), None),
            ("anchor byte limit", [self.bootstrap_root_a], None, b"x" * (64 * 1024 + 1)),
        )
        for label, roots, identity_bytes, anchor_bytes in cases:
            with self.subTest(label=label):
                self.events.unlink(missing_ok=True)
                self.output.unlink(missing_ok=True)
                self.bootstrap_arguments.unlink(missing_ok=True)
                self.identity.write_bytes(
                    identity_bytes
                    if identity_bytes is not None
                    else b'{"schemaVersion":1,"deploymentId":"deployment-a","environment":"canary","cell":"GRU"}'
                )
                self.anchor.write_bytes(
                    anchor_bytes if anchor_bytes is not None else b"mock signed anchor v2"
                )

                result = self.run_builder_with_roots(roots)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(self.events.exists(), result.stderr)
                self.assertFalse(self.bootstrap_arguments.exists())
                self.assertFalse(self.events.exists())
                self.assertFalse(self.output.exists())

    def test_sysusers_account_matches_controller_service_user_and_group(self) -> None:
        sysusers_lines = [
            line.strip()
            for line in (ROOT / "deploy/image/terrascale-orchestrator.sysusers").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        users = [shlex.split(line) for line in sysusers_lines if line.startswith("u ")]
        self.assertEqual(len(users), 2)
        by_name = {entry[1]: entry for entry in users}
        self.assertEqual(by_name["terrascale-workload"][2], "2000:2000")
        self.assertIn("g terrascale-workload 2000", sysusers_lines)

        unit = (ROOT / "deploy/systemd/terrascale-orchestrator-controller.service").read_text(encoding="utf-8")
        unit_user = next(line.split("=", 1)[1] for line in unit.splitlines() if line.startswith("User="))
        unit_group = next(line.split("=", 1)[1] for line in unit.splitlines() if line.startswith("Group="))
        self.assertEqual(by_name["terrascale-orchestrator"][2], "-")
        self.assertEqual(unit_user, "terrascale-orchestrator")
        self.assertEqual(unit_group, "terrascale-orchestrator")
        self.assertIn(unit_user, by_name)
        self.assertEqual(unit_user, unit_group)


class GuestfishListenTests(unittest.TestCase):
    def test_persistent_child_stderr_does_not_hold_launch_open(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ts-guestfish-listen-") as directory:
            root = Path(directory)
            child_pid = root / "child.pid"
            write_executable(
                root / "guestfish",
                """#!/usr/bin/env python3
import os, subprocess, sys
from pathlib import Path

if "--listen" in sys.argv:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
    )
    Path(os.environ["GUESTFISH_CHILD_PID_FILE"]).write_text(str(child.pid))
    print(f"GUESTFISH_PID={child.pid}; export GUESTFISH_PID", flush=True)
elif sys.argv[1:] != ["--remote", "exit"]:
    raise SystemExit("unexpected remote command")
""",
            )
            environment = dict(os.environ)
            environment["PATH"] = os.pathsep.join(
                (str(root), str(Path(sys.executable).parent), environment.get("PATH", ""))
            )
            environment["GUESTFISH_CHILD_PID_FILE"] = str(child_pid)
            probe = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("offline_guestfs", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
guest = module.Guest("unused.qcow2")
guest.close()
print("listen returned")
"""
            try:
                result = subprocess.run(
                    [sys.executable, "-c", probe, str(OFFLINE_HELPER)],
                    env=environment, capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "listen returned")
            finally:
                if child_pid.exists():
                    try:
                        os.kill(int(child_pid.read_text()), 15)
                    except ProcessLookupError:
                        pass

    def test_listener_failure_retains_daemon_stderr(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ts-guestfish-failure-") as directory:
            root = Path(directory)
            write_executable(
                root / "guestfish",
                """#!/usr/bin/env python3
import sys

if "--listen" in sys.argv:
    print("GUESTFISH_PID=999999; export GUESTFISH_PID")
    print("daemon startup failed", file=sys.stderr)
else:
    print("/tmp/.guestfish-0/socket-999999: No such file or directory", file=sys.stderr)
    print("guestfish: remote: looks like the server is not running", file=sys.stderr)
    raise SystemExit(1)
""",
            )
            environment = dict(os.environ)
            environment["PATH"] = os.pathsep.join(
                (str(root), str(Path(sys.executable).parent), environment.get("PATH", ""))
            )
            probe = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("offline_guestfs", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
guest = module.Guest("unused.qcow2")
try:
    guest.kind("/")
except RuntimeError as error:
    print(error)
finally:
    guest.close(ignore_remote_error=True)
"""
            result = subprocess.run(
                [sys.executable, "-c", probe, str(OFFLINE_HELPER)],
                env=environment, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("/socket-999999: No such file or directory", result.stdout)
            self.assertIn("listener pid=999999 state=exited", result.stdout)
            self.assertIn("listener stderr: daemon startup failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
