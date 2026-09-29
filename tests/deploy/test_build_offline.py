import gzip
import hashlib
import json
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
VOLUME_INIT_SOCKET_PATH = "/run/terrascale-orchestrator-volume-init.sock"
VOLUME_INIT_SOCKET_UNIT = "terrascale-orchestrator-host-volume-init.socket"
VOLUME_INIT_SERVICE_UNIT = "terrascale-orchestrator-host-volume-init.service"
VOLUME_INIT_STATE = "/var/lib/terrascale-orchestrator-volume-init"
TIMESYNCD_CONFIG_GUEST = "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf"
TIME_WAIT_SYNC_DROPIN = "/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf"
RUNTIME_PRIORITY_PROFILE_GUEST = "/etc/terrascale-orchestrator/runtime-priority.json"
RUNTIME_PRIORITY_HELPER_GUEST = "/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py"
NATIVE_VERIFIER_GUEST = "/usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server"
KERNEL_RELEASE = "6.8.0-142-generic"
KERNEL_GUEST = f"/boot/vmlinuz-{KERNEL_RELEASE}"
SOURCE_REVISION = "9f52ca3f861a3eec125eefb6e5025c806fbd0913"
# Deployment material travels in OCI launch metadata and must never be baked.
DEPLOYMENT_MATERIAL_GUEST_PATHS = (
    f"{BOOTSTRAP_DIRECTORY}/anchor.json",
    f"{BOOTSTRAP_DIRECTORY}/identity.json",
    f"{BOOTSTRAP_DIRECTORY}/host-enrollment-public.json",
    "/etc/terrascale-orchestrator/host-enrollment-public.json",
)
REMOVED_DEPLOYMENT_FLAGS = (
    "--bootstrap-tool", "--bootstrap-anchor", "--bootstrap-identity",
    "--host-enrollment-public", "--host-enrollment-public-sha256",
    "--receipt", "--delegation", "--root-key", "--environment",
)
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
        self.qualification = self.write_file(self.inputs / "qualification.json", b"mock qualification")
        self.bootstrap_root_a = self.write_file(self.inputs / "bootstrap root a.pem", b"bootstrap public key a")
        self.bootstrap_root_b = self.write_file(self.inputs / "bootstrap root b.pem", b"bootstrap public key b")
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
        self.release_arguments = self.root / "release-arguments.bin"
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
        self.kernel_output = self.root / "guest kernel"
        kernel_header = bytearray(64)
        kernel_header[56:60] = b"ARM\x64"
        self.kernel = bytes(kernel_header) + b"mock arm64 kernel"

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
            "/etc/sysusers.d", "/usr/local/bin", "/var/lib", "/srv", "/boot",
            f"/lib/modules/{KERNEL_RELEASE}",
        ):
            (self.base_image_root / directory.lstrip("/")).mkdir(parents=True, exist_ok=True)
        (self.base_image_root / KERNEL_GUEST.lstrip("/")).write_bytes(self.kernel)
        (self.base_image_root / "boot/vmlinuz").symlink_to(f"vmlinuz-{KERNEL_RELEASE}")
        (self.base_image_root / "srv").chmod(0o755)
        (self.base_image_root / "var/lib/dpkg").mkdir(parents=True)
        (self.base_image_root / "var/lib/dpkg/status").write_text(
            "Package: systemd\nStatus: install ok installed\nVersion: 255.4-1ubuntu8.12\n\n"
            "Package: e2fsprogs\nStatus: install ok installed\nVersion: 1.47.0-2.4~exp1ubuntu4.1\n\n"
            "Package: util-linux\nStatus: install ok installed\nVersion: 2.39.3-9ubuntu6.6\n\n",
            encoding="utf-8",
        )
        for directory in ("/usr/bin", "/usr/sbin"):
            (self.base_image_root / directory.lstrip("/")).mkdir(parents=True, exist_ok=True)
        for guest_path in ("/usr/sbin/mkfs.ext4", "/usr/sbin/blkid", "/usr/sbin/wipefs", "/usr/bin/mount"):
            tool = self.base_image_root / guest_path.lstrip("/")
            tool.write_bytes(b"pinned base image volume tool fixture")
            tool.chmod(0o755)
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
session_marker = Path(os.environ["GUESTFISH_SESSION_PATH"])
if "--listen" in arguments:
    read_only = "--ro" in arguments
    with open(os.environ["EVENTS_PATH"], "a", encoding="utf-8") as stream:
        stream.write("guestfish-listen-ro\n" if read_only else "guestfish-listen\n")
    session_marker.write_text("ro" if read_only else "rw")
    print("GUESTFISH_PID=1; export GUESTFISH_PID")
    raise SystemExit(0)
read_only = session_marker.read_text() == "ro"
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
    if read_only and args[0] == os.environ.get("GUESTFISH_CORRUPT_READBACK"):
        Path(args[1]).write_bytes(b"corrupt guest bytes")
    else:
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
if read_only and command not in ("is-symlink", "is-dir", "is-file", "exists", "lstatns", "ls",
                                 "readlink", "download", "exit"):
    raise SystemExit(f"read-only session attempted a write: {command}")
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
        self.release_tool = self.root / "release tool"
        write_executable(
            self.release_tool,
            """#!/usr/bin/env bash
set -euo pipefail
printf 'release-binary-candidate\\n' >> "$EVENTS_PATH"
printf '%s\\0' "$@" > "$RELEASE_ARGUMENTS_PATH"
if [[ "${RELEASE_CANDIDATE_FAIL:-0}" == 1 ]]; then
  echo 'mock binary does not match its qualification' >&2
  exit 1
fi
""",
        )

    def write_file(self, path: Path, data: bytes) -> Path:
        path.write_bytes(data)
        return path

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

    def builder_environment(self, **overrides: str) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.shims}{os.pathsep}{Path(sys.executable).parent}:/run/current-system/sw/bin:/usr/bin:/bin",
                "EVENTS_PATH": str(self.events),
                "RELEASE_ARGUMENTS_PATH": str(self.release_arguments),
                "GUESTFISH_SESSION_PATH": str(self.root / "guestfish-session"),
                "BASE_IMAGE_ROOT_PATH": str(self.base_image_root),
                "FS_METADATA_PATH": str(self.fs_metadata),
                "GUESTFISH_DEAD_MARKER_PATH": str(self.root / "guestfish-dead"),
            }
        )
        environment.update(overrides)
        return environment

    def run_builder(self, *extra_arguments: str, native_verifier_binary: Path | None = None,
                    native_verifier_sha256: str | None = None, replace: dict[str, str] | None = None,
                    **environment_overrides: str) -> subprocess.CompletedProcess[str]:
        return self.run_builder_with_roots(
            [self.bootstrap_root_a, self.bootstrap_root_b], *extra_arguments,
            native_verifier_binary=native_verifier_binary,
            native_verifier_sha256=native_verifier_sha256,
            replace=replace,
            **environment_overrides
        )

    def run_builder_with_roots(
        self, bootstrap_roots: list[Path], *extra_arguments: str,
        native_verifier_binary: Path | None = None,
        native_verifier_sha256: str | None = None,
        replace: dict[str, str] | None = None,
        **environment_overrides: str
    ) -> subprocess.CompletedProcess[str]:
        options = {
            "--base": str(self.base),
            "--kernel-release": KERNEL_RELEASE,
            "--binary": str(self.binary),
            "--qualification": str(self.qualification),
            "--source-revision": SOURCE_REVISION,
            "--native-verifier-binary": str(native_verifier_binary or self.native_verifier),
            "--native-verifier-sha256": native_verifier_sha256 or self.native_verifier_sha256,
            "--release-tool": str(self.release_tool),
            "--timesyncd-config": str(self.timesyncd_config),
            **self.priority_inputs,
            **(replace or {}),
        }
        arguments = [str(BUILDER)]
        for flag, value in options.items():
            arguments.extend((flag, value))
        for bootstrap_root in bootstrap_roots:
            arguments.extend(("--bootstrap-root", str(bootstrap_root)))
        arguments.extend(extra_arguments)
        arguments.extend(("--out", str(self.output), "--kernel-out", str(self.kernel_output)))
        return subprocess.run(
            arguments,
            cwd=ROOT,
            env=self.builder_environment(**environment_overrides),
            capture_output=True,
            check=False,
            text=True,
        )

    def assert_no_image_effects(self) -> None:
        events = self.events.read_text(encoding="utf-8") if self.events.exists() else ""
        self.assertNotIn("guestfish-listen", events)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.kernel_output.exists())

    def test_verified_public_inputs_and_directories_are_installed_offline(self) -> None:
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), self.base.read_bytes())
        self.assertEqual(self.kernel_output.read_bytes(), self.kernel)
        kernel_sha256 = hashlib.sha256(self.kernel).hexdigest()
        self.assertIn(f"base guest kernel release={KERNEL_RELEASE} bytes={len(self.kernel)} sha256={kernel_sha256}",
                      result.stdout)
        events = self.events.read_text(encoding="utf-8").splitlines()
        # The binary is qualified before the appliance starts, and one read-only
        # appliance reads the finished image back after the writable one.
        self.assertEqual(events, ["release-binary-candidate", "qemu-check", "qemu-info", "guestfish-listen",
                                  "qemu-check", "guestfish-listen-ro"])

        release_arguments = [part.decode() for part in self.release_arguments.read_bytes().split(b"\0")[:-1]]
        self.assertEqual(release_arguments[0], "binary-candidate")
        self.assertEqual(release_arguments[release_arguments.index("--source-revision") + 1], SOURCE_REVISION)
        self.assertEqual(release_arguments[release_arguments.index("--qualification") + 1], str(self.qualification))
        self.assertEqual(Path(release_arguments[release_arguments.index("--binary") + 1]).name,
                         "terrascale-orchestrator")
        self.assertNotIn(str(self.bootstrap_root_a), release_arguments)
        for guest_path, contents in (
            ("/usr/local/bin/terrascale-orchestrator", self.binary.read_bytes()),
            (NATIVE_VERIFIER_GUEST, self.native_verifier.read_bytes()),
            (KERNEL_GUEST, self.kernel),
        ):
            self.assertIn(f"image readback sha256={hashlib.sha256(contents).hexdigest()} guest_path={guest_path}",
                          result.stdout)

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

        for index, source in enumerate((self.bootstrap_root_a, self.bootstrap_root_b), 1):
            installed(f"{BOOTSTRAP_DIRECTORY}/trust-roots/{index:03d}.pem", source.read_bytes(), 0o444)
        self.assert_baked_loader_accepts_roots(["001.pem", "002.pem"])
        installed(NATIVE_VERIFIER_GUEST, self.native_verifier.read_bytes(), 0o755)
        installed("/usr/local/bin/terrascale-orchestrator", self.binary.read_bytes(), 0o755)
        installed(RUNTIME_PRIORITY_HELPER_GUEST, RUNTIME_PRIORITY_QUALIFIER.read_bytes(), 0o755)
        installed(TIME_WAIT_SYNC_DROPIN, b"[Service]\nTimeoutStartSec=300s\n")
        normalized_time = (
            b"[Time]\nNTP=\nNTP=ntp.deployment.example\nFallbackNTP=\n"
            b"PollIntervalMinSec=32\nPollIntervalMaxSec=64\n"
        )
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
        self.assertFalse((root / self.qualification.name).exists())

    def test_native_verifier_rejects_wrong_digest_and_architecture_before_image_copy(self) -> None:
        wrong_digest = "0" * 64
        result = self.run_builder(native_verifier_sha256=wrong_digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native verifier bytes do not match", result.stderr)
        self.assert_no_image_effects()

        native_bytes = bytearray(self.native_verifier.read_bytes())
        struct.pack_into("<H", native_bytes, 18, 62)
        self.native_verifier.write_bytes(native_bytes)
        result = self.run_builder(
            native_verifier_sha256=hashlib.sha256(native_bytes).hexdigest()
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ELF64 little-endian AArch64", result.stderr)
        self.assert_no_image_effects()

    def assert_readback_mismatch_discards_candidate(self, guest_path: str) -> None:
        result = self.run_builder(GUESTFISH_CORRUPT_READBACK=guest_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"finished image bytes differ from the expected SHA-256: {guest_path}", result.stderr)
        self.assertIn("guestfish-listen-ro", self.events.read_text(encoding="utf-8"))
        self.assertFalse(self.output.exists())
        self.assertFalse(self.kernel_output.exists())
        self.assertEqual(list(self.root.glob(".ts-orchestrator-image.*")), [])

    def test_orchestrator_readback_mismatch_discards_candidate(self) -> None:
        self.assert_readback_mismatch_discards_candidate("/usr/local/bin/terrascale-orchestrator")

    def test_native_verifier_readback_mismatch_discards_candidate(self) -> None:
        self.assert_readback_mismatch_discards_candidate(NATIVE_VERIFIER_GUEST)

    def test_kernel_readback_mismatch_discards_candidate(self) -> None:
        self.assert_readback_mismatch_discards_candidate(KERNEL_GUEST)

    def test_deployment_material_is_never_baked(self) -> None:
        # Launch metadata carries the deployment identity, signed anchor and
        # host enrollment bundle; the guest verifies them against these roots.
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        root = self.base_image_root
        for guest_path in DEPLOYMENT_MATERIAL_GUEST_PATHS:
            self.assertFalse((root / guest_path.lstrip("/")).exists(), guest_path)
        bootstrap = root / BOOTSTRAP_DIRECTORY.lstrip("/")
        self.assertEqual(sorted(path.name for path in bootstrap.iterdir()), ["trust-roots"])
        self.assertEqual(sorted(path.name for path in (bootstrap / "trust-roots").iterdir()), ["001.pem", "002.pem"])

    def test_deployment_material_flags_are_rejected_before_image_effects(self) -> None:
        material = self.write_file(self.inputs / "deployment material.json", b"{}")
        for flag in REMOVED_DEPLOYMENT_FLAGS:
            with self.subTest(flag=flag):
                result = self.run_builder(flag, str(material))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage: build-offline.sh", result.stderr)
                self.assertFalse(self.events.exists())
                self.assert_no_image_effects()

    def test_base_image_with_deployment_material_fails_closed(self) -> None:
        for guest_path in DEPLOYMENT_MATERIAL_GUEST_PATHS:
            with self.subTest(path=guest_path):
                existing = self.base_image_root / guest_path.lstrip("/")
                existing.parent.mkdir(parents=True, exist_ok=True)
                existing.write_text("{}\n", encoding="utf-8")
                result = self.run_builder()
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(
                    result.stderr,
                    "base image has a conflicting (bootstrap artifact|host enrollment public bundle): "
                    + re.escape(guest_path),
                )
                self.assertFalse(self.output.exists())
                existing.unlink()

    def test_rejected_binary_qualification_prevents_guest_copy(self) -> None:
        result = self.run_builder(RELEASE_CANDIDATE_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mock binary does not match its qualification", result.stderr)
        self.assertEqual(self.events.read_text(encoding="utf-8").splitlines(), ["release-binary-candidate"])
        self.assert_no_image_effects()
        self.assertEqual(list(self.root.glob(".ts-orchestrator-image.*")), [])

    def test_source_revision_and_kernel_release_are_validated_before_image_effects(self) -> None:
        for flag, value in (
            ("--source-revision", "HEAD"),
            ("--source-revision", SOURCE_REVISION.upper()),
            ("--kernel-release", "../vmlinuz"),
        ):
            with self.subTest(flag=flag, value=value):
                result = self.run_builder(replace={flag: value})
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.events.exists())
                self.assert_no_image_effects()

    def test_base_kernel_must_be_one_arm64_image_with_modules(self) -> None:
        boot = self.base_image_root / "boot"
        kernel = boot / f"vmlinuz-{KERNEL_RELEASE}"
        modules = self.base_image_root / f"lib/modules/{KERNEL_RELEASE}"
        extra = boot / "vmlinuz-6.8.0-1-generic"

        installed_binary = self.base_image_root / "usr/local/bin/terrascale-orchestrator"

        def assert_rejected(expected: str, **replace: str) -> None:
            result = self.run_builder(replace=replace)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
            self.assertFalse(self.output.exists())
            self.assertFalse(self.kernel_output.exists())
            # The audit precedes every write to the base image.
            self.assertFalse(installed_binary.exists())

        extra.write_bytes(self.kernel)
        assert_rejected(f"exactly one regular /boot/vmlinuz-{KERNEL_RELEASE}")
        extra.unlink()
        assert_rejected("exactly one regular /boot/vmlinuz-6.8.0-999-generic",
                        **{"--kernel-release": "6.8.0-999-generic"})

        modules.rmdir()
        assert_rejected(f"has no /lib/modules/{KERNEL_RELEASE} directory")
        modules.mkdir()

        kernel.write_bytes(bytes(64) + b"x86 kernel")
        assert_rejected("base guest kernel is not an AArch64 Linux boot Image")

        kernel.write_bytes(gzip.compress(self.kernel))
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.kernel_output.read_bytes(), gzip.compress(self.kernel))

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

    def test_every_image_provisions_fixed_managed_root_and_setup_units(self) -> None:
        host_unit = (ROOT / "deploy/systemd/terrascale-orchestrator-host.service").read_text()
        self.assertIn("ProtectSystem=strict\n", host_unit)
        self.assertIn(f"ReadWritePaths=-{MANAGED_DIRECTORY}\n", host_unit)
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        root = self.base_image_root
        managed = root / MANAGED_DIRECTORY.lstrip("/")
        self.assertTrue(managed.is_dir() and not managed.is_symlink())
        self.assertEqual(stat.S_IMODE(managed.stat().st_mode), 0o750)
        metadata = json.loads(self.fs_metadata.read_text())
        self.assertEqual(tuple(metadata[MANAGED_DIRECTORY]), (0, 2000))
        self.assertEqual(tuple(metadata[VOLUME_INIT_STATE]), (0, 0))
        state = root / VOLUME_INIT_STATE.lstrip("/")
        self.assertTrue(state.is_dir() and not state.is_symlink())
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
        for unit, target in (("terrascale-orchestrator-host-setup.service", "multi-user.target"),
                             ("terrascale-orchestrator-host-setup.timer", "timers.target"),
                             (VOLUME_INIT_SOCKET_UNIT, "sockets.target")):
            self.assertTrue((root / "etc/systemd/system" / (target + ".wants") / unit).is_symlink())
        for unit in (VOLUME_INIT_SOCKET_UNIT, VOLUME_INIT_SERVICE_UNIT):
            installed = root / "etc/systemd/system" / unit
            self.assertEqual(installed.read_bytes(), (ROOT / "deploy/systemd" / unit).read_bytes())
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o644)

    def test_volume_init_units_are_root_only_and_mount_in_the_host_namespace(self) -> None:
        socket_source = (ROOT / "deploy/systemd" / VOLUME_INIT_SOCKET_UNIT).read_text(encoding="utf-8")
        service_source = (ROOT / "deploy/systemd" / VOLUME_INIT_SERVICE_UNIT).read_text(encoding="utf-8")

        def directives(source: str, selected_section: str) -> dict[str, str]:
            section = ""
            found = {}
            for raw in source.splitlines():
                line = raw.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1]
                elif section == selected_section and "=" in line:
                    key, value = line.split("=", 1)
                    found[key] = value
            return found

        socket = directives(socket_source, "Socket")
        self.assertEqual(socket["ListenStream"], VOLUME_INIT_SOCKET_PATH)
        self.assertEqual(socket["SocketMode"], "0600")
        self.assertEqual(socket["SocketUser"], "root")
        self.assertEqual(socket["SocketGroup"], "root")
        self.assertEqual(socket["Accept"], "no")
        self.assertEqual(socket["Service"], VOLUME_INIT_SERVICE_UNIT)
        self.assertIn("WantedBy=sockets.target", socket_source)

        service = directives(service_source, "Service")
        self.assertEqual(service["User"], "root")
        self.assertEqual(service["Group"], "root")
        self.assertEqual(
            service["ExecStart"],
            "/usr/local/bin/terrascale-orchestrator host-volume-init --config /etc/terrascale-orchestrator/host.json",
        )
        self.assertEqual(set(service["CapabilityBoundingSet"].split()), {"CAP_SYS_ADMIN", "CAP_CHOWN"})
        self.assertEqual(service["NoNewPrivileges"], "yes")
        self.assertEqual(service["RestrictNamespaces"], "yes")

        filesystem_namespace_directives = {
            "BindPaths", "BindReadOnlyPaths", "CacheDirectory", "ConfigurationDirectory", "InaccessiblePaths",
            "LogsDirectory", "MountAPIVFS", "PrivateDevices", "PrivateMounts", "PrivateTmp", "PrivateUsers",
            "ProtectClock", "ProtectControlGroups", "ProtectHome", "ProtectHostname", "ProtectKernelLogs",
            "ProtectKernelModules", "ProtectKernelTunables", "ProtectProc", "ProtectSystem", "ProcSubset",
            "ReadOnlyPaths", "ReadWritePaths", "RootDirectory", "RootImage", "RuntimeDirectory",
            "StateDirectory", "TemporaryFileSystem",
        }
        self.assertFalse(filesystem_namespace_directives.intersection(service))

    def test_every_image_requires_pinned_volume_initialization_tools(self) -> None:
        status_path = self.base_image_root / "var/lib/dpkg/status"
        original_status = status_path.read_text(encoding="utf-8")
        cases = (
            ("missing package", original_status.replace(
                "Package: e2fsprogs\nStatus: install ok installed\nVersion: 1.47.0-2.4~exp1ubuntu4.1\n\n", ""), None,
             "pinned e2fsprogs"),
            ("missing tool", original_status, "/usr/sbin/mkfs.ext4", "missing required volume tool"),
        )
        for name, status, missing_tool, expected in cases:
            with self.subTest(name=name):
                status_path.write_text(status, encoding="utf-8")
                tool = self.base_image_root / missing_tool.lstrip("/") if missing_tool else None
                if tool:
                    tool.unlink()
                result = self.run_builder()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertFalse(self.output.exists())
                if tool:
                    tool.write_bytes(b"pinned base image volume tool fixture")
                    tool.chmod(0o755)
                status_path.write_text(original_status, encoding="utf-8")

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
            b"[Time]\nPollIntervalMinSec=16\nPollIntervalMaxSec=2048\n"
            b"NTP=198.19.8.1\nNTP=\nNTP=ntp.deployment.example\n"
            b"FallbackNTP=198.19.3.5\nFallbackNTP=\nFallbackNTP=fallback.deployment.example\n"
        )
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        generated_timesyncd_config = (
            b"# Systemd empty assignments reset earlier list members.\n"
            b"[Time]\nNTP=\nNTP=ntp.deployment.example\n"
            b"FallbackNTP=\nFallbackNTP=fallback.deployment.example\n"
            b"PollIntervalMinSec=32\nPollIntervalMaxSec=64\n"
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
        self.assertIn("base image has active NTP/FallbackNTP or poll interval configuration", result.stderr)
        self.assertIn("/etc/systemd/timesyncd.conf.d/20-base.conf", result.stderr)
        self.assertFalse(self.output.exists())
        self.assertIn("guestfish-listen", self.events.read_text(encoding="utf-8"))

    def test_competing_base_timesyncd_poll_interval_fails_closed(self) -> None:
        competing = self.base_image_root / "etc/systemd/timesyncd.conf.d/zz-base.conf"
        competing.parent.mkdir(parents=True)
        competing.write_text("[Time]\nPollIntervalMaxSec=2048\n", encoding="utf-8")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("base image has active NTP/FallbackNTP or poll interval configuration", result.stderr)
        self.assertFalse(self.output.exists())

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

    def test_clock_probe_units_preserve_read_only_adjtimex_access_in_image(self) -> None:
        # ProtectClock's syscall filter blocks adjtimex even with a zero-mode
        # Timex. The probe needs that read; clock mutation still needs CAP_SYS_TIME.
        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in (
            "terrascale-orchestrator-controller-install.service",
            "terrascale-orchestrator-bootstrap.service",
            "terrascale-orchestrator-controller.service",
            "terrascale-orchestrator-host.service",
        ):
            with self.subTest(unit=name):
                source = (ROOT / "deploy/systemd" / name).read_bytes()
                installed = (self.base_image_root / "etc/systemd/system" / name).read_bytes()
                self.assertEqual(installed, source)
                directives = dict(
                    line.split("=", 1) for line in source.decode().splitlines()
                    if "=" in line and not line.startswith("#")
                )
                self.assertNotIn("ProtectClock", directives)
                self.assertNotIn("SystemCallFilter", directives)
                # Initial admission's service-account child needs setuid without no_new_privs.
                expected_nnp = "no" if name == "terrascale-orchestrator-bootstrap.service" else "yes"
                self.assertEqual(directives["NoNewPrivileges"], expected_nnp)
                self.assertEqual(directives["AmbientCapabilities"], "")
                self.assertNotIn("CAP_SYS_TIME", directives["CapabilityBoundingSet"].split())

    def test_root_set_bounds_are_enforced_before_verification(self) -> None:
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
            ("too many roots", too_many_roots),
            ("per-root byte limit", [too_large_root]),
            ("total root byte limit", too_many_root_bytes),
        )
        for label, roots in cases:
            with self.subTest(label=label):
                result = self.run_builder_with_roots(roots)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(self.events.exists(), result.stderr)
                self.assert_no_image_effects()

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
