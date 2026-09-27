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
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "deploy/image/build-offline.sh"
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
        self.virt_arguments = self.root / "virt-arguments.json"
        self.virt_identity_bytes = self.root / "virt-identity-bytes.bin"
        self.virt_timesyncd_bytes = self.root / "virt-timesyncd-bytes.bin"
        self.virt_runtime_profile_bytes = self.root / "virt-runtime-priority-profile.json"
        self.virt_runtime_helper_bytes = self.root / "virt-runtime-priority-helper.py"
        self.virt_native_verifier_bytes = self.root / "virt-native-verifier.bin"
        self.virt_runtime_artifacts = self.root / "virt-runtime-priority-artifacts"
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
        write_executable(
            self.shims / "virt-customize",
            """#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
with open(os.environ["EVENTS_PATH"], "a", encoding="utf-8") as stream:
    stream.write("virt-customize\\n")
with open(os.environ["VIRT_ARGUMENTS_PATH"], "w", encoding="utf-8") as stream:
    json.dump(sys.argv[1:], stream)
arguments = sys.argv[1:]
if os.environ.get("VIRT_FAIL_TIME_UNITS") == "1" and any(
    argument == "--run-command"
    and "systemd-timesyncd.service systemd-time-wait-sync.service" in arguments[index + 1]
    for index, argument in enumerate(arguments[:-1])
):
    print("mock base image is missing a required systemd time unit", file=sys.stderr)
    raise SystemExit(1)
time_sync_setup = next(
    arguments[index + 1]
    for index, argument in enumerate(arguments[:-1])
    if argument == "--run-command" and "timesyncd_main_config=" in arguments[index + 1]
)
scan_boundary = "install -d -o root -g root -m 0755 /etc/systemd/timesyncd.conf.d"
scan_command = time_sync_setup.split(scan_boundary, 1)[0] + "exit 0\\n"
image_root = os.environ["BASE_IMAGE_ROOT_PATH"]
for systemd_path in (
    "/etc/systemd",
    "/run/systemd",
    "/usr/local/lib/systemd",
    "/usr/lib/systemd",
):
    scan_command = scan_command.replace(
        systemd_path, str(Path(image_root) / systemd_path.lstrip("/"))
    )
scan = subprocess.run(["bash", "-c", scan_command], capture_output=True, text=True, check=False)
if scan.returncode != 0:
    print(scan.stderr, end="", file=sys.stderr)
    raise SystemExit(scan.returncode)
priority_setup = next(
    arguments[index + 1]
    for index, argument in enumerate(arguments[:-1])
    if argument == "--run-command"
    and "base image has a conflicting runtime-priority profile artifact" in arguments[index + 1]
)
image_root = Path(image_root)
for guest_directory in (
    "/etc/terrascale-orchestrator",
    "/etc/systemd/system",
    "/usr/local/lib/terrascale-orchestrator",
):
    priority_setup = priority_setup.replace(
        guest_directory, str(image_root / guest_directory.lstrip("/"))
    )
priority_setup = priority_setup.replace("-o root -g root ", "")
priority_check = subprocess.run(["bash", "-c", priority_setup], capture_output=True, text=True, check=False)
if priority_check.returncode != 0:
    print(priority_check.stderr, end="", file=sys.stderr)
    raise SystemExit(priority_check.returncode)
for index, argument in enumerate(arguments[:-1]):
    if argument == "--upload":
        source, destination = arguments[index + 1].rsplit(":", 1)
        if destination == "/etc/terrascale-orchestrator/bootstrap/identity.json":
            Path(os.environ["VIRT_IDENTITY_BYTES_PATH"]).write_bytes(Path(source).read_bytes())
        if destination == "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf":
            Path(os.environ["VIRT_TIMESYNCD_BYTES_PATH"]).write_bytes(Path(source).read_bytes())
        if destination == os.environ["VIRT_RUNTIME_PROFILE_GUEST_PATH"]:
            Path(os.environ["VIRT_RUNTIME_PROFILE_BYTES_PATH"]).write_bytes(Path(source).read_bytes())
        if destination in os.environ["VIRT_RUNTIME_DROPIN_PATHS"].split(os.pathsep):
            artifact_root = Path(os.environ["VIRT_RUNTIME_ARTIFACTS_PATH"])
            artifact = artifact_root / destination.lstrip("/")
            artifact.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, artifact)
        if destination == os.environ["VIRT_RUNTIME_HELPER_GUEST_PATH"]:
            Path(os.environ["VIRT_RUNTIME_HELPER_BYTES_PATH"]).write_bytes(Path(source).read_bytes())
        if destination == os.environ["VIRT_NATIVE_VERIFIER_GUEST_PATH"]:
            Path(os.environ["VIRT_NATIVE_VERIFIER_BYTES_PATH"]).write_bytes(Path(source).read_bytes())
""",
        )
        write_executable(
            self.shims / "virt-cat",
            """#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 && $1 == -a && $3 == "$VIRT_NATIVE_VERIFIER_GUEST_PATH" ]]
if [[ ${VIRT_CORRUPT_NATIVE:-0} == 1 ]]; then
  printf 'corrupt guest bytes'
else
  cat "$VIRT_NATIVE_VERIFIER_BYTES_PATH"
fi
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
        loader_source = BAKED_LOADER.read_text(encoding="utf-8")
        anchor_source = (ROOT / "internal/bootstrap/anchor.go").read_text(encoding="utf-8")
        baked_directory = re.search(r'BakedDirectory\s*=\s*"([^"]+)"', loader_source)
        builder_directory = re.search(r"^bootstrap_directory=(.+)$", builder_source, re.MULTILINE)
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
                "PATH": f"{self.shims}{os.pathsep}{environment['PATH']}",
                "EVENTS_PATH": str(self.events),
                "BOOTSTRAP_ARGUMENTS_PATH": str(self.bootstrap_arguments),
                "RELEASE_ARGUMENTS_PATH": str(self.release_arguments),
                "VIRT_ARGUMENTS_PATH": str(self.virt_arguments),
                "VIRT_IDENTITY_BYTES_PATH": str(self.virt_identity_bytes),
                "VIRT_TIMESYNCD_BYTES_PATH": str(self.virt_timesyncd_bytes),
                "VIRT_RUNTIME_PROFILE_BYTES_PATH": str(self.virt_runtime_profile_bytes),
                "VIRT_RUNTIME_HELPER_BYTES_PATH": str(self.virt_runtime_helper_bytes),
                "VIRT_NATIVE_VERIFIER_BYTES_PATH": str(self.virt_native_verifier_bytes),
                "VIRT_NATIVE_VERIFIER_GUEST_PATH": NATIVE_VERIFIER_GUEST,
                "VIRT_RUNTIME_ARTIFACTS_PATH": str(self.virt_runtime_artifacts),
                "VIRT_RUNTIME_DROPIN_PATHS": os.pathsep.join(RUNTIME_PRIORITY_DROPINS),
                "VIRT_RUNTIME_PROFILE_GUEST_PATH": RUNTIME_PRIORITY_PROFILE_GUEST,
                "VIRT_RUNTIME_HELPER_GUEST_PATH": RUNTIME_PRIORITY_HELPER_GUEST,
                "BASE_IMAGE_ROOT_PATH": str(self.base_image_root),
            }
        )
        environment.update(overrides)
        return environment

    def run_builder(self, *, managed_workload_gid: str | None = None,
                    native_verifier_binary: Path | None = None,
                    native_verifier_sha256: str | None = None,
                    **environment_overrides: str) -> subprocess.CompletedProcess[str]:
        return self.run_builder_with_roots(
            [self.bootstrap_root_a, self.bootstrap_root_b], managed_workload_gid=managed_workload_gid,
            native_verifier_binary=native_verifier_binary,
            native_verifier_sha256=native_verifier_sha256,
            **environment_overrides
        )

    def run_builder_with_roots(
        self, bootstrap_roots: list[Path], *, managed_workload_gid: str | None = None,
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
        if managed_workload_gid is not None:
            arguments.extend(("--managed-workload-gid", managed_workload_gid))
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

        bootstrap_arguments = self.bootstrap_arguments.read_bytes().split(b"\0")[:-1]
        self.assertEqual(
            [argument.decode() for argument in bootstrap_arguments],
            [
                "verify-anchor",
                "--anchor",
                str(self.anchor),
                "--identity",
                str(self.identity),
                "--root-key",
                str(self.bootstrap_root_a),
                "--root-key",
                str(self.bootstrap_root_b),
            ],
        )
        self.assertEqual(
            self.virt_identity_bytes.read_bytes(), self.identity.read_bytes()
        )

        release_arguments = self.release_arguments.read_bytes().split(b"\0")[:-1]
        release_arguments_text = [argument.decode() for argument in release_arguments]
        self.assertEqual(release_arguments_text[release_arguments_text.index("--root-key") + 1], str(self.release_root))
        self.assertEqual(release_arguments_text[release_arguments_text.index("--qualification") + 1], str(self.qualification))
        self.assertNotIn(str(self.bootstrap_root_a), release_arguments_text)
        self.assertNotIn(str(self.bootstrap_root_b), release_arguments_text)

        events = self.events.read_text(encoding="utf-8").splitlines()
        self.assertLess(events.index("bootstrap-verify"), events.index("virt-customize"))

        virt_arguments = json.loads(self.virt_arguments.read_text(encoding="utf-8"))
        uploads = [
            virt_arguments[index + 1]
            for index, argument in enumerate(virt_arguments[:-1])
            if argument == "--upload"
        ]
        destinations = {upload.rsplit(":", 1)[1]: upload.rsplit(":", 1)[0] for upload in uploads}
        self.assertEqual(
            self.virt_native_verifier_bytes.read_bytes(), self.native_verifier.read_bytes()
        )
        self.assertTrue(destinations[NATIVE_VERIFIER_GUEST].endswith("/terrabase-server"))
        self.assertIn(f"native verifier image sha256={self.native_verifier_sha256}", result.stdout)
        self.assertEqual(destinations[f"{BOOTSTRAP_DIRECTORY}/anchor.json"], str(self.anchor))
        self.assertEqual(destinations[f"{BOOTSTRAP_DIRECTORY}/identity.json"], str(self.identity))
        generated_timesyncd_config = (
            b"[Time]\nNTP=\nNTP=ntp.deployment.example\nFallbackNTP=\n"
        )
        self.assertNotEqual(destinations[TIMESYNCD_CONFIG_GUEST], str(self.timesyncd_config))
        self.assertEqual(self.virt_timesyncd_bytes.read_bytes(), generated_timesyncd_config)
        self.assertIn(
            hashlib.sha256(generated_timesyncd_config).hexdigest(),
            result.stdout,
        )
        self.assertEqual(
            self.virt_runtime_profile_bytes.read_bytes(),
            json.dumps(
                {
                    "version": 1,
                    "profile_id": RUNTIME_PRIORITY_PROFILE_ID,
                    "system_reserve_bytes": RUNTIME_PRIORITY_SYSTEM_RESERVE_BYTES,
                },
                separators=(",", ":"),
            ).encode(),
        )
        self.assertEqual(
            self.virt_runtime_helper_bytes.read_bytes(),
            (ROOT / "tests/runtime_priority/qualify.py").read_bytes(),
        )
        self.assertTrue(
            destinations[RUNTIME_PRIORITY_PROFILE_GUEST].endswith("/runtime-priority.json")
        )
        self.assertEqual(
            destinations[RUNTIME_PRIORITY_HELPER_GUEST],
            "tests/runtime_priority/qualify.py",
        )
        for guest_path, expected_section, minimum, low in (
            (RUNTIME_PRIORITY_DROPINS[0], "[Slice]", 128 << 20, 256 << 20),
            (RUNTIME_PRIORITY_DROPINS[1], "[Service]", 64 << 20, 128 << 20),
            (RUNTIME_PRIORITY_DROPINS[2], "[Service]", 64 << 20, 128 << 20),
        ):
            dropin = self.virt_runtime_artifacts / guest_path.lstrip("/")
            content = dropin.read_text(encoding="utf-8")
            self.assertIn(expected_section, content)
            self.assertIn(f"# Profile: {RUNTIME_PRIORITY_PROFILE_ID}\n", content)
            self.assertIn(f"MemoryMin={minimum}\n", content)
            self.assertIn(f"MemoryLow={low}\n", content)
            self.assertIn(
                hashlib.sha256(dropin.read_bytes()).hexdigest(), result.stdout
            )
        self.assertEqual(
            destinations[f"{BOOTSTRAP_DIRECTORY}/trust-roots/001.pem"], str(self.bootstrap_root_a)
        )
        self.assertEqual(
            destinations[f"{BOOTSTRAP_DIRECTORY}/trust-roots/002.pem"], str(self.bootstrap_root_b)
        )
        generated_root_names = sorted(
            path.rsplit("/", 1)[1]
            for path in destinations
            if path.startswith(f"{BOOTSTRAP_DIRECTORY}/trust-roots/")
        )
        self.assertEqual(generated_root_names, ["001.pem", "002.pem"])
        self.assert_baked_loader_accepts_roots(generated_root_names)
        self.assertIn(
            "deploy/systemd/terrascale-orchestrator-bootstrap.service:/etc/systemd/system/terrascale-orchestrator-bootstrap.service",
            uploads,
        )
        self.assertIn(
            "deploy/systemd/terrascale-orchestrator-controller.service:/etc/systemd/system/terrascale-orchestrator-controller.service",
            uploads,
        )
        self.assertIn(
            "deploy/systemd/terrascale-orchestrator-host.service:/etc/systemd/system/terrascale-orchestrator-host.service",
            uploads,
        )
        for private_or_build_only_input in (
            self.release_root,
            self.receipt,
            self.delegation,
            self.bootstrap_tool,
            self.release_tool,
        ):
            self.assertFalse(any(upload.startswith(f"{private_or_build_only_input}:") for upload in uploads))

        run_commands = [
            virt_arguments[index + 1]
            for index, argument in enumerate(virt_arguments[:-1])
            if argument == "--run-command"
        ]
        guest_commands = "\n".join(run_commands)
        self.assertIn("base image has a conflicting managed-material verifier directory", guest_commands)
        self.assertIn(
            f"chown root:root {NATIVE_VERIFIER_GUEST}", guest_commands
        )
        self.assertIn(
            f"chmod 0755 {NATIVE_VERIFIER_GUEST}", guest_commands
        )
        priority_setup = next(
            command
            for command in run_commands
            if "base image has a conflicting runtime-priority profile artifact" in command
        )
        self.assertIn(f"{RUNTIME_PRIORITY_PROFILE_GUEST}", priority_setup)
        self.assertIn(RUNTIME_PRIORITY_HELPER_GUEST, priority_setup)
        self.assertIn("install -d -o root -g root -m 0755 /etc/systemd/system/system.slice.d", priority_setup)
        self.assertIn("install -d -o root -g root -m 0755 /usr/local/lib/terrascale-orchestrator/runtime-priority", priority_setup)
        self.assertIn("systemd-sysusers /etc/sysusers.d/terrascale-orchestrator.conf", guest_commands)
        self.assertIn(
            "install -d -o root -g root -m 0755 /etc/terrascale-orchestrator", guest_commands
        )
        self.assertIn(
            f"chown root:root {BOOTSTRAP_DIRECTORY} {BOOTSTRAP_DIRECTORY}/trust-roots", guest_commands
        )
        self.assertIn(f"install -d -o root -g root -m 0755 {MARKER_DIRECTORY}", guest_commands)
        self.assertIn(
            f"install -d -o terrascale-orchestrator -g terrascale-orchestrator -m 0700 {SECRETS_DIRECTORY}",
            guest_commands,
        )
        self.assertIn(
            f"install -d -o terrascale-orchestrator -g terrascale-orchestrator -m 0700 {CONTROLLER_DIRECTORY}",
            guest_commands,
        )
        self.assertIn(f"chmod 0755 {BOOTSTRAP_DIRECTORY} {BOOTSTRAP_DIRECTORY}/trust-roots", guest_commands)
        self.assertIn(
            f"chmod 0444 {BOOTSTRAP_DIRECTORY}/anchor.json {BOOTSTRAP_DIRECTORY}/identity.json {BOOTSTRAP_DIRECTORY}/trust-roots/*.pem",
            guest_commands,
        )
        self.assertIn(
            f"chown root:root {TIMESYNCD_CONFIG_GUEST}",
            guest_commands,
        )
        self.assertTrue(
            any(
                command.startswith("chmod 0644 ") and TIMESYNCD_CONFIG_GUEST in command
                for command in run_commands
            )
        )
        self.assertIn(TIME_WAIT_SYNC_DROPIN, guest_commands)
        self.assertIn("TimeoutStartSec=300s", guest_commands)
        for config_directory in (
            "/etc/systemd/timesyncd.conf",
            "/etc/systemd/timesyncd.conf.d/*.conf",
            "/run/systemd/timesyncd.conf.d/*.conf",
            "/usr/local/lib/systemd/timesyncd.conf.d/*.conf",
            "/usr/lib/systemd/timesyncd.conf.d/*.conf",
        ):
            self.assertIn(config_directory, guest_commands)
        self.assertIn("base image has active NTP/FallbackNTP configuration", guest_commands)
        self.assertIn("config_name=${config_file##*/}", guest_commands)
        self.assertIn("[ -L", guest_commands)
        self.assertIn(
            "install -d -o root -g root -m 0755 /etc/systemd/system/systemd-time-wait-sync.service.d",
            guest_commands,
        )
        self.assertIn(f"chmod 0644 {TIME_WAIT_SYNC_DROPIN}", guest_commands)
        enable_commands = [
            command for command in run_commands if "SYSTEMD_OFFLINE=1 systemctl enable" in command
        ]
        self.assertEqual(len(enable_commands), 1)
        time_sync_setup = next(command for command in run_commands if TIME_WAIT_SYNC_DROPIN in command)
        priority_setup_index = run_commands.index(priority_setup)
        enable_index = run_commands.index(enable_commands[0])
        self.assertLess(priority_setup_index, run_commands.index(time_sync_setup))
        self.assertLess(run_commands.index(time_sync_setup), enable_index)
        upload_positions = [
            index for index, argument in enumerate(virt_arguments) if argument == "--upload"
        ]
        self.assertLess(virt_arguments.index(priority_setup), min(upload_positions))
        self.assertLess(max(upload_positions), virt_arguments.index(enable_commands[0]))
        self.assertIn(f"chown root:root \\\n\t{RUNTIME_PRIORITY_PROFILE_GUEST}", enable_commands[0])
        self.assertIn(f"chmod 0644 \\\n\t{RUNTIME_PRIORITY_PROFILE_GUEST}", enable_commands[0])
        self.assertIn(f"chmod 0755 {RUNTIME_PRIORITY_HELPER_GUEST}", enable_commands[0])
        self.assertIn(
            "SYSTEMD_OFFLINE=1 systemctl enable systemd-timesyncd.service systemd-time-wait-sync.service terrascale-orchestrator-controller.service terrascale-orchestrator-host.service",
            enable_commands[0],
        )
        self.assertNotIn("terrascale-orchestrator-bootstrap.service", enable_commands[0])
        self.assertIn(
            'time_unit_state=$(SYSTEMD_OFFLINE=1 systemctl is-enabled "$time_unit")',
            enable_commands[0],
        )
        self.assertLess(run_commands.index(time_sync_setup), run_commands.index(enable_commands[0]))
        self.assertIn("--no-network", virt_arguments)
        self.assertNotIn("/run/terrascale-orchestrator-bootstrap", guest_commands)

    def test_native_verifier_rejects_wrong_digest_and_architecture_before_image_copy(self) -> None:
        wrong_digest = "0" * 64
        result = self.run_builder(native_verifier_sha256=wrong_digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native verifier bytes do not match", result.stderr)
        self.assertFalse(self.virt_arguments.exists())
        self.assertFalse(self.output.exists())

        native_bytes = bytearray(self.native_verifier.read_bytes())
        struct.pack_into("<H", native_bytes, 18, 62)
        self.native_verifier.write_bytes(native_bytes)
        result = self.run_builder(
            native_verifier_sha256=hashlib.sha256(native_bytes).hexdigest()
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ELF64 little-endian AArch64", result.stderr)
        self.assertFalse(self.virt_arguments.exists())
        self.assertFalse(self.output.exists())

    def test_native_verifier_guest_readback_mismatch_discards_candidate(self) -> None:
        result = self.run_builder(VIRT_CORRUPT_NATIVE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed native verifier bytes do not match", result.stderr)
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
                self.assertFalse(self.virt_identity_bytes.exists())

                existing.unlink()

        self.assertIn("virt-customize", self.events.read_text(encoding="utf-8"))

    def test_runtime_priority_profile_rejects_slice_floor_below_child_aggregate(self) -> None:
        self.priority_inputs["--system-slice-memory-min-bytes"] = str(64 << 20)
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("system.slice floors must cover aggregate", result.stderr)
        self.assertFalse(self.events.exists())
        self.assertFalse(self.virt_arguments.exists())
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

    def test_managed_root_is_opt_in_and_matches_shipped_host_namespace(self) -> None:
        host_unit = (ROOT / "deploy/systemd/terrascale-orchestrator-host.service").read_text(encoding="utf-8")
        self.assertIn("ProtectSystem=strict\n", host_unit)
        self.assertIn(f"ReadWritePaths=-{MANAGED_DIRECTORY}\n", host_unit)
        self.assertNotIn("ReadWritePaths=/srv\n", host_unit)

        result = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.virt_arguments.read_text(encoding="utf-8"))
        commands = [arguments[index + 1] for index, argument in enumerate(arguments[:-1])
                    if argument == "--run-command"]
        self.assertFalse(any(MANAGED_DIRECTORY in command for command in commands))

        self.output.unlink()
        self.virt_arguments.unlink()
        result = self.run_builder(managed_workload_gid="65534")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.virt_arguments.read_text(encoding="utf-8"))
        commands = [arguments[index + 1] for index, argument in enumerate(arguments[:-1])
                    if argument == "--run-command"]
        managed = [command for command in commands if "install -d -o root -g 65534 -m 0750 /srv/ts-managed"
                   in command]
        self.assertEqual(len(managed), 1)
        self.assertIn("[ ! -L /srv ] && [ -d /srv ]", managed[0])
        self.assertIn("[ ! -e /srv/ts-managed ] && [ ! -L /srv/ts-managed ]", managed[0])
        self.assertIn("'0:65534:750'", managed[0])
        self.assertLess(commands.index(managed[0]), next(index for index, command in enumerate(commands)
                                                 if "SYSTEMD_OFFLINE=1 systemctl enable" in command))

    def test_managed_workload_gid_rejects_unsafe_values_before_image_effects(self) -> None:
        for value in ("0", "00", "065534", "-1", "abc", "4294967295", "4294967296"):
            with self.subTest(gid=value):
                result = self.run_builder(managed_workload_gid=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("managed workload GID", result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse(self.virt_arguments.exists())
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
        self.assertFalse(self.virt_arguments.exists())
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
                self.assertFalse(self.virt_arguments.exists())
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
        self.assertEqual(self.virt_timesyncd_bytes.read_bytes(), generated_timesyncd_config)
        self.assertNotIn(b"198.19.", self.virt_timesyncd_bytes.read_bytes())
        self.assertIn(hashlib.sha256(generated_timesyncd_config).hexdigest(), result.stdout)

    def test_competing_base_timesyncd_configuration_fails_closed(self) -> None:
        competing_config = self.base_image_root / "etc/systemd/timesyncd.conf.d/20-base.conf"
        competing_config.parent.mkdir(parents=True)
        competing_config.write_text("[Time]\nNTP=base.example\n", encoding="utf-8")
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("base image has active NTP/FallbackNTP configuration", result.stderr)
        self.assertIn(str(competing_config), result.stderr)
        self.assertFalse(self.output.exists())
        self.assertIn("virt-customize", self.events.read_text(encoding="utf-8"))

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
        self.assertIn("virt-customize", self.events.read_text(encoding="utf-8"))

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
        self.assertFalse(self.virt_arguments.exists())
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
        self.assertFalse(self.virt_arguments.exists())
        self.assertFalse(self.output.exists())

    def test_bootstrap_identity_must_match_baked_schema_and_canonical_field_order(self) -> None:
        self.identity.write_bytes(
            b'{"deploymentId":"deployment-a","environment":"canary","cell":"GRU"}'
        )
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schemaVersion, deploymentId, environment, and cell", result.stderr)
        self.assertFalse(self.bootstrap_arguments.exists())
        self.assertFalse(self.virt_arguments.exists())

        self.identity.write_bytes(
            b'{"deploymentId":"deployment-a","schemaVersion":1,"environment":"canary","cell":"GRU"}'
        )
        result = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical schema-version-1 JSON", result.stderr)
        self.assertFalse(self.bootstrap_arguments.exists())
        self.assertFalse(self.virt_arguments.exists())

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
                self.virt_arguments.unlink(missing_ok=True)
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
                self.assertFalse(self.virt_arguments.exists())
                self.assertFalse(self.output.exists())

    def test_sysusers_account_matches_controller_service_user_and_group(self) -> None:
        sysusers_lines = [
            line.strip()
            for line in (ROOT / "deploy/image/terrascale-orchestrator.sysusers").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        users = [shlex.split(line) for line in sysusers_lines if line.startswith("u ")]
        self.assertEqual(len(users), 1)

        unit = (ROOT / "deploy/systemd/terrascale-orchestrator-controller.service").read_text(encoding="utf-8")
        unit_user = next(line.split("=", 1)[1] for line in unit.splitlines() if line.startswith("User="))
        unit_group = next(line.split("=", 1)[1] for line in unit.splitlines() if line.startswith("Group="))
        self.assertEqual(users[0][1], "terrascale-orchestrator")
        self.assertEqual(unit_user, "terrascale-orchestrator")
        self.assertEqual(unit_group, "terrascale-orchestrator")
        self.assertEqual(users[0][1], unit_user)
        self.assertEqual(unit_user, unit_group)


if __name__ == "__main__":
    unittest.main()
