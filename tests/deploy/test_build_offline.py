import json
import hashlib
import os
import re
import shlex
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "deploy/image/build-offline.sh"
BOOTSTRAP_DIRECTORY = "/etc/terrascale-orchestrator/bootstrap"
MARKER_DIRECTORY = "/var/lib/terrascale-orchestrator-bootstrap"
SECRETS_DIRECTORY = "/var/lib/terrascale-orchestrator-secrets"
TIMESYNCD_CONFIG_GUEST = "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf"
TIME_WAIT_SYNC_DROPIN = "/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf"
BAKED_LOADER = ROOT / "internal/bootstrapstart/baked.go"


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
        self.receipt = self.write_file(self.inputs / "release receipt.json", b"mock receipt")
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
for index, argument in enumerate(arguments[:-1]):
    if argument == "--upload":
        source, destination = arguments[index + 1].rsplit(":", 1)
        if destination == "/etc/terrascale-orchestrator/bootstrap/identity.json":
            Path(os.environ["VIRT_IDENTITY_BYTES_PATH"]).write_bytes(Path(source).read_bytes())
        if destination == "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf":
            Path(os.environ["VIRT_TIMESYNCD_BYTES_PATH"]).write_bytes(Path(source).read_bytes())
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
                "BASE_IMAGE_ROOT_PATH": str(self.base_image_root),
            }
        )
        environment.update(overrides)
        return environment

    def run_builder(self, **environment_overrides: str) -> subprocess.CompletedProcess[str]:
        return self.run_builder_with_roots(
            [self.bootstrap_root_a, self.bootstrap_root_b], **environment_overrides
        )

    def run_builder_with_roots(
        self, bootstrap_roots: list[Path], **environment_overrides: str
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            str(BUILDER),
            "--base",
            str(self.base),
            "--binary",
            str(self.binary),
            "--receipt",
            str(self.receipt),
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
        for bootstrap_root in bootstrap_roots:
            arguments.extend(("--bootstrap-root", str(bootstrap_root)))
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
        self.assertIn(
            "SYSTEMD_OFFLINE=1 systemctl enable systemd-timesyncd.service systemd-time-wait-sync.service terrascale-orchestrator-controller.service terrascale-orchestrator-host.service",
            enable_commands[0],
        )
        self.assertNotIn("terrascale-orchestrator-bootstrap.service", enable_commands[0])
        self.assertIn(
            'time_unit_state=$(SYSTEMD_OFFLINE=1 systemctl is-enabled "$time_unit")',
            enable_commands[0],
        )
        time_sync_setup = next(command for command in run_commands if TIME_WAIT_SYNC_DROPIN in command)
        self.assertLess(run_commands.index(time_sync_setup), run_commands.index(enable_commands[0]))
        self.assertIn("--no-network", virt_arguments)
        self.assertNotIn("/run/terrascale-orchestrator-bootstrap", guest_commands)

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
        self.assertIn(
            "CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID CAP_DAC_OVERRIDE CAP_KILL",
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
