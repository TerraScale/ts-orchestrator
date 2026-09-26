from __future__ import annotations

import signal
import json
import hashlib
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import os
import stat
import unittest
from unittest.mock import patch

import qualify


GO_PASS = """=== RUN   TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery
--- PASS: TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery (0.00s)
PASS
"""

RUST_NAME = qualify.RUST_TEST_NAME
RUST_PASS = f"""running 1 test
test {RUST_NAME} ...
MEMBER_STATUS_GO_OK
{qualify.SENDER_SUCCESS}
ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""
MANAGED_VOLUME_EVIDENCE = (
    "managed-volume-v1 device=/dev/oracleoci/oraclevdb "
    f"uuid={qualify.MANAGED_VOLUME_UUID} mount={qualify.MANAGED_MOUNT_PATH} "
    "mount_id=23 replication_shard=absent"
)
MANAGED_VOLUME_PASS = f"""=== RUN   {qualify.MANAGED_VOLUME_GO_TEST_NAME}
    managed_runtime_firecracker_test.go:1: {MANAGED_VOLUME_EVIDENCE}
--- PASS: {qualify.MANAGED_VOLUME_GO_TEST_NAME} (0.00s)
PASS
"""


class ResultParserTests(unittest.TestCase):
    def test_accepts_explicit_focused_go_and_rust_passes(self):
        serial = GO_PASS + RUST_PASS + qualify.RUNNER_SUCCESS + "\n"
        results = qualify.parse_qualification_result(GO_PASS, 0, RUST_PASS, 0, serial, RUST_NAME)

        self.assertEqual(results["go_host_test"]["status"], "PASS")
        self.assertEqual(results["rust_test"]["status"], "PASS")
        self.assertEqual(results["rust_test"]["sender_marker"], qualify.SENDER_SUCCESS)

    def test_accepts_systemd_prefixed_console_output(self):
        raw = GO_PASS + RUST_PASS + qualify.RUNNER_SUCCESS + "\n"
        serial = "\n".join(
            f"[   33.785579] ts-member-status-qualification[770]: {line}"
            for line in raw.splitlines())
        results = qualify.parse_qualification_result(GO_PASS, 0, RUST_PASS, 0, serial, RUST_NAME)

        self.assertEqual(results["rust_test"]["status"], "PASS")

    def test_go_parser_rejects_skip_missing_multiple_zero_wrong_name_and_failure(self):
        cases = (
            ("skip", GO_PASS.replace("--- PASS:", "--- SKIP:"), 0),
            ("missing", "PASS\n", 0),
            ("multiple", GO_PASS + GO_PASS, 0),
            ("zero", "testing: warning: no tests to run\nPASS\n", 0),
            ("wrong name", GO_PASS.replace(qualify.GO_TEST_NAME, "TestSomethingElse"), 0),
            ("failed exit", GO_PASS, 1),
        )
        for label, output, returncode in cases:
            with self.subTest(label=label), self.assertRaises(qualify.QualificationError):
                qualify.parse_go_test_output(output, returncode)

    def test_managed_volume_parser_requires_exact_test_and_mount_evidence(self):
        serial = MANAGED_VOLUME_PASS + qualify.MANAGED_VOLUME_RUNNER_SUCCESS + "\n"
        result = qualify.parse_managed_volume_result(MANAGED_VOLUME_PASS, 0, serial)
        self.assertEqual(result["go_host_test"]["name"], qualify.MANAGED_VOLUME_GO_TEST_NAME)
        self.assertEqual(result["managed_volume"]["mount_id"], 23)
        self.assertEqual(result["managed_volume"]["replication_shard"], "absent")

        cases = (
            (MANAGED_VOLUME_PASS.replace("--- PASS:", "--- SKIP:"), serial),
            (MANAGED_VOLUME_PASS, serial.replace("mount_id=23", "mount_id=0")),
            (MANAGED_VOLUME_PASS, serial.replace("replication_shard=absent", "replication_shard=present")),
            (MANAGED_VOLUME_PASS, serial.replace(qualify.MANAGED_VOLUME_RUNNER_SUCCESS,
                                                  qualify.MANAGED_VOLUME_RUNNER_SUCCESS + "\n" +
                                                  qualify.MANAGED_VOLUME_RUNNER_SUCCESS)),
            (MANAGED_VOLUME_PASS, qualify.MANAGED_VOLUME_RUNNER_SUCCESS + "\n" + MANAGED_VOLUME_PASS),
        )
        for output, bad_serial in cases:
            with self.subTest(output=output[:24], serial=bad_serial[-48:]), \
                    self.assertRaises(qualify.QualificationError):
                qualify.parse_managed_volume_result(output, 0, bad_serial)

    def test_managed_volume_manifest_requires_exact_test_inputs_uuid_and_no_rust(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = qualify.MANAGED_VOLUME_INPUT_NAMES
            inputs = {}
            for name in names:
                path = root / name
                path.write_bytes(name.encode())
                if name in ("firecracker", "go_host_test"):
                    path.chmod(0o755)
                inputs[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            manifest = {
                "profile": qualify.MANAGED_VOLUME_PROFILE,
                "source_commits": {"orchestrator": "a" * 40, "terrabase": "b" * 40},
                "go_test_name": qualify.MANAGED_VOLUME_GO_TEST_NAME,
                "managed_volume": {"filesystem_uuid": qualify.MANAGED_VOLUME_UUID},
                "inputs": inputs,
            }
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest))
            loaded, _, resolved = qualify.load_manifest(path)
            self.assertEqual(set(resolved), set(names))
            self.assertEqual(loaded["profile"], qualify.MANAGED_VOLUME_PROFILE)

            invalid = []
            invalid.append({**manifest, "rust_test_name": qualify.RUST_TEST_NAME})
            invalid.append({**manifest, "go_test_name": "TestSomethingElse"})
            invalid.append({**manifest, "managed_volume": {"filesystem_uuid": "not-pinned"}})
            invalid.append({**manifest, "inputs": {**inputs, "rust_test": inputs["go_host_test"]}})
            for candidate in invalid:
                path.write_text(json.dumps(candidate))
                with self.subTest(candidate=candidate.keys()), self.assertRaises(qualify.QualificationError):
                    qualify.load_manifest(path)

    def test_absent_profile_preserves_legacy_manifest_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = {}
            for name in qualify.INPUT_NAMES:
                path = root / name
                path.write_bytes(name.encode())
                if name in ("firecracker", "go_host_test", "memberstatus_probe", "rust_server", "rust_test"):
                    path.chmod(0o755)
                inputs[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            manifest = {
                "source_commits": {"orchestrator": "a" * 40, "terrabase": "b" * 40},
                "rust_test_name": qualify.RUST_TEST_NAME,
                "inputs": inputs,
            }
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest))
            loaded, _, resolved = qualify.load_manifest(path)
            self.assertIsNone(loaded["profile"])
            self.assertEqual(set(resolved), set(qualify.INPUT_NAMES))
            self.assertEqual(loaded["rust_test_name"], qualify.RUST_TEST_NAME)

    def test_rust_parser_rejects_zero_ignored_wrong_name_multiple_and_failed_exit(self):
        cases = (
            ("zero", RUST_PASS.replace("running 1 test", "running 0 tests")
             .replace(f"test {RUST_NAME} ... \n", "")
             .replace("1 passed", "0 passed"), 0),
            ("ignored", RUST_PASS.replace("1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored"), 0),
            ("measured", RUST_PASS.replace("0 measured", "1 measured"), 0),
            ("wrong name", RUST_PASS.replace(RUST_NAME, "some_other_test"), 0),
            ("multiple", RUST_PASS.replace("running 1 test", "running 2 tests")
             .replace("1 passed;", "2 passed;"), 0),
            ("failed exit", RUST_PASS, 1),
        )
        for label, output, returncode in cases:
            with self.subTest(label=label), self.assertRaises(qualify.QualificationError):
                qualify.parse_rust_test_output(output, returncode, RUST_NAME)

    def test_rust_parser_requires_nested_probe_and_current_sender_success(self):
        cases = (
            ("missing Go marker", RUST_PASS.replace(qualify.MEMBER_STATUS_SUCCESS + "\n", "")),
            ("missing sender marker", RUST_PASS.replace(qualify.SENDER_SUCCESS + "\n", "")),
            ("duplicate sender marker", RUST_PASS.replace(qualify.SENDER_SUCCESS,
                                                           qualify.SENDER_SUCCESS + "\n" + qualify.SENDER_SUCCESS)),
        )
        for label, output in cases:
            with self.subTest(label=label), self.assertRaises(qualify.QualificationError):
                qualify.parse_rust_test_output(output, 0, RUST_NAME)

    def test_qualification_parser_rejects_missing_runner_sentinel(self):
        serial = GO_PASS + RUST_PASS
        with self.assertRaisesRegex(qualify.QualificationError, "terminal runner result"):
            qualify.parse_qualification_result(GO_PASS, 0, RUST_PASS, 0, serial, RUST_NAME)

    def test_runner_failure_parser_reports_actual_prefixed_serial_stage_and_status(self):
        serial = ("[   33.785579] ts-member-status-qualification[770]: "
                  "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=rust-test status=101\n")

        result = qualify.parse_runner_result(serial)

        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["stage"], "rust-test")
        self.assertEqual(result["exit_status"], 101)

    def test_runner_result_parser_rejects_missing_or_duplicate_terminal_results(self):
        cases = (
            "guest shut down unexpectedly\n",
            qualify.RUNNER_SUCCESS + "\n" + qualify.RUNNER_SUCCESS + "\n",
            "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=unknown status=101\n",
        )
        for serial in cases:
            with self.subTest(serial=serial), self.assertRaises(qualify.QualificationError):
                qualify.parse_runner_result(serial)

    def test_qualification_parser_rejects_sentinel_before_test_results(self):
        serial = qualify.RUNNER_SUCCESS + "\n" + GO_PASS + RUST_PASS
        with self.assertRaisesRegex(qualify.QualificationError, "before"):
            qualify.parse_qualification_result(GO_PASS, 0, RUST_PASS, 0, serial, RUST_NAME)

    def test_guest_path_resolution_rejects_symlink_ancestors_and_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "guest"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "var").symlink_to(outside, target_is_directory=True)
            (outside / "evidence.log").write_text("forged evidence")

            with self.assertRaisesRegex(qualify.QualificationError, "symlink"):
                qualify._read_guest_regular_file(root, Path("/var/evidence.log"), 1024)

    def test_guest_path_resolution_only_reads_regular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "guest"
            (root / "var/log").mkdir(parents=True)
            (root / "var/log/evidence.log").write_text("regular evidence")
            text, oversized = qualify._read_guest_regular_file(root, Path("/var/log/evidence.log"), 1024)

        self.assertEqual(text, "regular evidence")
        self.assertFalse(oversized)


class PrivateSocketDirectoryTests(unittest.TestCase):
    def test_socket_directory_is_private_and_owned_by_caller(self):
        directory = qualify.make_private_socket_dir()
        try:
            metadata = directory.stat()
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700)
            self.assertLess(len(os.fsencode(directory / "api.sock")), 100)
        finally:
            directory.rmdir()


class BoundedLogTests(unittest.TestCase):
    def test_command_log_truncation_fails_the_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "commands").mkdir()
            (root / "logs").mkdir()
            events = qualify.EventLog(root / "logs/events.json")
            runner = qualify.CommandRunner(root, events)
            with patch.object(qualify, "MAX_COMMAND_LOG_BYTES", 4):
                with self.assertRaisesRegex(qualify.CommandFailure, "log was truncated"):
                    runner.run("truncate", [sys.executable, "-c", "print('more than four bytes')"], timeout=2)

    def test_firecracker_serial_truncation_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = qualify.EventLog(root / "events.json")
            read_fd, write_fd = os.pipe()
            capture = qualify.BoundedOutput(os.fdopen(read_fd, "rb"), root / "serial.log", 4)
            try:
                os.write(write_fd, b"serial output exceeds limit")
            finally:
                os.close(write_fd)
            vm = qualify.FirecrackerVM.__new__(qualify.FirecrackerVM)
            vm.serial_capture = capture
            vm.vmm_capture = None
            vm.output_capture = {}
            vm.events = events

            with self.assertRaisesRegex(qualify.QualificationError, "truncated: serial"):
                vm._finish_output()


class ManagedVolumeAttachTests(unittest.TestCase):
    def test_volume_drive_is_registered_before_instance_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            socket_dir = root / "socket"
            socket_dir.mkdir()
            socket_path = socket_dir / "api.sock"
            socket_path.touch()
            logs = root / "logs"
            logs.mkdir()
            events = qualify.EventLog(logs / "events.json")
            vm = qualify.FirecrackerVM(
                root / "firecracker", root / "kernel", root / "rootfs", socket_dir, logs, events,
                root / "managed-volume.ext4")
            calls = []

            class Capture:
                def __init__(self, stream, path, maximum):
                    self.path = path

            process = type("Process", (), {"pid": 123, "stdout": object(), "stderr": object(),
                                             "returncode": None})()
            with patch.object(qualify.subprocess, "Popen", return_value=process), \
                    patch.object(qualify, "BoundedOutput", Capture), \
                    patch.object(qualify, "_child_exited_without_reaping", return_value=False), \
                    patch.object(vm, "_api", side_effect=lambda method, path, payload=None:
                                 calls.append((method, path, payload)) or {}):
                vm.start()

            drive_index = next(index for index, call in enumerate(calls)
                               if call[1] == "/drives/managed-volume")
            start_index = next(index for index, call in enumerate(calls)
                               if call[1] == "/actions" and call[2]["action_type"] == "InstanceStart")
            self.assertLess(drive_index, start_index)
            self.assertEqual(calls[drive_index][2], {
                "drive_id": "managed-volume", "path_on_host": str(root / "managed-volume.ext4"),
                "is_root_device": False, "is_read_only": False})


class GuestRunnerFailureTests(unittest.TestCase):
    def test_service_timeout_leaves_host_shutdown_fallback(self):
        self.assertLess(qualify.GUEST_SERVICE_TIMEOUT_SECONDS, qualify.GUEST_DEADLINE_SECONDS)
        self.assertIn(f"TimeoutStartSec={qualify.GUEST_SERVICE_TIMEOUT_SECONDS}s",
                      qualify._service_unit())

    def test_successful_guest_commands_record_pass_and_request_reboot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = root / "guest"
            binary_dir = guest / "opt/ts-member-status"
            binary_dir.mkdir(parents=True)
            go_binary = binary_dir / "go-host-test"
            rust_binary = binary_dir / "rust-test"
            go_binary.write_text("#!/bin/sh\nprintf 'Go tests passed\\n'\n")
            rust_binary.write_text("#!/bin/sh\nprintf 'Rust test passed\\n'\n")
            go_binary.chmod(0o755)
            rust_binary.chmod(0o755)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            reboot_record = root / "reboot-args"
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >{str(reboot_record)!r}\n")
            fake_systemctl.chmod(0o755)
            script = root / "runner.sh"
            script.write_text(qualify._shell_runner(
                Path("unused-go"), Path("unused-probe"), Path("unused-server"),
                Path("unused-rust"), RUST_NAME, guest_root=guest))
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"

            process = subprocess.run(["/bin/sh", str(script)], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, env=environment, timeout=5,
                                     check=False, text=True)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(process.stdout.count(qualify.RUNNER_SUCCESS), 1)
            self.assertNotIn("MEMBER_STATUS_QUALIFICATION_RESULT=FAILED", process.stdout)
            self.assertEqual(reboot_record.read_text().strip(), "--no-wall reboot")

    def test_failed_guest_command_records_stage_and_requests_reboot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = root / "guest"
            go_binary = guest / "opt/ts-member-status/go-host-test"
            go_binary.parent.mkdir(parents=True)
            go_binary.write_text("#!/bin/sh\nprintf 'focused Go failure\\n'\nexit 37\n")
            go_binary.chmod(0o755)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            reboot_record = root / "reboot-args"
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >{str(reboot_record)!r}\n")
            fake_systemctl.chmod(0o755)
            script = root / "runner.sh"
            script.write_text(qualify._shell_runner(
                Path("unused-go"), Path("unused-probe"), Path("unused-server"),
                Path("unused-rust"), RUST_NAME, guest_root=guest))
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"

            process = subprocess.run(["/bin/sh", str(script)], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, env=environment, timeout=5,
                                     check=False, text=True)
            output = guest / "var/log/ts-member-status-qualification/go-host-test.log"

            self.assertEqual(process.returncode, 37)
            self.assertEqual(process.stdout.count(
                "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=go-host-test status=37"), 1)
            self.assertNotIn(qualify.RUNNER_SUCCESS, process.stdout)
            self.assertEqual(reboot_record.read_text().strip(), "--no-wall reboot")
            self.assertIn("stage=go-host-test status=37", output.read_text())
            result = qualify.parse_runner_result(process.stdout)
            self.assertEqual(result["stage"], "go-host-test")
            self.assertEqual(result["exit_status"], 37)

    def test_managed_volume_runner_records_mount_evidence_and_requests_reboot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = root / "guest"
            binary = guest / "opt/ts-managed-volume-qualification/host.test"
            binary.parent.mkdir(parents=True)
            binary.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' '=== RUN   {qualify.MANAGED_VOLUME_GO_TEST_NAME}'\n"
                f"printf '%s\\n' '    managed_runtime_firecracker_test.go:1: {MANAGED_VOLUME_EVIDENCE}'\n"
                f"printf '%s\\n' '--- PASS: {qualify.MANAGED_VOLUME_GO_TEST_NAME} (0.00s)' 'PASS'\n")
            binary.chmod(0o755)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            reboot_record = root / "reboot-args"
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >{str(reboot_record)!r}\n")
            fake_systemctl.chmod(0o755)
            script = root / "runner.sh"
            script.write_text(qualify._managed_volume_shell_runner(guest_root=guest))
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            process = subprocess.run(["/bin/sh", str(script)], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, env=environment, timeout=5,
                                     check=False, text=True)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(reboot_record.read_text().strip(), "--no-wall reboot")
            results = qualify.parse_managed_volume_result(
                (guest / "var/log/ts-managed-volume-qualification/go-host-test.log").read_text(),
                0, process.stdout)
            self.assertEqual(results["managed_volume"]["mount_id"], 23)

    def test_managed_volume_setup_and_service_keep_mount_privilege_separate(self):
        script = qualify._managed_volume_setup_script()
        setup = qualify._managed_volume_setup_unit(qualify.MANAGED_VOLUME_UUID)
        service = qualify._service_unit(qualify.MANAGED_VOLUME_UUID)

        self.assertIn('ln -s ../vdb "$ALIAS"', script)
        self.assertIn(f"mount -t ext4 -o rw \"$ALIAS\" \"$MOUNT\"", script)
        self.assertNotIn("replication/shard", script)
        self.assertIn("Environment=TS_FC_VOLUME_UUID=", setup)
        self.assertIn(f"Before={qualify.SERVICE_NAME}", setup)
        self.assertIn(f"Requires={qualify.MANAGED_VOLUME_SETUP_SERVICE_NAME}", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertNotIn("SYS_ADMIN", service)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "setup.sh"
            path.write_text(script)
            checked = subprocess.run(["/bin/sh", "-n", str(path)], check=False)
            self.assertEqual(checked.returncode, 0)


class QualificationCleanupTests(unittest.TestCase):
    def make_qualification(self, root: Path) -> qualify.Qualification:
        for name in ("logs", "commands", "images", "mount", "stage"):
            (root / name).mkdir(parents=True, exist_ok=True)
        return qualify.Qualification(
            {"source_commits": {}, "rust_test_name": RUST_NAME}, b"{}", {}, root)

    def test_driver_surfaces_guest_failure_before_requiring_pass_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            qualification = self.make_qualification(Path(directory) / "run")
            (qualification.logs / "guest-serial.log").write_text(
                "[   33.785579] ts-member-status-qualification[770]: "
                "MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=rust-test status=101\n")

            with self.assertRaisesRegex(qualify.QualificationError, "stage=rust-test status=101"):
                qualification._check_results()

            self.assertEqual(qualification.test_results["runner"]["stage"], "rust-test")
            self.assertEqual(qualification.test_results["runner"]["exit_status"], 101)

    def test_private_image_is_retained_after_qualification_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            qualification = self.make_qualification(root)
            qualification.image.write_bytes(b"guest evidence")
            qualification.failure = "QualificationError: focused test failed"

            qualification._cleanup_image()

            self.assertTrue(qualification.image.exists())

    def test_unquiesced_vmm_retains_its_socket_and_private_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            qualification = self.make_qualification(root)
            qualification.image.write_bytes(b"guest evidence")
            socket_dir = root / "api-socket"
            socket_dir.mkdir()
            qualification.socket_dir = socket_dir
            ready = root / "vmm-ready"
            source = (f"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                      f"open({str(ready)!r}, 'w').close(); time.sleep(20)")
            output = (root / "fake-vmm.log").open("wb")
            self.addCleanup(output.close)
            process = subprocess.Popen([sys.executable, "-c", source], stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            fake_vm = type("FakeVM", (), {})()
            fake_vm.process = process
            fake_vm.process_group_stopped = False
            fake_vm.socket_path = socket_dir / "api.sock"
            qualification.vm = fake_vm
            try:
                deadline = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "fake VMM did not become ready")
                with patch.object(qualify, "_wait_process_group_quiescent", return_value=False):
                    with self.assertRaisesRegex(qualify.QualificationError, "live members"):
                        qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=0.1)

                qualification._cleanup_socket_dir()
                qualification._cleanup_image()

                self.assertIsNone(process.returncode, "unquiesced leader must remain unreaped")
                self.assertTrue(socket_dir.exists(), "API socket directory must remain while VMM is unresolved")
                self.assertTrue(qualification.image.exists(), "guest image must remain while VMM is unresolved")
            finally:
                if process.returncode is None:
                    qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=1)


class ProcessGroupCleanupTests(unittest.TestCase):
    def spawn(self, directory: str, source: str) -> subprocess.Popen[bytes]:
        output = Path(directory) / f"process-{len(list(Path(directory).glob('process-*.log')))}.log"
        stream = output.open("wb")
        self.addCleanup(stream.close)
        return subprocess.Popen([sys.executable, "-c", source], stdout=stream,
                                stderr=subprocess.STDOUT, start_new_session=True)

    def wait_ready(self, path: Path, process: subprocess.Popen[bytes]) -> None:
        deadline = time.monotonic() + 2
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(path.exists(), "signal-test child did not become ready")

    def test_graceful_term_reaps_owned_group(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            source = (f"import signal,time,sys; signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
                      f"open({str(ready)!r}, 'w').close(); time.sleep(20)")
            process = self.spawn(directory, source)
            self.wait_ready(ready, process)
            result = qualify.stop_process_group(process, term_timeout=1, kill_timeout=1)

        self.assertEqual(result, 0)
        self.assertIsNotNone(process.poll())

    def test_escalates_to_kill_when_term_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            source = (f"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                      f"open({str(ready)!r}, 'w').close(); time.sleep(20)")
            process = self.spawn(directory, source)
            self.wait_ready(ready, process)
            result = qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=1)

        self.assertEqual(result, -signal.SIGKILL)
        self.assertIsNotNone(process.poll())

    def test_quiescence_timeout_leaves_leader_unreaped_for_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            source = (f"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                      f"open({str(ready)!r}, 'w').close(); time.sleep(20)")
            process = self.spawn(directory, source)
            self.wait_ready(ready, process)
            with patch.object(qualify, "_wait_process_group_quiescent", return_value=False):
                with self.assertRaisesRegex(qualify.QualificationError, "live members"):
                    qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=0.1)
            self.assertIsNone(process.returncode, "group leader must remain unreaped after inconclusive cleanup")
            result = qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=1)

        self.assertEqual(result, -signal.SIGKILL)
        self.assertIsNotNone(process.returncode)

    def test_already_gone_group_needs_no_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            process = self.spawn(directory, "pass")
            self.assertEqual(process.wait(timeout=2), 0)

        with self.assertRaisesRegex(qualify.QualificationError, "reaped before its process group"):
            qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=0.1)

    def test_cleanup_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            source = (f"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                      f"open({str(ready)!r}, 'w').close(); time.sleep(20)")
            process = self.spawn(directory, source)
            self.wait_ready(ready, process)
            first = qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=1)
            second = qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=1)

        self.assertEqual(first, second)
        self.assertEqual(process.returncode, -signal.SIGKILL)

    def test_kills_child_that_survives_its_exited_leader(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "child-ready"
            progress = Path(directory) / "child-progress"
            source = f"""
import os
import signal
import time

child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    open({str(ready)!r}, 'w').close()
    progress = {str(progress)!r}
    while True:
        with open(progress, 'a') as stream:
            stream.write('x')
        time.sleep(0.02)
else:
    os._exit(0)
"""
            process = self.spawn(directory, source)
            try:
                self.wait_ready(ready, process)
                deadline = time.monotonic() + 2
                while (not progress.exists() or progress.stat().st_size == 0) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(progress.exists() and progress.stat().st_size > 0)
                self.assertTrue(qualify._wait_child_without_reaping(process, 2),
                                "session leader did not exit while its child remained")
                self.assertIsNone(process.returncode, "leader must remain unreaped until group cleanup")

                result = qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=1)
                stopped_size = progress.stat().st_size
                time.sleep(0.1)
                self.assertEqual(progress.stat().st_size, stopped_size,
                                 "child continued after its process group was cleaned")
            finally:
                if process.returncode is None:
                    qualify.stop_process_group(process, term_timeout=0.1, kill_timeout=1)

        self.assertEqual(result, 0)
        self.assertIsNotNone(process.returncode)

    def test_cleanup_does_not_signal_an_unrelated_group(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            source = (f"import signal,time,sys; signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
                      f"open({str(ready)!r}, 'w').close(); time.sleep(20)")
            owned = self.spawn(directory, source)
            self.wait_ready(ready, owned)
            unrelated = self.spawn(directory, "import time; time.sleep(20)")
            self.assertNotEqual(owned.pid, unrelated.pid)
            qualify.stop_process_group(owned, term_timeout=1, kill_timeout=1)
            self.assertIsNone(unrelated.poll())
            qualify.stop_process_group(unrelated, term_timeout=1, kill_timeout=1)


if __name__ == "__main__":
    unittest.main()
