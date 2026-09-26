from __future__ import annotations

import signal
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


class ResultParserTests(unittest.TestCase):
    def test_accepts_explicit_focused_go_and_rust_passes(self):
        serial = GO_PASS + RUST_PASS + qualify.RUNNER_SUCCESS + "\n"
        results = qualify.parse_qualification_result(GO_PASS, 0, RUST_PASS, 0, serial, RUST_NAME)

        self.assertEqual(results["go_host_test"]["status"], "PASS")
        self.assertEqual(results["rust_test"]["status"], "PASS")
        self.assertEqual(results["rust_test"]["sender_marker"], qualify.SENDER_SUCCESS)

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
        with self.assertRaisesRegex(qualify.QualificationError, "runner PASS sentinel"):
            qualify.parse_qualification_result(GO_PASS, 0, RUST_PASS, 0, serial, RUST_NAME)

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


class QualificationCleanupTests(unittest.TestCase):
    def make_qualification(self, root: Path) -> qualify.Qualification:
        for name in ("logs", "commands", "images", "mount", "stage"):
            (root / name).mkdir(parents=True, exist_ok=True)
        return qualify.Qualification(
            {"source_commits": {}, "rust_test_name": RUST_NAME}, b"{}", {}, root)

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
