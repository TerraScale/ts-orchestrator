#!/usr/bin/env python3
"""Qualify the native member-status reader in one isolated Firecracker guest.

All executable inputs are supplied by an immutable manifest. The driver never
builds code or provisions network access, and it stages files only into a
private writable copy of the supplied ext4 image.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Iterable


REPO = Path(__file__).resolve().parents[3]
INPUT_NAMES = (
    "kernel",
    "rootfs",
    "firecracker",
    "go_host_test",
    "memberstatus_probe",
    "rust_server",
    "rust_test",
)
GO_TEST_NAME = "TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery"
RUST_TEST_NAME = "member_control_managed::managed_member_status_cross_language_process_boundary"
GO_SUCCESS = "PASS"
MEMBER_STATUS_SUCCESS = "MEMBER_STATUS_GO_OK"
SENDER_SUCCESS = "memberstatus: authenticated Go client accepted real sender-enabled process"
RUNNER_SUCCESS = "MEMBER_STATUS_QUALIFICATION_RESULT=PASS"
RUNNER_RESULT_PREFIX = "MEMBER_STATUS_QUALIFICATION_RESULT="
RUNNER_FAILURE = re.compile(
    r"^MEMBER_STATUS_QUALIFICATION_RESULT=FAILED stage=(?P<stage>[a-z0-9-]+) "
    r"status=(?P<status>[1-9][0-9]{0,2})$")
RUNNER_STAGES = {"go-host-test", "rust-test", "runner"}
_SERIAL_SERVICE_LINE = re.compile(
    r"^\[\s*\d+(?:\.\d+)?\]\s+ts-member-status-qualification\[\d+\]: (?P<payload>.*)$")
SERVICE_NAME = "ts-member-status-qualification.service"
BOOT_ARGS = "console=ttyS0 reboot=k panic=-1 pci=off root=/dev/vda rw systemd.unit=multi-user.target"
GUEST_RAM_MIB = 6144
GUEST_VCPUS = 2
GUEST_DEADLINE_SECONDS = 300
GUEST_SERVICE_TIMEOUT_SECONDS = 270
API_SOCKET_SECONDS = 20
GO_TEST_TIMEOUT = "120s"
MAX_COMMAND_LOG_BYTES = 8 << 20
MAX_SERIAL_LOG_BYTES = 32 << 20
MAX_GUEST_LOG_BYTES = 8 << 20
IMAGE_MIN_BYTES = 8 << 30
CAPABILITY_BOUNDING_SET = "CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP"


class QualificationError(RuntimeError):
    """A manifest, test-result, resource, or cleanup invariant failed."""


class CommandFailure(QualificationError):
    def __init__(self, command: list[str], returncode: int | None,
                 log_path: Path, detail: str = ""):
        suffix = f": {detail}" if detail else ""
        super().__init__(f"command failed ({returncode}): {command!r}; log: {log_path}{suffix}")
        self.command = command
        self.returncode = returncode
        self.log_path = log_path


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_replace(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content)
    temporary.chmod(0o600)
    with temporary.open("rb+") as stream:
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _valid_commit(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40,64}", value) is not None


def make_private_socket_dir() -> Path:
    uid = os.getuid()
    candidates = [Path(f"/run/user/{uid}"), Path("/tmp")]
    failures: list[str] = []
    for parent in candidates:
        try:
            metadata = parent.stat()
            if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
                continue
            if parent != Path("/tmp") and (metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) & 0o077):
                continue
            directory = Path(tempfile.mkdtemp(prefix="tsms-", dir=parent))
            directory.chmod(0o700)
            created = directory.stat()
            if created.st_uid != uid or stat.S_IMODE(created.st_mode) != 0o700:
                directory.rmdir()
                failures.append(f"unexpected owner or mode at {directory}")
                continue
            if len(os.fsencode(directory / "api.sock")) >= 100:
                directory.rmdir()
                failures.append(f"Unix socket path too long under {parent}")
                continue
            return directory
        except OSError as error:
            failures.append(f"{parent}: {error}")
    raise QualificationError("could not create a private short API socket directory: " + "; ".join(failures))


def _guest_path_without_symlinks(mount_root: Path, guest_path: Path) -> Path:
    if not guest_path.is_absolute() or ".." in guest_path.parts:
        raise QualificationError(f"unsafe guest path: {guest_path}")
    current = mount_root
    parts = guest_path.parts[1:]
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise QualificationError(f"guest path contains a symlink that could escape the image: {current}")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise QualificationError(f"guest path parent is not a directory: {current}")
    return mount_root / guest_path.relative_to("/")


def _read_guest_regular_file(mount_root: Path, guest_path: Path,
                             maximum: int) -> tuple[str, bool]:
    host_path = _guest_path_without_symlinks(mount_root, guest_path)
    try:
        metadata = host_path.lstat()
    except OSError:
        raise
    if not stat.S_ISREG(metadata.st_mode):
        raise QualificationError(f"guest evidence path is not a regular file: {guest_path}")
    return _read_text_bounded(host_path, maximum)


def load_manifest(path: Path) -> tuple[dict[str, Any], bytes, dict[str, Path]]:
    """Read and validate every input hash before creating any resources."""
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise QualificationError(f"cannot read manifest {path}: {error}") from error
    if not isinstance(manifest, dict):
        raise QualificationError("manifest root must be an object")
    commits = manifest.get("source_commits")
    if (not isinstance(commits, dict) or
            not _valid_commit(commits.get("orchestrator")) or
            not _valid_commit(commits.get("terrabase"))):
        raise QualificationError("source_commits must contain full orchestrator and terrabase commit IDs")
    rust_test_name = manifest.get("rust_test_name")
    if (not isinstance(rust_test_name, str) or not rust_test_name or
            "\x00" in rust_test_name or "\n" in rust_test_name or "\r" in rust_test_name):
        raise QualificationError("rust_test_name must be a non-empty single-line test name")
    if rust_test_name != RUST_TEST_NAME:
        raise QualificationError(f"rust_test_name must select the reviewed test {RUST_TEST_NAME}")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != set(INPUT_NAMES):
        missing = sorted(set(INPUT_NAMES) - set(inputs or {})) if isinstance(inputs, dict) else list(INPUT_NAMES)
        extra = sorted(set(inputs) - set(INPUT_NAMES)) if isinstance(inputs, dict) else []
        raise QualificationError(f"manifest inputs must contain exactly {INPUT_NAMES}; missing={missing}, extra={extra}")

    resolved: dict[str, Path] = {}
    input_identity: dict[str, dict[str, Any]] = {}
    for name in INPUT_NAMES:
        record = inputs[name]
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise QualificationError(f"input {name} must include a path and sha256")
        expected = record.get("sha256")
        if not _valid_sha256(expected):
            raise QualificationError(f"input {name} has an invalid sha256")
        supplied = Path(record["path"])
        if not supplied.is_absolute():
            raise QualificationError(f"input {name} path must be absolute: {supplied}")
        try:
            actual_path = supplied.resolve(strict=True)
        except OSError as error:
            raise QualificationError(f"input {name} does not resolve: {supplied}: {error}") from error
        if not actual_path.is_file():
            raise QualificationError(f"input {name} is not a regular file: {actual_path}")
        actual_hash = sha256_file(actual_path)
        if actual_hash != expected:
            raise QualificationError(
                f"input {name} SHA-256 mismatch: expected {expected}, got {actual_hash}: {actual_path}")
        if name in ("firecracker", "go_host_test", "memberstatus_probe", "rust_server", "rust_test"):
            if not os.access(actual_path, os.X_OK):
                raise QualificationError(f"input {name} is not executable: {actual_path}")
        resolved[name] = actual_path
        input_identity[name] = {
            "supplied_path": record["path"],
            "resolved_path": str(actual_path),
            "sha256": actual_hash,
            "size_bytes": actual_path.stat().st_size,
        }

    normalized = dict(manifest)
    normalized["inputs"] = input_identity
    return normalized, raw, resolved


def parse_go_test_output(output: str, returncode: int,
                         test_name: str = GO_TEST_NAME) -> dict[str, Any]:
    lines = [line.strip() for line in output.splitlines()]
    runs = [line[len("=== RUN   "):] for line in lines if line.startswith("=== RUN   ")]
    passed = [line[len("--- PASS: "):].split(" (", 1)[0]
              for line in lines if line.startswith("--- PASS: ")]
    skipped = [line for line in lines if line.startswith("--- SKIP: ")]
    failed = [line for line in lines if line.startswith("--- FAIL: ")]
    terminal_passes = [line for line in lines if line == GO_SUCCESS]
    if returncode != 0:
        raise QualificationError(f"focused Go test exited {returncode}")
    if runs != [test_name]:
        raise QualificationError(f"focused Go test must run exactly {test_name}; observed {runs}")
    if passed != [test_name] or skipped or failed:
        raise QualificationError(
            f"focused Go test result was not one explicit PASS: passed={passed}, skipped={skipped}, failed={failed}")
    if terminal_passes != [GO_SUCCESS] or not lines or lines[-1] != GO_SUCCESS:
        raise QualificationError("focused Go test omitted its single terminal PASS result")
    return {"name": test_name, "status": "PASS", "runs": 1, "skips": 0}


_RUST_SUMMARY = re.compile(
    r"^test result: (?P<status>ok|FAILED)\. (?P<passed>\d+) passed; "
    r"(?P<failed>\d+) failed; (?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
    r"(?P<filtered>\d+) filtered out; finished in .+$")


def parse_rust_test_output(output: str, returncode: int,
                           test_name: str) -> dict[str, Any]:
    lines = [line.strip() for line in output.splitlines()]
    running = [int(match.group(1)) for line in lines
               if (match := re.fullmatch(r"running (\d+) tests?", line))]
    test_lines: list[str] = []
    for line in lines:
        match = re.match(r"^test (.+?) \.\.\.", line)
        if match:
            test_lines.append(match.group(1))
    summaries = [match for line in lines if (match := _RUST_SUMMARY.fullmatch(line))]
    if returncode != 0:
        raise QualificationError(f"Rust member-status test exited {returncode}")
    if running != [1] or test_lines != [test_name]:
        raise QualificationError(
            f"Rust test must run exactly {test_name}; running={running}, observed={test_lines}")
    if len(summaries) != 1:
        raise QualificationError(f"Rust test must report one result summary; found {len(summaries)}")
    summary = summaries[0]
    counts = {name: int(summary.group(name))
              for name in ("passed", "failed", "ignored", "measured", "filtered")}
    if (summary.group("status") != "ok" or counts["passed"] != 1 or
            counts["failed"] != 0 or counts["ignored"] != 0 or counts["measured"] != 0):
        raise QualificationError(f"Rust test did not report one non-ignored pass: {summary.group(0)}")
    if output.count(MEMBER_STATUS_SUCCESS) != 1:
        raise QualificationError(
            f"Rust test must include exactly one nested {MEMBER_STATUS_SUCCESS} marker")
    if output.count(SENDER_SUCCESS) != 1:
        raise QualificationError(
            "Rust test output must include the current sender-enabled Go probe success marker exactly once")
    return {"name": test_name, "status": "PASS", "runs": 1, "skips": 0,
            "nested_go_marker": MEMBER_STATUS_SUCCESS, "sender_marker": SENDER_SUCCESS,
            **counts}


def _serial_payload_lines(serial_output: str) -> list[str]:
    payloads = []
    for line in serial_output.splitlines():
        line = line.strip()
        match = _SERIAL_SERVICE_LINE.fullmatch(line)
        payloads.append(match.group("payload") if match else line)
    return payloads


def parse_qualification_result(go_output: str, go_returncode: int,
                               rust_output: str, rust_returncode: int,
                               serial_output: str,
                               rust_test_name: str) -> dict[str, dict[str, Any]]:
    go_result = parse_go_test_output(go_output, go_returncode)
    rust_result = parse_rust_test_output(rust_output, rust_returncode, rust_test_name)
    runner_result = parse_runner_result(serial_output)
    if runner_result["status"] != "PASS":
        raise QualificationError(
            f"guest command failed stage={runner_result['stage']} status={runner_result['exit_status']}")
    serial = "\n".join(_serial_payload_lines(serial_output))
    sentinel_position = serial.index(RUNNER_SUCCESS)
    if serial.find(SENDER_SUCCESS) < 0 or sentinel_position < serial.find(SENDER_SUCCESS):
        raise QualificationError("guest runner PASS sentinel appeared before the Go sender probe succeeded")
    if not go_output.rstrip().endswith(GO_SUCCESS):
        raise QualificationError("guest Go command output did not end with its explicit PASS result")
    rust_summary_position = serial.rfind("test result: ok.")
    if rust_summary_position < 0 or sentinel_position < rust_summary_position:
        raise QualificationError("guest runner PASS sentinel appeared before the Rust test result")
    return {"go_host_test": go_result, "rust_test": rust_result}


def parse_runner_result(serial_output: str) -> dict[str, Any]:
    """Parse one terminal guest result, preserving an explicit command failure."""
    result_lines = [line for line in _serial_payload_lines(serial_output)
                    if line.startswith(RUNNER_RESULT_PREFIX)]
    if len(result_lines) != 1:
        raise QualificationError(
            f"guest serial must contain exactly one terminal runner result; found {len(result_lines)}")
    result = result_lines[0]
    if result == RUNNER_SUCCESS:
        return {"status": "PASS"}
    failure = RUNNER_FAILURE.fullmatch(result)
    if failure is None or failure.group("stage") not in RUNNER_STAGES:
        raise QualificationError(f"guest serial contains a malformed runner result: {result}")
    return {"status": "FAILED", "stage": failure.group("stage"),
            "exit_status": int(failure.group("status")), "sentinel": result}


def _send_group_signal(process: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    if process.pid in (os.getpid(), os.getpgrp()):
        raise QualificationError("refusing to signal the current process group")
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return


def _child_exited_without_reaping(process: subprocess.Popen[bytes]) -> bool:
    if process.returncode is not None:
        return True
    try:
        observed = os.waitid(os.P_PID, process.pid,
                             os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return process.returncode is not None
    return observed is not None and observed.si_pid == process.pid


def _wait_child_without_reaping(process: subprocess.Popen[bytes], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if _child_exited_without_reaping(process):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))


def _live_process_group_members(process_group: int) -> list[int]:
    """Return non-zombie Linux processes that still belong to one owned group."""
    members: list[int] = []
    try:
        entries = list(os.scandir("/proc"))
    except OSError as error:
        raise QualificationError(f"cannot inspect /proc while cleaning process group {process_group}: {error}") from error
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            with open(f"/proc/{entry.name}/stat", "rb") as stream:
                raw = stream.read(8192).decode(errors="replace")
        except FileNotFoundError:
            # A process can exit between enumerating /proc and reading stat.
            continue
        except OSError as error:
            raise QualificationError(
                f"cannot inspect /proc/{entry.name}/stat while cleaning process group "
                f"{process_group}: {error}") from error
        close = raw.rfind(")")
        if close < 0:
            raise QualificationError(f"malformed /proc/{entry.name}/stat while cleaning process group {process_group}")
        fields = raw[close + 1:].split()
        if len(fields) < 3:
            raise QualificationError(f"short /proc/{entry.name}/stat while cleaning process group {process_group}")
        state = fields[0]
        try:
            group = int(fields[2])
        except ValueError as error:
            raise QualificationError(
                f"invalid process group in /proc/{entry.name}/stat while cleaning {process_group}") from error
        if group == process_group and state not in ("Z", "X"):
            members.append(int(entry.name))
    return members


def _wait_process_group_quiescent(process_group: int, timeout: float) -> bool:
    """Wait until every member is gone or zombie-only, without reaping the leader."""
    deadline = time.monotonic() + timeout
    while True:
        if not _live_process_group_members(process_group):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))


def stop_process_group(process: subprocess.Popen[bytes], *, term_timeout: float = 5,
                       kill_timeout: float = 5) -> int | None:
    """Stop one owned session, escalating TERM to KILL and reaping its leader."""
    if process.pid in (os.getpid(), os.getpgrp()):
        raise QualificationError("refusing to stop a process outside an owned session")
    if getattr(process, "_ts_process_group_stopped", False):
        return process.returncode
    if process.returncode is not None:
        raise QualificationError(
            f"owned process {process.pid} was reaped before its process group was stopped; "
            "refusing to signal a potentially reused PGID")
    try:
        if os.getpgid(process.pid) != process.pid:
            raise QualificationError(f"process {process.pid} is not its own process-group leader")
    except ProcessLookupError as error:
        raise QualificationError(
            f"owned process {process.pid} disappeared before its group could be stopped") from error
    _send_group_signal(process, signal.SIGTERM)
    _wait_child_without_reaping(process, term_timeout)
    # Keep the leader as an unreaped zombie while signaling its original
    # process group. This removes children even if the leader exits first
    # and prevents PID reuse from redirecting cleanup.
    _send_group_signal(process, signal.SIGKILL)
    if not _wait_process_group_quiescent(process.pid, kill_timeout):
        members = _live_process_group_members(process.pid)
        raise QualificationError(
            f"owned process group {process.pid} still has live members after SIGKILL: {members}")
    try:
        process.wait(timeout=kill_timeout)
    except subprocess.TimeoutExpired as error:
        raise QualificationError(f"owned process group {process.pid} survived TERM and KILL") from error
    process._ts_process_group_stopped = True
    return process.returncode


class BoundedOutput:
    """Drain a child pipe continuously while retaining at most a fixed log size."""

    def __init__(self, stream: Any, path: Path, maximum: int):
        self.stream = stream
        self.path = path
        self.maximum = maximum
        self.bytes_written = 0
        self.truncated = False
        self.error = ""
        self.thread = threading.Thread(target=self._drain, name=f"log-{path.name}", daemon=True)
        self.thread.start()

    def _drain(self) -> None:
        output = None
        try:
            output = self.path.open("wb")
        except OSError as error:
            self.error = f"open log: {error}"
        try:
            while True:
                chunk = self.stream.read(64 << 10)
                if not chunk:
                    break
                room = self.maximum - self.bytes_written
                if room <= 0:
                    self.truncated = True
                    continue
                kept = chunk[:room]
                if output is None:
                    self.truncated = True
                    continue
                try:
                    output.write(kept)
                    self.bytes_written += len(kept)
                except OSError as error:
                    self.error = f"write log: {error}"
                    self.truncated = True
                    try:
                        output.close()
                    finally:
                        output = None
                if len(chunk) > len(kept):
                    self.truncated = True
        except OSError as error:
            self.error = self.error or f"read child output: {error}"
        finally:
            if output is not None:
                try:
                    output.flush()
                    os.fsync(output.fileno())
                    output.close()
                except OSError as error:
                    self.error = self.error or f"flush log: {error}"
            try:
                self.stream.close()
            except OSError as error:
                self.error = self.error or f"close output stream: {error}"

    def finish(self, timeout: float = 5) -> dict[str, Any]:
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise QualificationError(f"bounded log collector did not finish: {self.path}")
        if self.error:
            raise QualificationError(f"bounded log collector failed for {self.path}: {self.error}")
        return {"path": str(self.path), "bytes_written": self.bytes_written,
                "limit_bytes": self.maximum, "truncated": self.truncated}


class CommandRunner:
    def __init__(self, root: Path, events: "EventLog"):
        self.root = root
        self.events = events
        self.sequence = 0
        self.pending: list[tuple[str, subprocess.Popen[bytes], BoundedOutput]] = []

    def _remember_pending(self, label: str, process: subprocess.Popen[bytes],
                          capture: BoundedOutput) -> None:
        if (process.returncode is None and
                not getattr(process, "_ts_process_group_stopped", False) and
                not any(existing.pid == process.pid for _, existing, _ in self.pending)):
            self.pending.append((label, process, capture))

    def stop_pending(self) -> list[str]:
        errors: list[str] = []
        pending, self.pending = self.pending, []
        for label, process, capture in pending:
            try:
                stop_process_group(process)
            except Exception as error:
                detail = f"stop pending command process group {process.pid} ({label}): {error}"
                errors.append(detail)
                self.pending.append((label, process, capture))
                self.events.add("pending_command_cleanup_failed", label=label,
                                pid=process.pid, detail=str(error))
                continue
            try:
                output = capture.finish()
                self.events.add("pending_command_stopped", label=label, pid=process.pid,
                                returncode=process.returncode, output=output)
            except Exception as error:
                errors.append(f"collect pending command log ({label}): {error}")
                self.events.add("pending_command_log_failed", label=label,
                                pid=process.pid, detail=str(error))
        return errors

    def run(self, label: str, command: Iterable[str], *, timeout: float,
            allowed_returncodes: set[int] | None = None,
            env: dict[str, str] | None = None) -> tuple[int, Path]:
        if self.pending:
            raise QualificationError("refusing to start a command while an earlier process group is not confirmed stopped")
        args = [str(part) for part in command]
        self.sequence += 1
        log_path = self.root / "commands" / f"{self.sequence:03d}-{label}.log"
        metadata_path = log_path.with_suffix(".json")
        metadata = {"label": label, "command": args, "timeout_seconds": timeout,
                    "log": str(log_path), "log_limit_bytes": MAX_COMMAND_LOG_BYTES}
        metadata_path.write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
        metadata_path.chmod(0o600)
        self.events.add("command_start", label=label, command=args, timeout_seconds=timeout,
                        log=str(log_path))
        started = time.monotonic()
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True, bufsize=0)
        assert process.stdout is not None
        capture = BoundedOutput(process.stdout, log_path, MAX_COMMAND_LOG_BYTES)
        try:
            if not _wait_child_without_reaping(process, timeout):
                raise subprocess.TimeoutExpired(args, timeout)
            returncode = stop_process_group(process, term_timeout=0.1, kill_timeout=1)
        except subprocess.TimeoutExpired as error:
            cleanup_error = ""
            try:
                stop_process_group(process)
            except Exception as stop_error:
                cleanup_error = f"; process cleanup failed: {stop_error}"
                self._remember_pending(label, process, capture)
            try:
                log_result = capture.finish()
            except Exception as log_error:
                cleanup_error += f"; log collector failed: {log_error}"
                log_result = {}
            self.events.add("command_timeout", label=label, pid=process.pid,
                            timeout_seconds=timeout, cleanup_error=cleanup_error,
                            log=str(log_path), output=log_result)
            raise CommandFailure(args, None, log_path,
                                 f"timed out after {timeout}s{cleanup_error}") from error
        except BaseException:
            try:
                stop_process_group(process)
            except Exception as stop_error:
                self.events.add("command_interruption_cleanup_failed", label=label,
                                pid=process.pid, detail=str(stop_error), log=str(log_path))
                self._remember_pending(label, process, capture)
            try:
                capture.finish()
            except Exception as log_error:
                self.events.add("command_interruption_log_failed", label=label,
                                detail=str(log_error), log=str(log_path))
            raise
        try:
            log_result = capture.finish()
        except Exception as error:
            self.events.add("command_log_failed", label=label, pid=process.pid,
                            returncode=returncode, detail=str(error), log=str(log_path))
            raise CommandFailure(args, returncode, log_path,
                                 f"bounded log collection failed: {error}") from error
        self.events.add("command_exit", label=label, returncode=returncode,
                        elapsed_seconds=round(time.monotonic() - started, 3),
                        log=str(log_path), output=log_result)
        if log_result["truncated"]:
            raise CommandFailure(args, returncode, log_path, "bounded command log was truncated")
        allowed = {0} if allowed_returncodes is None else allowed_returncodes
        if returncode not in allowed:
            raise CommandFailure(args, returncode, log_path)
        return returncode, log_path


class EventLog:
    def __init__(self, path: Path):
        self.path = path
        self.started_at = time.monotonic()
        self.entries: list[dict[str, Any]] = []

    def add(self, event: str, **fields: Any) -> None:
        self.entries.append({"time": datetime.now(timezone.utc).isoformat(),
                             "event": event, **fields})
        _atomic_replace(self.path, json.dumps(self.entries, sort_keys=True, indent=2) + "\n")


def _read_text_bounded(path: Path, maximum: int) -> tuple[str, bool]:
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    oversized = len(data) > maximum or path.stat().st_size > maximum
    return data[:maximum].decode(errors="replace"), oversized


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: Path, timeout: float = 5):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(str(self.path))
        self.sock = connection


class FirecrackerVM:
    def __init__(self, firecracker: Path, kernel: Path, image: Path,
                 socket_dir: Path, logs: Path, events: EventLog):
        self.firecracker = firecracker
        self.kernel = kernel
        self.image = image
        self.socket_dir = socket_dir
        self.socket_path = socket_dir / "api.sock"
        self.logs = logs
        self.events = events
        self.process: subprocess.Popen[bytes] | None = None
        self.serial_path = logs / "guest-serial.log"
        self.vmm_path = logs / "firecracker-vmm.log"
        self.serial_capture: BoundedOutput | None = None
        self.vmm_capture: BoundedOutput | None = None
        self.output_capture: dict[str, Any] = {}
        self.process_group_stopped = False
        if len(os.fsencode(self.socket_path)) >= 100:
            raise QualificationError(f"Firecracker API socket path must be shorter than 100 bytes: {self.socket_path}")

    def _api(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        connection = UnixHTTPConnection(self.socket_path)
        try:
            body = None if payload is None else json.dumps(payload)
            connection.request(method, path, body=body,
                               headers={"Content-Type": "application/json"} if body is not None else {})
            response = connection.getresponse()
            data = response.read(1 << 20).decode(errors="replace")
            if response.status not in (200, 204):
                raise QualificationError(f"Firecracker {method} {path}: HTTP {response.status}: {data}")
            return json.loads(data) if data else {}
        finally:
            connection.close()

    def start(self) -> None:
        command = [str(self.firecracker), "--api-sock", str(self.socket_path),
                   "--log-path", "/dev/stderr"]
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True, bufsize=0)
        assert self.process.stdout is not None and self.process.stderr is not None
        self.serial_capture = BoundedOutput(self.process.stdout, self.serial_path,
                                            MAX_SERIAL_LOG_BYTES)
        self.vmm_capture = BoundedOutput(self.process.stderr, self.vmm_path,
                                         MAX_COMMAND_LOG_BYTES)
        self.events.add("firecracker_start", pid=self.process.pid, command=command,
                        api_socket=str(self.socket_path), serial=str(self.serial_path),
                        vmm_log=str(self.vmm_path), serial_log_limit_bytes=MAX_SERIAL_LOG_BYTES,
                        vmm_log_limit_bytes=MAX_COMMAND_LOG_BYTES)
        deadline = time.monotonic() + API_SOCKET_SECONDS
        last_error: BaseException | None = None
        while time.monotonic() < deadline:
            if _child_exited_without_reaping(self.process):
                self.stop_process_group(self.process)
                raise QualificationError(
                    f"Firecracker exited before API became ready ({self.process.returncode}); see {self.serial_path}")
            if self.socket_path.exists():
                try:
                    self._api("GET", "/version")
                    break
                except (OSError, http.client.HTTPException, QualificationError, ValueError) as error:
                    last_error = error
            time.sleep(0.1)
        else:
            raise TimeoutError(f"Firecracker API socket did not become ready in {API_SOCKET_SECONDS}s: {last_error}")

        self._api("PUT", "/machine-config", {
            "vcpu_count": GUEST_VCPUS,
            "mem_size_mib": GUEST_RAM_MIB,
            "smt": False,
        })
        self._api("PUT", "/boot-source", {
            "kernel_image_path": str(self.kernel),
            "boot_args": BOOT_ARGS,
        })
        self._api("PUT", "/drives/rootfs", {
            "drive_id": "rootfs",
            "path_on_host": str(self.image),
            "is_root_device": True,
            "is_read_only": False,
        })
        self._api("PUT", "/actions", {"action_type": "InstanceStart"})
        self.events.add("guest_boot", pid=self.process.pid, memory_mib=GUEST_RAM_MIB,
                        vcpus=GUEST_VCPUS, network_interfaces=[])

    def wait_for_shutdown(self) -> int:
        if self.process is None:
            raise QualificationError("Firecracker was not started")
        if not _wait_child_without_reaping(self.process, GUEST_DEADLINE_SECONDS):
            raise TimeoutError(f"guest exceeded {GUEST_DEADLINE_SECONDS}s deadline")
        returncode = self.stop_process_group(self.process, term_timeout=0.1, kill_timeout=1)
        self.process_group_stopped = True
        self._finish_output()
        self.events.add("guest_vmm_exit", returncode=returncode)
        if returncode != 0:
            raise QualificationError(f"Firecracker exited with status {returncode}")
        return returncode

    def stop_process_group(self, process: subprocess.Popen[bytes], *,
                           term_timeout: float = 5, kill_timeout: float = 5) -> int | None:
        result = stop_process_group(process, term_timeout=term_timeout, kill_timeout=kill_timeout)
        self.process_group_stopped = process.returncode is not None
        return result

    def _finish_output(self) -> None:
        results: dict[str, Any] = {}
        for label, capture in (("serial", self.serial_capture), ("vmm", self.vmm_capture)):
            if capture is None:
                continue
            results[label] = capture.finish()
        self.output_capture = results
        self.events.add("firecracker_output_collected", output=results)
        truncated = [label for label, result in results.items() if result["truncated"]]
        if truncated:
            raise QualificationError(f"Firecracker output log was truncated: {', '.join(truncated)}")

    def stop(self) -> list[str]:
        errors: list[str] = []
        process = self.process
        if process is None:
            return errors
        if not self.process_group_stopped and process.returncode is None:
            if not _child_exited_without_reaping(process):
                try:
                    self._api("PUT", "/actions", {"action_type": "SendCtrlAltDel"})
                    self.events.add("guest_ctrl_alt_del")
                except Exception as error:
                    errors.append(f"send guest CtrlAltDel: {error}")
                _wait_child_without_reaping(process, 25)
            try:
                self.stop_process_group(process, term_timeout=5, kill_timeout=5)
            except Exception as error:
                errors.append(f"stop Firecracker process group {process.pid}: {error}")
        if not self.process_group_stopped:
            errors.append(f"Firecracker process group {process.pid} is not confirmed stopped")
        elif not self.output_capture:
            try:
                self._finish_output()
            except Exception as error:
                errors.append(f"collect Firecracker serial/VMM logs: {error}")
        if not errors:
            self.events.add("firecracker_stopped", pid=process.pid, returncode=process.returncode)
        return errors


def _shell_runner(go_test: Path, member_probe: Path, rust_server: Path,
                  rust_test: Path, rust_test_name: str, *,
                  guest_root: Path = Path("/")) -> str:
    def guest_path(path: str) -> str:
        return str(guest_root / path.lstrip("/"))

    go_run = f"-test.run=^{GO_TEST_NAME}$"
    rust_name = shlex.quote(rust_test_name)
    log_dir = shlex.quote(guest_path("/var/log/ts-member-status-qualification"))
    probe = shlex.quote(guest_path("/opt/ts-member-status/memberstatus-probe"))
    server = shlex.quote(guest_path("/opt/ts-member-status/tb-server"))
    go_binary = shlex.quote(guest_path("/opt/ts-member-status/go-host-test"))
    rust_binary = shlex.quote(guest_path("/opt/ts-member-status/rust-test"))
    script = f"""#!/bin/sh
set -eu
RUNNER_STAGE=runner
RUNNER_LOG=
RUNNER_RESULT=FAILED

finish() {{
    status=$?
    trap - EXIT
    if [ "$RUNNER_RESULT" = PASS ] && [ "$status" -eq 0 ]; then
        result='{RUNNER_SUCCESS}'
    else
        if [ "$status" -eq 0 ]; then
            status=1
        fi
        result="{RUNNER_RESULT_PREFIX}FAILED stage=$RUNNER_STAGE status=$status"
        if [ -n "$RUNNER_LOG" ]; then
            printf '%s\\n' "$result" >>"$RUNNER_LOG" || :
        fi
    fi
    printf '%s\\n' "$result" >&2
    sync || :
    systemctl --no-wall poweroff || :
    exit "$status"
}}

trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

LOG_DIR={log_dir}
mkdir -p "$LOG_DIR"
export TB_MEMBER_STATUS_PROBE_BINARY={probe}
export TB_SERVER_TEST_BINARY={server}

run_capture() {{
    label=$1
    shift
    output="$LOG_DIR/$label.log"
    RUNNER_STAGE=$label
    RUNNER_LOG=$output
    if "$@" >"$output" 2>&1; then
        cat "$output"
        RUNNER_LOG=
    else
        status=$?
        cat "$output"
        exit "$status"
    fi
}}

run_capture go-host-test {go_binary} -test.v -test.timeout={GO_TEST_TIMEOUT} {go_run}
run_capture rust-test {rust_binary} --exact {rust_name} --nocapture --test-threads=1
RUNNER_RESULT=PASS
exit 0
"""
    return script


def _service_unit() -> str:
    return f"""[Unit]
Description=TerraScale member-status Firecracker qualification
After=local-fs.target

[Service]
Type=oneshot
User=root
Group=root
Delegate=yes
DelegateSubgroup=supervisor
MemoryMax=5G
NoNewPrivileges=yes
AmbientCapabilities=
CapabilityBoundingSet={CAPABILITY_BOUNDING_SET}
TimeoutStartSec={GUEST_SERVICE_TIMEOUT_SECONDS}s
KillMode=control-group
StandardOutput=journal+console
StandardError=journal+console
ExecStart=/usr/local/sbin/ts-member-status-qualification

[Install]
WantedBy=multi-user.target
"""


class Qualification:
    def __init__(self, manifest: dict[str, Any], raw_manifest: bytes,
                 inputs: dict[str, Path], run_dir: Path):
        self.manifest = manifest
        self.raw_manifest = raw_manifest
        self.inputs = inputs
        self.root = run_dir
        self.logs = self.root / "logs"
        self.commands = self.root / "commands"
        self.images = self.root / "images"
        self.mount_root = self.root / "mount"
        self.stage = self.root / "stage"
        self.image = self.images / "member-status.ext4"
        self.mount_path = self.mount_root / "guest"
        self.events = EventLog(self.logs / "events.json")
        self.command_runner = CommandRunner(self.root, self.events)
        self.vm: FirecrackerVM | None = None
        self.socket_dir: Path | None = None
        self.mount_owned = False
        self.mountpoint_owned = False
        self.image_safe_to_remove = False
        self.test_results: dict[str, Any] = {}
        self.failure = ""
        self.cleanup_errors: list[str] = []
        self.logs_out = {
            "events": str(self.logs / "events.json"),
            "serial": str(self.logs / "guest-serial.log"),
            "vmm": str(self.logs / "firecracker-vmm.log"),
            "go_host_test": str(self.logs / "guest-go-host-test.log"),
            "rust_test": str(self.logs / "guest-rust-test.log"),
        }
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.local_source_paths = {
            "driver": Path(__file__).resolve(),
            "tests": Path(__file__).with_name("test_qualify.py").resolve(),
            "readme": REPO / "tests/firecracker/README.md",
            "memberstatus_probe_source": REPO / "tests/firecracker/memberstatus/main.go",
            "focused_go_test_source": REPO / "internal/host/runner_test.go",
        }
        self.local_source_hashes = {name: sha256_file(path)
                                    for name, path in self.local_source_paths.items()}

    def prepare_dirs(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.root.chmod(0o700)
        for path in (self.logs, self.commands, self.images, self.mount_root, self.stage):
            path.mkdir(mode=0o700)
        manifest_path = self.root / "manifest.json"
        manifest_path.write_bytes(self.raw_manifest)
        manifest_path.chmod(0o600)
        self.events.add("qualification_start", manifest_sha256=sha256_bytes(self.raw_manifest),
                        source_commits=self.manifest["source_commits"],
                        rust_test_name=self.manifest["rust_test_name"], run_dir=str(self.root))

    def _sudo(self) -> str:
        candidate = Path("/run/wrappers/bin/sudo")
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        located = shutil.which("sudo")
        if located is None:
            raise QualificationError("sudo is required for scoped mount and staging commands")
        return located

    def _run(self, label: str, *args: str | Path, timeout: float = 120,
             allowed_returncodes: set[int] | None = None) -> tuple[int, Path]:
        return self.command_runner.run(label, [str(arg) for arg in args], timeout=timeout,
                                       allowed_returncodes=allowed_returncodes)

    def _sudo_run(self, label: str, *args: str | Path, timeout: float = 60,
                  allowed_returncodes: set[int] | None = None) -> tuple[int, Path]:
        return self._run(label, self._sudo(), "-n", *args, timeout=timeout,
                         allowed_returncodes=allowed_returncodes)

    def _recheck_inputs(self) -> None:
        for name in INPUT_NAMES:
            current = sha256_file(self.inputs[name])
            expected = self.manifest["inputs"][name]["sha256"]
            if current != expected:
                raise QualificationError(f"input {name} changed during qualification: {self.inputs[name]}")
        self.events.add("inputs_rechecked", hashes={name: self.manifest["inputs"][name]["sha256"]
                                                    for name in INPUT_NAMES})

    def _create_private_image(self) -> None:
        self._run("copy-rootfs", "cp", "--reflink=auto", "--sparse=always",
                  self.inputs["rootfs"], self.image, timeout=240)
        self.image.chmod(0o600)
        copied_hash = sha256_file(self.image)
        expected_hash = self.manifest["inputs"]["rootfs"]["sha256"]
        if copied_hash != expected_hash:
            raise QualificationError(
                f"private rootfs copy SHA-256 mismatch: expected {expected_hash}, got {copied_hash}")
        self.events.add("private_image_copy_verified", sha256=copied_hash)
        image_size = max(self.image.stat().st_size, IMAGE_MIN_BYTES)
        with self.image.open("r+b") as private_copy:
            private_copy.truncate(image_size)
        self.events.add("private_image_created", source=str(self.inputs["rootfs"]),
                        image=str(self.image), virtual_size_bytes=image_size)
        _, check_log = self._run("e2fsck", "e2fsck", "-f", "-y", self.image,
                                 timeout=240, allowed_returncodes={0, 1})
        self.events.add("private_image_checked", log=str(check_log))
        self._run("resize2fs", "resize2fs", self.image, timeout=240)

    def _mount(self, *, read_only: bool = False) -> None:
        if os.path.lexists(self.mount_path):
            raise QualificationError(f"owned mount path unexpectedly exists: {self.mount_path}")
        self.mount_path.mkdir(mode=0o700)
        self.mountpoint_owned = True
        options = "loop,ro,noload" if read_only else "loop"
        try:
            self._sudo_run("mount-readonly" if read_only else "mount-writable",
                           "mount", "-o", options, self.image, self.mount_path, timeout=60)
        except Exception:
            if os.path.ismount(self.mount_path):
                self.mount_owned = True
            else:
                self._remove_mountpoint()
            raise
        if not os.path.ismount(self.mount_path):
            self._remove_mountpoint()
            raise QualificationError(f"mount command returned successfully without mounting {self.mount_path}")
        self.mount_owned = True
        self.events.add("image_mounted", mount=str(self.mount_path), read_only=read_only,
                        image=str(self.image))

    def _unmount(self) -> None:
        if not os.path.ismount(self.mount_path):
            self.mount_owned = False
            self._remove_mountpoint()
            return
        if not self.mount_owned:
            raise QualificationError(f"refusing to unmount unowned mount: {self.mount_path}")
        try:
            self._sudo_run("umount", "umount", self.mount_path, timeout=60)
        finally:
            if not os.path.ismount(self.mount_path):
                self.mount_owned = False
                self._remove_mountpoint()
        if self.mount_owned:
            raise QualificationError(f"owned mount remains active after umount: {self.mount_path}")
        self.events.add("image_unmounted", mount=str(self.mount_path))

    def _remove_mountpoint(self) -> None:
        if self.mountpoint_owned and self.mount_path.exists():
            self.mount_path.rmdir()
            self.mountpoint_owned = False

    def _write_stage_file(self, relative: str, content: str, mode: int = 0o600) -> Path:
        path = self.stage / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        return path

    def _install(self, source: Path, destination: Path, mode: str) -> None:
        if not destination.is_absolute() or ".." in destination.parts:
            raise QualificationError(f"unsafe guest destination: {destination}")
        target = _guest_path_without_symlinks(self.mount_path, destination)
        self._sudo_run("install-" + destination.name, "install", "-D", "-o", "root", "-g", "root",
                       "-m", mode, source, target, timeout=60)

    def _enable_guest_service(self) -> None:
        unit_path = Path("/etc/systemd/system") / SERVICE_NAME
        wants_dir = Path("/etc/systemd/system/multi-user.target.wants")
        link_path = wants_dir / SERVICE_NAME
        _guest_path_without_symlinks(self.mount_path, unit_path)
        wants_host = _guest_path_without_symlinks(self.mount_path, wants_dir)
        self._sudo_run("create-service-wants-dir", "install", "-d", "-o", "root", "-g", "root",
                       "-m", "0755", wants_host, timeout=30)
        link_host = _guest_path_without_symlinks(self.mount_path, link_path)
        if os.path.lexists(link_host):
            raise QualificationError(f"guest service enable path already exists: {link_path}")
        self._sudo_run("enable-guest-service", "ln", "-s", f"../{SERVICE_NAME}", link_host, timeout=30)

    def _stage_guest(self) -> None:
        self._mount()
        try:
            systemd_binary = _guest_path_without_symlinks(
                self.mount_path, Path("/usr/lib/systemd/systemd"))
            if not systemd_binary.is_file():
                raise QualificationError(f"guest rootfs has no systemd binary at {systemd_binary}")
            for required in ("usr/bin/setpriv", "usr/bin/curl", "usr/bin/systemctl"):
                required_path = _guest_path_without_symlinks(self.mount_path, Path("/" + required))
                if not required_path.is_file():
                    raise QualificationError(f"guest rootfs is missing required probe executable: /{required}")
            package_status = Path("/var/lib/dpkg/status")
            package_status_text, oversized = _read_guest_regular_file(
                self.mount_path, package_status, 16 << 20)
            if oversized:
                raise QualificationError("guest package status database exceeded its read bound")
            version_match = None
            for stanza in package_status_text.split("\n\n"):
                fields = dict(line.split(": ", 1) for line in stanza.splitlines() if ": " in line)
                if fields.get("Package") == "systemd" and fields.get("Status") == "install ok installed":
                    version_match = re.match(r"^(?:\d+:)?(\d+)(?:\.|-|$)", fields.get("Version", ""))
                    break
            if version_match is None or int(version_match.group(1)) < 255:
                raise QualificationError("guest requires an installed systemd package at version 255 or newer")
            self.events.add("guest_systemd_version", version=int(version_match.group(1)),
                            source="dpkg-status")

            payloads = (
                ("go_host_test", Path("/opt/ts-member-status/go-host-test")),
                ("memberstatus_probe", Path("/opt/ts-member-status/memberstatus-probe")),
                ("rust_server", Path("/opt/ts-member-status/tb-server")),
                ("rust_test", Path("/opt/ts-member-status/rust-test")),
            )
            for key, destination in payloads:
                self._install(self.inputs[key], destination, "0755")
                installed = self.mount_path / destination.relative_to("/")
                actual = sha256_file(installed)
                expected = self.manifest["inputs"][key]["sha256"]
                if actual != expected:
                    raise QualificationError(f"staged {key} SHA-256 mismatch: expected {expected}, got {actual}")
                self.events.add("guest_binary_staged", name=key, path=str(destination), sha256=actual)

            runner = self._write_stage_file(
                "runner.sh", _shell_runner(self.inputs["go_host_test"],
                                           self.inputs["memberstatus_probe"],
                                           self.inputs["rust_server"], self.inputs["rust_test"],
                                           self.manifest["rust_test_name"]), 0o700)
            unit = self._write_stage_file("unit.service", _service_unit(), 0o644)
            self._install(runner, Path("/usr/local/sbin/ts-member-status-qualification"), "0755")
            self._install(unit, Path("/etc/systemd/system/" + SERVICE_NAME), "0644")
            self._enable_guest_service()
            self.events.add("guest_service_staged", unit=SERVICE_NAME,
                            runner="/usr/local/sbin/ts-member-status-qualification",
                            delegate=True, delegate_subgroup="supervisor", memory_max="5G",
                            no_new_privileges=True, ambient_capabilities=[],
                            capability_bounding_set=CAPABILITY_BOUNDING_SET)
        finally:
            self._unmount()

    def _make_socket_dir(self) -> None:
        self.socket_dir = make_private_socket_dir()
        self.events.add("api_socket_dir_created", path=str(self.socket_dir))

    def _verify_input_and_start_vm(self) -> None:
        self._recheck_inputs()
        if not Path("/dev/kvm").exists() or not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise QualificationError("Firecracker requires readable and writable /dev/kvm")
        self._make_socket_dir()
        self.vm = FirecrackerVM(self.inputs["firecracker"], self.inputs["kernel"], self.image,
                                self.socket_dir, self.logs, self.events)
        self.vm.start()
        self.vm.wait_for_shutdown()

    def _collect_guest_logs(self) -> None:
        if not self.image.exists():
            return
        self._mount(read_only=True)
        try:
            guest_log_dir = Path("/var/log/ts-member-status-qualification")
            for guest_name, output_name in (("go-host-test.log", "guest-go-host-test.log"),
                                            ("rust-test.log", "guest-rust-test.log")):
                guest_path = guest_log_dir / guest_name
                source = _guest_path_without_symlinks(self.mount_path, guest_path)
                try:
                    text, oversized = _read_guest_regular_file(
                        self.mount_path, guest_path, MAX_GUEST_LOG_BYTES)
                except FileNotFoundError:
                    self.events.add("guest_log_missing", path=str(guest_path))
                    continue
                metadata = source.lstat()
                target = self.logs / output_name
                target.write_text(text)
                target.chmod(0o600)
                self.events.add("guest_log_collected", source=str(source), target=str(target),
                                source_size_bytes=metadata.st_size, oversized=oversized)
                if oversized:
                    raise QualificationError(f"guest test log exceeded {MAX_GUEST_LOG_BYTES} bytes: {source}")
        finally:
            self._unmount()

    def _check_results(self) -> None:
        serial_path = self.logs / "guest-serial.log"
        go_path = self.logs / "guest-go-host-test.log"
        rust_path = self.logs / "guest-rust-test.log"
        if not serial_path.is_file():
            raise QualificationError(f"required guest evidence log is missing: {serial_path}")
        serial, serial_oversized = _read_text_bounded(serial_path, MAX_SERIAL_LOG_BYTES)
        if serial_oversized:
            raise QualificationError("guest serial log exceeded its collection bound")
        runner_result = parse_runner_result(serial)
        if runner_result["status"] == "FAILED":
            self.test_results = {"runner": runner_result}
            self.events.add("test_results", results=self.test_results)
            raise QualificationError(
                f"guest test command failed stage={runner_result['stage']} "
                f"status={runner_result['exit_status']}")
        for path in (go_path, rust_path):
            if not path.is_file():
                raise QualificationError(f"required guest evidence log is missing: {path}")
        go, go_oversized = _read_text_bounded(go_path, MAX_GUEST_LOG_BYTES)
        rust, rust_oversized = _read_text_bounded(rust_path, MAX_GUEST_LOG_BYTES)
        if go_oversized or rust_oversized:
            raise QualificationError("a guest evidence log exceeded its collection bound")
        self.test_results = parse_qualification_result(
            go, 0, rust, 0, serial, self.manifest["rust_test_name"])
        self.events.add("test_results", results=self.test_results)

    def _cleanup_socket_dir(self) -> None:
        if self.socket_dir is None:
            return
        if (self.vm is not None and self.vm.process is not None and
                (self.vm.process.returncode is None or not self.vm.process_group_stopped)):
            self.cleanup_errors.append(f"API socket directory retained while Firecracker is live: {self.socket_dir}")
            return
        try:
            if self.vm is not None and os.path.lexists(self.vm.socket_path):
                if not self.vm.socket_path.is_socket():
                    self.cleanup_errors.append(f"unexpected non-socket at owned API path: {self.vm.socket_path}")
                    return
                self.vm.socket_path.unlink()
            self.socket_dir.rmdir()
            self.events.add("api_socket_dir_removed", path=str(self.socket_dir))
        except Exception as error:
            self.cleanup_errors.append(f"remove owned API socket directory {self.socket_dir}: {error}")

    def _cleanup_image(self) -> None:
        stopped = (self.vm is None or self.vm.process is None or
                   (self.vm.process.returncode is not None and self.vm.process_group_stopped))
        mounted = os.path.ismount(self.mount_path)
        commands_stopped = not self.command_runner.pending
        self.image_safe_to_remove = stopped and commands_stopped and not mounted and not self.mount_owned
        if not self.image_safe_to_remove:
            self.events.add("private_image_retained", image=str(self.image),
                            stopped=stopped, commands_stopped=commands_stopped,
                            mounted=mounted, tracked_mount=self.mount_owned)
            return
        if self.image.exists() and self.failure:
            self.events.add("private_image_retained", image=str(self.image),
                            reason="qualification failed; preserve guest-side evidence")
            return
        if self.image.exists() and self.cleanup_errors:
            self.events.add("private_image_retained", image=str(self.image),
                            reason="cleanup failed; preserve guest-side evidence")
            return
        if self.image.exists():
            try:
                self.image.unlink()
                self.events.add("private_image_removed", image=str(self.image))
            except OSError as error:
                self.cleanup_errors.append(f"remove stopped and unmounted private image {self.image}: {error}")

    def run(self) -> dict[str, Any]:
        self.prepare_dirs()
        try:
            self._create_private_image()
            self._stage_guest()
            self._verify_input_and_start_vm()
            self._collect_guest_logs()
            self._check_results()
        except BaseException as error:
            self.failure = f"{type(error).__name__}: {error}"
            self.events.add("qualification_failure", failure=self.failure)
        finally:
            self._check_local_source_stability()
            if self.vm is not None:
                try:
                    self.cleanup_errors.extend(self.vm.stop())
                except Exception as error:
                    self.cleanup_errors.append(f"stop Firecracker: {error}")
            self.cleanup_errors.extend(self.command_runner.stop_pending())
            if os.path.ismount(self.mount_path):
                try:
                    self._unmount()
                except Exception as error:
                    self.cleanup_errors.append(f"unmount owned guest image: {error}")
            self._cleanup_socket_dir()
            self._cleanup_image()

        outcome = "PASS"
        if self.cleanup_errors:
            outcome = "CLEANUP_FAILED"
        elif self.failure:
            outcome = "FAILED"
        summary = {
            "schema_version": 1,
            "outcome": outcome,
            "failure": self.failure,
            "cleanup_errors": self.cleanup_errors,
            "cleanup_clean": not self.cleanup_errors,
            "started_at": self.started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "run_dir": str(self.root),
            "source_commits": self.manifest["source_commits"],
            "rust_test_name": self.manifest["rust_test_name"],
            "manifest_sha256": sha256_bytes(self.raw_manifest),
            "local_source_hashes": self.local_source_hashes,
            "local_source_hashes_after": self.local_source_hashes_after,
            "local_source_stable": self.local_source_stable,
            "input_hashes": {name: self.manifest["inputs"][name]["sha256"] for name in INPUT_NAMES},
            "input_paths": {name: self.manifest["inputs"][name]["resolved_path"] for name in INPUT_NAMES},
            "resources": {
                "guest_ram_mib": GUEST_RAM_MIB,
                "guest_vcpus": GUEST_VCPUS,
                "guest_network_interfaces": [],
                "service_name": SERVICE_NAME,
                "service_memory_max": "5G",
                "service_delegate": True,
                "service_delegate_subgroup": "supervisor",
                "private_image": str(self.image),
                "private_image_removed": not self.image.exists(),
                "private_image_retained": self.image.exists(),
                "api_socket_dir": str(self.socket_dir) if self.socket_dir else None,
                "api_socket_dir_removed": self.socket_dir is None or not self.socket_dir.exists(),
            },
            "tests": self.test_results,
            "logs": self.logs_out,
            "events": self.events.entries,
        }
        self._write_summary(summary)
        print(json.dumps({"outcome": outcome, "summary": str(self.root / "summary.json"),
                          "failure": self.failure}, sort_keys=True), flush=True)
        return summary

    def _write_summary(self, summary: dict[str, Any]) -> None:
        path = self.root / "summary.json"
        _atomic_replace(path, json.dumps(summary, sort_keys=True, indent=2) + "\n")

    def _check_local_source_stability(self) -> None:
        self.local_source_hashes_after: dict[str, str] = {}
        for name, path in self.local_source_paths.items():
            try:
                self.local_source_hashes_after[name] = sha256_file(path)
            except OSError as error:
                detail = f"local source disappeared during qualification: {path}: {error}"
                self.local_source_stable = False
                self.failure = "; ".join(part for part in (self.failure, detail) if part)
                self.events.add("source_changed_during_qualification", detail=detail,
                                initial=self.local_source_hashes, observed=self.local_source_hashes_after)
                return
        self.local_source_stable = self.local_source_hashes_after == self.local_source_hashes
        if not self.local_source_stable:
            detail = "local source files changed during qualification"
            self.failure = "; ".join(part for part in (self.failure, detail) if part)
            self.events.add("source_changed_during_qualification", detail=detail,
                            initial=self.local_source_hashes, observed=self.local_source_hashes_after)


def _validate_host_prerequisites(inputs: dict[str, Path], run_dir: Path) -> None:
    if os.path.lexists(run_dir):
        raise QualificationError(f"--run-dir must be a new path: {run_dir}")
    parent = run_dir.parent
    if not parent.exists() or not parent.is_dir():
        raise QualificationError(f"--run-dir parent must already exist: {parent}")
    required = ("cp", "e2fsck", "resize2fs", "mount", "umount", "install", "ln")
    missing = [name for name in required if shutil.which(name) is None]
    if not Path("/run/wrappers/bin/sudo").is_file() and shutil.which("sudo") is None:
        missing.append("sudo")
    if missing:
        raise QualificationError(f"host prerequisites are missing: {missing}")
    if not inputs["firecracker"].is_file() or not os.access(inputs["firecracker"], os.X_OK):
        raise QualificationError("Firecracker input must be an executable file")
    if not Path("/dev/kvm").exists():
        raise QualificationError("Firecracker requires /dev/kvm")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path,
                        help="immutable JSON manifest with source commits, exact test name, and SHA-256 inputs")
    parser.add_argument("--run-dir", required=True, type=Path,
                        help="new durable evidence directory; it must not already exist")
    args = parser.parse_args(argv)
    try:
        manifest, raw_manifest, inputs = load_manifest(args.manifest)
        run_dir = args.run_dir.expanduser().absolute()
        _validate_host_prerequisites(inputs, run_dir)
    except Exception as error:
        print(f"member-status qualification preflight failed: {error}", file=sys.stderr, flush=True)
        return 2
    try:
        outcome = Qualification(manifest, raw_manifest, inputs, run_dir).run()
    except Exception as error:
        print(f"member-status qualification failed before evidence setup: {error}", file=sys.stderr, flush=True)
        return 1
    return 0 if outcome["outcome"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
