#!/usr/bin/env python3
"""Read-only qualification of orchestrator and managed-member priorities."""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path


CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_ROOT = Path("/proc")
MAX_MEMORY_STAT_BYTES = 16_384
MAX_MEMORY_COUNTER_BYTES = 128
MAX_SYSTEM_SLICE_CHILD_CGROUPS = 256
MAX_SYSTEM_SLICE_CHILD_NAME_BYTES = 16_384
HOST_UNIT_DEFAULT = "terrascale-orchestrator-host.service"
CONTROLLER_UNIT_DEFAULT = "terrascale-orchestrator-controller.service"
RUNTIME_PRIORITY_PROFILE = Path("/etc/terrascale-orchestrator/runtime-priority.json")
UNIT_PROPERTIES = (
    "ActiveState", "MainPID", "ControlGroup", "Nice", "OOMScoreAdjust",
    "CPUWeight", "IOWeight", "CPUSchedulingPolicy", "IOSchedulingClass",
    "IOSchedulingPriority", "ManagedOOMPreference", "Delegate",
    "DelegateSubgroup", "MemoryMin", "MemoryLow",
)


class QualificationError(RuntimeError):
    pass


class Probe:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.log: list[str] = []

    def command(self, argv: list[str]) -> str:
        result = subprocess.run(argv, text=True, capture_output=True, check=False)
        self.log.append(
            f"$ {' '.join(argv)}\nexit={result.returncode}\n"
            f"stdout:\n{result.stdout}stderr:\n{result.stderr}"
        )
        if result.returncode != 0:
            raise QualificationError(
                f"command failed ({result.returncode}): {' '.join(argv)}"
            )
        return result.stdout.strip()

    def unit(self, name: str) -> dict[str, str]:
        output = self.command([
            "systemctl", "show", name,
            *(f"--property={key}" for key in UNIT_PROPERTIES),
        ])
        values: dict[str, str] = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        missing = [key for key in UNIT_PROPERTIES if key not in values]
        if missing:
            raise QualificationError(
                f"{name}: systemd lacks required properties: {', '.join(missing)}"
            )
        return values

    def assert_unit_priority(self, name: str, values: dict[str, str], host: bool) -> int:
        expected = {
            "ActiveState": "active",
            "Nice": "-20",
            "OOMScoreAdjust": "-1000",
            "CPUWeight": "10000",
            "IOWeight": "10000",
            "CPUSchedulingPolicy": "other",
            "IOSchedulingPriority": "0",
            "ManagedOOMPreference": "omit",
        }
        if values.get("IOSchedulingClass") not in {"best-effort", "2"}:
            expected["IOSchedulingClass"] = "best-effort"
        else:
            expected["IOSchedulingClass"] = values["IOSchedulingClass"]
        if host:
            expected.update({"Delegate": "yes", "DelegateSubgroup": "supervisor"})
        for key, want in expected.items():
            got = values.get(key, "").lower() if key in {"ActiveState", "Delegate"} else values.get(key, "")
            if got != want:
                raise QualificationError(
                    f"{name}: systemctl show {key}={values.get(key)!r}, expected {want!r}"
                )
        try:
            pid = int(values["MainPID"])
        except ValueError as error:
            raise QualificationError(f"{name}: invalid MainPID {values['MainPID']!r}") from error
        if pid <= 1:
            raise QualificationError(f"{name}: no running MainPID")
        if host and values["ControlGroup"].rstrip("/") == "":
            raise QualificationError(f"{name}: empty ControlGroup")
        return pid

    @staticmethod
    def number(path: Path) -> int:
        try:
            value = path.read_text().strip()
            return int(value)
        except (OSError, ValueError) as error:
            raise QualificationError(f"cannot read numeric cgroup value {path}: {error}") from error

    @staticmethod
    def utc_now() -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="milliseconds",
        ).replace("+00:00", "Z")

    @staticmethod
    def canonical_json(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii")

    def memory_usage_sample(self, cgroups: dict[str, Path], systemd_version: str) -> dict[str, object]:
        started_at = self.utc_now()
        root = CGROUP_ROOT.resolve(strict=True)
        rows: dict[str, object] = {}
        for scope, path in cgroups.items():
            try:
                if path.is_symlink() or not path.is_dir():
                    raise QualificationError(f"{scope} memory sample path is not a cgroup directory: {path}")
                resolved = path.resolve(strict=True)
                if root not in resolved.parents or resolved == root:
                    raise QualificationError(f"{scope} memory sample escaped the cgroup root: {path}")
                directory_fd = os.open(
                    resolved,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    directory_stat = os.fstat(directory_fd)
                    if not stat.S_ISDIR(directory_stat.st_mode):
                        raise QualificationError(f"{scope} memory sample target is not a directory: {path}")
                    before_stat = resolved.stat(follow_symlinks=False)
                    if (before_stat.st_dev, before_stat.st_ino) != (directory_stat.st_dev, directory_stat.st_ino):
                        raise QualificationError(f"{scope} memory sample cgroup changed before capture: {path}")

                    def read_cgroup_file(name: str, maximum_bytes: int, encoding: str) -> str:
                        file_fd = os.open(
                            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=directory_fd,
                        )
                        with os.fdopen(file_fd, "rb") as cgroup_file:
                            raw = cgroup_file.read(maximum_bytes + 1)
                        if len(raw) > maximum_bytes:
                            raise QualificationError(f"{scope} {name} exceeds its fixed evidence bound")
                        try:
                            return raw.decode(encoding)
                        except UnicodeDecodeError as error:
                            raise QualificationError(f"{scope} {name} is not {encoding} text") from error

                    current_raw = read_cgroup_file("memory.current", MAX_MEMORY_COUNTER_BYTES, "ascii")
                    peak_raw = read_cgroup_file("memory.peak", MAX_MEMORY_COUNTER_BYTES, "ascii")
                    stat_raw = read_cgroup_file("memory.stat", MAX_MEMORY_STAT_BYTES, "utf-8")
                    after_stat = resolved.stat(follow_symlinks=False)
                    if (after_stat.st_dev, after_stat.st_ino) != (directory_stat.st_dev, directory_stat.st_ino):
                        raise QualificationError(f"{scope} memory sample cgroup changed during capture: {path}")
                    inode = directory_stat.st_ino
                finally:
                    os.close(directory_fd)
            except OSError as error:
                raise QualificationError(f"cannot capture {scope} cgroup memory usage at {path}: {error}") from error
            current_text, peak_text = current_raw.strip(), peak_raw.strip()
            if not current_text.isdecimal() or not peak_text.isdecimal():
                raise QualificationError(f"{scope} memory.current/memory.peak is not decimal bytes")
            rows[scope] = {
                "cgroup_path": str(resolved), "cgroup_inode": inode,
                "memory_current_raw": current_raw, "memory_current_bytes": int(current_text),
                "memory_peak_raw": peak_raw, "memory_peak_bytes": int(peak_text),
                "memory_stat_raw": stat_raw,
                "memory_stat_sha256": hashlib.sha256(stat_raw.encode("utf-8")).hexdigest(),
            }
        system_slice = cgroups["system_slice"].resolve(strict=True)
        children: list[str] = []
        children_size = 0
        try:
            for child in system_slice.iterdir():
                if child.is_symlink():
                    raise QualificationError("system.slice contains a symlink while its child scopes are sampled")
                if not child.is_dir():
                    continue
                child_name = child.name
                child_size = len(child_name.encode("utf-8"))
                if (len(children) >= MAX_SYSTEM_SLICE_CHILD_CGROUPS or
                        children_size + child_size > MAX_SYSTEM_SLICE_CHILD_NAME_BYTES):
                    raise QualificationError("system.slice child-cgroup list exceeds its fixed evidence bound")
                children.append(child_name)
                children_size += child_size
        except OSError as error:
            raise QualificationError(f"cannot enumerate system.slice direct child cgroups: {error}") from error
        children.sort()
        sample: dict[str, object] = {
            "schema": "terrascale.d15.memory-usage-sample/v1",
            "oci_instance_id": self.args.oci_instance_id,
            "image_id": self.args.image_id,
            "artifact_id": self.args.artifact_id,
            "config_id": self.args.config_id,
            "profile_id": self.args.profile_id,
            "host_boot_id": (PROC_ROOT / "sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
            "kernel_release": os.uname().release,
            "systemd_version": systemd_version,
            "started_at_utc": started_at,
            "finished_at_utc": self.utc_now(),
            "scopes": rows,
            "system_slice_direct_child_cgroups": children,
        }
        sample["sample_sha256"] = hashlib.sha256(self.canonical_json(sample)).hexdigest()
        return sample

    @staticmethod
    def io_weight(path: Path) -> int:
        try:
            lines = path.read_text().splitlines()
        except OSError as error:
            raise QualificationError(f"cannot read cgroup I/O weight {path}: {error}") from error
        for line in lines:
            fields = line.split()
            if len(fields) == 2 and fields[0] == "default":
                try:
                    return int(fields[1])
                except ValueError:
                    break
        raise QualificationError(f"{path}: missing numeric default I/O weight")

    @staticmethod
    def cgroup_path(pid: int) -> Path:
        try:
            rows = (PROC_ROOT / str(pid) / "cgroup").read_text().splitlines()
        except OSError as error:
            raise QualificationError(f"cannot inspect PID {pid} cgroup: {error}") from error
        matches = [row[3:] for row in rows if row.startswith("0::")]
        if len(matches) != 1 or not matches[0].startswith("/"):
            raise QualificationError(f"PID {pid} has no unique unified cgroup membership")
        relative = Path(matches[0].lstrip("/"))
        if ".." in relative.parts:
            raise QualificationError(f"PID {pid} has an unsafe cgroup membership")
        return CGROUP_ROOT / relative

    @staticmethod
    def process_values(pid: int) -> dict[str, object]:
        proc = PROC_ROOT / str(pid)
        try:
            stat = (proc / "stat").read_text()
            end = stat.rfind(")")
            fields = stat[end + 1 :].split()
            nice = int(fields[16])
            scheduler_policy = int(fields[38])
            start_time = int(fields[19])
            oom = int((proc / "oom_score_adj").read_text().strip())
        except (OSError, ValueError, IndexError) as error:
            raise QualificationError(f"cannot inspect scheduling/OOM values for PID {pid}: {error}") from error
        return {"pid": pid, "nice": nice, "scheduler_policy": scheduler_policy,
                "oom_score_adj": oom, "process_start_time": str(start_time)}

    def assert_process(self, pid: int, label: str, protected: bool) -> dict[str, object]:
        values = self.process_values(pid)
        nice = int(values["nice"])
        scheduler_policy = int(values["scheduler_policy"])
        oom = int(values["oom_score_adj"])
        if scheduler_policy != 0:
            raise QualificationError(
                f"{label} PID {pid}: /proc reports scheduler policy {scheduler_policy}; expected SCHED_OTHER"
            )
        if protected and (nice != -20 or oom != -1000):
            raise QualificationError(
                f"{label} PID {pid}: /proc reports nice={nice}, oom_score_adj={oom}; "
                "expected -20 and -1000"
            )
        if not protected and (nice != 0 or oom != 0):
            raise QualificationError(
                f"{label} PID {pid}: nice={nice}, oom_score_adj={oom}; expected reset values 0 and 0"
            )
        ionice = self.command(["ionice", "-p", str(pid)])
        match = re.search(r"(none|realtime|best-effort|idle):\s*prio\s+(\d+)", ionice)
        if not match:
            raise QualificationError(f"{label} PID {pid}: unrecognized ionice output {ionice!r}")
        io_class, io_priority = match.group(1), int(match.group(2))
        want_priority = 0 if protected else 4
        if io_class != "best-effort" or io_priority != want_priority:
            raise QualificationError(
                f"{label} PID {pid}: ionice={io_class}:{io_priority}, "
                f"expected best-effort:{want_priority}"
            )
        values["io_class"] = io_class
        values["io_priority"] = io_priority
        values["cgroup"] = str(self.cgroup_path(pid))
        return values

    @staticmethod
    def oomd_xattr(path: Path, name: str) -> str | None:
        try:
            value = os.getxattr(path, name).decode("ascii")
        except OSError as error:
            if error.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
                return None
            raise QualificationError(f"cannot inspect {name} on {path}: {error}") from error
        except UnicodeDecodeError as error:
            raise QualificationError(f"invalid non-ASCII value for {name} on {path}") from error
        return value

    def verify_oomd_policy(self, unit_root: Path, supervisor: Path, runner: Path,
                           roles: list[Path], controller: Path) -> dict[str, object]:
        expected = "1"
        protected = {
            "host_service": unit_root,
            "host_supervisor": supervisor,
            "controller_service": controller,
        }
        observations: dict[str, object] = {"omit": {}, "avoid": {}}
        for label, path in protected.items():
            omit = self.oomd_xattr(path, "user.oomd_omit")
            avoid = self.oomd_xattr(path, "user.oomd_avoid")
            if omit != expected or avoid is not None:
                raise QualificationError(
                    f"{label}: systemd-oomd xattrs omit={omit!r}, avoid={avoid!r}; expected omit='1' only"
                )
            observations["omit"][label] = omit
            observations["avoid"][label] = avoid
        workload_paths = {"native_runner": runner}
        workload_paths.update({f"role:{path.name}": path for path in roles})
        for label, path in workload_paths.items():
            omit = self.oomd_xattr(path, "user.oomd_omit")
            avoid = self.oomd_xattr(path, "user.oomd_avoid")
            if omit is not None or avoid is not None:
                raise QualificationError(
                    f"{label}: workload cgroup must stay eligible for systemd-oomd; "
                    f"omit={omit!r}, avoid={avoid!r}"
                )
            observations["omit"][label] = omit
            observations["avoid"][label] = avoid
        return observations

    def verify_priority_cgroup(self, path: Path, cpu: int, io: int, label: str) -> dict[str, int]:
        if not path.is_dir():
            raise QualificationError(f"{label}: missing cgroup {path}")
        actual_cpu = self.number(path / "cpu.weight")
        actual_io = self.io_weight(path / "io.weight")
        if actual_cpu != cpu or actual_io != io:
            raise QualificationError(
                f"{label}: cpu.weight={actual_cpu}, io.weight={actual_io}; "
                f"expected {cpu} and {io}"
            )
        return {"cpu_weight": actual_cpu, "io_weight": actual_io}

    def verify_memory_budget(self, host_values: dict[str, str], controller_values: dict[str, str],
                             service: Path, controller: Path) -> dict[str, object]:
        args = self.args
        page = os.sysconf("SC_PAGE_SIZE")
        limits = {
            "expected_memory_min_bytes": args.expected_memory_min_bytes,
            "expected_memory_low_bytes": args.expected_memory_low_bytes,
            "expected_controller_memory_min_bytes": args.expected_controller_memory_min_bytes,
            "expected_controller_memory_low_bytes": args.expected_controller_memory_low_bytes,
            "expected_system_slice_memory_min_bytes": args.expected_system_slice_memory_min_bytes,
            "expected_system_slice_memory_low_bytes": args.expected_system_slice_memory_low_bytes,
            "system_reserve_bytes": args.system_reserve_bytes,
            "allocatable_memory_bytes": args.allocatable_memory_bytes,
        }
        if any(value <= 0 or value % page for value in limits.values()):
            raise QualificationError(f"memory profile values must be positive, page-aligned bytes: {limits}")
        min_bytes = args.expected_memory_min_bytes
        low_bytes = args.expected_memory_low_bytes
        controller_min = args.expected_controller_memory_min_bytes
        controller_low = args.expected_controller_memory_low_bytes
        slice_min = args.expected_system_slice_memory_min_bytes
        slice_low = args.expected_system_slice_memory_low_bytes
        reserve = args.system_reserve_bytes
        if (min_bytes > low_bytes or controller_min > controller_low or
                slice_min < min_bytes + controller_min or slice_low < low_bytes + controller_low or
                slice_min > slice_low or slice_low > reserve):
            raise QualificationError(
                "require positive service floors, system.slice aggregate >= both protected units, "
                "and aggregate MemoryLow <= signed SystemReserveBytes"
            )
        for name, values, expected in (
            ("host", host_values, {"MemoryMin": min_bytes, "MemoryLow": low_bytes}),
            ("controller", controller_values,
             {"MemoryMin": controller_min, "MemoryLow": controller_low}),
        ):
            for label, value in expected.items():
                try:
                    actual = int(values[label])
                except ValueError as error:
                    raise QualificationError(f"{name} unit {label} is not a finite byte count") from error
                if actual != value:
                    raise QualificationError(
                        f"{name} unit {label}={actual}, expected profile value {value}"
                    )

        actual_min = self.number(service / "memory.min")
        actual_low = self.number(service / "memory.low")
        controller_min_actual = self.number(controller / "memory.min")
        controller_low_actual = self.number(controller / "memory.low")
        supervisor = service / "supervisor"
        supervisor_min = self.number(supervisor / "memory.min")
        supervisor_low = self.number(supervisor / "memory.low")
        system_slice = service.parent
        if system_slice.name != "system.slice":
            raise QualificationError(f"host unit is not a child of system.slice: {service}")
        system_slice_min = self.number(system_slice / "memory.min")
        system_slice_low = self.number(system_slice / "memory.low")
        actual = {
            "service_memory_min_bytes": actual_min,
            "service_memory_low_bytes": actual_low,
            "supervisor_memory_min_bytes": supervisor_min,
            "supervisor_memory_low_bytes": supervisor_low,
            "controller_memory_min_bytes": controller_min_actual,
            "controller_memory_low_bytes": controller_low_actual,
            "system_slice_memory_min_bytes": system_slice_min,
            "system_slice_memory_low_bytes": system_slice_low,
        }
        if (actual_min, actual_low, supervisor_min, supervisor_low,
                controller_min_actual, controller_low_actual, system_slice_min, system_slice_low) != (
            min_bytes, low_bytes, min_bytes, low_bytes,
            controller_min, controller_low, slice_min, slice_low,
        ):
            raise QualificationError(
                f"service/supervisor/controller/system.slice memory protections differ from profile: {actual}"
            )

        ancestor_protections = []
        root = CGROUP_ROOT.resolve()
        for service_path, want_min, want_low, label in (
            (service, min_bytes, low_bytes, "host"),
            (controller, controller_min, controller_low, "controller"),
        ):
            ancestor = service_path.parent
            while ancestor.resolve() != root:
                ancestor_min = self.number(ancestor / "memory.min")
                ancestor_low = self.number(ancestor / "memory.low")
                if ancestor_min < want_min or ancestor_low < want_low:
                    raise QualificationError(
                        f"{label} ancestor {ancestor} protects memory.min/low={ancestor_min}/{ancestor_low}, "
                        f"below required service reservation {want_min}/{want_low}"
                    )
                ancestor_protections.append({
                    "service": label, "cgroup": str(ancestor),
                    "memory_min_bytes": ancestor_min, "memory_low_bytes": ancestor_low,
                })
                parent = ancestor.parent
                if parent == ancestor or root not in parent.resolve().parents and parent.resolve() != root:
                    raise QualificationError(f"cgroup ancestor escaped unified root: {ancestor}")
                ancestor = parent

        try:
            meminfo = (PROC_ROOT / "meminfo").read_text()
            total_kib = next(
                int(match.group(1))
                for line in meminfo.splitlines()
                if (match := re.match(r"MemTotal:\s+(\d+)\s+kB", line))
            )
        except (OSError, StopIteration, ValueError) as error:
            raise QualificationError(f"cannot read physical memory total: {error}") from error
        available = total_kib * 1024
        cursor = service
        while True:
            value_path = cursor / "memory.max"
            try:
                value = value_path.read_text().strip()
            except OSError as error:
                raise QualificationError(f"cannot read ancestor memory.max {value_path}: {error}") from error
            if value != "max":
                try:
                    available = min(available, int(value))
                except ValueError as error:
                    raise QualificationError(f"invalid ancestor memory.max at {value_path}") from error
            if cursor.resolve() == root:
                break
            parent = cursor.parent
            if parent == cursor or root not in parent.resolve().parents and parent.resolve() != root:
                raise QualificationError(f"cgroup ancestor escaped unified root: {cursor}")
            cursor = parent
        needed = args.allocatable_memory_bytes + reserve
        if needed > available:
            raise QualificationError(
                f"signed allocatable+reserve is {needed} bytes, exceeding physical/ancestor limit {available}"
            )
        return {
            **actual,
            "allocatable_memory_bytes": args.allocatable_memory_bytes,
            "system_reserve_bytes": reserve,
            "available_physical_and_ancestor_memory_bytes": available,
            "ancestor_protections": ancestor_protections,
        }

    def verify_baked_profile(self) -> dict[str, object]:
        path = RUNTIME_PRIORITY_PROFILE
        try:
            metadata = path.lstat()
            wire = path.read_bytes()
        except OSError as error:
            raise QualificationError(f"cannot inspect baked runtime-priority profile {path}: {error}") from error
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or
                stat.S_IMODE(metadata.st_mode) != 0o644 or metadata.st_nlink != 1):
            raise QualificationError(
                f"baked runtime-priority profile must be a root-owned regular 0644 file with one link: {path}"
            )
        if not wire or len(wire) > 4096:
            raise QualificationError(f"baked runtime-priority profile has invalid size: {len(wire)}")

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise QualificationError(f"baked runtime-priority profile repeats field {key!r}")
                result[key] = value
            return result

        try:
            profile = json.loads(wire, object_pairs_hook=unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise QualificationError(f"baked runtime-priority profile is invalid JSON: {error}") from error
        expected = {
            "version": 1,
            "profile_id": self.args.profile_id,
            "system_reserve_bytes": self.args.system_reserve_bytes,
        }
        if type(profile) is not dict or set(profile) != set(expected):
            raise QualificationError("baked runtime-priority profile has an unsupported schema")
        if (type(profile.get("version")) is not int or type(profile.get("system_reserve_bytes")) is not int or
                profile != expected):
            raise QualificationError(
                "baked runtime-priority profile ID/reserve differs from the requested signed placement profile"
            )
        canonical = json.dumps(expected, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if wire != canonical:
            raise QualificationError("baked runtime-priority profile is not canonical JSON")
        return {
            "path": str(path), "sha256": hashlib.sha256(wire).hexdigest(), **expected,
        }

    def source_identity(self) -> tuple[str | None, Path]:
        source = Path(__file__).resolve()
        repository = next(
            (parent for parent in source.parents if (parent / "deploy/systemd").is_dir()),
            None,
        )
        if repository is None:
            return None, Path("/etc/systemd/system")
        revision = self.command(["git", "-C", str(repository), "rev-parse", "HEAD"])
        return revision, repository / "deploy/systemd"

    def run(self) -> dict[str, object]:
        args = self.args
        systemd_version = self.command(["systemctl", "--version"]).splitlines()[0]
        version = re.match(r"systemd\s+(\d+)", systemd_version)
        if not version or int(version.group(1)) < 255:
            raise QualificationError(
                f"target requires systemd 255 or newer for DelegateSubgroup=: {systemd_version!r}"
            )
        host = self.unit(args.host_unit)
        controller = self.unit(args.controller_unit)
        baked_profile = self.verify_baked_profile()
        host_pid = self.assert_unit_priority(args.host_unit, host, host=True)
        controller_pid = self.assert_unit_priority(args.controller_unit, controller, host=False)

        host_service = CGROUP_ROOT / host["ControlGroup"].lstrip("/")
        controller_service = CGROUP_ROOT / controller["ControlGroup"].lstrip("/")
        host_process = self.assert_process(host_pid, "host supervisor", protected=True)
        controller_process = self.assert_process(controller_pid, "controller", protected=True)
        if Path(str(host_process["cgroup"])) != host_service / "supervisor":
            raise QualificationError(
                f"host PID {host_pid} is outside exact DelegateSubgroup=supervisor: {host_process['cgroup']}"
            )
        if Path(str(controller_process["cgroup"])) != controller_service:
            raise QualificationError(
                f"controller PID {controller_pid} is outside its service cgroup: {controller_process['cgroup']}"
            )

        service_controllers = set((host_service / "cgroup.controllers").read_text().split())
        if not {"cpu", "io", "memory"}.issubset(service_controllers):
            raise QualificationError(
                f"host service lacks delegated cpu/io/memory controllers: {sorted(service_controllers)}"
            )
        service_enabled = set((host_service / "cgroup.subtree_control").read_text().split())
        if not {"cpu", "io", "memory"}.issubset(service_enabled):
            raise QualificationError(
                f"host service has not enabled cpu/io/memory for children: {sorted(service_enabled)}"
            )
        cpu_max = (host_service / "cpu.max").read_text().strip().split()
        if len(cpu_max) != 2 or cpu_max[0] != "max":
            raise QualificationError(f"host service has a CPU quota: cpu.max={cpu_max}")

        host_weights = self.verify_priority_cgroup(host_service, 10000, 10000, "host service")
        controller_weights = self.verify_priority_cgroup(controller_service, 10000, 10000, "controller service")
        supervisor = host_service / "supervisor"
        supervisor_weights = self.verify_priority_cgroup(supervisor, 10000, 10000, "host supervisor subgroup")
        memory = self.verify_memory_budget(host, controller, host_service, controller_service)
        system_slice = host_service.parent
        if system_slice != controller_service.parent or system_slice.name != "system.slice":
            raise QualificationError("host and controller service cgroups must share system.slice")

        roots = sorted(host_service.glob("terrascale-host-*"))
        if len(roots) != 1 or not roots[0].is_dir():
            raise QualificationError(
                f"expected one native workload runner cgroup under {host_service}, found {[p.name for p in roots]}"
            )
        runner = roots[0]
        runner_weights = self.verify_priority_cgroup(runner, 1000, 1000, "native workload runner")
        quota = derive_workload_cpu_quota(host_service, len(os.sched_getaffinity(host_pid)))
        runner_cpu_max = normalize_cpu_max(runner / "cpu.max")
        expected_cpu_max = f"{quota} 100000"
        if runner_cpu_max != expected_cpu_max:
            raise QualificationError(
                f"native runner cpu.max={runner_cpu_max!r}, expected derived workload cap {expected_cpu_max!r}"
            )
        runner_resources = {
            "memory_min_bytes": self.number(runner / "memory.min"),
            "memory_low_bytes": self.number(runner / "memory.low"),
        }
        if runner_resources != {"memory_min_bytes": 0, "memory_low_bytes": 0}:
            raise QualificationError(f"native runner inherited manager memory protection: {runner_resources}")
        roles: dict[str, object] = {}
        for role in sorted(path for path in runner.iterdir() if path.is_dir()):
            role_weights = self.verify_priority_cgroup(role, 1000, 1000, f"native role {role.name}")
            role_cpu_max = normalize_cpu_max(role / "cpu.max")
            if role_cpu_max != expected_cpu_max:
                raise QualificationError(
                    f"native role {role.name} cpu.max={role_cpu_max!r}, expected {expected_cpu_max!r}"
                )
            role_memory = {
                "memory_min_bytes": self.number(role / "memory.min"),
                "memory_low_bytes": self.number(role / "memory.low"),
                "memory_max": (role / "memory.max").read_text().strip(),
            }
            if role_memory["memory_min_bytes"] != 0 or role_memory["memory_low_bytes"] != 0:
                raise QualificationError(f"native role {role.name} inherited manager memory protection: {role_memory}")
            roles[role.name] = {"weights": role_weights, "memory": role_memory}
        oomd_policy = self.verify_oomd_policy(
            host_service, supervisor, runner,
            [runner / name for name in roles], controller_service,
        )

        database = None
        if args.database_pid is not None:
            database = self.assert_process(args.database_pid, "TerraBase", protected=False)
            database_group = Path(str(database["cgroup"]))
            if database_group == runner or runner not in database_group.parents:
                raise QualificationError(
                    f"TerraBase PID {args.database_pid} is outside native workload cgroup {runner}: {database_group}"
                )
            relative_role = database_group.relative_to(runner).parts[0]
            if relative_role not in roles:
                raise QualificationError(f"TerraBase PID {args.database_pid} has no direct role cgroup")
            if args.database_memory_max_bytes is not None:
                role_cap = (runner / relative_role / "memory.max").read_text().strip()
                if role_cap != str(args.database_memory_max_bytes):
                    raise QualificationError(
                        f"TerraBase memory.max={role_cap}, expected signed profile cap {args.database_memory_max_bytes}"
                    )
        elif args.database_memory_max_bytes is not None:
            raise QualificationError("--database-memory-max-bytes requires --database-pid")

        rev, unit_root = self.source_identity()
        unit_hashes = {}
        for name in ("terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service"):
            path = unit_root / name
            unit_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        qualifier_hash = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
        return {
            "status": "PASS",
            "repository_revision": rev,
            "qualifier_sha256": qualifier_hash,
            "baked_runtime_priority_profile": baked_profile,
            "artifact_id": args.artifact_id,
            "config_id": args.config_id,
            "profile_id": args.profile_id,
            "systemd_version": systemd_version,
            "units": {"host": host, "controller": controller},
            "processes": {"host_supervisor": host_process, "controller": controller_process, "terrabase": database},
            "cgroups": {
                "host_service": str(host_service), "host_service_weights": host_weights,
                "host_cpu_max": " ".join(cpu_max), "host_supervisor_weights": supervisor_weights,
                "native_runner": str(runner), "native_runner_weights": runner_weights,
                "native_workload_cpu_max": expected_cpu_max,
                "native_runner_memory": runner_resources, "roles": roles,
                "controller_service": str(controller_service), "controller_weights": controller_weights,
            },
            "memory_usage_sample": self.memory_usage_sample({
                "host_service": host_service,
                "controller_service": controller_service,
                "system_slice": system_slice,
            }, systemd_version),
            "memory_profile": memory,
            "systemd_oomd_policy": oomd_policy,
            "unit_sha256": unit_hashes,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    qualify = modes.add_parser("qualify", help="read live systemd, process and cgroup state")
    qualify.add_argument("--host-unit", default=HOST_UNIT_DEFAULT)
    qualify.add_argument("--controller-unit", default=CONTROLLER_UNIT_DEFAULT)
    qualify.add_argument("--database-pid", type=int)
    qualify.add_argument("--database-memory-max-bytes", type=int)
    qualify.add_argument("--expected-memory-min-bytes", type=int, required=True)
    qualify.add_argument("--expected-memory-low-bytes", type=int, required=True)
    qualify.add_argument("--expected-controller-memory-min-bytes", type=int, required=True)
    qualify.add_argument("--expected-controller-memory-low-bytes", type=int, required=True)
    qualify.add_argument("--expected-system-slice-memory-min-bytes", type=int, required=True)
    qualify.add_argument("--expected-system-slice-memory-low-bytes", type=int, required=True)
    qualify.add_argument("--system-reserve-bytes", type=int, required=True)
    qualify.add_argument("--allocatable-memory-bytes", type=int, required=True)
    qualify.add_argument("--artifact-id", required=True)
    qualify.add_argument("--oci-instance-id", required=True)
    qualify.add_argument("--image-id", required=True)
    qualify.add_argument("--config-id", required=True)
    qualify.add_argument("--profile-id", required=True)
    qualify.add_argument("--evidence-dir", type=Path, required=True)
    render = modes.add_parser("render-drop-ins", help="render profile-bound drop-ins into an image staging root")
    render.add_argument("--profile-id", required=True)
    render.add_argument("--service-memory-min-bytes", type=int, required=True)
    render.add_argument("--service-memory-low-bytes", type=int, required=True)
    render.add_argument("--controller-memory-min-bytes", type=int, required=True)
    render.add_argument("--controller-memory-low-bytes", type=int, required=True)
    render.add_argument("--system-slice-memory-min-bytes", type=int, required=True)
    render.add_argument("--system-slice-memory-low-bytes", type=int, required=True)
    render.add_argument("--system-reserve-bytes", type=int, required=True)
    render.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "qualify":
        if args.database_pid is not None and args.database_pid <= 1:
            parser.error("--database-pid must be greater than 1")
        if args.database_memory_max_bytes is not None and args.database_memory_max_bytes <= 0:
            parser.error("--database-memory-max-bytes must be positive")
        if args.database_memory_max_bytes is not None and args.database_pid is None:
            parser.error("--database-memory-max-bytes requires --database-pid")
    return args


def render_drop_ins(args: argparse.Namespace) -> int:
    page = os.sysconf("SC_PAGE_SIZE")
    values = {
        "service MemoryMin": args.service_memory_min_bytes,
        "service MemoryLow": args.service_memory_low_bytes,
        "controller MemoryMin": args.controller_memory_min_bytes,
        "controller MemoryLow": args.controller_memory_low_bytes,
        "system.slice MemoryMin": args.system_slice_memory_min_bytes,
        "system.slice MemoryLow": args.system_slice_memory_low_bytes,
        "SystemReserveBytes": args.system_reserve_bytes,
    }
    if any(value <= 0 or value % page for value in values.values()):
        raise QualificationError(f"drop-in memory values must be positive, page-aligned bytes: {values}")
    service_min, service_low = args.service_memory_min_bytes, args.service_memory_low_bytes
    controller_min, controller_low = args.controller_memory_min_bytes, args.controller_memory_low_bytes
    slice_min, slice_low, reserve = (
        args.system_slice_memory_min_bytes,
        args.system_slice_memory_low_bytes,
        args.system_reserve_bytes,
    )
    if (service_min > service_low or controller_min > controller_low or slice_min > slice_low or
            slice_low > reserve):
        raise QualificationError("service/controller/system.slice floors must satisfy MemoryMin <= MemoryLow <= signed SystemReserveBytes")
    if slice_min < service_min + controller_min or slice_low < service_low + controller_low:
        raise QualificationError("system.slice floors must cover aggregate host and controller child floors")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.profile_id):
        raise QualificationError("profile ID must be a 1-128 character safe token")
    if not args.output_root.is_absolute():
        raise QualificationError("--output-root must be an absolute image staging path")
    root = args.output_root.resolve()
    forbidden = [Path("/"), Path("/etc"), Path("/usr"), Path("/lib")]
    if root in forbidden or any(root == path or path in root.parents for path in forbidden[1:]):
        raise QualificationError("refusing to write systemd drop-ins into a live system directory")
    content = (
        f"# Profile: {args.profile_id}\n"
        f"# Signed SystemReserveBytes: {reserve}\n"
        "# Explicit image-profile allocations; adequacy requires target pressure qualification.\n"
        "[Service]\n"
    )
    files = {
        root / "etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf":
            content.replace("[Service]", "[Slice]")
            + f"MemoryMin={slice_min}\nMemoryLow={slice_low}\n",
        root / "etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf":
            content + f"MemoryMin={service_min}\nMemoryLow={service_low}\n",
        root / "etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf":
            content + f"MemoryMin={controller_min}\nMemoryLow={controller_low}\n",
    }
    for path, rendered in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_text() != rendered:
                raise QualificationError(f"refusing to replace conflicting image profile drop-in: {path}")
        else:
            path.write_text(rendered)
    for path in files:
        print(f"{path} sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")
    return 0


def normalize_cpu_max(path: Path) -> str:
    try:
        fields = path.read_text().split()
    except OSError as error:
        raise QualificationError(f"cannot read CPU quota {path}: {error}") from error
    if len(fields) != 2:
        raise QualificationError(f"invalid cpu.max at {path}: {fields}")
    return " ".join(fields)


def derive_workload_cpu_quota(service_root: Path, available_cpus: int) -> int:
    if available_cpus <= 0 or available_cpus > 1024:
        raise QualificationError(f"invalid service CPU affinity count: {available_cpus}")
    available = available_cpus * 100000
    root = CGROUP_ROOT.resolve()
    ancestor = service_root
    while True:
        fields = normalize_cpu_max(ancestor / "cpu.max").split()
        try:
            period = int(fields[1])
            quota_text = fields[0]
            if period <= 0:
                raise ValueError("zero period")
            if quota_text != "max":
                quota = int(quota_text)
                if quota <= 0:
                    raise ValueError("zero quota")
                if quota < available_cpus * period:
                    available = min(available, quota * 100000 // period)
        except ValueError as error:
            raise QualificationError(f"invalid ancestor CPU limit at {ancestor}: {fields}") from error
        if ancestor.resolve() == root:
            break
        parent = ancestor.parent
        if parent == ancestor or root not in parent.resolve().parents and parent.resolve() != root:
            raise QualificationError(f"CPU quota path escaped unified cgroup root: {ancestor}")
        ancestor = parent
    result = available * 3 // 4
    if result < 1000 or result >= available:
        raise QualificationError("derived native workload CPU cap leaves no manager headroom")
    return result


def main() -> int:
    args = parse_args()
    if args.mode == "render-drop-ins":
        try:
            return render_drop_ins(args)
        except (QualificationError, OSError) as error:
            print(f"runtime priority drop-in generation failed: {error}", file=sys.stderr)
            return 1
    try:
        args.evidence_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print(f"evidence directory already exists: {args.evidence_dir}", file=sys.stderr)
        return 2
    probe = Probe(args)
    started_at_utc = dt.datetime.now(dt.timezone.utc).isoformat(
        timespec="milliseconds",
    ).replace("+00:00", "Z")
    status = "FAILED"
    result: dict[str, object] = {
        "status": status,
        "artifact_id": args.artifact_id,
        "config_id": args.config_id,
        "profile_id": args.profile_id,
    }
    try:
        result = probe.run()
        status = "PASS"
    except (QualificationError, OSError, subprocess.SubprocessError) as error:
        result.update({"stage": "effective_priority_and_resource_validation", "error": str(error)})
        print(f"runtime priority qualification failed: {error}", file=sys.stderr)
    finally:
        result["started_at_utc"] = started_at_utc
        result["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="milliseconds",
        ).replace("+00:00", "Z")
        result["status"] = status
        (args.evidence_dir / "commands.log").write_text("\n".join(probe.log) + "\n")
        (args.evidence_dir / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"{status}: {args.evidence_dir / 'summary.json'}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
