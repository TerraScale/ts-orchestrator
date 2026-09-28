#!/usr/bin/env python3
"""Bounded D15 qualification runner and cgroup-confined workload generator.

The alpha adapter owns the pinned operator, SSH, and TLS transport. The
pressure worker never moves a process into a cgroup; it verifies the transient
systemd scope in which its caller already started it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import math
import mmap
import os
import queue
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
import urllib.parse
from multiprocessing import Event, Process, Queue, get_context
from pathlib import Path
from typing import Any


SCHEMA = "terrascale.runtime-priority-pressure/v4"
ADAPTER_INPUT_SCHEMA = "terrascale.d15.adapter-input/v2"
ADAPTER_RESULT_SCHEMA = "terrascale.d15.adapter-result/v1"
ADAPTER_CONTRACT_SCHEMA = "terrascale.d15.adapter-contract/v4"
DATABASE_FRONTIER_BINDING = "object_durable.event{database,shard,replica,incarnation,sequence};serving_proof.v1/same_scope/v1"
OOM_JOURNAL_FORMAT = "systemd-journal-kernel-oom/v1"
FAILURE_TARGET_WITNESS = "accepted-managed-report+proc-stat+cgroup+boot-id/v1"
PRESSURE_SURVIVAL_POLICY = "all-pressure-workers-through-duration/v1"
PRESSURE_WORKER_STATE_SCHEMA = "terrascale.d15.pressure-worker-state/v2"
MAX_TARGET_WITNESS_AGE_MS = 1000
CGROUP_ROOT = Path("/sys/fs/cgroup")
MAX_PRESSURE_SECONDS = 900
MAX_ADAPTER_SECONDS = 300
MAX_CPU_WORKERS = 64
MAX_IO_WORKERS = 32
MAX_PRESSURE_SAMPLES = 180
MAX_PRESSURE_MEMORY_BYTES = 16 * 1024 * 1024 * 1024
MAX_PRESSURE_IO_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_PRESSURE_IO_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
MAX_PRESSURE_IO_BYTES_PER_SECOND = 128 * 1024 * 1024
MAX_PRESSURE_IO_SCRATCH_BYTES = 4 * 1024 * 1024 * 1024
MAX_ADAPTER_OUTPUT_BYTES = 1 << 20
MAX_RUN_ADAPTER_BYTES = 64 << 20
MAX_FINAL_ADAPTER_RESERVE_BYTES = 16 << 20
MAX_ADAPTER_ARGV_BYTES = 64 << 10
MAX_ADAPTER_ARGS = 128
MAX_ADAPTER_ARG_BYTES = 4096
MAX_ADAPTER_COMMAND_BYTES = 68 << 10
MAX_ADAPTER_OBSERVATION_BYTES = 16 << 10
MAX_PRESSURE_WORKER_STATE_BYTES = 16 << 10
MAX_PINNED_FILE_BYTES = 16 << 20
MAX_OOM_EVENTS = 4096
MEMORY_USAGE_SAMPLE_SCHEMA = "terrascale.d15.memory-usage-sample/v2"
MAX_MEMORY_COUNTER_BYTES = 128
MAX_MEMORY_STAT_BYTES = 16_384
MAX_SYSTEM_SLICE_CHILD_CGROUPS = 256
MAX_SYSTEM_SLICE_CHILD_NAME_BYTES = 16_384
BASE_ADAPTERS = (
    "target_identity",
    "qualify",
    "host_status",
    "database_progress",
    "service_state",
    "pressure_start",
    "pressure_status",
    "pressure_stop",
    "cleanup_verify",
)
INJECTED_FAILURE_ADAPTERS = {"terrabase_process", "host_manager_sigkill"}
REQUIRED_SERVICE_NAMES = {
    "host": "terrascale-orchestrator-host.service",
    "controller": "terrascale-orchestrator-controller.service",
}
IDENTITY_KEYS = (
    "oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id",
    "architecture", "cell", "environment",
)
QUALIFICATION_KEYS = (
    "expected_memory_min_bytes", "expected_memory_low_bytes",
    "expected_controller_memory_min_bytes", "expected_controller_memory_low_bytes",
    "expected_system_slice_memory_min_bytes", "expected_system_slice_memory_low_bytes",
    "system_reserve_bytes", "allocatable_memory_bytes", "database_memory_max_bytes",
)
FLOOR_SCOPES = ("host_service", "controller_service", "system_slice")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SCENARIOS = {"management_stability", "terrabase_process", "terrabase_oom", "host_manager_sigkill"}
SCOPE_KEYS = {"cluster_id", "tenant_id", "database_id", "shard_id", "member_id", "incarnation"}
AUTHORITY_KEYS = {"epoch", "configuration_id", "certificate_sha256", "tls_leaf_sha256"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
OCI_INSTANCE_ID_RE = re.compile(r"^ocid1\.instance\.oc1\.[A-Za-z0-9._-]{16,}$")
OCI_IMAGE_ID_RE = re.compile(r"^ocid1\.image\.oc1\.[A-Za-z0-9._-]{16,}$")


class HarnessError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp(value: object, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HarnessError(f"{field} must be an RFC3339 UTC timestamp ending in Z")
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise HarnessError(f"{field} is not a valid RFC3339 UTC timestamp") from error


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _memory_stat_values(raw: object, field: str) -> dict[str, int]:
    text = require_text(raw, field)
    values: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[a-zA-Z0-9_]+", parts[0]) or not parts[1].isdecimal():
            raise HarnessError(f"{field} must contain unique key and nonnegative decimal value rows")
        if parts[0] in values:
            raise HarnessError(f"{field} repeats key {parts[0]!r}")
        values[parts[0]] = int(parts[1])
    if not values:
        raise HarnessError(f"{field} is empty")
    return values


def validate_memory_usage_sample(sample: object, *, identity: dict[str, Any],
                                 guest_role: str, expected_service_cgroup: str,
                                 expected_boot_id: str,
                                 expected_systemd_version: str,
                                 not_before: dt.datetime,
                                 not_after: dt.datetime) -> dict[str, Any]:
    """Validate root-read cgroup usage telemetry and its exact qualification identity."""
    sample = require_object(sample, "qualify.summary.memory_usage_sample")
    expected_fields = {
        "schema", "guest_role", "oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id",
        "host_boot_id", "kernel_release", "systemd_version", "started_at_utc",
        "finished_at_utc", "scopes", "system_slice_direct_child_cgroups", "sample_sha256",
    }
    if set(sample) != expected_fields:
        raise HarnessError("memory usage sample fields differ from the pinned schema")
    if sample.get("schema") != MEMORY_USAGE_SAMPLE_SCHEMA:
        raise HarnessError("memory usage sample schema is unsupported")
    if guest_role not in {"host", "controller"} or sample.get("guest_role") != guest_role:
        raise HarnessError("memory usage sample guest role differs from the pinned target")
    for key in ("oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"):
        if sample.get(key) != identity.get(key):
            raise HarnessError(f"memory usage sample {key} differs from the pinned target")
    boot_id = require_text(sample.get("host_boot_id"), "memory usage sample host_boot_id")
    if not UUID_RE.fullmatch(boot_id) or boot_id != expected_boot_id:
        raise HarnessError("memory usage sample boot ID differs from the accepted guest")
    require_text(sample.get("kernel_release"), "memory usage sample kernel_release")
    systemd_version = require_text(sample.get("systemd_version"), "memory usage sample systemd_version")
    if systemd_version != expected_systemd_version:
        raise HarnessError("memory usage sample systemd version differs from the packaged qualifier")
    started = parse_timestamp(sample.get("started_at_utc"), "memory usage sample started_at_utc")
    finished = parse_timestamp(sample.get("finished_at_utc"), "memory usage sample finished_at_utc")
    if not_before > started or started > finished or finished > not_after:
        raise HarnessError("memory usage sample is stale or outside its exact qualification request")

    scopes = require_object(sample.get("scopes"), "memory usage sample scopes")
    if set(scopes) != {f"{guest_role}_service", "system_slice"}:
        raise HarnessError("memory usage sample must contain the selected service and system.slice scopes")
    service_path = Path(expected_service_cgroup)
    system_slice_path = service_path.parent
    if not service_path.is_absolute() or system_slice_path.name != "system.slice":
        raise HarnessError("qualified service cgroup is outside the expected system.slice")
    expected_paths = {
        f"{guest_role}_service": expected_service_cgroup,
        "system_slice": str(system_slice_path),
    }
    for scope, expected_path in expected_paths.items():
        row = require_object(scopes.get(scope), f"memory usage sample scopes.{scope}")
        row_fields = {
            "cgroup_path", "cgroup_inode", "memory_current_raw", "memory_current_bytes",
            "memory_peak_raw", "memory_peak_bytes", "memory_stat_raw", "memory_stat_sha256",
        }
        if set(row) != row_fields:
            raise HarnessError(f"memory usage sample {scope} fields differ from the pinned schema")
        cgroup_path = require_text(row.get("cgroup_path"), f"memory usage sample {scope}.cgroup_path")
        path = Path(cgroup_path)
        if (cgroup_path != expected_path or not path.is_absolute() or ".." in path.parts or
                not cgroup_path.startswith(str(CGROUP_ROOT) + "/")):
            raise HarnessError(f"memory usage sample {scope} cgroup differs from the exact unit scope")
        require_int(row.get("cgroup_inode"), f"memory usage sample {scope}.cgroup_inode", 1)
        for raw_key, byte_key in (("memory_current_raw", "memory_current_bytes"),
                                  ("memory_peak_raw", "memory_peak_bytes")):
            raw = require_text(row.get(raw_key), f"memory usage sample {scope}.{raw_key}")
            if len(raw.encode("utf-8")) > MAX_MEMORY_COUNTER_BYTES:
                raise HarnessError(f"memory usage sample {scope}.{raw_key} exceeds its fixed evidence bound")
            number = raw[:-1] if raw.endswith("\n") else raw
            if not number.isdecimal():
                raise HarnessError(f"memory usage sample {scope}.{raw_key} must be decimal bytes")
            actual = require_int(row.get(byte_key), f"memory usage sample {scope}.{byte_key}", 0)
            if int(number) != actual:
                raise HarnessError(f"memory usage sample {scope}.{byte_key} differs from its raw cgroup value")
            if raw_key == "memory_peak_raw":
                peak_bytes = actual
            elif raw_key == "memory_current_raw":
                current_bytes = actual
        if peak_bytes < current_bytes:
            raise HarnessError(f"memory usage sample {scope} peak is below its current usage")
        stat_raw = require_text(row.get("memory_stat_raw"), f"memory usage sample {scope}.memory_stat_raw")
        if len(stat_raw.encode("utf-8")) > MAX_MEMORY_STAT_BYTES:
            raise HarnessError(f"memory usage sample {scope}.memory_stat_raw exceeds its fixed evidence bound")
        _memory_stat_values(stat_raw, f"memory usage sample {scope}.memory_stat_raw")
        stat_digest = require_text(row.get("memory_stat_sha256"), f"memory usage sample {scope}.memory_stat_sha256")
        if (not HASH_RE.fullmatch(stat_digest) or
                hashlib.sha256(stat_raw.encode("utf-8")).hexdigest() != stat_digest):
            raise HarnessError(f"memory usage sample {scope} memory.stat hash differs from its raw value")
    children = sample.get("system_slice_direct_child_cgroups")
    if type(children) is not list or len(children) > MAX_SYSTEM_SLICE_CHILD_CGROUPS:
        raise HarnessError("memory usage sample system.slice child list exceeds its fixed evidence bound")
    if (any(not isinstance(name, str) or not name for name in children) or
            sum(len(name.encode("utf-8")) for name in children) > MAX_SYSTEM_SLICE_CHILD_NAME_BYTES):
        raise HarnessError("memory usage sample system.slice child list is malformed or exceeds its fixed evidence bound")
    if children != sorted(set(children)):
        raise HarnessError("memory usage sample system.slice child list is malformed or unordered")
    if service_path.name not in children:
        raise HarnessError("memory usage sample system.slice does not list its protected service cgroup")
    digest = require_text(sample.get("sample_sha256"), "memory usage sample sample_sha256")
    unhashed = {key: value for key, value in sample.items() if key != "sample_sha256"}
    if not HASH_RE.fullmatch(digest) or hashlib.sha256(canonical_json_bytes(unhashed)).hexdigest() != digest:
        raise HarnessError("memory usage sample hash differs from its canonical contents")
    return sample


def load_json(path: Path, max_bytes: int = 1 << 20) -> tuple[dict[str, Any], bytes]:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise HarnessError(f"{path} must be a regular file no larger than {max_bytes} bytes")
        wire = path.read_bytes()
        value = json.loads(wire, object_pairs_hook=unique_json_object)
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"cannot read JSON file {path}: {error}") from error
    if type(value) is not dict:
        raise HarnessError(f"{path} must contain a JSON object")
    return value, wire


def require_object(value: object, field: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HarnessError(f"{field} must be an object")
    return value


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HarnessError(f"JSON object repeats field {key!r}")
        result[key] = value
    return result


def require_int(value: object, field: str, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise HarnessError(f"{field} must be an integer >= {minimum}")
    return value


def require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HarnessError(f"{field} must be a non-empty string")
    return value


def require_pid_list(value: object, field: str) -> list[int]:
    if (type(value) is not list or any(type(pid) is not int or pid <= 1 for pid in value) or
            value != sorted(set(value))):
        raise HarnessError(f"{field} must be a sorted unique list of process IDs")
    return value


def validate_scope(value: object, field: str) -> dict[str, Any]:
    scope = require_object(value, field)
    if set(scope) != SCOPE_KEYS:
        raise HarnessError(f"{field} must contain exactly the alpha member scope fields")
    for key in ("cluster_id", "incarnation"):
        if not isinstance(scope.get(key), str) or not re.fullmatch(r"[0-9a-f]{32}", scope[key]):
            raise HarnessError(f"{field}.{key} must be 32 lowercase hexadecimal characters")
    for key in ("tenant_id", "database_id", "member_id"):
        if not isinstance(scope.get(key), str) or not UUID_RE.fullmatch(scope[key]):
            raise HarnessError(f"{field}.{key} must be a canonical lowercase UUID")
    require_int(scope.get("shard_id"), f"{field}.shard_id")
    return scope


def validate_authority(value: object, field: str) -> dict[str, Any]:
    authority = require_object(value, field)
    if set(authority) != AUTHORITY_KEYS:
        raise HarnessError(f"{field} must contain exactly the alpha authority fields")
    require_int(authority.get("epoch"), f"{field}.epoch")
    for key in AUTHORITY_KEYS - {"epoch"}:
        if not HASH_RE.fullmatch(str(authority.get(key, ""))):
            raise HarnessError(f"{field}.{key} must be a lowercase SHA-256 digest")
    return authority


def validate_managed_member(value: object) -> dict[str, Any]:
    member = require_object(value, "managed_member")
    if set(member) != {"source", "peer", "document", "acknowledgment_profile"}:
        raise HarnessError("managed_member fields must be exactly source, peer, document, and acknowledgment_profile")
    if member.get("acknowledgment_profile") != "object_durable":
        raise HarnessError("D15 managed member must pin the ObjectDurable acknowledgment profile")
    identities: dict[str, dict[str, Any]] = {}
    for label in ("source", "peer"):
        row = require_object(member.get(label), f"managed_member.{label}")
        if set(row) != {"cell", "node", "environment", "role", "scope", "authority"}:
            raise HarnessError(f"managed_member.{label} fields do not match the alpha host report")
        for key in ("cell", "node", "environment", "role"):
            require_text(row.get(key), f"managed_member.{label}.{key}")
        if row["role"] != "terrabase":
            raise HarnessError(f"managed_member.{label}.role must be 'terrabase'")
        scope = validate_scope(row.get("scope"), f"managed_member.{label}.scope")
        authority = validate_authority(row.get("authority"), f"managed_member.{label}.authority")
        identities[label] = {**row, "scope": scope, "authority": authority}
    source = identities["source"]
    peer = identities["peer"]
    if (source["cell"] != peer["cell"] or source["environment"] != peer["environment"] or
            source["node"] == peer["node"]):
        raise HarnessError("source and peer must be distinct nodes in one cell and environment")
    for key in ("cluster_id", "tenant_id", "database_id", "shard_id"):
        if source["scope"][key] != peer["scope"][key]:
            raise HarnessError(f"source and peer scopes disagree on {key}")
    if source["scope"]["member_id"] == peer["scope"]["member_id"] or source["scope"]["incarnation"] == peer["scope"]["incarnation"]:
        raise HarnessError("source and peer require distinct member IDs and incarnations")
    document = require_object(member.get("document"), "managed_member.document")
    if set(document) != {"collection_id", "schema_generation", "schema_digest", "field_id"}:
        raise HarnessError("managed_member.document does not match the alpha document transaction input")
    if not isinstance(document["collection_id"], str) or not UUID_RE.fullmatch(document["collection_id"]):
        raise HarnessError("managed_member.document.collection_id must be a canonical lowercase UUID")
    require_int(document.get("schema_generation"), "managed_member.document.schema_generation")
    if not HASH_RE.fullmatch(str(document.get("schema_digest", ""))):
        raise HarnessError("managed_member.document.schema_digest must be a lowercase SHA-256 digest")
    require_int(document.get("field_id"), "managed_member.document.field_id")
    return {"source": source, "peer": peer, "document": document,
            "acknowledgment_profile": member["acknowledgment_profile"]}


def _validate_https_endpoint(value: object, field: str) -> None:
    if not isinstance(value, str):
        raise HarnessError(f"{field} must be an HTTPS URL")
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or
            parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise HarnessError(f"{field} must be an origin-only HTTPS URL without userinfo or query")


def _validate_metrics_endpoint(value: object, field: str) -> None:
    if not isinstance(value, str):
        raise HarnessError(f"{field} must be a loopback HTTP /metrics URL")
    parsed = urllib.parse.urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as error:
        raise HarnessError(f"{field} must use a literal loopback address") from error
    if (parsed.scheme != "http" or not address.is_loopback or parsed.path != "/metrics" or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise HarnessError(f"{field} must be a loopback HTTP /metrics URL")


def _validate_private_file(value: object, field: str, missing: list[str]) -> None:
    if not isinstance(value, str) or not value:
        missing.append(f"{field} path is missing")
        return
    path = Path(value)
    if not path.is_absolute():
        missing.append(f"{field} path must be absolute")
        return
    try:
        info = path.lstat()
    except OSError:
        missing.append(f"{field} file is unavailable: {path}")
        return
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or
            not info.st_mode & 0o400 or info.st_uid != os.getuid()):
        missing.append(f"{field} must be a current-user-owned regular file with mode 0400 or 0600")


def validate_transport(manifest: dict[str, Any], missing: list[str]) -> None:
    transport = require_object(manifest.get("transport"), "transport")
    operator = require_object(transport.get("operator"), "transport.operator")
    for field in ("executable_path", "config_path"):
        if not isinstance(operator.get(field), str) or not Path(operator[field]).is_absolute():
            missing.append(f"transport.operator.{field} must be an absolute pinned path")
    try:
        verify_adapter_executable(operator.get("executable_path"), operator.get("executable_sha256"))
    except HarnessError as error:
        missing.append(f"operator executable pin: {error}")
    verify_pinned_file(operator.get("config_path"), operator.get("config_sha256"),
                       "operator hosts config", missing)

    ssh = require_object(transport.get("ssh"), "transport.ssh")
    if not isinstance(ssh.get("executable_path"), str) or not Path(ssh["executable_path"]).is_absolute():
        missing.append("transport.ssh.executable_path must be an absolute pinned path")
    try:
        verify_adapter_executable(ssh.get("executable_path"), ssh.get("executable_sha256"))
    except HarnessError as error:
        missing.append(f"SSH executable pin: {error}")
    targets = require_object(ssh.get("targets"), "transport.ssh.targets")
    if set(targets) != {"source", "peer", "controller"}:
        raise HarnessError("transport.ssh.targets must contain source, peer, and controller targets")
    member = manifest["managed_member"]
    target_ids: set[str] = set()
    for label in ("source", "peer", "controller"):
        target = require_object(targets[label], f"transport.ssh.targets.{label}")
        required = {"address", "user", "port", "host_key_alias", "known_hosts_path",
                    "known_hosts_sha256", "identity_file_path", "oci_instance_id"}
        if set(target) != required:
            raise HarnessError(f"transport.ssh.targets.{label} fields differ from the pinned SSH settings")
        address = require_text(target.get("address"), f"transport.ssh.targets.{label}.address")
        if address.startswith("-") or not re.fullmatch(r"[A-Za-z0-9.:%_-]{1,253}", address):
            raise HarnessError(f"transport.ssh.targets.{label}.address is not a safe SSH host address")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*", address):
                raise HarnessError(f"transport.ssh.targets.{label}.address is not a valid host or IP address")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", str(target.get("user", ""))):
            raise HarnessError(f"transport.ssh.targets.{label}.user is not a safe account name")
        port = require_int(target.get("port"), f"transport.ssh.targets.{label}.port")
        if port > 65535:
            raise HarnessError(f"transport.ssh.targets.{label}.port must not exceed 65535")
        for key in ("host_key_alias", "oci_instance_id"):
            require_text(target.get(key), f"transport.ssh.targets.{label}.{key}")
        if not OCI_INSTANCE_ID_RE.fullmatch(target["oci_instance_id"]):
            missing.append(f"transport.ssh.targets.{label}.oci_instance_id must be a real OCI instance OCID")
        if target["oci_instance_id"] in target_ids:
            raise HarnessError("SSH targets must pin distinct OCI instance IDs")
        target_ids.add(target["oci_instance_id"])
        verify_pinned_file(target.get("known_hosts_path"), target.get("known_hosts_sha256"),
                           f"{label} SSH known_hosts", missing)
        _validate_private_file(target.get("identity_file_path"),
                               f"{label} SSH identity file", missing)
    if targets["source"]["oci_instance_id"] != manifest["identity"]["oci_instance_id"]:
        raise HarnessError("source SSH target OCI instance ID differs from the target identity pin")
    if targets["controller"]["oci_instance_id"] != manifest["controller_identity"]["oci_instance_id"]:
        raise HarnessError("controller SSH target OCI instance ID differs from its target identity pin")

    https = require_object(transport.get("https"), "transport.https")
    for label in ("source", "peer"):
        _validate_https_endpoint(https.get(f"{label}_base_url"), f"transport.https.{label}_base_url")
        _validate_private_file(https.get(f"{label}_credential_file"),
                               f"transport.https.{label}_credential_file", missing)
        _validate_metrics_endpoint(https.get(f"{label}_metrics_url"),
                                   f"transport.https.{label}_metrics_url")
    verify_pinned_file(https.get("ca_bundle_path"), https.get("ca_bundle_sha256"),
                       "TerraBase client CA bundle", missing)

    runtime = require_object(transport.get("runtime"), "transport.runtime")
    if runtime.get("service_names") != REQUIRED_SERVICE_NAMES:
        raise HarnessError("transport.runtime.service_names must pin the exact alpha host/controller units")
    for key in ("sudo_path", "remote_python_path", "qualify_path", "stress_launcher_path",
                "systemctl_path", "systemd_run_path", "journalctl_path"):
        value = require_text(runtime.get(key), f"transport.runtime.{key}")
        if not value.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9._/-]+", value):
            raise HarnessError(f"transport.runtime.{key} must be an absolute safe executable path")
    workload_slice = require_text(runtime.get("workload_slice"), "transport.runtime.workload_slice")
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.slice", workload_slice):
        raise HarnessError("transport.runtime.workload_slice must be one exact systemd .slice unit")
    if runtime.get("stress_launcher_contract") != "terrascale.d15.cgroup-launch/v1":
        missing.append("target native pressure launcher must implement terrascale.d15.cgroup-launch/v1")
    if not HASH_RE.fullmatch(str(runtime.get("stress_launcher_sha256", ""))):
        missing.append("target native pressure launcher SHA-256 is missing or malformed")

    adapter = require_object(manifest.get("adapter"), "adapter")
    if set(adapter) != {"python_path", "python_sha256", "source_path", "source_sha256", "deadlines_seconds"}:
        raise HarnessError("adapter fields must be exactly the pinned interpreter, source, and deadlines")
    try:
        verify_adapter_executable(adapter.get("python_path"), adapter.get("python_sha256"))
    except HarnessError as error:
        missing.append(f"alpha adapter interpreter pin: {error}")
    verify_pinned_file(adapter.get("source_path"), adapter.get("source_sha256"),
                       "alpha adapter source", missing)
    if (adapter.get("source_path") != manifest["adapter_contract"].get("source_path") or
            adapter.get("source_sha256") != manifest["adapter_contract"].get("source_sha256")):
        missing.append("adapter source pin differs from the frozen alpha contract source pin")
    roles = set(BASE_ADAPTERS)
    scenario = manifest["pressure"].get("scenario")
    if scenario in INJECTED_FAILURE_ADAPTERS:
        roles.add("failure_inject")
    if scenario == "terrabase_oom":
        roles.add("kernel_oom_evidence")
    deadlines = require_object(adapter.get("deadlines_seconds"), "adapter.deadlines_seconds")
    if set(deadlines) != roles:
        missing.append("alpha adapter deadlines must cover exactly the required scenario roles")
        for role in sorted(roles - set(deadlines)):
            missing.append(f"required adapter {role!r} is missing")
    for role, value in deadlines.items():
        deadline = require_int(value, f"adapter.deadlines_seconds.{role}")
        if deadline > MAX_ADAPTER_SECONDS:
            missing.append(f"adapter deadline for {role} exceeds {MAX_ADAPTER_SECONDS} seconds")
        if role == "database_progress" and deadline != manifest["adapter_contract"].get("database_progress_deadline_seconds"):
            missing.append("database progress deadline differs from the frozen alpha contract")


def validate_manifest(manifest: dict[str, Any], *, dry_run: bool,
                      allow_allocations: bool = False) -> list[str]:
    if manifest.get("schema") != SCHEMA:
        raise HarnessError(f"manifest schema must be {SCHEMA!r}")

    identity = require_object(manifest.get("identity"), "identity")
    for key in IDENTITY_KEYS:
        require_text(identity.get(key), f"identity.{key}")
    if not OCI_INSTANCE_ID_RE.fullmatch(identity["oci_instance_id"]):
        missing_identity = "identity.oci_instance_id must be a real OCI instance OCID"
    else:
        missing_identity = None
    if not OCI_IMAGE_ID_RE.fullmatch(identity["image_id"]):
        image_identity_missing = "identity.image_id must be the actual imported OCI image OCID"
    else:
        image_identity_missing = None
    if identity["architecture"] != "aarch64":
        raise HarnessError("D15 target architecture must be aarch64")
    controller_identity = require_object(manifest.get("controller_identity"), "controller_identity")
    if set(controller_identity) != set(IDENTITY_KEYS):
        raise HarnessError("controller_identity must pin the exact controller guest identity")
    for key in IDENTITY_KEYS:
        require_text(controller_identity.get(key), f"controller_identity.{key}")
    if (controller_identity["architecture"] != "aarch64" or
            controller_identity["cell"] != identity["cell"] or
            controller_identity["environment"] != identity["environment"] or
            controller_identity["oci_instance_id"] == identity["oci_instance_id"]):
        raise HarnessError("controller identity must pin a distinct ARM guest in the same cell/environment")
    member_identity = validate_managed_member(manifest.get("managed_member"))
    if (member_identity["source"]["cell"] != identity["cell"] or
            member_identity["source"]["environment"] != identity["environment"]):
        raise HarnessError("identity cell/environment differs from the signed source member")
    revision = manifest.get("repository_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise HarnessError("repository_revision must pin a full Git object ID")

    authorization = require_object(manifest.get("authorization"), "authorization")
    contract = require_object(manifest.get("adapter_contract"), "adapter_contract")
    missing: list[str] = []
    if missing_identity:
        missing.append(missing_identity)
    if image_identity_missing:
        missing.append(image_identity_missing)
    if not OCI_INSTANCE_ID_RE.fullmatch(controller_identity["oci_instance_id"]):
        missing.append("controller_identity.oci_instance_id must be a real OCI instance OCID")
    if not OCI_IMAGE_ID_RE.fullmatch(controller_identity["image_id"]):
        missing.append("controller_identity.image_id must be the actual imported OCI image OCID")
    if authorization.get("live_stress_authorized") is not True:
        missing.append("OCI owner has not explicitly authorized live pressure")
    if not HASH_RE.fullmatch(str(authorization.get("owner_handoff_sha256", ""))):
        missing.append("exact OCI owner handoff SHA-256 is missing")
    verify_pinned_file(authorization.get("owner_handoff_path"),
                       authorization.get("owner_handoff_sha256"),
                       "OCI owner handoff", missing)
    if contract.get("frozen") is not True:
        missing.append("alpha host, database, target, and recovery adapter contract is not frozen")
    if (contract.get("schema") != ADAPTER_CONTRACT_SCHEMA or
            type(contract.get("version")) is not int or contract.get("version") != 4):
        missing.append(f"adapter contract must declare schema {ADAPTER_CONTRACT_SCHEMA!r} and version 4")
    require_text(contract.get("id"), "adapter_contract.id")
    if contract.get("database_frontier_binding") != DATABASE_FRONTIER_BINDING:
        missing.append("adapter contract must bind ObjectDurable event identity to the matching v1 serving proof")
    if contract.get("host_status_source") != "operator-hosts-json/controller-admitted/read-only/v1":
        missing.append("adapter contract must pin the actual read-only operator hosts JSON evidence source")
    if contract.get("managed_process_witness") != FAILURE_TARGET_WITNESS:
        missing.append("adapter contract must pin the accepted managed report and target /proc witness")
    if contract.get("pressure_survival_policy") != PRESSURE_SURVIVAL_POLICY:
        missing.append("adapter contract must require every bounded pressure worker to survive the full duration")
    database_deadline = contract.get("database_progress_deadline_seconds")
    if type(database_deadline) is not int or database_deadline < 1 or database_deadline > MAX_ADAPTER_SECONDS:
        missing.append("adapter contract must pin a database progress deadline from 1 to 300 seconds")
    host_report_age = contract.get("host_report_max_age_seconds")
    if type(host_report_age) is not int or host_report_age != 30:
        missing.append("adapter contract must pin the source host report's 30-second acceptance freshness")
    target_witness_age = contract.get("target_witness_max_age_ms")
    if (type(target_witness_age) is not int or target_witness_age < 1 or
            target_witness_age > MAX_TARGET_WITNESS_AGE_MS):
        missing.append(
            f"adapter contract must pin a managed process witness age from 1 to {MAX_TARGET_WITNESS_AGE_MS} milliseconds"
        )
    if contract.get("oom_journal_format") != OOM_JOURNAL_FORMAT:
        missing.append(f"adapter contract must pin supported OOM journal format {OOM_JOURNAL_FORMAT!r}")
    oom_window = contract.get("oom_event_window_seconds")
    if type(oom_window) is not int or oom_window < 1 or oom_window > MAX_ADAPTER_SECONDS:
        missing.append("adapter contract must pin an OOM event window from 1 to 300 seconds")
    if not HASH_RE.fullmatch(str(contract.get("source_sha256", ""))):
        missing.append("adapter contract source SHA-256 is missing")
    verify_pinned_file(contract.get("source_path"), contract.get("source_sha256"),
                       "adapter contract", missing)

    qualification = require_object(manifest.get("qualification"), "qualification")
    for key in QUALIFICATION_KEYS:
        require_int(qualification.get(key), f"qualification.{key}")
    page = int(manifest.get("page_size_bytes", 0))
    if page <= 0 or page & (page - 1):
        raise HarnessError("page_size_bytes must be a positive power of two")
    memory_values = [qualification[key] for key in QUALIFICATION_KEYS[:8]]
    if any(value % page for value in memory_values):
        raise HarnessError("profile memory values must be page aligned")
    if (qualification["expected_memory_min_bytes"] > qualification["expected_memory_low_bytes"] or
            qualification["expected_controller_memory_min_bytes"] > qualification["expected_controller_memory_low_bytes"] or
            qualification["expected_system_slice_memory_min_bytes"] > qualification["expected_system_slice_memory_low_bytes"] or
            qualification["expected_system_slice_memory_min_bytes"] <
            qualification["expected_memory_min_bytes"] + qualification["expected_controller_memory_min_bytes"] or
            qualification["expected_system_slice_memory_low_bytes"] <
            qualification["expected_memory_low_bytes"] + qualification["expected_controller_memory_low_bytes"] or
            qualification["expected_system_slice_memory_low_bytes"] > qualification["system_reserve_bytes"]):
        raise HarnessError("service and system.slice floor values violate the signed reserve relationship")
    controller_qualification = require_object(manifest.get("controller_qualification"),
                                              "controller_qualification")
    controller_keys = (
        "expected_controller_memory_min_bytes", "expected_controller_memory_low_bytes",
        "expected_system_slice_memory_min_bytes", "expected_system_slice_memory_low_bytes",
        "system_reserve_bytes", "allocatable_memory_bytes",
    )
    if set(controller_qualification) != set(controller_keys):
        raise HarnessError("controller_qualification must pin exact controller memory allocations")
    for key in controller_keys:
        value = require_int(controller_qualification.get(key), f"controller_qualification.{key}")
        if value % page:
            raise HarnessError(f"controller_qualification.{key} must be page aligned")
    if (controller_qualification["expected_controller_memory_min_bytes"] >
            controller_qualification["expected_controller_memory_low_bytes"] or
            controller_qualification["expected_system_slice_memory_min_bytes"] <
            controller_qualification["expected_controller_memory_min_bytes"] or
            controller_qualification["expected_system_slice_memory_low_bytes"] <
            controller_qualification["expected_controller_memory_low_bytes"] or
            controller_qualification["expected_system_slice_memory_min_bytes"] >
            controller_qualification["expected_system_slice_memory_low_bytes"] or
            controller_qualification["expected_system_slice_memory_low_bytes"] >
            controller_qualification["system_reserve_bytes"]):
        raise HarnessError("controller service and system.slice floors violate its signed reserve")

    floor_evidence = require_object(manifest.get("memory_floor_evidence"), "memory_floor_evidence")
    for scope in FLOOR_SCOPES:
        evidence = require_object(floor_evidence.get(scope), f"memory_floor_evidence.{scope}")
        if evidence.get("basis") not in {"measured", "allocation"}:
            raise HarnessError(f"memory_floor_evidence.{scope}.basis must be measured or allocation")
        require_text(evidence.get("source"), f"memory_floor_evidence.{scope}.source")
        require_text(evidence.get("observed_at_utc"), f"memory_floor_evidence.{scope}.observed_at_utc")
        parse_timestamp(evidence["observed_at_utc"], f"memory_floor_evidence.{scope}.observed_at_utc")
        source_reasons: list[str] = []
        verify_pinned_file(evidence.get("source_path"), evidence.get("source_sha256"),
                           f"{scope} floor evidence", source_reasons)
        missing.extend(source_reasons)
        if evidence["basis"] != "measured" and not allow_allocations:
            missing.append(f"{scope} memory floors are allocations, not measured floors")
    controller_floor_evidence = require_object(manifest.get("controller_memory_floor_evidence"),
                                               "controller_memory_floor_evidence")
    if set(controller_floor_evidence) != {"controller_service", "system_slice"}:
        raise HarnessError("controller floor evidence must pin controller service and slice sources")
    for scope, evidence_value in controller_floor_evidence.items():
        evidence = require_object(evidence_value, f"controller_memory_floor_evidence.{scope}")
        if evidence.get("basis") not in {"measured", "allocation"}:
            raise HarnessError(f"controller_memory_floor_evidence.{scope}.basis must be measured or allocation")
        require_text(evidence.get("source"), f"controller_memory_floor_evidence.{scope}.source")
        observed_at = require_text(evidence.get("observed_at_utc"),
                                   f"controller_memory_floor_evidence.{scope}.observed_at_utc")
        parse_timestamp(observed_at, f"controller_memory_floor_evidence.{scope}.observed_at_utc")
        verify_pinned_file(evidence.get("source_path"), evidence.get("source_sha256"),
                           f"controller {scope} floor evidence", missing)
        if evidence["basis"] != "measured" and not allow_allocations:
            missing.append(f"controller {scope} memory floors are allocations, not measured floors")

    pressure = require_object(manifest.get("pressure"), "pressure")
    scenario = require_text(pressure.get("scenario"), "pressure.scenario")
    if scenario not in SCENARIOS:
        raise HarnessError(f"pressure.scenario must be one of {sorted(SCENARIOS)}")
    duration = require_int(pressure.get("duration_seconds"), "pressure.duration_seconds")
    if duration > MAX_PRESSURE_SECONDS:
        raise HarnessError(f"pressure.duration_seconds must not exceed {MAX_PRESSURE_SECONDS}")
    interval = require_int(pressure.get("sample_interval_seconds"), "pressure.sample_interval_seconds")
    scenario_event = None
    if scenario != "management_stability":
        scenario_event = require_int(pressure.get("scenario_event_after_seconds"),
                                     "pressure.scenario_event_after_seconds")
        if scenario_event >= duration:
            raise HarnessError("scenario event time must be below pressure duration")
        if scenario_event <= interval:
            raise HarnessError("scenario event time must allow at least one pressure status sample")
    if interval >= duration:
        raise HarnessError("sample interval must be below pressure duration")
    if (duration + interval - 1) // interval > MAX_PRESSURE_SAMPLES:
        raise HarnessError(f"pressure plan exceeds the {MAX_PRESSURE_SAMPLES} sample harness limit")
    for key in ("cpu_workers", "memory_bytes", "memory_headroom_bytes", "io_workers",
                "io_file_bytes", "io_total_bytes", "io_bytes_per_second", "io_block_bytes"):
        require_int(pressure.get(key), f"pressure.{key}")
    if pressure["cpu_workers"] > MAX_CPU_WORKERS:
        raise HarnessError(f"pressure.cpu_workers must not exceed {MAX_CPU_WORKERS}")
    if pressure["io_workers"] > MAX_IO_WORKERS:
        raise HarnessError(f"pressure.io_workers must not exceed {MAX_IO_WORKERS}")
    if pressure["memory_bytes"] + pressure["memory_headroom_bytes"] > MAX_PRESSURE_MEMORY_BYTES:
        raise HarnessError(
            f"memory payload plus headroom must not exceed {MAX_PRESSURE_MEMORY_BYTES} bytes"
        )
    if pressure["memory_bytes"] + pressure["memory_headroom_bytes"] > qualification["allocatable_memory_bytes"]:
        raise HarnessError("memory payload plus headroom exceeds signed allocatable memory")
    if pressure["io_file_bytes"] > MAX_PRESSURE_IO_FILE_BYTES:
        raise HarnessError(f"pressure.io_file_bytes must not exceed {MAX_PRESSURE_IO_FILE_BYTES}")
    if pressure["io_file_bytes"] * pressure["io_workers"] > MAX_PRESSURE_IO_SCRATCH_BYTES:
        raise HarnessError(
            f"pressure I/O scratch allocation must not exceed {MAX_PRESSURE_IO_SCRATCH_BYTES} bytes"
        )
    if pressure["io_total_bytes"] > MAX_PRESSURE_IO_TOTAL_BYTES:
        raise HarnessError(f"pressure.io_total_bytes must not exceed {MAX_PRESSURE_IO_TOTAL_BYTES}")
    if pressure["io_bytes_per_second"] > MAX_PRESSURE_IO_BYTES_PER_SECOND:
        raise HarnessError(
            f"pressure.io_bytes_per_second must not exceed {MAX_PRESSURE_IO_BYTES_PER_SECOND}"
        )
    block = pressure["io_block_bytes"]
    if block & (block - 1):
        raise HarnessError("pressure.io_block_bytes must be a power of two")
    if pressure["io_file_bytes"] < block or pressure["io_total_bytes"] < block:
        raise HarnessError("pressure I/O bounds must be at least one I/O block")
    if pressure["io_total_bytes"] < pressure["io_bytes_per_second"] * duration:
        raise HarnessError("finite I/O byte budget must cover the configured rate for the full duration")
    if pressure["io_file_bytes"] % block:
        raise HarnessError("pressure.io_file_bytes must be a multiple of io_block_bytes")
    io_directory = require_text(pressure.get("io_directory"), "pressure.io_directory")
    if not Path(io_directory).is_absolute():
        raise HarnessError("pressure.io_directory must be an absolute managed-host scratch directory")
    workload_cgroup = require_object(pressure.get("workload_cgroup"), "pressure.workload_cgroup")
    cgroup_path = require_text(workload_cgroup.get("parent_path"), "pressure.workload_cgroup.parent_path")
    if not cgroup_path.startswith("/sys/fs/cgroup/") or ".." in Path(cgroup_path).parts:
        raise HarnessError("pressure workload_cgroup.parent_path must identify the existing native workload slice")
    cpu_max = require_text(workload_cgroup.get("cpu_max"), "pressure.workload_cgroup.cpu_max")
    cpu_fields = cpu_max.split()
    if (len(cpu_fields) != 2 or not all(field.isdecimal() for field in cpu_fields) or
            int(cpu_fields[0]) <= 0 or int(cpu_fields[1]) != 100000):
        raise HarnessError("pressure workload cgroup cpu_max must be '<quota> 100000' for systemd CPUQuota")
    require_int(workload_cgroup.get("memory_max_bytes"), "pressure.workload_cgroup.memory_max_bytes")
    require_int(workload_cgroup.get("io_weight"), "pressure.workload_cgroup.io_weight")
    io_device = require_text(workload_cgroup.get("io_device"), "pressure.workload_cgroup.io_device")
    if not re.fullmatch(r"\d+:\d+", io_device):
        raise HarnessError("pressure.workload_cgroup.io_device must be a block major:minor pair")
    if not dry_run and int(io_device.split(":", 1)[0]) == 0:
        raise HarnessError("live pressure I/O must target a block-backed filesystem, not a pseudo device")
    if pressure["memory_bytes"] + pressure["memory_headroom_bytes"] > workload_cgroup["memory_max_bytes"]:
        raise HarnessError("memory payload plus explicit headroom exceeds the pressure cgroup memory.max")

    if scenario == "terrabase_oom":
        fault = require_object(pressure.get("oom_fault"), "pressure.oom_fault")
        if set(fault) != {"target_memory_max_bytes", "deadline_seconds"}:
            raise HarnessError("pressure.oom_fault must pin exactly the temporary native-role cap and deadline")
        fault_limit = require_int(fault.get("target_memory_max_bytes"),
                                  "pressure.oom_fault.target_memory_max_bytes", page)
        if fault_limit % page:
            raise HarnessError("OOM target memory.max must be page aligned")
        if fault_limit >= qualification["database_memory_max_bytes"]:
            raise HarnessError("OOM target memory.max must be below the signed TerraBase role cap")
        timeout = require_int(fault.get("deadline_seconds"), "pressure.oom_fault.deadline_seconds")
        if timeout > 30:
            raise HarnessError("bounded OOM fault deadline must not exceed 30 seconds")
    elif "oom_fault" in pressure:
        raise HarnessError("oom_fault is supported only by the terrabase_oom scenario")

    validate_transport(manifest, missing)

    if not dry_run and missing:
        raise HarnessError("live qualification is unqualified: " + "; ".join(missing))
    return missing


def verify_pinned_file(path_value: object, digest_value: object, label: str,
                       missing: list[str]) -> None:
    if not isinstance(path_value, str) or not path_value:
        missing.append(f"{label} pinned source path is missing")
        return
    if not HASH_RE.fullmatch(str(digest_value or "")):
        missing.append(f"{label} pinned source SHA-256 is missing or malformed")
        return
    path = Path(path_value)
    if not path.is_absolute():
        missing.append(f"{label} pinned source path must be absolute")
        return
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise HarnessError(f"{label} pinned source is not a regular file: {path}")
        digest = hash_regular_file(path, MAX_PINNED_FILE_BYTES, label)
    except OSError:
        missing.append(f"{label} pinned source file is unavailable: {path}")
        return
    if digest != digest_value:
        missing.append(f"{label} SHA-256 differs from its pinned source file")


def hash_regular_file(path: Path, max_bytes: int, label: str) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HarnessError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise HarnessError(f"{label} is not a regular file")
    if metadata.st_size > max_bytes:
        raise HarnessError(f"{label} exceeds the {max_bytes}-byte pin limit")
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise HarnessError(f"{label} exceeds the {max_bytes}-byte pin limit")
                digest.update(chunk)
    except OSError as error:
        raise HarnessError(f"cannot read {label}: {error}") from error
    return digest.hexdigest()


def verify_adapter_executable(path_value: object, expected_hash: object) -> tuple[Path, str]:
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        raise HarnessError("executable path must be absolute")
    if not HASH_RE.fullmatch(str(expected_hash or "")):
        raise HarnessError("expected executable SHA-256 is missing or malformed")
    try:
        path = Path(path_value).resolve(strict=True)
    except OSError as error:
        raise HarnessError(f"executable is unavailable: {error}") from error
    digest = hash_regular_file(path, 1 << 30, "adapter executable")
    if not os.access(path, os.X_OK):
        raise HarnessError("adapter executable is not executable")
    if digest != expected_hash:
        raise HarnessError("executable SHA-256 differs from its expected pin")
    return path, digest


def open_pinned_executable(path: Path, expected_hash: str) -> tuple[int, str]:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > (1 << 30):
            raise HarnessError("adapter executable is not a bounded regular file")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > (1 << 30):
                raise HarnessError("adapter executable exceeds the 1073741824-byte pin limit")
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except (OSError, HarnessError) as error:
        if descriptor is not None:
            os.close(descriptor)
        if isinstance(error, HarnessError):
            raise
        raise HarnessError(f"cannot open pinned adapter executable: {error}") from error
    actual = digest.hexdigest()
    if actual != expected_hash:
        os.close(descriptor)
        raise HarnessError("executable SHA-256 differs from its expected pin")
    return descriptor, actual


def communicate_bounded(process: subprocess.Popen[bytes], input_bytes: bytes,
                        timeout_seconds: float,
                        output_limit: int = MAX_ADAPTER_OUTPUT_BYTES) -> tuple[bytes, bytes]:
    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    streams = (("stdout", process.stdout), ("stderr", process.stderr))
    try:
        for name, stream in streams:
            if stream is None:
                raise HarnessError(f"adapter {name} pipe is unavailable")
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (name, "read"))
        input_offset = 0
        input_stream = process.stdin
        if input_stream is None:
            raise HarnessError("adapter stdin pipe is unavailable")
        os.set_blocking(input_stream.fileno(), False)
        if input_bytes:
            selector.register(input_stream, selectors.EVENT_WRITE, ("stdin", "write"))
        else:
            input_stream.close()
            input_stream = None
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout_seconds,
                                                output=bytes(output["stdout"]),
                                                stderr=bytes(output["stderr"]))
            if not selector.get_map():
                time.sleep(min(remaining, 0.05))
                continue
            for key, _ in selector.select(min(remaining, 0.25)):
                stream = key.fileobj
                name, direction = key.data
                if direction == "write":
                    try:
                        written = os.write(stream.fileno(), input_bytes[input_offset:input_offset + 65536])
                    except BrokenPipeError:
                        selector.unregister(stream)
                        stream.close()
                        input_stream = None
                        continue
                    input_offset += written
                    if input_offset == len(input_bytes):
                        selector.unregister(stream)
                        stream.close()
                        input_stream = None
                    continue
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if sum(len(value) for value in output.values()) + len(chunk) > output_limit:
                    raise HarnessError(
                        f"adapter stdout/stderr exceeded the {output_limit}-byte output limit"
                    )
                output[name].extend(chunk)
        if input_stream is not None:
            input_stream.close()
        return bytes(output["stdout"]), bytes(output["stderr"])
    finally:
        selector.close()


def command_result_path(evidence_dir: Path, sequence: int, role: str, phase: str) -> Path:
    safe_role = re.sub(r"[^a-zA-Z0-9_-]", "_", role)
    safe_phase = re.sub(r"[^a-zA-Z0-9_-]", "_", phase)
    return evidence_dir / f"{sequence:04d}-{safe_phase}-{safe_role}"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_checksums(directory: Path) -> None:
    entries = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise HarnessError(f"refusing to checksum symlink evidence path {path}")
        if path.is_file() and path.name != "checksums.sha256":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append(f"{digest}  {path.relative_to(directory)}")
    (directory / "checksums.sha256").write_text("\n".join(entries) + "\n", encoding="ascii")


def read_process_cgroup(pid: int) -> Path:
    try:
        rows = (Path("/proc") / str(pid) / "cgroup").read_text().splitlines()
    except OSError as error:
        raise HarnessError(f"cannot read process cgroup for PID {pid}: {error}") from error
    matches = [row[3:] for row in rows if row.startswith("0::")]
    if len(matches) != 1 or not matches[0].startswith("/") or ".." in Path(matches[0]).parts:
        raise HarnessError(f"PID {pid} has no safe unified cgroup membership")
    return CGROUP_ROOT / matches[0].lstrip("/")


def read_process_start_time(pid: int) -> str:
    try:
        wire = (Path("/proc") / str(pid) / "stat").read_text()
        end = wire.rfind(")")
        fields = wire[end + 1:].split()
        start_time = int(fields[19])
    except (OSError, ValueError, IndexError) as error:
        raise HarnessError(f"cannot inspect process start time for PID {pid}: {error}") from error
    return str(start_time)


def proc_stat_identity(value: str) -> tuple[int, str]:
    try:
        pid_text, remainder = value.split(" ", 1)
        end = remainder.rfind(")")
        fields = remainder[end + 1:].split()
        return int(pid_text), str(int(fields[19]))
    except (ValueError, IndexError) as error:
        raise HarnessError("raw /proc/<pid>/stat record is malformed") from error


def proc_cgroup_path(value: str) -> Path:
    matches = [line[3:] for line in value.splitlines() if line.startswith("0::")]
    if len(matches) != 1 or not matches[0].startswith("/") or ".." in Path(matches[0]).parts:
        raise HarnessError("raw /proc/<pid>/cgroup record has no safe unified membership")
    return CGROUP_ROOT / matches[0].lstrip("/")


def _unescape_mountinfo(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _block_device_chain(device: str, sysfs_root: Path,
                        visiting: set[str] | None = None) -> tuple[list[dict[str, object]], list[str]]:
    visiting = set() if visiting is None else visiting
    if device in visiting:
        raise HarnessError(f"block-device backing graph contains a cycle at {device}")
    visiting.add(device)
    node_link = sysfs_root / "dev" / "block" / device
    try:
        node = node_link.resolve(strict=True)
        sysfs_devices = (sysfs_root / "devices").resolve(strict=True)
        if not _path_is_within(node, sysfs_devices):
            raise HarnessError(f"block device {device} does not resolve inside sysfs devices")
        if (node / "dev").read_text().strip() != device:
            raise HarnessError(f"block device {device} has a mismatched sysfs device number")
        size = (node / "size").read_text().strip()
        if not size.isdecimal() or int(size) <= 0:
            raise HarnessError(f"block device {device} has no positive sysfs size")
        if (node / "subsystem").resolve(strict=True).name != "block":
            raise HarnessError(f"device {device} is not exposed by the sysfs block subsystem")
    except OSError as error:
        raise HarnessError(f"cannot prove block-device backing for {device}: {error}") from error

    if (node / "loop").exists() or node.name.startswith(("loop", "ram", "zram")):
        raise HarnessError(f"pseudo block device {device} is not an eligible scratch backing")

    slaves_dir = node / "slaves"
    try:
        slaves = sorted(entry.name for entry in slaves_dir.iterdir()) if slaves_dir.is_dir() else []
    except OSError as error:
        raise HarnessError(f"cannot enumerate block-device backing for {device}: {error}") from error
    partition_parent: str | None = None
    if (node / "partition").is_file():
        parent_dev = node.parent / "dev"
        try:
            partition_parent = parent_dev.read_text().strip()
        except OSError as error:
            raise HarnessError(f"cannot read parent device for partition {device}: {error}") from error
        if not re.fullmatch(r"[1-9][0-9]*:[0-9]+", partition_parent):
            raise HarnessError(f"partition {device} has an invalid parent block-device number")
    chain = [{
        "device": device, "sysfs_path": str(node), "slaves": [],
        "partition_parent": partition_parent,
        "size_sectors": int(size),
        "subsystem": "block",
        "virtual": _path_is_within(node, (sysfs_root / "devices" / "virtual").resolve()),
        "pseudo": bool((node / "loop").exists() or node.name.startswith(("loop", "ram", "zram"))),
    }]
    leaves: list[str] = []
    if slaves:
        slave_devices: list[str] = []
        for slave in slaves:
            child_device_file = slaves_dir / slave / "dev"
            try:
                child_device = child_device_file.read_text().strip()
            except OSError as error:
                raise HarnessError(f"cannot read block slave {slave} for {device}: {error}") from error
            if not re.fullmatch(r"[1-9][0-9]*:[0-9]+", child_device):
                raise HarnessError(f"block slave {slave} has an invalid device number")
            slave_devices.append(child_device)
            child_chain, child_leaves = _block_device_chain(child_device, sysfs_root, visiting)
            chain.extend(child_chain)
            leaves.extend(child_leaves)
        chain[0]["slaves"] = sorted(slave_devices)
    elif partition_parent is not None:
        parent_chain, parent_leaves = _block_device_chain(partition_parent, sysfs_root, visiting)
        chain.extend(parent_chain)
        leaves.extend(parent_leaves)
    else:
        virtual_root = (sysfs_root / "devices" / "virtual" / "block").resolve()
        if _path_is_within(node, virtual_root):
            raise HarnessError(f"virtual block device {device} has no physical block backing")
        leaves.append(device)
    visiting.remove(device)
    return chain, leaves


def prove_block_backing(path_value: str | Path, *,
                        mountinfo_path: Path = Path("/proc/self/mountinfo"),
                        sysfs_root: Path = Path("/sys"),
                        device_override: int | None = None) -> dict[str, object]:
    target = Path(path_value).resolve(strict=True)
    try:
        device_number = os.stat(target).st_dev if device_override is None else device_override
        actual_device = f"{os.major(device_number)}:{os.minor(device_number)}"
        mountinfo = mountinfo_path.read_text(encoding="utf-8")
    except OSError as error:
        raise HarnessError(f"cannot identify scratch filesystem mount: {error}") from error

    candidates: list[tuple[int, dict[str, object]]] = []
    for line_number, line in enumerate(mountinfo.splitlines(), 1):
        before, separator, after = line.partition(" - ")
        left = before.split()
        right = after.split()
        if not separator or len(left) < 6 or len(right) < 3:
            raise HarnessError(f"/proc/self/mountinfo line {line_number} is malformed")
        mount_device = left[2]
        mountpoint = Path(_unescape_mountinfo(left[4]))
        if mount_device != actual_device or not _path_is_within(target, mountpoint):
            continue
        candidates.append((len(mountpoint.parts), {
            "mount_id": left[0], "mountpoint": str(mountpoint),
            "filesystem_type": right[0], "filesystem_source": _unescape_mountinfo(right[1]),
            "filesystem_device": mount_device,
        }))
    if not candidates:
        raise HarnessError(
            f"scratch path {target} has no mountinfo entry matching filesystem device {actual_device}"
        )
    mount = max(candidates, key=lambda item: item[0])[1]
    if actual_device.startswith("0:"):
        raise HarnessError("scratch filesystem is not directly backed by a block device")
    chain, leaves = _block_device_chain(actual_device, sysfs_root)
    if not leaves:
        raise HarnessError("scratch filesystem has no physical block-device backing")
    return {
        **mount,
        "block_device_chain": chain,
        "block_leaf_devices": sorted(set(leaves)),
    }


def parse_journal_record(raw_record: str, *, expected_transport: str) -> dict[str, Any]:
    if len(raw_record.encode("utf-8")) > 65536:
        raise HarnessError("raw journal record exceeds the 65536-byte limit")
    try:
        record = json.loads(raw_record, object_pairs_hook=unique_json_object)
    except json.JSONDecodeError as error:
        raise HarnessError(f"raw journal record is not valid JSON: {error}") from error
    if type(record) is not dict:
        raise HarnessError("raw journal record must be a JSON object")
    required = {"__REALTIME_TIMESTAMP", "_BOOT_ID", "_CURSOR", "_TRANSPORT", "MESSAGE"}
    if not required.issubset(record):
        raise HarnessError("raw journal record omits timestamp, boot ID, cursor, transport, or message")
    timestamp = record["__REALTIME_TIMESTAMP"]
    boot_id = record["_BOOT_ID"]
    cursor = record["_CURSOR"]
    message = record["MESSAGE"]
    if (not isinstance(timestamp, str) or not timestamp.isdecimal() or
            not re.fullmatch(r"[0-9a-f]{32}", str(boot_id)) or
            not isinstance(cursor, str) or not cursor or len(cursor) > 4096 or
            record["_TRANSPORT"] != expected_transport or
            not isinstance(message, str) or not message or len(message.encode("utf-8")) > 32768):
        raise HarnessError("raw journal record has an invalid timestamp/source/boot/cursor/message field")
    try:
        event_time = dt.datetime.fromtimestamp(int(timestamp) / 1_000_000, dt.timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise HarnessError("raw journal timestamp is outside the supported UTC range") from error
    return {
        "record": record,
        "boot_id": boot_id,
        "cursor": cursor,
        "message": message,
        "event_at_utc": event_time.isoformat(timespec="microseconds").replace("+00:00", "Z"),
    }


def parse_kernel_oom_record(raw_record: str) -> dict[str, object]:
    parsed = parse_journal_record(raw_record, expected_transport="kernel")
    message = parsed["message"]
    fields: dict[str, str] = {}
    for field in message.split(","):
        key, separator, value = field.partition("=")
        if not separator:
            continue
        if key in {"pid", "task_memcg"}:
            if key in fields:
                raise HarnessError("kernel OOM journal record repeats the exact pid/cgroup field")
            fields[key] = value
    if (not fields.get("pid", "").isdecimal() or
            not fields.get("task_memcg", "").startswith("/")):
        raise HarnessError("kernel OOM journal record lacks one exact pid and task_memcg binding")
    raw_cgroup = fields["task_memcg"]
    if not raw_cgroup.startswith("/") or ".." in Path(raw_cgroup).parts:
        raise HarnessError("kernel OOM journal record has an unsafe task_memcg path")
    return {
        "victim_pid": int(fields["pid"]),
        "cgroup_path": str(CGROUP_ROOT / raw_cgroup.lstrip("/")),
        "event_at_utc": parsed["event_at_utc"],
        "boot_id": parsed["boot_id"],
        "journal_cursor": parsed["cursor"],
    }


def validate_block_backing_evidence(value: object, expected_device: str) -> dict[str, Any]:
    evidence = require_object(value, "pressure_cgroup.io_backing")
    if evidence.get("filesystem_device") != expected_device:
        raise HarnessError("scratch mount device differs from the pinned pressure I/O device")
    if not isinstance(evidence.get("mountpoint"), str) or not evidence["mountpoint"].startswith("/"):
        raise HarnessError("scratch mount evidence has no absolute mountpoint")
    if not isinstance(evidence.get("filesystem_type"), str) or not evidence["filesystem_type"]:
        raise HarnessError("scratch mount evidence omits its filesystem type")
    chain = evidence.get("block_device_chain")
    leaves = evidence.get("block_leaf_devices")
    if type(chain) is not list or not chain or type(leaves) is not list or not leaves:
        raise HarnessError("scratch mount evidence has no sysfs block-device backing chain")
    by_device: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(chain):
        node = require_object(item, f"pressure_cgroup.io_backing.block_device_chain[{index}]")
        device = node.get("device")
        sysfs_path = node.get("sysfs_path")
        slaves = node.get("slaves")
        parent = node.get("partition_parent")
        if (not isinstance(device, str) or not re.fullmatch(r"[1-9][0-9]*:[0-9]+", device) or
                not isinstance(sysfs_path, str) or not sysfs_path.startswith("/sys/devices/") or
                type(slaves) is not list or any(not isinstance(slave, str) for slave in slaves) or
                node.get("subsystem") != "block" or type(node.get("virtual")) is not bool or
                node.get("pseudo") is not False or type(node.get("size_sectors")) is not int or
                node["size_sectors"] <= 0 or (parent is not None and not isinstance(parent, str))):
            raise HarnessError(f"scratch sysfs block-device node {index} is malformed or ineligible")
        if device in by_device:
            raise HarnessError("scratch sysfs block-device chain repeats a device")
        by_device[device] = node
    if expected_device not in by_device:
        raise HarnessError("scratch filesystem device is absent from its sysfs backing chain")
    graph_leaves: set[str] = set()
    for device, node in by_device.items():
        children = list(node["slaves"])
        if node["partition_parent"] is not None:
            children.append(node["partition_parent"])
        if any(child not in by_device for child in children):
            raise HarnessError("scratch sysfs backing chain omits a mapper or partition parent")
        if not children:
            if node["virtual"] or "/virtual/" in node["sysfs_path"]:
                raise HarnessError("scratch sysfs backing chain ends in a virtual block device")
            graph_leaves.add(device)
    if not graph_leaves or sorted(graph_leaves) != sorted(set(leaves)):
        raise HarnessError("scratch block leaves do not match the retained sysfs backing graph")
    return evidence


def parse_systemd_show(value: str, label: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in value.splitlines():
        key, separator, field_value = line.partition("=")
        if not separator or key in fields:
            raise HarnessError(f"{label} raw systemd properties are malformed or duplicated")
        fields[key] = field_value
    required = {"ActiveState", "MainPID", "NRestarts", "ControlGroup"}
    if not required.issubset(fields):
        raise HarnessError(f"{label} raw systemd properties omit required fields")
    return fields


def cgroup_io_weight(path: Path, device: str) -> int:
    try:
        lines = (path / "io.weight").read_text().splitlines()
    except OSError as error:
        raise HarnessError(f"cannot read workload cgroup I/O weight: {error}") from error
    weights: dict[str, int] = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 2 and fields[1].isdecimal():
            weights[fields[0]] = int(fields[1])
    if device in weights:
        return weights[device]
    if "default" in weights:
        return weights["default"]
    raise HarnessError(f"{path}/io.weight lacks a default weight")


def assert_exclusive_cgroup(cgroup_path: Path, expected_pids: set[int]) -> list[int]:
    if any(type(pid) is not int or pid <= 1 for pid in expected_pids):
        raise HarnessError("expected pressure cgroup PIDs must be valid process IDs")
    try:
        raw_pids = (cgroup_path / "cgroup.procs").read_text().splitlines()
        entries = list(cgroup_path.iterdir())
        symlinks = [entry.name for entry in entries if entry.is_symlink()]
        child_groups = [entry.name for entry in entries if entry.is_dir()]
    except OSError as error:
        raise HarnessError(f"cannot enumerate pressure cgroup {cgroup_path}: {error}") from error
    if symlinks:
        raise HarnessError(f"pressure cgroup contains unexpected symlinks {sorted(symlinks)}")
    try:
        observed = [int(value) for value in raw_pids]
    except ValueError as error:
        raise HarnessError(f"{cgroup_path}/cgroup.procs contains a malformed PID") from error
    if any(pid <= 1 for pid in observed) or len(set(observed)) != len(observed):
        raise HarnessError(f"{cgroup_path}/cgroup.procs contains invalid or duplicate PIDs")
    if child_groups:
        raise HarnessError(
            f"pressure cgroup must be a leaf; found child cgroups {sorted(child_groups)}"
        )
    if set(observed) != expected_pids:
        raise HarnessError(
            f"pressure cgroup process set {sorted(observed)} differs from owned PIDs {sorted(expected_pids)}"
        )
    return sorted(observed)


def pressure_cgroup_inventory(cgroup_path: Path, expected_pids: set[int],
                              process_roles: dict[int, str] | None = None) -> dict[str, object]:
    pids = assert_exclusive_cgroup(cgroup_path, expected_pids)
    try:
        raw = (cgroup_path / "cgroup.procs").read_text()
        reread = [int(value) for value in raw.splitlines()]
    except (OSError, ValueError) as error:
        raise HarnessError(f"cannot retain pressure cgroup process inventory: {error}") from error
    if sorted(reread) != pids:
        raise HarnessError("pressure cgroup membership changed while inventory was captured")
    roles = process_roles or {}
    processes = []
    for pid in pids:
        try:
            stat_raw = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
            cgroup_raw = (Path("/proc") / str(pid) / "cgroup").read_text(encoding="utf-8")
        except OSError as error:
            raise HarnessError(f"cannot retain raw process identity for pressure PID {pid}: {error}") from error
        raw_pid, start_time = proc_stat_identity(stat_raw)
        if raw_pid != pid:
            raise HarnessError(f"raw /proc stat PID differs from pressure membership PID {pid}")
        processes.append({
            "pid": pid, "process_start_time": start_time,
            "role": roles.get(pid, "pressure_runner" if pid == os.getpid() else "unknown"),
            "process_stat_raw": stat_raw,
            "process_cgroup_raw": cgroup_raw,
        })
    disposable_pids = sorted(pid for pid, role in roles.items() if pid in pids and
                             role in {"cpu_worker", "memory_worker", "io_worker"})
    canonical = json.dumps(processes, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {
        "process_pids": pids,
        "processes": processes,
        "worker_process_pids": disposable_pids,
        "cgroup_procs_raw": raw,
        "process_inventory_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def assert_pressure_cgroup(config: dict[str, Any], native_runner_path: Path,
                           database_path: Path) -> dict[str, object]:
    expected = config["workload_cgroup"]
    actual = read_process_cgroup(os.getpid())
    expected_path = Path(expected["path"]).resolve(strict=True)
    if actual.resolve(strict=True) != expected_path:
        raise HarnessError(f"pressure worker is in {actual}, expected {expected_path}")
    runner_path = native_runner_path.resolve(strict=True)
    database_cgroup = database_path.resolve(strict=True)
    if actual.resolve(strict=True) == database_cgroup or actual.resolve(strict=True) in database_cgroup.parents:
        raise HarnessError("pressure scope cannot share or contain TerraBase's native role cgroup")
    if runner_path in actual.resolve(strict=True).parents:
        raise HarnessError("pressure scope must remain outside the manually owned native role tree")
    parent_path = Path(expected["parent_path"]).resolve(strict=True)
    if actual.resolve(strict=True).parent != parent_path:
        raise HarnessError("pressure worker must run directly under its pinned systemd workload slice")
    cpu_max = (actual / "cpu.max").read_text().strip()
    memory_max = (actual / "memory.max").read_text().strip()
    io_backing = prove_block_backing(config["io_directory"])
    io_device = str(io_backing["filesystem_device"])
    if io_device != expected["io_device"]:
        raise HarnessError(f"pressure filesystem device is {io_device}, expected {expected['io_device']}")
    io_weight = cgroup_io_weight(actual, io_device)
    if cpu_max != expected["cpu_max"]:
        raise HarnessError(f"pressure cgroup cpu.max={cpu_max!r}, expected {expected['cpu_max']!r}")
    if memory_max != str(expected["memory_max_bytes"]):
        raise HarnessError(f"pressure cgroup memory.max={memory_max!r}, expected {expected['memory_max_bytes']!r}")
    if io_weight != expected["io_weight"]:
        raise HarnessError(f"pressure cgroup default io.weight={io_weight}, expected {expected['io_weight']}")
    if os.path.commonpath((str(CGROUP_ROOT.resolve()), str(expected_path))) != str(CGROUP_ROOT.resolve()):
        raise HarnessError("pressure cgroup is outside the unified cgroup root")
    inventory = pressure_cgroup_inventory(expected_path, {os.getpid()})
    return {"path": str(actual), "cpu_max": cpu_max, "memory_max_bytes": int(memory_max),
            "io_weight": io_weight, "io_device": io_device, "io_backing": io_backing,
            "pid": os.getpid(), **inventory}


def validate_stress_worker_manifest(manifest: dict[str, Any]) -> None:
    """Recheck the resource-only contract on the target without operator paths."""
    if manifest.get("schema") != SCHEMA:
        raise HarnessError(f"stress manifest schema must be {SCHEMA!r}")
    pressure = require_object(manifest.get("pressure"), "stress pressure")
    for key in ("duration_seconds", "sample_interval_seconds", "cpu_workers", "memory_bytes",
                "memory_headroom_bytes", "io_workers", "io_file_bytes", "io_total_bytes",
                "io_bytes_per_second", "io_block_bytes"):
        require_int(pressure.get(key), f"stress pressure.{key}")
    duration = pressure["duration_seconds"]
    if duration > MAX_PRESSURE_SECONDS:
        raise HarnessError("stress duration exceeds its harness bound")
    if (pressure["cpu_workers"] > MAX_CPU_WORKERS or pressure["io_workers"] > MAX_IO_WORKERS or
            pressure["memory_bytes"] + pressure["memory_headroom_bytes"] > MAX_PRESSURE_MEMORY_BYTES):
        raise HarnessError("stress worker count or memory request exceeds its harness bound")
    io_file = pressure["io_file_bytes"]
    io_total = pressure["io_total_bytes"]
    io_rate = pressure["io_bytes_per_second"]
    block = pressure["io_block_bytes"]
    if (io_file > MAX_PRESSURE_IO_FILE_BYTES or io_file * pressure["io_workers"] > MAX_PRESSURE_IO_SCRATCH_BYTES or
            io_total > MAX_PRESSURE_IO_TOTAL_BYTES or io_rate > MAX_PRESSURE_IO_BYTES_PER_SECOND or
            io_total < io_rate * duration or block & (block - 1) or io_file % block):
        raise HarnessError("stress I/O request exceeds its finite worker bounds")
    workload = require_object(pressure.get("workload_cgroup"), "stress pressure.workload_cgroup")
    if set(workload) != {"parent_path", "path", "cpu_max", "memory_max_bytes", "io_weight", "io_device"}:
        raise HarnessError("stress workload cgroup fields do not match the transient-scope contract")
    for key in ("parent_path", "path"):
        value = require_text(workload.get(key), f"stress workload cgroup {key}")
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts or path == CGROUP_ROOT:
            raise HarnessError(f"stress workload cgroup {key} is not a safe cgroup path")
    cpu_fields = require_text(workload.get("cpu_max"), "stress workload cpu_max").split()
    if (len(cpu_fields) != 2 or not all(field.isdecimal() for field in cpu_fields) or
            int(cpu_fields[0]) <= 0 or int(cpu_fields[1]) != 100000):
        raise HarnessError("stress workload cpu_max must have an explicit finite 100000 period")
    memory_max = require_int(workload.get("memory_max_bytes"), "stress workload memory_max_bytes")
    require_int(workload.get("io_weight"), "stress workload io_weight")
    io_device = require_text(workload.get("io_device"), "stress workload io_device")
    if not re.fullmatch(r"\d+:\d+", io_device) or int(io_device.split(":", 1)[0]) == 0:
        raise HarnessError("stress workload I/O device must be a block device")
    if pressure["memory_bytes"] + pressure["memory_headroom_bytes"] > memory_max:
        raise HarnessError("stress memory request exceeds its transient-scope memory.max")
    io_directory = Path(require_text(pressure.get("io_directory"), "stress io_directory"))
    if not io_directory.is_absolute():
        raise HarnessError("stress io_directory must be an absolute path")


def _burn_cpu(stop: Event) -> None:
    value = 0
    while not stop.is_set():
        value = (value * 33 + 7) & 0xFFFFFFFF


def _hold_memory(memory_bytes: int, stop: Event) -> None:
    memory_map = mmap.mmap(-1, memory_bytes)
    try:
        for offset in range(0, memory_bytes, mmap.PAGESIZE):
            memory_map[offset:offset + 1] = b"\x01"
        while not stop.is_set():
            stop.wait(0.1)
    finally:
        memory_map.close()


def _io_worker(directory: str, file_bytes: int, total_bytes: int, block_bytes: int,
               bytes_per_second: float, duration_seconds: int,
               stop: Event, counts: Queue, worker_id: int) -> None:
    path = Path(directory) / f"io-{worker_id}.bin"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_EXCL, 0o600)
    written = 0
    offset = 0
    payload = bytes(block_bytes)
    deadline = time.monotonic() + duration_seconds
    try:
        os.ftruncate(fd, file_bytes)
        while not stop.is_set() and time.monotonic() < deadline:
            if written >= total_bytes:
                stop.wait(min(0.1, max(0.0, deadline - time.monotonic())))
                continue
            amount = min(block_bytes, total_bytes - written)
            view = payload if amount == block_bytes else payload[:amount]
            count = os.pwrite(fd, view, offset)
            if count != amount:
                raise OSError(f"short pwrite: {count} of {amount} bytes")
            os.fdatasync(fd)
            written += count
            offset = (offset + count) % file_bytes
            next_write = deadline - duration_seconds + written / bytes_per_second
            while not stop.is_set() and time.monotonic() < next_write:
                stop.wait(min(0.1, next_write - time.monotonic()))
        while not stop.is_set():
            stop.wait(0.1)
    finally:
        os.close(fd)
        counts.put({"worker": worker_id, "bytes_written": written})


def write_pressure_worker_state(path: Path, state: dict[str, object]) -> tuple[str, str]:
    wire = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(wire) > MAX_PRESSURE_WORKER_STATE_BYTES:
        raise HarnessError("pressure worker status record exceeds its fixed evidence bound")
    temporary = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(wire):
            offset += os.write(descriptor, wire[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    return wire.decode("utf-8"), hashlib.sha256(wire).hexdigest()


def run_stress_worker(config: dict[str, Any], native_runner_path: Path,
                      database_path: Path, run_id: str, *, retain_evidence: bool = False) -> int:
    pressure = config["pressure"]
    if not re.fullmatch(r"[0-9a-f-]{36}", run_id):
        raise HarnessError("stress worker requires the current qualification run ID")
    cgroup_evidence = assert_pressure_cgroup(pressure, native_runner_path, database_path)
    target = Path(pressure["io_directory"])
    if not target.is_absolute() or not target.is_dir() or target.is_symlink():
        raise HarnessError("pressure.io_directory must be an existing, non-symlink directory")
    target = target.resolve(strict=True)
    stats = os.statvfs(target)
    available = stats.f_bavail * stats.f_frsize
    if pressure["io_file_bytes"] * pressure["io_workers"] > available:
        raise HarnessError("pressure I/O working files exceed free bytes on the selected filesystem")
    if not os.access(target, os.W_OK | os.X_OK):
        raise HarnessError("pressure.io_directory is not writable by the workload identity")
    if pressure["memory_bytes"] + pressure["memory_headroom_bytes"] > pressure["workload_cgroup"]["memory_max_bytes"]:
        raise HarnessError("memory request exceeds its explicit cgroup cap and headroom")

    work_dir = target / f"terrascale-d15-{run_id}"
    try:
        work_dir.mkdir(mode=0o700)
    except FileExistsError as error:
        raise HarnessError("run-scoped pressure scratch path already exists") from error
    context = get_context("fork")
    stop = context.Event()
    counts: Queue = context.Queue()
    workers: list[Process] = []
    worker_roles: dict[int, str] = {os.getpid(): "pressure_runner"}
    started = utc_now()
    start_monotonic = time.monotonic()
    start_monotonic_ns = time.monotonic_ns()
    status_path = work_dir / "runner-status.json"
    cleanup_failures: list[int] = []
    completed = False
    try:
        if pressure["memory_bytes"]:
            worker = context.Process(
                target=_hold_memory, args=(pressure["memory_bytes"], stop),
            )
            worker.start()
            workers.append(worker)
            worker_roles[worker.pid or 0] = "memory_worker"
        cpu_workers: list[Process] = []
        for _ in range(pressure["cpu_workers"]):
            worker = context.Process(target=_burn_cpu, args=(stop,))
            worker.start()
            workers.append(worker)
            cpu_workers.append(worker)
            worker_roles[worker.pid or 0] = "cpu_worker"
        total_io = pressure["io_total_bytes"]
        per_worker = [total_io // pressure["io_workers"]] * pressure["io_workers"]
        per_worker_rate = pressure["io_bytes_per_second"] / pressure["io_workers"]
        for index in range(total_io % pressure["io_workers"]):
            per_worker[index] += 1
        for index, byte_budget in enumerate(per_worker):
            if byte_budget == 0:
                continue
            worker = context.Process(
                target=_io_worker,
                args=(str(work_dir), pressure["io_file_bytes"], byte_budget,
                      pressure["io_block_bytes"], per_worker_rate,
                      pressure["duration_seconds"], stop, counts, index),
            )
            worker.start()
            workers.append(worker)
            worker_roles[worker.pid or 0] = "io_worker"
        expected_cgroup = str(Path(cgroup_evidence["path"]))
        expected_pids = {os.getpid()}
        for worker in workers:
            observed = read_process_cgroup(worker.pid)
            if str(observed.resolve(strict=True)) != expected_cgroup:
                raise HarnessError(f"pressure child PID {worker.pid} escaped cgroup {expected_cgroup}: {observed}")
            expected_pids.add(worker.pid)
        assert_exclusive_cgroup(Path(expected_cgroup), expected_pids)
        startup_inventory = pressure_cgroup_inventory(
            Path(expected_cgroup), expected_pids, worker_roles,
        )
        cgroup_evidence.update({
            "scratch_directory": str(work_dir),
            "status_file_path": str(status_path),
        })
        worker_role_rows = [
            {"pid": pid, "role": worker_roles[pid]}
            for pid in sorted(worker_roles) if pid != os.getpid()
        ]
        state: dict[str, object] = {
            "schema": PRESSURE_WORKER_STATE_SCHEMA,
            "run_id": run_id,
            "status": "RUNNING",
            "started_at_utc": started,
            "started_monotonic_ns": start_monotonic_ns,
            "observed_at_utc": utc_now(),
            "elapsed_monotonic_ns": time.monotonic_ns() - start_monotonic_ns,
            "worker_pids": sorted(worker.pid for worker in workers if worker.pid),
            "worker_roles": worker_role_rows,
            "active_worker_pids": sorted(worker.pid for worker in workers if worker.pid),
            "finished_at_utc": None,
            "finished_monotonic_ns": None,
        }
        state_record, state_sha256 = write_pressure_worker_state(status_path, state)
        startup_inventory = {
            **cgroup_evidence, **startup_inventory,
            "worker_state_record": state_record,
            "worker_state_sha256": state_sha256,
        }
        print(json.dumps({
            "status": "STARTED", "harness_sha256": hashlib.sha256(
                Path(__file__).resolve().read_bytes()).hexdigest(),
            "pressure_cgroup": startup_inventory,
        }, sort_keys=True), flush=True)
        deadline = start_monotonic + pressure["duration_seconds"]
        while time.monotonic() < deadline:
            now = time.monotonic()
            active_pids = {os.getpid()}
            for worker in workers:
                if worker.exitcode is None:
                    active_pids.add(worker.pid or 0)
                    continue
                worker.join(timeout=0)
                raise HarnessError(f"pressure worker PID {worker.pid} exited before the configured duration")
            assert_exclusive_cgroup(Path(expected_cgroup), active_pids)
            state = {
                "schema": PRESSURE_WORKER_STATE_SCHEMA,
                "run_id": run_id,
                "status": "RUNNING",
                "started_at_utc": started,
                "started_monotonic_ns": start_monotonic_ns,
                "observed_at_utc": utc_now(),
                "elapsed_monotonic_ns": time.monotonic_ns() - start_monotonic_ns,
                "worker_pids": sorted(pid for pid in active_pids if pid != os.getpid()),
                "worker_roles": worker_role_rows,
                "active_worker_pids": sorted(pid for pid in active_pids if pid != os.getpid()),
                "finished_at_utc": None,
                "finished_monotonic_ns": None,
            }
            state_record, state_sha256 = write_pressure_worker_state(status_path, state)
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        now = time.monotonic()
        stop.set()
        for worker in workers:
            worker.join(timeout=5)
            if worker.is_alive() or worker.exitcode != 0:
                raise HarnessError(f"pressure child PID {worker.pid} did not finish within the configured duration")
        cgroup_evidence.update(pressure_cgroup_inventory(Path(expected_cgroup), {os.getpid()}))
        cgroup_evidence["owned_worker_pids"] = sorted(
            worker.pid for worker in workers if worker.pid is not None
        )
        expected_io_workers = sum(budget > 0 for budget in per_worker)
        written = 0
        for _ in range(expected_io_workers):
            try:
                written += int(counts.get(timeout=2)["bytes_written"])
            except queue.Empty as error:
                raise HarnessError("an I/O worker did not report its bounded byte count") from error
        elapsed = time.monotonic() - start_monotonic
        if elapsed < pressure["duration_seconds"]:
            raise HarnessError("pressure worker elapsed time is shorter than the configured duration")
        finished = utc_now()
        finished_monotonic_ns = time.monotonic_ns()
        state = {
            "schema": PRESSURE_WORKER_STATE_SCHEMA,
            "run_id": run_id,
            "status": "COMPLETED",
            "started_at_utc": started,
            "started_monotonic_ns": start_monotonic_ns,
            "observed_at_utc": finished,
            "elapsed_monotonic_ns": finished_monotonic_ns - start_monotonic_ns,
            "worker_pids": [],
            "worker_roles": worker_role_rows,
            "active_worker_pids": [],
            "finished_at_utc": finished,
            "finished_monotonic_ns": finished_monotonic_ns,
        }
        state_record, state_sha256 = write_pressure_worker_state(status_path, state)
        completed = True
        cgroup_evidence.update({
            "scratch_directory": str(work_dir),
            "status_file_path": str(status_path),
            "worker_state_record": state_record,
            "worker_state_sha256": state_sha256,
        })
        print(json.dumps({
            "status": "PASS", "started_at_utc": started, "finished_at_utc": finished,
            "harness_sha256": hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest(),
            "elapsed_seconds": round(elapsed, 3), "pressure_cgroup": cgroup_evidence,
            "pressure_worker_state_record": state_record,
            "pressure_worker_state_sha256": state_sha256,
            "cpu_workers": pressure["cpu_workers"],
            "memory_payload_bytes": pressure["memory_bytes"],
            "io_bytes_written": written, "io_total_bytes_limit": pressure["io_total_bytes"],
            "io_bytes_per_second_limit": pressure["io_bytes_per_second"],
            "io_file_bytes_per_worker": pressure["io_file_bytes"],
        }, sort_keys=True))
        return 0
    finally:
        stop.set()
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
            worker.join(timeout=5)
            if worker.is_alive():
                worker.kill()
                worker.join(timeout=5)
            if worker.is_alive():
                cleanup_failures.append(worker.pid or 0)
        if cleanup_failures:
            raise HarnessError(
                f"pressure children could not be killed; scratch retained at {work_dir}: {cleanup_failures}"
            )
        if retain_evidence and completed and not cleanup_failures:
            for path in work_dir.iterdir():
                if path != status_path and path.is_file():
                    path.unlink()
        else:
            shutil.rmtree(work_dir, ignore_errors=False)


def run_qualification(manifest: dict[str, Any], manifest_wire: bytes,
                      manifest_hash: str, evidence_dir: Path) -> int:
    """Execute qualification using source-backed alpha evidence validators."""
    from alpha_runner import run_qualification as run_alpha_qualification

    return run_alpha_qualification(manifest, manifest_wire, manifest_hash, evidence_dir)


def dry_run(manifest: dict[str, Any], manifest_hash: str) -> int:
    missing = validate_manifest(manifest, dry_run=True)
    identity = manifest["identity"]
    authorization = manifest["authorization"]
    contract = manifest["adapter_contract"]
    adapter = manifest.get("adapter", {})
    reasons = list(missing)
    if authorization.get("live_stress_authorized") is not True:
        if "OCI owner has not explicitly authorized live pressure" not in reasons:
            reasons.append("OCI owner has not explicitly authorized live pressure")
    if contract.get("frozen") is not True and "alpha host, database, target, and recovery adapter contract is not frozen" not in reasons:
        reasons.append("alpha host, database, target, and recovery adapter contract is not frozen")
    plan = {
        "schema": SCHEMA,
        "mode": "DRY_RUN_ONLY",
        "qualification_status": "UNQUALIFIED",
        "commands_executed": False,
        "pressure_started": False,
        "manifest_sha256": manifest_hash,
        "identity": identity,
        "controller_identity": manifest["controller_identity"],
        "controller_memory_floor_evidence": manifest["controller_memory_floor_evidence"],
        "adapter_source": {
            "python_path": adapter.get("python_path"),
            "python_sha256": adapter.get("python_sha256"),
            "source_path": adapter.get("source_path"),
            "source_sha256": adapter.get("source_sha256"),
        },
        "planned_adapter_roles": sorted(adapter.get("deadlines_seconds", {})),
        "missing_or_unqualified": sorted(set(reasons)),
        "required_adapter_roles": sorted(
            set(BASE_ADAPTERS)
            | ({"failure_inject"} if manifest["pressure"]["scenario"] in INJECTED_FAILURE_ADAPTERS else set())
            | ({"kernel_oom_evidence"} if manifest["pressure"]["scenario"] == "terrabase_oom" else set())
        ),
        "resource_plan": manifest["pressure"],
    }
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for mode in ("dry-run", "run"):
        command = modes.add_parser(mode, help="validate or execute a pinned D15 run manifest")
        command.add_argument("--manifest", required=True, type=Path)
        if mode == "run":
            command.add_argument("--evidence-dir", required=True, type=Path)
    worker = modes.add_parser("stress-worker", help="run bounded load inside an already-assigned cgroup")
    worker.add_argument("--manifest", required=True, type=Path)
    worker.add_argument("--expected-native-runner-cgroup", required=True, type=Path)
    worker.add_argument("--protected-database-cgroup", required=True, type=Path)
    worker.add_argument("--assigned-pressure-cgroup", required=True, type=Path)
    worker.add_argument("--run-id", required=True)
    worker.add_argument("--retain-evidence", action="store_true")
    args = parser.parse_args()
    return args


def main() -> int:
    args = parse_args()
    try:
        manifest, wire = load_json(args.manifest)
        manifest_hash = hashlib.sha256(wire).hexdigest()
        if args.mode == "dry-run":
            return dry_run(manifest, manifest_hash)
        if args.mode == "run":
            return run_qualification(manifest, wire, manifest_hash, args.evidence_dir)
        validate_stress_worker_manifest(manifest)
        manifest = json.loads(json.dumps(manifest))
        manifest["pressure"]["workload_cgroup"]["path"] = str(args.assigned_pressure_cgroup)
        return run_stress_worker(manifest, args.expected_native_runner_cgroup,
                                 args.protected_database_cgroup, args.run_id,
                                 retain_evidence=args.retain_evidence)
    except (HarnessError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"runtime pressure qualification failed closed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
