"""Alpha D15 adapter runner and source-backed evidence checks.

The wire validators below consume the Go operator's real HostStatus JSON and
TerraBase's real ObjectDurable transaction/point response JSON. Adapter
commands provide transport only; they cannot replace those records with
synthetic status, heartbeat, or sequence fields.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import signal
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import pressure
from pressure import (
    ADAPTER_INPUT_SCHEMA,
    ADAPTER_RESULT_SCHEMA,
    CGROUP_ROOT,
    HASH_RE,
    MAX_ADAPTER_OBSERVATION_BYTES,
    MAX_ADAPTER_OUTPUT_BYTES,
    MAX_RUN_ADAPTER_BYTES,
    MAX_FINAL_ADAPTER_RESERVE_BYTES,
    MAX_OOM_EVENTS,
    MAX_PRESSURE_WORKER_STATE_BYTES,
    OOM_JOURNAL_FORMAT,
    PRESSURE_WORKER_STATE_SCHEMA,
    HarnessError,
    communicate_bounded,
    command_result_path,
    load_json,
    open_pinned_executable,
    parse_kernel_oom_record,
    parse_timestamp,
    pressure_cgroup_inventory,
    proc_cgroup_path,
    proc_stat_identity,
    require_int,
    require_object,
    require_text,
    unique_json_object,
    utc_now,
    verify_adapter_executable,
    validate_block_backing_evidence,
    write_checksums,
    write_json,
)


SOURCE_UNIT = "terrascale-orchestrator-host.service"
CONTROLLER_UNIT = "terrascale-orchestrator-controller.service"
SERVICE_PROPERTIES = ("ActiveState", "MainPID", "ControlGroup", "NRestarts")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
OCI_REGION_NAMES = {
    "GRU": "sa-saopaulo-1",
    "SFO": "us-sanjose-1",
    "FRA": "eu-frankfurt-1",
}


def _verify_wire_hash(raw: str, digest: object, field: str, maximum: int) -> None:
    if len(raw.encode("utf-8")) > maximum:
        raise HarnessError(f"{field} exceeds its {maximum}-byte evidence bound")
    if not HASH_RE.fullmatch(str(digest or "")) or hashlib.sha256(raw.encode("utf-8")).hexdigest() != digest:
        raise HarnessError(f"{field} hash is absent or does not match its retained bytes")


def _parse_raw_json(raw: str, field: str, maximum: int) -> Any:
    if len(raw.encode("utf-8")) > maximum:
        raise HarnessError(f"{field} exceeds its {maximum}-byte evidence bound")
    try:
        return json.loads(raw, object_pairs_hook=unique_json_object)
    except json.JSONDecodeError as error:
        raise HarnessError(f"{field} is invalid JSON: {error}") from error


def _scope_to_report(scope: dict[str, Any]) -> dict[str, Any]:
    return dict(scope)


def _cgroup_file_path(report_path: str) -> Path:
    if not report_path.startswith("/") or ".." in Path(report_path).parts:
        raise HarnessError("managed report process_cgroup is not a safe cgroup-root-relative path")
    path = CGROUP_ROOT / report_path.lstrip("/")
    if path == CGROUP_ROOT or CGROUP_ROOT not in path.parents:
        raise HarnessError("managed report process_cgroup is not below the cgroup root")
    return path


def _qualified_role_cgroups(native_runner_report: object, database_report: object) -> tuple[Path, Path, str]:
    native_text = require_text(native_runner_report, "qualify.summary.cgroups.native_runner")
    native = Path(native_text)
    if (not native.is_absolute() or ".." in native.parts or native == CGROUP_ROOT or
            CGROUP_ROOT not in native.parents):
        raise HarnessError("qualifier native runner cgroup is not safely below the cgroup root")
    database_text = require_text(database_report, "qualify.summary.processes.terrabase.cgroup")
    database = _cgroup_file_path(database_text)
    try:
        role_path = database.relative_to(native)
    except ValueError as error:
        raise HarnessError("TerraBase cgroup is not below the measured native runner") from error
    if len(role_path.parts) != 1:
        raise HarnessError("TerraBase cgroup must be a direct native role child")
    return native, database, role_path.parts[0]


def _validate_proof(report: dict[str, Any], member: dict[str, Any], label: str) -> dict[str, Any]:
    managed = require_object(report.get("managed"), f"{label} report.managed")
    proof = require_object(managed.get("serving_proof"), f"{label} report.managed.serving_proof")
    proof_fields = {
        "schema_version", "nonce", "process", "scope", "authority", "serving",
        "listeners", "object", "replication",
    }
    if set(proof) != proof_fields or proof.get("schema_version") != 1:
        raise HarnessError(f"{label} ServingProof must be the alpha wire version 1 shape")
    if not isinstance(proof.get("nonce"), str) or not re.fullmatch(r"[0-9a-f]{32}", proof["nonce"]):
        raise HarnessError(f"{label} ServingProof nonce is malformed")
    process = require_object(proof.get("process"), f"{label} ServingProof.process")
    scope = require_object(proof.get("scope"), f"{label} ServingProof.scope")
    authority = require_object(proof.get("authority"), f"{label} ServingProof.authority")
    listeners = require_object(proof.get("listeners"), f"{label} ServingProof.listeners")
    object_proof = require_object(proof.get("object"), f"{label} ServingProof.object")
    replication = require_object(proof.get("replication"), f"{label} ServingProof.replication")
    if set(process) != {"pid", "start_nonce"} or set(scope) != set(member["scope"]):
        raise HarnessError(f"{label} ServingProof process/scope fields differ from the alpha wire")
    if set(authority) != set(member["authority"]):
        raise HarnessError(f"{label} ServingProof authority fields differ from the alpha wire")
    if set(listeners) != {"client", "replication"}:
        raise HarnessError(f"{label} ServingProof listener fields differ from the alpha wire")
    object_fields = {
        "root_sha256", "target_sha256", "native_commit_seq_at_recovery",
        "inbox_archive_sha256_at_recovery", "local_source_sequence",
        "remote_inbox_durable_sequence", "remote_applied_sequence",
    }
    replication_fields = {
        "local_source_sequence", "peer_member_id", "peer_incarnation",
        "current_authenticated", "peer_durable_sequence", "peer_applied_sequence",
        "local_inbox_durable_sequence", "local_inbox_applied_sequence",
    }
    if set(object_proof) != object_fields or set(replication) != replication_fields:
        raise HarnessError(f"{label} ServingProof frontier fields differ from alpha v1")
    expected_managed = managed.get("member")
    expected_authority = managed.get("authority")
    if (type(process.get("pid")) is not int or process["pid"] != managed.get("process_pid") or
            process.get("start_nonce") != managed.get("process_boot_id") or
            scope != member["scope"] or authority != member["authority"] or
            expected_managed is None or expected_managed.get("scope") != member["scope"] or
            expected_authority != member["authority"]):
        raise HarnessError(f"{label} ServingProof does not match the accepted host managed report")
    if (proof.get("serving") is not True or listeners.get("client") is not True or
            listeners.get("replication") is not True):
        raise HarnessError(f"{label} ServingProof does not assert serving client and replication listeners")
    for key in ("root_sha256", "target_sha256", "inbox_archive_sha256_at_recovery"):
        if not HASH_RE.fullmatch(str(object_proof.get(key, ""))):
            raise HarnessError(f"{label} ServingProof object.{key} is not a lowercase SHA-256")
    for key in ("native_commit_seq_at_recovery", "local_source_sequence",
                "remote_inbox_durable_sequence", "remote_applied_sequence"):
        require_int(object_proof.get(key), f"{label} ServingProof object.{key}", 0)
    for key in ("local_source_sequence", "peer_durable_sequence", "peer_applied_sequence",
                "local_inbox_durable_sequence", "local_inbox_applied_sequence"):
        require_int(replication.get(key), f"{label} ServingProof replication.{key}", 0)
    if not isinstance(replication.get("current_authenticated"), bool):
        raise HarnessError(f"{label} ServingProof current_authenticated is not boolean")
    if (replication["local_source_sequence"] != object_proof["local_source_sequence"] or
            object_proof["remote_applied_sequence"] > object_proof["remote_inbox_durable_sequence"] or
            replication["peer_applied_sequence"] > replication["peer_durable_sequence"] or
            replication["local_inbox_applied_sequence"] > replication["local_inbox_durable_sequence"]):
        raise HarnessError(f"{label} ServingProof contains an inconsistent alpha v1 frontier")
    return proof


def validate_database_wire(evidence: dict[str, Any], request: dict[str, Any],
                           member: dict[str, Any]) -> dict[str, Any]:
    source_scope = member["source"]["scope"]
    document = member["document"]
    expected_write_path = (
        f"/v1/tenants/{source_scope['tenant_id']}/databases/{source_scope['database_id']}"
        f"/shards/{source_scope['shard_id']}/transactions"
    )
    expected_read_path = (
        f"/v1/tenants/{source_scope['tenant_id']}/databases/{source_scope['database_id']}"
        f"/shards/{source_scope['shard_id']}/collections/{document['collection_id']}"
        f"/documents/{request['document_id']}"
    )
    if evidence.get("write_path") != expected_write_path or evidence.get("peer_read_path") != expected_read_path:
        raise HarnessError("database adapter did not use the exact alpha transaction and cross-member point routes")
    if evidence.get("document_id") != request.get("document_id"):
        raise HarnessError("database adapter read a different document than this transaction operation")
    request_raw = require_text(evidence.get("transaction_request_raw"), "database.transaction_request_raw")
    _verify_wire_hash(request_raw, evidence.get("transaction_request_sha256"),
                      "database transaction request", 65536)
    transaction_request = _parse_raw_json(request_raw, "database transaction request", 65536)
    expected_value = {"kind": "live", "fields": [{
        "id": document["field_id"],
        "value": {"type": "i64", "value": str(request["value"])},
    }]}
    if (type(transaction_request) is not dict or set(transaction_request) != {"version", "transaction_id", "writes"} or
            transaction_request.get("version") != 1 or transaction_request.get("transaction_id") != request.get("transaction_id") or
            type(transaction_request.get("writes")) is not list or len(transaction_request["writes"]) != 1):
        raise HarnessError("transaction request does not match the alpha v1 typed write request")
    write = transaction_request["writes"][0]
    expected_write = {
        "collection": document["collection_id"], "document": request["document_id"],
        "schema_generation": str(document["schema_generation"]),
        "schema_digest": document["schema_digest"], "observed": [], "value": expected_value,
    }
    if write != expected_write:
        raise HarnessError("transaction request bytes do not bind the exact scoped schema/document/value")
    receipt_raw = require_text(evidence.get("write_receipt_raw"), "database.write_receipt_raw")
    _verify_wire_hash(receipt_raw, evidence.get("write_receipt_sha256"),
                      "database write receipt", 65536)
    receipt = _parse_raw_json(receipt_raw, "database write receipt", 65536)
    required_receipt_fields = {"version", "durability", "transaction_id", "event", "commit_sequence"}
    if type(receipt) is not dict or set(receipt) != required_receipt_fields:
        raise HarnessError("write receipt does not match the alpha transaction ACK shape")
    if receipt.get("version") != 1 or receipt.get("durability") != "object_durable":
        raise HarnessError("write receipt did not acknowledge ObjectDurable")
    transaction = require_object(receipt.get("transaction_id"), "database receipt.transaction_id")
    if transaction != request.get("transaction_id"):
        raise HarnessError("ObjectDurable receipt transaction ID differs from this exact write request")
    commit_sequence = receipt.get("commit_sequence")
    if not isinstance(commit_sequence, str) or not commit_sequence.isdecimal():
        raise HarnessError("ObjectDurable receipt commit_sequence must remain an opaque decimal string")
    event = require_object(receipt.get("event"), "database receipt.event")
    if set(event) != {"database", "shard", "replica", "incarnation", "sequence"}:
        raise HarnessError("receipt event does not match the alpha scoped event identity")
    expected_event = {
        "database": source_scope["database_id"],
        "shard": str(source_scope["shard_id"]),
        "replica": source_scope["member_id"],
        "incarnation": source_scope["incarnation"],
    }
    if any(event.get(key) != value for key, value in expected_event.items()):
        raise HarnessError("ObjectDurable receipt event scope/origin differs from the signed source member")
    if not isinstance(event.get("sequence"), str) or not event["sequence"].isdecimal() or int(event["sequence"]) < 1:
        raise HarnessError("ObjectDurable receipt event.sequence must be a positive decimal string")

    read_raw = require_text(evidence.get("peer_read_raw"), "database.peer_read_raw")
    _verify_wire_hash(read_raw, evidence.get("peer_read_sha256"), "peer point read", 65536)
    point = _parse_raw_json(read_raw, "peer point read", 65536)
    if (type(point) is not dict or point.get("version") != 1 or point.get("state") != "value" or
            type(point.get("siblings")) is not list):
        raise HarnessError("cross-member point read did not return an alpha value point")
    expected_fields = [{
        "id": document["field_id"],
        "value": {"type": "i64", "value": str(request["value"])},
    }]
    exact_matches = []
    for sibling in point["siblings"]:
        if type(sibling) is not dict or sibling.get("event") != event:
            continue
        if (sibling.get("kind") != "live" or
                sibling.get("schema_generation") != str(document["schema_generation"]) or
                sibling.get("schema_digest") != document["schema_digest"] or
                sibling.get("fields") != expected_fields):
            raise HarnessError("peer read event matches the receipt but document schema/value does not")
        exact_matches.append(sibling)
    if len(exact_matches) != 1:
        raise HarnessError("peer read does not contain exactly one sibling matching the ObjectDurable event")
    return {"receipt": receipt, "event": event, "point": point,
            "event_sequence": int(event["sequence"]),
            "commit_sequence_opaque": commit_sequence}


def validate_report_evidence(evidence: dict[str, Any], request: dict[str, Any],
                             observed_at: str, member: dict[str, Any],
                             previous_rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = require_text(evidence.get("operator_hosts_json"), "host_status.operator_hosts_json")
    _verify_wire_hash(raw, evidence.get("operator_hosts_sha256"), "operator hosts JSON", 1 << 20)
    value = _parse_raw_json(raw, "operator hosts JSON", 1 << 20)
    if type(value) is not list:
        raise HarnessError("operator hosts output must be the actual HostStatus JSON array")
    sampled_at = parse_timestamp(observed_at, "operator hosts observation time")
    witnesses = require_object(evidence.get("process_witnesses"), "host_status.process_witnesses")
    if set(witnesses) != {"source", "peer"}:
        raise HarnessError("operator hosts adapter must witness both managed member processes")
    selected: dict[str, Any] = {}
    for label in ("source", "peer"):
        expected = member[label]
        previous = previous_rows.get(label)
        matches = []
        for host in value:
            if type(host) is not dict:
                raise HarnessError("operator hosts array contains a non-object row")
            registration = host.get("registration")
            if type(registration) is not dict:
                continue
            binding = registration.get("managed_member")
            if (registration.get("cell") == expected["cell"] and
                    registration.get("node") == expected["node"] and
                    registration.get("environment") == expected["environment"] and
                    type(binding) is dict and binding.get("scope") == expected["scope"]):
                matches.append(host)
        if len(matches) != 1:
            raise HarnessError(f"operator hosts output has {len(matches)} exact {label} registrations")
        host = matches[0]
        registration = host["registration"]
        if host.get("verified") is not False:
            raise HarnessError("read-only operator HostStatus.verified must remain false")
        expires = parse_timestamp(host.get("session_expires_at"), f"{label} session_expires_at")
        if expires <= sampled_at:
            raise HarnessError(f"{label} host session is expired at the observation time")
        reports = host.get("reports")
        if type(reports) is not list:
            raise HarnessError(f"{label} HostStatus.reports is not an array")
        report_matches = [report for report in reports if type(report) is dict and
                          report.get("cell") == expected["cell"] and
                          report.get("node") == expected["node"] and
                          report.get("environment") == expected["environment"] and
                          report.get("role") == expected["role"]]
        if len(report_matches) != 1:
            raise HarnessError(f"{label} HostStatus does not contain one exact managed-role report")
        report = report_matches[0]
        report_time = parse_timestamp(report.get("observed_at"), f"{label} report.observed_at")
        age = (sampled_at - report_time).total_seconds()
        if age < -2 or age >= 30:
            raise HarnessError(f"{label} accepted report is future-dated or at least 30 seconds old")
        if previous is not None and report_time <= previous["report_time"]:
            raise HarnessError(f"{label} report observed_at did not strictly advance")
        if report.get("state") != "running":
            raise HarnessError(
                f"{label} actual report state={report.get('state')!r}, error={report.get('error')!r}"
            )
        if (report.get("generation", 0) < 1 or not HASH_RE.fullmatch(str(report.get("digest", ""))) or
                not isinstance(report.get("session_id"), str) or not report["session_id"] or
                type(report.get("epoch")) is not int or report["epoch"] < 1 or
                type(registration.get("generation")) is not int or registration["generation"] < 1):
            raise HarnessError(f"{label} host report lacks its accepted desired/session identity")
        if previous is not None:
            if (registration["generation"] != previous["registration_generation"] or
                    report["generation"] != previous["generation"] or report["digest"] != previous["digest"]):
                raise HarnessError(f"{label} registration or desired report identity changed during D15")
            manager_restarted = (label == "source" and
                                 request["pressure"].get("scenario") == "host_manager_sigkill" and
                                 request["phase"] == "post_recovery")
            if not manager_restarted and (report["session_id"] != previous["session_id"] or
                                          report["epoch"] != previous["epoch"]):
                raise HarnessError(f"{label} host session identity changed without a host-manager restart")
        managed = require_object(report.get("managed"), f"{label} report.managed")
        expected_member = expected["scope"]
        binding = require_object(managed.get("member"), f"{label} report.managed.member")
        registration_binding = require_object(
            registration.get("managed_member"), f"{label} registration.managed_member",
        )
        pid_value = managed.get("process_pid")
        if (set(registration_binding) != {"scope", "host_attempt"} or
                registration_binding.get("scope") != expected_member or
                type(registration_binding.get("host_attempt")) is not int or
                registration_binding["host_attempt"] < 1 or
                set(binding) != {"scope", "host_attempt"} or binding.get("scope") != expected_member or
                binding.get("host_attempt") != registration_binding["host_attempt"] or
                type(binding.get("host_attempt")) is not int or binding["host_attempt"] < 1 or
                managed.get("authority") != expected["authority"] or
                type(pid_value) is not int or pid_value <= 1 or not isinstance(managed.get("process_start"), str) or
                not managed["process_start"] or managed.get("process_boot_id") is None or
                not re.fullmatch(r"[0-9a-f]{32}", str(managed.get("process_boot_id"))) or
                not isinstance(managed.get("process_cgroup"), str) or
                not managed["process_cgroup"].startswith("/") or
                managed.get("storage_recovered") is not True or managed.get("listener_ready") is not True):
            raise HarnessError(f"{label} accepted managed report lacks exact process/mount readiness")
        proof = _validate_proof(report, expected, label)
        witness = require_object(witnesses.get(label), f"host_status.process_witnesses.{label}")
        if set(witness) != {"pid", "stat_raw", "cgroup_raw", "host_boot_id"}:
            raise HarnessError(f"{label} raw process witness has unexpected fields")
        pid = require_int(witness.get("pid"), f"{label} process witness PID", 2)
        stat_raw = require_text(witness.get("stat_raw"), f"{label} process stat_raw")
        cgroup_raw = require_text(witness.get("cgroup_raw"), f"{label} process cgroup_raw")
        actual_pid, actual_start = proc_stat_identity(stat_raw)
        actual_group = proc_cgroup_path(cgroup_raw)
        expected_group = _cgroup_file_path(managed["process_cgroup"])
        if (pid != managed["process_pid"] or actual_pid != pid or actual_start != managed["process_start"] or
                actual_group != expected_group):
            raise HarnessError(f"{label} raw process witness differs from the accepted managed report")
        host_boot_id = witness.get("host_boot_id")
        if not isinstance(host_boot_id, str) or not UUID_RE.fullmatch(host_boot_id):
            raise HarnessError(f"{label} host boot ID is not a canonical UUID")
        if previous is not None:
            old_identity = previous["managed_identity"]
            now_identity = (managed["process_pid"], managed["process_start"], managed["process_boot_id"])
            old_tuple = (old_identity["pid"], old_identity["start"], old_identity["nonce"])
            may_restart = (label == "source" and request["phase"] in {"post_recovery", "after", "after_write"}
                           and request["pressure"].get("scenario") in {"terrabase_process", "terrabase_oom"})
            if not may_restart and now_identity != old_tuple:
                raise HarnessError(f"{label} managed process identity changed outside its recovery scenario")
            if host_boot_id != previous["host_boot_id"]:
                raise HarnessError(f"{label} host boot ID changed during the pressure scenario")
        selected[label] = {
            "host": host, "report": report, "proof": proof, "report_time": report_time,
            "session_expires_at": expires, "verified": host["verified"],
            "registration_generation": registration["generation"],
            "generation": report["generation"], "digest": report["digest"],
            "session_id": report["session_id"], "epoch": report["epoch"],
            "managed_identity": {"pid": managed["process_pid"], "start": managed["process_start"],
                                 "nonce": managed["process_boot_id"],
                                 "cgroup": managed["process_cgroup"]},
            "host_boot_id": host_boot_id,
        }
    return {"raw": value, "members": selected, "process_witnesses": witnesses}


def assert_event_covered(snapshot: dict[str, Any], member: dict[str, Any],
                         event: dict[str, Any], event_sequence: int) -> None:
    source_proof = snapshot["members"]["source"]["proof"]
    peer_proof = snapshot["members"]["peer"]["proof"]
    source_replication = source_proof["replication"]
    source_scope = member["source"]["scope"]
    peer_scope = member["peer"]["scope"]
    if (source_replication["peer_member_id"] != peer_scope["member_id"] or
            source_replication["peer_incarnation"] != peer_scope["incarnation"] or
            source_replication["current_authenticated"] is not True or
            source_replication["local_source_sequence"] < event_sequence or
            source_replication["peer_durable_sequence"] < event_sequence or
            source_replication["peer_applied_sequence"] < event_sequence):
        raise HarnessError("source ServingProof v1 does not durably/applied-cover the matching event origin")
    peer_replication = peer_proof["replication"]
    if (peer_replication["peer_member_id"] != source_scope["member_id"] or
            peer_replication["peer_incarnation"] != source_scope["incarnation"] or
            peer_replication["current_authenticated"] is not True or
            peer_replication["local_inbox_durable_sequence"] < event_sequence or
            peer_replication["local_inbox_applied_sequence"] < event_sequence):
        raise HarnessError("peer ServingProof v1 lacks matching durable/applied inbox coverage")


class AdapterRunner:
    def __init__(self, manifest: dict[str, Any], manifest_hash: str, evidence_dir: Path) -> None:
        self.manifest = manifest
        self.manifest_hash = manifest_hash
        self.evidence_dir = evidence_dir
        self.harness_sha256 = hashlib.sha256(Path(pressure.__file__).read_bytes()).hexdigest()
        self.contract = manifest["adapter_contract"]
        self.contract_id = self.contract["id"]
        self.run_id = str(uuid.uuid4())
        self.identity = manifest["identity"]
        self.controller_identity = manifest["controller_identity"]
        self.controller_qualification = manifest["controller_qualification"]
        self.member = manifest["managed_member"]
        self.qualification = manifest["qualification"]
        self.pressure = manifest["pressure"]
        self.sequence = 0
        self.adapter_bytes = 0
        self.results: list[dict[str, Any]] = []
        self.handle: str | None = None
        self.host_snapshot: dict[str, Any] | None = None
        self.previous_host_rows: dict[str, dict[str, Any]] = {}
        self.service_snapshot: dict[str, Any] | None = None
        self.previous_services: dict[str, dict[str, Any]] = {}
        self.baseline_host_rows: dict[str, dict[str, Any]] = {}
        self.baseline_services: dict[str, dict[str, Any]] = {}
        self.last_event: dict[str, Any] | None = None
        self.last_event_sequence_by_origin: dict[tuple[str, str, str, str], int] = {}
        self.last_database_receipt: dict[str, Any] | None = None
        self.database_operations: set[str] = set()
        self.probe_fingerprint: dict[str, dict[str, Any]] = {}
        self.memory_usage_samples: list[dict[str, str]] = []
        self.native_runner_path: Path | None = None
        self.database_cgroup_path: Path | None = None
        self.pressure_backing: dict[str, Any] | None = None
        self.pressure_path: str | None = None
        self.pressure_processes: dict[int, tuple[str, str]] = {}
        self.pressure_started_at: dt.datetime | None = None
        self.pressure_started_monotonic: float | None = None
        self.pressure_completed = False
        self.failure_injection_at: dt.datetime | None = None
        self.failure_observed = False
        self.recovery_observed = False
        self.oom_watermark: dict[str, str] | None = None
        self.oom_target: dict[str, Any] | None = None
        self.oom_observed = False
        self.oom_restore_intent: dict[str, Any] | None = None
        self.oom_restore_receipt: dict[str, Any] | None = None
        self.oom_restore_cleanup_verified = False
        self.oom_restore_unresolved_reason: str | None = None

    def call(self, role: str, phase: str, **fields: object) -> dict[str, Any]:
        self.sequence += 1
        adapter = self.manifest["adapter"]
        directory = command_result_path(self.evidence_dir, self.sequence, role, phase)
        directory.mkdir(mode=0o700)
        request_id = str(uuid.uuid4())
        sent = dt.datetime.now(dt.timezone.utc)
        deadline = adapter["deadlines_seconds"][role]
        request: dict[str, Any] = {
            "schema": ADAPTER_INPUT_SCHEMA,
            "request_id": request_id,
            "run_id": self.run_id,
            "run_manifest_sha256": self.manifest_hash,
            "harness_sha256": self.harness_sha256,
            "contract_id": self.contract_id,
            "role": role,
            "phase": phase,
            "sent_at_utc": sent.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "deadline_seconds": deadline,
            "deadline_at_utc": (sent + dt.timedelta(seconds=deadline)).isoformat(
                timespec="milliseconds").replace("+00:00", "Z"),
            "identity": self.identity,
            "controller_identity": self.controller_identity,
            "managed_member": self.member,
            "transport": self.manifest["transport"],
            "adapter_source_path": adapter["source_path"],
            "adapter_source_sha256": adapter["source_sha256"],
            "qualification": self.qualification,
            "controller_qualification": self.controller_qualification,
            "memory_floor_evidence": self.manifest["memory_floor_evidence"],
            "pressure": self.pressure,
            "evidence_dir": str(self.evidence_dir),
            **fields,
        }
        if role == "database_progress":
            request["transaction_id"] = {
                "expires_at_unix_ms": str(int(time.time() * 1000) + 600_000),
                "nonce": uuid.uuid4().hex,
            }
            request["document_id"] = str(uuid.uuid4())
            request["value"] = time.time_ns() % 2_000_000_000
        if role in {"qualify", "service_state"}:
            guest_role = fields.get("guest_role")
            if guest_role not in {"host", "controller"}:
                raise HarnessError(f"{role} requires an explicit guest role")
            request["guest_role"] = guest_role
        if role == "qualify" and request["guest_role"] == "host" and self.host_snapshot:
            request["managed_process"] = self.host_snapshot["members"]["source"]["managed_identity"]
        if role == "host_status" and self.last_event is not None:
            request["pending_object_durable_event"] = self.last_event
        if role == "pressure_start" and self.native_runner_path is not None:
            request["native_runner_cgroup_path"] = str(self.native_runner_path)
            if self.database_cgroup_path is None:
                raise HarnessError("pressure launch lacks the preflight TerraBase cgroup")
            request["protected_database_cgroup_path"] = str(self.database_cgroup_path)
            request["pressure_manifest"] = self.manifest
        if role == "failure_inject":
            request["target_process"] = self._failure_target()
            request["protected_processes"] = self._protected_processes()
            if request["target_process"]["kind"] == "terrabase":
                if self.native_runner_path is None or self.database_cgroup_path is None:
                    raise HarnessError("TerraBase SIGKILL lacks the qualifier-pinned native role cgroup")
                request["native_runner_cgroup_path"] = str(self.native_runner_path)
                request["protected_database_cgroup_path"] = str(self.database_cgroup_path)
        if role == "kernel_oom_evidence":
            if self.native_runner_path is None or self.database_cgroup_path is None:
                raise HarnessError("OOM evidence lacks qualifier-pinned native and TerraBase cgroups")
            request["oom_target"] = self._terrabase_target()
            request["native_runner_cgroup_path"] = str(self.native_runner_path)
            request["protected_database_cgroup_path"] = str(self.database_cgroup_path)
            request["target_report_observed_at_utc"] = self.host_snapshot["members"]["source"]["report_time"].isoformat(
                timespec="milliseconds").replace("+00:00", "Z")
            if self.oom_watermark is not None:
                request["journal_watermark"] = self.oom_watermark
            if self.oom_restore_intent is not None:
                request["oom_restore_intent"] = self.oom_restore_intent
        if role == "cleanup_verify" and self.oom_restore_intent is not None:
            request["oom_restore_intent"] = self.oom_restore_intent
            request["native_runner_cgroup_path"] = self.oom_restore_intent["native_runner_cgroup_path"]
            request["protected_database_cgroup_path"] = self.oom_restore_intent["database_cgroup_path"]
        request_wire = (json.dumps(request, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(request_wire) > MAX_ADAPTER_OUTPUT_BYTES:
            raise HarnessError("adapter request exceeds the 1048576-byte input limit")
        phase_budget = (MAX_RUN_ADAPTER_BYTES if phase in {"cleanup", "after"} else
                        MAX_RUN_ADAPTER_BYTES - MAX_FINAL_ADAPTER_RESERVE_BYTES)
        self._account(len(request_wire), phase_budget)
        (directory / "request.json").write_bytes(request_wire)
        executable_fd: int | None = None
        process: subprocess.Popen[bytes] | None = None
        stdout_bytes = b""
        stderr_bytes = b""
        failure: str | None = None
        return_code: int | None = None
        started = time.monotonic()
        try:
            executable_path, _ = verify_adapter_executable(adapter["python_path"], adapter["python_sha256"])
            executable_fd, executable_digest = open_pinned_executable(executable_path, adapter["python_sha256"])
            argv = [adapter["python_path"], adapter["source_path"]]
            command = {
                "argv": argv, "executable": str(executable_path),
                "executable_sha256": executable_digest,
                "adapter_source_sha256": adapter["source_sha256"],
                "deadline_seconds": deadline,
                "input_contract": ADAPTER_INPUT_SCHEMA,
                "result_schema": ADAPTER_RESULT_SCHEMA,
                "purpose": f"pinned alpha adapter for {role}",
            }
            command_wire = (json.dumps(command, sort_keys=True, indent=2) + "\n").encode("utf-8")
            self._account(len(command_wire), phase_budget)
            (directory / "command.json").write_bytes(command_wire)
            output_limit = min(MAX_ADAPTER_OUTPUT_BYTES,
                               phase_budget - self.adapter_bytes - MAX_ADAPTER_OBSERVATION_BYTES)
            if output_limit <= 0:
                raise HarnessError("run adapter evidence budget is exhausted")
            process = subprocess.Popen(
                [f"/proc/self/fd/{executable_fd}", adapter["source_path"]],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, close_fds=True, pass_fds=(executable_fd,),
                env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
            try:
                stdout_bytes, stderr_bytes = communicate_bounded(
                    process, json.dumps(request, sort_keys=True).encode("utf-8"),
                    deadline - (time.monotonic() - started), output_limit,
                )
            except subprocess.TimeoutExpired as error:
                failure = f"adapter exceeded {deadline} second deadline"
                stdout_bytes, stderr_bytes = error.output or b"", error.stderr or b""
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=1)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
            return_code = process.returncode
            if return_code != 0 and failure is None:
                failure = f"adapter exited with status {return_code}"
        except (OSError, HarnessError) as error:
            failure = str(error)
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        finally:
            if executable_fd is not None:
                os.close(executable_fd)
            self._account(len(stdout_bytes) + len(stderr_bytes), phase_budget)
            (directory / "stdout.log").write_bytes(stdout_bytes)
            (directory / "stderr.log").write_bytes(stderr_bytes)
        try:
            stdout = stdout_bytes.decode("utf-8")
            stderr = stderr_bytes.decode("utf-8")
        except UnicodeDecodeError:
            stdout, stderr = "", ""
            failure = failure or "adapter stdout or stderr is not valid UTF-8"
        response = None
        if failure is None:
            try:
                parsed = json.loads(stdout, object_pairs_hook=unique_json_object)
                if type(parsed) is not dict:
                    raise HarnessError("adapter stdout must contain one JSON object")
                self._validate_envelope(parsed, role, request_id)
                response = parsed
            except (json.JSONDecodeError, HarnessError) as error:
                failure = str(error)
        observed = response["observed_at_utc"] if response else utc_now()
        result = {
            "sequence": self.sequence, "role": role, "phase": phase,
            "started_at_utc": request["sent_at_utc"], "finished_at_utc": utc_now(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "request_id": request_id, "return_code": return_code,
            "evidence_path": str(directory), "failure": failure,
            "status": response.get("status") if response else "FAIL",
            "observed_at_utc": observed,
        }
        if failure is None and response is not None:
            try:
                if response["status"] != "PASS":
                    raise HarnessError(f"adapter reported {response['status']}")
                self._validate_role(role, phase, request, response)
            except HarnessError as error:
                failure = str(error)
                result["failure"] = failure
                result["status"] = "FAIL"
        if failure is not None:
            self._write_observation(directory, result, phase_budget)
            self.results.append(result)
            raise HarnessError(f"{role}/{phase}: {failure}")
        self._write_observation(directory, result, phase_budget)
        self.results.append(result)
        return response

    def _validate_envelope(self, response: dict[str, Any], role: str, request_id: str) -> None:
        expected = {"schema", "request_id", "contract_id", "role", "status", "observed_at_utc", "evidence"}
        if set(response) != expected or response.get("schema") != ADAPTER_RESULT_SCHEMA or response.get("role") != role:
            raise HarnessError("adapter result envelope differs from the pinned alpha result schema")
        if response.get("request_id") != request_id or response.get("contract_id") != self.contract_id:
            raise HarnessError("adapter result is stale or bound to a different request/contract")
        if response.get("status") not in {"PASS", "FAIL"}:
            raise HarnessError("adapter result status must be PASS or FAIL; held is a source report state")
        parse_timestamp(response.get("observed_at_utc"), "adapter observed_at_utc")
        require_object(response.get("evidence"), "adapter evidence")

    def _validate_role(self, role: str, phase: str, request: dict[str, Any],
                       response: dict[str, Any]) -> None:
        evidence = response["evidence"]
        observed_at = response["observed_at_utc"]
        active_write_proof = (role == "host_status" and phase == "after_write" and
                              self.pressure_started_at is not None and not self.pressure_completed)
        if ((phase == "during" and role in {"service_state", "host_status", "qualify", "database_progress"}) or
                active_write_proof):
            observed = parse_timestamp(observed_at, f"{role} pressure observed_at_utc")
            if (self.pressure_started_at is None or observed < self.pressure_started_at or
                    observed >= self.pressure_started_at + dt.timedelta(
                        seconds=self.pressure["duration_seconds"])):
                raise HarnessError(f"{role} observation did not complete during active pressure")
        if role == "target_identity":
            if set(evidence) != {"operator_hosts_json", "operator_hosts_sha256",
                                 "architecture_by_member", "source_oci_metadata",
                                 "controller_oci_metadata"}:
                raise HarnessError("target identity evidence does not match its alpha source schema")
            raw_hosts = require_text(evidence.get("operator_hosts_json"), "target_identity.operator_hosts_json")
            _verify_wire_hash(raw_hosts, evidence.get("operator_hosts_sha256"),
                              "target identity operator hosts JSON", 1 << 20)
            hosts = _parse_raw_json(raw_hosts, "target identity operator hosts JSON", 1 << 20)
            if type(hosts) is not list:
                raise HarnessError("target identity HostStatus evidence must be an array")
            architectures = require_object(evidence.get("architecture_by_member"),
                                           "target_identity.architecture_by_member")
            if architectures != {"source": "aarch64", "peer": "aarch64", "controller": "aarch64"}:
                raise HarnessError("SSH targets do not report the pinned aarch64 architecture")
            target_ids = self.manifest["transport"]["ssh"]["targets"]
            registrations: dict[str, dict[str, Any]] = {}
            for label in ("source", "peer"):
                expected = self.member[label]
                matches = []
                for host in hosts:
                    if type(host) is not dict or type(host.get("registration")) is not dict:
                        continue
                    registration = host["registration"]
                    binding = registration.get("managed_member")
                    if (registration.get("cell") == expected["cell"] and
                            registration.get("node") == expected["node"] and
                            registration.get("environment") == expected["environment"] and
                            type(binding) is dict and binding.get("scope") == expected["scope"]):
                        matches.append(host)
                if len(matches) != 1 or matches[0].get("verified") is not False:
                    raise HarnessError(f"target identity lacks one read-only admitted {label} HostStatus")
                registration = matches[0]["registration"]
                oci = require_object(registration.get("managed_oci"),
                                     f"target_identity.{label}.registration.managed_oci")
                if (oci.get("instance_id") != target_ids[label]["oci_instance_id"] or
                        type(oci.get("region")) is not str or oci["region"] not in OCI_REGION_NAMES):
                    raise HarnessError(f"{label} HostStatus does not match its pinned OCI instance/region")
                registrations[label] = registration
            metadata = require_object(evidence.get("source_oci_metadata"),
                                      "target_identity.source_oci_metadata")
            if set(metadata) != {"instance_id", "image_id", "region", "shape"}:
                raise HarnessError("OCI metadata evidence contains fields outside its allowlist")
            source_oci = registrations["source"]["managed_oci"]
            if (metadata.get("instance_id") != self.identity["oci_instance_id"] or
                    metadata.get("instance_id") != source_oci["instance_id"] or
                    metadata.get("image_id") != self.identity["image_id"] or
                    metadata.get("region") != OCI_REGION_NAMES[source_oci["region"]] or
                    not isinstance(metadata.get("shape"), str) or not metadata["shape"]):
                raise HarnessError("live OCI metadata does not match the pinned source instance, image and region")
            controller_metadata = require_object(evidence.get("controller_oci_metadata"),
                                                 "target_identity.controller_oci_metadata")
            if (set(controller_metadata) != {"instance_id", "image_id", "region", "shape"} or
                    controller_metadata.get("instance_id") != self.controller_identity["oci_instance_id"] or
                    controller_metadata.get("image_id") != self.controller_identity["image_id"] or
                    controller_metadata.get("region") != OCI_REGION_NAMES[source_oci["region"]] or
                    not isinstance(controller_metadata.get("shape"), str) or
                    not controller_metadata["shape"]):
                raise HarnessError("live OCI metadata does not match the pinned controller instance, image and region")
        elif role == "host_status":
            snapshot = validate_report_evidence(
                evidence, request, observed_at, self.member, self.previous_host_rows,
            )
            for label in ("source", "peer"):
                old = self.previous_host_rows.get(label)
                if old is not None:
                    validate_report_evidence_for_previous(snapshot, label, old, request)
                self.previous_host_rows[label] = snapshot["members"][label]
            if not self.baseline_host_rows:
                self.baseline_host_rows = dict(snapshot["members"])
            self.host_snapshot = snapshot
            if self.last_event is not None:
                assert_event_covered(snapshot, self.member, self.last_event, self.last_database_receipt["event_sequence"])
                self.last_event = None
        elif role == "service_state":
            if evidence.get("guest_role") != request["guest_role"]:
                raise HarnessError("service_state guest role differs from its request")
            current = self._parse_service_state(evidence, observed_at)
            if all(unit in self.baseline_services for unit in current):
                self._compare_services(current, phase)
            else:
                self.baseline_services.update(current)
            self.previous_services.update(current)
            if self.service_snapshot is None:
                self.service_snapshot = {}
            self.service_snapshot.update(current)
        elif role == "qualify":
            self._validate_qualifier(evidence, request, observed_at, phase)
        elif role == "database_progress":
            self.last_database_receipt = validate_database_wire(evidence, request, self.member)
            event = self.last_database_receipt["event"]
            origin = (event["database"], event["shard"], event["replica"], event["incarnation"])
            previous_sequence = self.last_event_sequence_by_origin.get(origin, 0)
            if self.last_database_receipt["event_sequence"] <= previous_sequence:
                raise HarnessError("ObjectDurable event sequence did not advance for its exact origin/scope")
            self.last_event_sequence_by_origin[origin] = self.last_database_receipt["event_sequence"]
            self.last_event = event
        elif role in {"pressure_start", "pressure_status"}:
            self._validate_pressure(role, evidence, response, request)
        elif role == "failure_inject":
            self._validate_failure_action(evidence, request, observed_at)
        elif role == "kernel_oom_evidence":
            self._validate_oom(evidence, request, observed_at)
        elif role == "pressure_stop":
            if evidence.get("handle") != self.handle or evidence.get("pressure_cgroup_process_pids") != [] or evidence.get("pressure_cgroup_procs_raw") != "":
                raise HarnessError("pressure stop did not prove the exact workload cgroup is empty")
        elif role == "cleanup_verify":
            cleanup = require_object(evidence.get("cleanup"), "cleanup_verify.cleanup")
            if (cleanup.get("pressure_cgroup_procs_raw") != "" or
                    cleanup.get("pressure_child_cgroups") != [] or cleanup.get("scratch_paths") != []):
                raise HarnessError("cleanup did not prove an empty workload cgroup and removed scratch paths")
            if self.oom_restore_intent is not None:
                intent = self.oom_restore_intent
                current_inode = cleanup.get("oom_restore_cgroup_inode")
                restored = (cleanup.get("oom_restore_verified") is True and
                            cleanup.get("oom_restore_target") == intent["target"] and
                            type(current_inode) is int and current_inode > 0 and
                            cleanup.get("current_database_memory_max_bytes") ==
                            self.qualification["database_memory_max_bytes"] and
                            current_inode == intent["cgroup_inode"])
                if not restored:
                    reason = cleanup.get("oom_restore_unresolved_reason")
                    self.oom_restore_unresolved_reason = str(reason or "cleanup could not verify the exact native role cap")
                    raise HarnessError("cleanup left the native OOM restore obligation unresolved")
                self.oom_restore_cleanup_verified = True
                self.oom_restore_unresolved_reason = None

    def _parse_service_state(self, evidence: dict[str, Any], observed_at: str) -> dict[str, Any]:
        if set(evidence) != {"guest_role", "units", "host_boot_id"}:
            raise HarnessError("service_state evidence must contain exact systemd snapshots and host boot ID")
        guest_role = evidence.get("guest_role")
        if guest_role not in {"host", "controller"}:
            raise HarnessError("service_state has no valid guest role")
        units = require_object(evidence.get("units"), "service_state.units")
        expected_unit = SOURCE_UNIT if guest_role == "host" else CONTROLLER_UNIT
        if set(units) != {expected_unit}:
            raise HarnessError("service_state must observe only its guest's exact unit")
        host_boot = evidence.get("host_boot_id")
        if not isinstance(host_boot, str) or not UUID_RE.fullmatch(host_boot):
            raise HarnessError("service_state host_boot_id is malformed")
        if guest_role == "host":
            if (self.host_snapshot is not None and
                    host_boot != self.host_snapshot["members"]["source"]["host_boot_id"]):
                raise HarnessError("systemd and managed report witnesses disagree on the source host boot ID")
        elif CONTROLLER_UNIT in self.baseline_services and host_boot != self.baseline_services[CONTROLLER_UNIT]["host_boot_id"]:
            raise HarnessError("controller service boot ID changed during D15")
        result: dict[str, Any] = {}
        for unit in (expected_unit,):
            row = require_object(units[unit], f"service_state.units.{unit}")
            if set(row) != {"systemctl_show_raw", "process_stat_raw", "process_cgroup_raw"}:
                raise HarnessError(f"{unit} evidence must retain raw systemctl and /proc process identity")
            raw = require_text(row["systemctl_show_raw"], f"{unit}.systemctl_show_raw")
            values: dict[str, str] = {}
            for line in raw.splitlines():
                key, separator, value = line.partition("=")
                if separator:
                    values[key] = value
            if any(key not in values for key in SERVICE_PROPERTIES):
                raise HarnessError(f"{unit} systemctl show output omits required properties")
            if values["ActiveState"].lower() != "active" or not values["ControlGroup"].startswith("/"):
                raise HarnessError(f"{unit} is not active in its exact systemd cgroup")
            pid = require_int(int(values["MainPID"]) if values["MainPID"].isdecimal() else None,
                              f"{unit}.MainPID", 2)
            restarts = require_int(int(values["NRestarts"]) if values["NRestarts"].isdecimal() else None,
                                   f"{unit}.NRestarts", 0)
            stat_raw = require_text(row["process_stat_raw"], f"{unit}.process_stat_raw")
            cgroup_raw = require_text(row["process_cgroup_raw"], f"{unit}.process_cgroup_raw")
            actual_pid, start = proc_stat_identity(stat_raw)
            actual_group = proc_cgroup_path(cgroup_raw)
            expected_group = CGROUP_ROOT / values["ControlGroup"].lstrip("/")
            if guest_role == "host":
                expected_group /= "supervisor"
            if actual_pid != pid or actual_group != expected_group:
                raise HarnessError(f"{unit} raw /proc identity differs from systemd MainPID/ControlGroup")
            result[unit] = {
                "active_state": values["ActiveState"], "main_pid": pid,
                "control_group": values["ControlGroup"], "n_restarts": restarts,
                "process_start": start, "process_stat_raw": stat_raw,
                "process_cgroup_raw": cgroup_raw,
                "host_boot_id": host_boot,
                "observed_at": parse_timestamp(observed_at, "service_state observed_at_utc"),
            }
        return result

    def _compare_services(self, current: dict[str, Any], phase: str) -> None:
        scenario = self.pressure["scenario"]
        for unit in current:
            old = self.previous_services[unit]
            now = current[unit]
            if old["control_group"] != now["control_group"]:
                raise HarnessError(f"{unit} systemd cgroup changed during the D15 scenario")
            if unit == SOURCE_UNIT and scenario == "host_manager_sigkill" and phase in {
                    "post_recovery", "after", "after_write"} and self.failure_observed:
                if (now["n_restarts"] <= self.baseline_services[unit]["n_restarts"] or
                        (now["main_pid"], now["process_start"]) ==
                        (self.baseline_services[unit]["main_pid"], self.baseline_services[unit]["process_start"])):
                    raise HarnessError("host manager systemd restart count/process identity did not advance")
            elif (now["main_pid"], now["process_start"], now["n_restarts"]) != (
                    old["main_pid"], old["process_start"], old["n_restarts"]):
                raise HarnessError(f"{unit} process identity/restart counter changed outside its target scenario")

    def _validate_qualifier(self, evidence: dict[str, Any], request: dict[str, Any],
                            observed_at: str, phase: str) -> None:
        summary = require_object(evidence.get("summary"), "qualify.summary")
        probe = require_object(evidence.get("probe_evidence"), "qualify.probe_evidence")
        if summary.get("status") != "PASS" or probe.get("fresh_for_request_id") != request["request_id"]:
            raise HarnessError("qualify adapter must return a fresh packaged probe PASS")
        for key in ("summary_sha256", "commands_sha256"):
            if not HASH_RE.fullmatch(str(probe.get(key, ""))):
                raise HarnessError(f"qualify probe evidence omits {key}")
        summary_wire = (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode("utf-8")
        commands = probe.get("commands_log")
        if (hashlib.sha256(summary_wire).hexdigest() != probe["summary_sha256"] or
                not isinstance(commands, str) or
                hashlib.sha256(commands.encode("utf-8")).hexdigest() != probe["commands_sha256"]):
            raise HarnessError("qualify summary/commands log differs from its exact content hashes")
        guest_role = request["guest_role"]
        if summary.get("guest_role") != guest_role:
            raise HarnessError("qualifier guest role differs from its pinned request")
        identity = self.identity if guest_role == "host" else self.controller_identity
        qualification = self.qualification if guest_role == "host" else self.controller_qualification
        unit = SOURCE_UNIT if guest_role == "host" else CONTROLLER_UNIT
        units = summary.get("unit_sha256")
        if (not HASH_RE.fullmatch(str(summary.get("qualifier_sha256", ""))) or
                type(units) is not dict or set(units) != {unit} or
                not HASH_RE.fullmatch(str(units[unit]))):
            raise HarnessError("qualify summary omits its packaged probe or role unit hash")
        fingerprint = {"qualifier_sha256": summary["qualifier_sha256"], "unit_sha256": units,
                       "systemd_version": summary.get("systemd_version")}
        previous_fingerprint = self.probe_fingerprint.get(guest_role)
        if previous_fingerprint is None:
            self.probe_fingerprint[guest_role] = fingerprint
        elif fingerprint != previous_fingerprint:
            raise HarnessError(f"{guest_role} qualifier or systemd unit identity changed during D15")
        for key in ("oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id"):
            if summary.get(key) != identity[key]:
                raise HarnessError(f"{guest_role} qualify summary {key} differs from its pinned target")
        profile = require_object(summary.get("memory_profile"), "qualify.summary.memory_profile")
        prefix = guest_role
        expected_profile = {
            f"{prefix}_memory_min_bytes": qualification[f"expected_{'memory' if guest_role == 'host' else 'controller_memory'}_min_bytes"],
            f"{prefix}_memory_low_bytes": qualification[f"expected_{'memory' if guest_role == 'host' else 'controller_memory'}_low_bytes"],
            "system_slice_memory_min_bytes": qualification["expected_system_slice_memory_min_bytes"],
            "system_slice_memory_low_bytes": qualification["expected_system_slice_memory_low_bytes"],
            "system_reserve_bytes": qualification["system_reserve_bytes"],
            "allocatable_memory_bytes": qualification["allocatable_memory_bytes"],
        }
        for key, expected in expected_profile.items():
            if profile.get(key) != expected:
                raise HarnessError(f"{guest_role} qualify summary {key} differs from its pinned profile values")
        if self.service_snapshot is None or unit not in self.service_snapshot:
            raise HarnessError(f"{guest_role} qualify must follow a current service witness")
        process_key = "host_supervisor" if guest_role == "host" else "controller"
        processes = require_object(summary.get("processes"), "qualify.summary.processes")
        process = require_object(processes.get(process_key), f"qualify.summary.processes.{process_key}")
        service = self.service_snapshot[unit]
        if (process.get("pid") != service["main_pid"] or
                process.get("process_start_time") != service["process_start"]):
            raise HarnessError(f"{guest_role} qualifier process differs from the witnessed unit process")
        cgroups = require_object(summary.get("cgroups"), "qualify.summary.cgroups")
        service_path = require_text(cgroups.get(f"{guest_role}_service"), f"{guest_role} service cgroup")
        if service_path != str(CGROUP_ROOT / service["control_group"].lstrip("/")):
            raise HarnessError(f"{guest_role} qualifier cgroup differs from the witnessed unit")
        if guest_role == "host":
            if self.host_snapshot is None:
                raise HarnessError("host qualify must follow a current accepted operator hosts observation")
            current = self.host_snapshot["members"]["source"]["managed_identity"]
            database = require_object(processes.get("terrabase"), "qualify.summary.processes.terrabase")
            if database.get("pid") != current["pid"] or database.get("cgroup") != current["cgroup"]:
                raise HarnessError("priority probe TerraBase identity differs from the accepted host report")
            native, database_path, db_role = _qualified_role_cgroups(
                cgroups.get("native_runner"), database.get("cgroup"),
            )
            if database_path != _cgroup_file_path(current["cgroup"]):
                raise HarnessError("priority probe TerraBase cgroup differs from the accepted host report")
            roles = require_object(cgroups.get("roles"), "qualify.summary.cgroups.roles")
            if db_role not in roles:
                raise HarnessError("qualifier summary does not identify the signed TerraBase role")
            db_memory = require_object(roles[db_role].get("memory"), f"qualify role {db_role}.memory")
            if db_memory.get("memory_max") != str(self.qualification["database_memory_max_bytes"]):
                raise HarnessError("TerraBase cgroup memory.max differs from its signed profile cap")
            if self.native_runner_path is None:
                self.native_runner_path = native
                self.database_cgroup_path = database_path
            elif self.native_runner_path != native or self.database_cgroup_path != database_path:
                raise HarnessError("native runner or TerraBase cgroup path changed during qualification")
        else:
            if (set(processes) != {"controller"} or
                    set(cgroups) != {"controller_service", "controller_weights", "controller_cpu_max"} or
                    not re.fullmatch(r"max [1-9][0-9]*", str(cgroups.get("controller_cpu_max", "")))):
                raise HarnessError("controller qualifier must contain only controller role state")
        sent = parse_timestamp(request["sent_at_utc"], "qualify request sent_at_utc")
        finished = parse_timestamp(summary.get("finished_at_utc"), "qualify summary finished_at_utc")
        observed = parse_timestamp(observed_at, "qualify observed_at_utc")
        started = parse_timestamp(summary.get("started_at_utc"), "qualify summary started_at_utc")
        if not sent <= started <= finished <= observed:
            raise HarnessError("priority probe is stale or outside this exact request window")
        sample = pressure.validate_memory_usage_sample(
            summary.get("memory_usage_sample"), identity=identity,
            guest_role=guest_role, expected_service_cgroup=service_path,
            expected_boot_id=service["host_boot_id"],
            expected_systemd_version=require_text(summary.get("systemd_version"),
                                                   "qualify.summary.systemd_version"),
            not_before=sent, not_after=finished,
        )
        sample_hash = require_text(sample.get("sample_sha256"), "memory usage sample sample_sha256")
        self.memory_usage_samples.append({
            "phase": phase, "guest_role": guest_role,
            "request_id": require_text(request.get("request_id"), "qualify request_id"),
            "sample_sha256": sample_hash,
        })

    def _validate_pressure(self, role: str, evidence: dict[str, Any],
                           response: dict[str, Any], request: dict[str, Any]) -> None:
        if role == "pressure_start":
            handle = require_text(evidence.get("handle"), "pressure_start.handle")
            if evidence.get("worker_harness_sha256") != self.harness_sha256:
                raise HarnessError("pressure start did not execute the pinned stress worker source")
            self.handle = handle
            initial = True
        else:
            if evidence.get("handle") != self.handle:
                raise HarnessError("pressure status is not bound to the active workload handle")
            initial = False
        observed = require_object(evidence.get("pressure_cgroup"), "pressure_cgroup")
        expected = self.pressure["workload_cgroup"]
        for key in ("cpu_max", "io_device"):
            if observed.get(key) != expected[key]:
                raise HarnessError(f"pressure cgroup {key} differs from its pinned workload role")
        if (observed.get("memory_max_bytes") != expected["memory_max_bytes"] or
                observed.get("io_weight") != expected["io_weight"]):
            raise HarnessError("pressure cgroup effective memory/I/O limits differ from the manifest")
        if (observed.get("memory_min_bytes") != 0 or
                observed.get("memory_low_bytes") != 0):
            raise HarnessError("pressure cgroup must keep memory.min and memory.low at zero")
        backing = validate_block_backing_evidence(observed.get("io_backing"), expected["io_device"])
        if self.pressure_backing is None:
            self.pressure_backing = backing
        elif backing != self.pressure_backing:
            raise HarnessError("pressure scratch block backing changed during the run")
        path_text = require_text(observed.get("path"), "pressure scope cgroup path")
        path = Path(path_text)
        parent_path = Path(expected["parent_path"])
        if (not path.is_absolute() or ".." in path.parts or path.parent != parent_path or
                path == self.native_runner_path or
                (self.native_runner_path is not None and self.native_runner_path in path.parents) or
                (self.database_cgroup_path is not None and
                 (path == self.database_cgroup_path or path in self.database_cgroup_path.parents))):
            raise HarnessError("pressure systemd scope is outside its pinned slice or overlaps the native role tree")
        if self.pressure_path is None:
            self.pressure_path = path_text
        elif path_text != self.pressure_path:
            raise HarnessError("pressure cgroup path changed during the run")
        scope = require_object(observed.get("systemd_scope"), "pressure systemd scope")
        if set(scope) != {"unit", "slice", "control_group", "parent_control_group",
                          "active_state", "cgroup_present", "systemctl_show_raw"}:
            raise HarnessError("pressure scope evidence does not match the exact transient-unit schema")
        unit = f"terrascale-d15-{self.run_id}.scope"
        runtime = self.manifest["transport"]["runtime"]
        parent_control_group = str(parent_path).removeprefix(str(CGROUP_ROOT))
        if (scope.get("unit") != unit or scope.get("slice") != runtime["workload_slice"] or
                scope.get("parent_control_group") != parent_control_group or
                scope.get("control_group") != path_text.removeprefix(str(CGROUP_ROOT))):
            raise HarnessError("pressure systemd unit placement differs from the pinned workload slice")
        completed = request.get("expect_pressure_completed") is True
        if ((not completed and (scope.get("active_state") != "active" or scope.get("cgroup_present") is not True)) or
                (completed and (scope.get("active_state") not in {"inactive", "failed"} or
                                scope.get("cgroup_present") is not False))):
            raise HarnessError("pressure systemd scope lifecycle does not match its phase")
        properties: dict[str, str] = {}
        for line in require_text(scope.get("systemctl_show_raw"), "scope systemctl show output").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                properties[key] = value
        required_scope_properties = {"ActiveState", "ControlGroup", "Slice", "CPUQuotaPerSecUSec",
                                     "MemoryMax", "MemoryMin", "MemoryLow", "IOWeight"}
        if (not required_scope_properties.issubset(properties) or
                properties["ActiveState"] != scope["active_state"] or
                properties["ControlGroup"] != scope["control_group"] or
                properties["Slice"] != scope["slice"] or
                properties["MemoryMax"] != str(expected["memory_max_bytes"]) or
                properties["MemoryMin"] != "0" or properties["MemoryLow"] != "0" or
                properties["IOWeight"] != str(expected["io_weight"])):
            raise HarnessError("systemd scope properties differ from the pinned limits or placement")
        quota, period = expected["cpu_max"].split()
        expected_quota_usec = str(int(quota) * 1_000_000 // int(period))
        if properties["CPUQuotaPerSecUSec"] != expected_quota_usec:
            raise HarnessError("systemd scope CPU quota differs from the pinned cpu.max")
        raw_state = require_text(observed.get("worker_state_record"), "pressure worker state record")
        digest = observed.get("worker_state_sha256")
        if len(raw_state.encode("utf-8")) > MAX_PRESSURE_WORKER_STATE_BYTES or not HASH_RE.fullmatch(str(digest or "")) or hashlib.sha256(raw_state.encode("utf-8")).hexdigest() != digest:
            raise HarnessError("pressure worker state record is missing, oversized, or hash-mismatched")
        state = _parse_raw_json(raw_state, "pressure worker state", MAX_PRESSURE_WORKER_STATE_BYTES)
        if type(state) is not dict or state.get("schema") != PRESSURE_WORKER_STATE_SCHEMA or state.get("run_id") != self.run_id:
            raise HarnessError("pressure worker state is not bound to this run and version")
        if set(state) != {"schema", "run_id", "status", "started_at_utc", "started_monotonic_ns",
                          "observed_at_utc", "elapsed_monotonic_ns", "worker_pids", "worker_roles",
                          "active_worker_pids", "finished_at_utc", "finished_monotonic_ns"}:
            raise HarnessError("pressure worker state contains obsolete victim or non-alpha fields")
        state_observed = parse_timestamp(state.get("observed_at_utc"), "worker state observed_at_utc")
        response_observed = parse_timestamp(response["observed_at_utc"], "pressure response observed_at_utc")
        if state_observed > response_observed:
            raise HarnessError("pressure worker state is future-dated")
        started = parse_timestamp(state.get("started_at_utc"), "worker state started_at_utc")
        if initial:
            if state.get("status") != "RUNNING":
                raise HarnessError("pressure worker did not report RUNNING at start")
            self.pressure_started_at = started
            self.pressure_started_monotonic = time.monotonic()
        elif self.pressure_started_at != started:
            raise HarnessError("pressure worker start time changed after startup")
        processes = observed.get("processes")
        pids = observed.get("process_pids")
        raw_procs = observed.get("cgroup_procs_raw")
        worker_pids = observed.get("worker_process_pids")
        if type(processes) is not list or type(pids) is not list or type(worker_pids) is not list or not isinstance(raw_procs, str):
            raise HarnessError("pressure cgroup lacks an enumerated actual process inventory")
        try:
            if sorted(int(value) for value in raw_procs.splitlines()) != pids:
                raise HarnessError("pressure cgroup raw cgroup.procs differs from its PID list")
        except ValueError as error:
            raise HarnessError("pressure cgroup raw process list contains a malformed PID") from error
        current: dict[int, tuple[str, str]] = {}
        roles: dict[int, str] = {}
        for row in processes:
            if type(row) is not dict or set(row) != {"pid", "process_start_time", "role", "process_stat_raw", "process_cgroup_raw"}:
                raise HarnessError("pressure process inventory does not retain exact raw /proc identity")
            pid = require_int(row.get("pid"), "pressure process PID", 2)
            start = require_text(row.get("process_start_time"), "pressure process start time")
            role_name = row.get("role")
            if role_name not in {"pressure_runner", "cpu_worker", "memory_worker", "io_worker"}:
                raise HarnessError("pressure process role is not a load worker")
            actual_pid, actual_start = proc_stat_identity(require_text(row.get("process_stat_raw"), "pressure /proc stat"))
            actual_group = proc_cgroup_path(require_text(row.get("process_cgroup_raw"), "pressure /proc cgroup"))
            if actual_pid != pid or actual_start != start or str(actual_group) != path_text:
                raise HarnessError("pressure worker raw process identity differs from cgroup inventory")
            current[pid] = (start, role_name)
            roles[pid] = role_name
        if pids != sorted(current) or set(pids) != set(current):
            raise HarnessError("pressure cgroup process IDs differ from its raw process records")
        canonical_inventory = json.dumps(
            processes, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
        inventory_digest = observed.get("process_inventory_sha256")
        if (not HASH_RE.fullmatch(str(inventory_digest or "")) or
                hashlib.sha256(canonical_inventory).hexdigest() != inventory_digest):
            raise HarnessError("pressure process inventory hash differs from its raw process records")
        if set(current) & set(self._protected_pids()):
            raise HarnessError("pressure cgroup includes TerraBase or management service process")
        listed_worker_pids = sorted(pid for pid, role_name in roles.items() if role_name != "pressure_runner")
        if worker_pids != listed_worker_pids:
            raise HarnessError("pressure worker PID list differs from its actual inventory")
        if initial:
            if sum(name == "pressure_runner" for name in roles.values()) != 1:
                raise HarnessError("pressure startup inventory must contain exactly one pressure runner")
            if sum(name == "cpu_worker" for name in roles.values()) != self.pressure["cpu_workers"] or sum(name == "memory_worker" for name in roles.values()) != (1 if self.pressure["memory_bytes"] else 0) or sum(name == "io_worker" for name in roles.values()) != self.pressure["io_workers"]:
                raise HarnessError("pressure startup process inventory differs from the configured load workers")
            self.pressure_processes = current
            worker_roles = state.get("worker_roles")
            expected_worker_roles = [{"pid": pid, "role": role_name}
                                     for pid, (_start, role_name) in sorted(current.items())
                                     if role_name != "pressure_runner"]
            if worker_roles != expected_worker_roles:
                raise HarnessError("pressure worker state roles differ from the startup process inventory")
        elif request.get("expect_pressure_completed") is True:
            if pids != [] or processes != [] or raw_procs != "" or worker_pids != []:
                raise HarnessError("completed pressure workload left a process in its cgroup")
        elif current != self.pressure_processes:
            raise HarnessError("a pressure worker disappeared or changed identity before full duration")
        elif state.get("worker_roles") != [{"pid": pid, "role": role_name}
                                           for pid, (_start, role_name) in sorted(self.pressure_processes.items())
                                           if role_name != "pressure_runner"]:
            raise HarnessError("pressure worker state roles changed during the configured duration")
        state_workers = state.get("worker_pids")
        active_workers = state.get("active_worker_pids")
        if request.get("expect_pressure_completed") is True:
            elapsed = require_int(state.get("elapsed_monotonic_ns"), "worker elapsed time", 0)
            started_ns = require_int(state.get("started_monotonic_ns"), "worker start monotonic time", 0)
            finished_ns = require_int(state.get("finished_monotonic_ns"), "worker finish monotonic time", 0)
            finished_at = parse_timestamp(state.get("finished_at_utc"), "worker finished_at_utc")
            expected_roles = [{"pid": pid, "role": role_name}
                              for pid, (_start, role_name) in sorted(self.pressure_processes.items())
                              if role_name != "pressure_runner"]
            if (state.get("status") != "COMPLETED" or state_workers != [] or active_workers != [] or
                    state.get("worker_roles") != expected_roles or
                    finished_ns <= started_ns or elapsed < self.pressure["duration_seconds"] * 1_000_000_000 or
                    finished_at < started + dt.timedelta(seconds=self.pressure["duration_seconds"])):
                raise HarnessError("pressure completion did not prove all workers survived the full duration")
            self.pressure_completed = True
        else:
            if state.get("status") != "RUNNING" or state_workers != listed_worker_pids or active_workers != listed_worker_pids:
                raise HarnessError("pressure workers are not all running through the configured duration")

    def _validate_failure_action(self, evidence: dict[str, Any], request: dict[str, Any], observed_at: str) -> None:
        action = require_object(evidence.get("action_receipt"), "failure_inject.action_receipt")
        if set(action) != {"target_process", "signal", "requested_at_utc", "completed_at_utc", "exit_status"}:
            raise HarnessError("failure action receipt does not match the exact targeted signal operation")
        if (action.get("target_process") != request.get("target_process") or
                action.get("signal") != "SIGKILL" or action.get("exit_status") != 0):
            raise HarnessError("failure action did not target the exact current TerraBase/host manager process")
        sent = parse_timestamp(request["sent_at_utc"], "failure request timestamp")
        requested = parse_timestamp(action.get("requested_at_utc"), "failure requested_at_utc")
        completed = parse_timestamp(action.get("completed_at_utc"), "failure completed_at_utc")
        observed = parse_timestamp(observed_at, "failure result observed_at_utc")
        if not sent <= requested <= completed <= observed:
            raise HarnessError("failure action timestamps are outside the exact request window")
        self.failure_injection_at = completed
        self.failure_observed = True

    def _validate_oom(self, evidence: dict[str, Any], request: dict[str, Any], observed_at: str) -> None:
        events = evidence.get("events")
        if type(events) is not list or len(events) > MAX_OOM_EVENTS:
            raise HarnessError("OOM evidence must retain a bounded array of raw kernel records")
        if request["phase"] == "before":
            if events:
                raise HarnessError("pre-pressure OOM watermark must not contain pre-existing event candidates")
            raw = require_text(evidence.get("journal_watermark_raw_record"), "OOM journal watermark record")
            digest = evidence.get("journal_watermark_raw_record_sha256")
            _verify_wire_hash(raw, digest, "OOM journal watermark", 65536)
            parsed = pressure.parse_journal_record(raw, expected_transport="kernel")
            self.oom_watermark = {"boot_id": parsed["boot_id"], "cursor": parsed["cursor"],
                                  "raw_record": raw, "raw_record_sha256": digest}
            target = self._terrabase_target()
            if request.get("oom_target") != target:
                raise HarnessError("pre-mutation OOM target differs from the current accepted process witness")
            raw_intent = require_object(evidence.get("oom_restore_intent"), "OOM pre-mutation restore intent")
            expected_fields = {
                "target", "native_runner_cgroup_path", "database_cgroup_path", "cgroup_inode",
                "prior_memory_max_bytes", "temporary_memory_max_bytes",
            }
            target_identity = {key: target[key] for key in (
                "kind", "pid", "process_start", "process_nonce", "cgroup", "host_boot_id",
            )}
            if set(raw_intent) != expected_fields:
                raise HarnessError("OOM pre-mutation restore intent has an unexpected shape")
            try:
                native, database, _role = _qualified_role_cgroups(
                    raw_intent["native_runner_cgroup_path"], target["cgroup"],
                )
            except HarnessError as error:
                raise HarnessError("OOM pre-mutation intent does not name the exact native TerraBase role") from error
            if (raw_intent.get("target") != target_identity or
                    native != self.native_runner_path or database != self.database_cgroup_path or
                    raw_intent.get("native_runner_cgroup_path") != str(self.native_runner_path) or
                    raw_intent.get("database_cgroup_path") != str(self.database_cgroup_path) or
                    require_int(raw_intent.get("cgroup_inode"), "OOM intent cgroup_inode", 1) <= 0 or
                    raw_intent.get("prior_memory_max_bytes") != self.qualification["database_memory_max_bytes"] or
                    raw_intent.get("temporary_memory_max_bytes") !=
                    self.pressure["oom_fault"]["target_memory_max_bytes"]):
                raise HarnessError("OOM pre-mutation restore intent differs from its exact signed target/cap")
            intent_path = self.evidence_dir / "oom-restore-intent.json"
            try:
                fd = os.open(intent_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(raw_intent, stream, sort_keys=True, indent=2)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                directory_fd = os.open(self.evidence_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as error:
                raise HarnessError("could not durably persist the native OOM restore obligation") from error
            self.oom_restore_intent = raw_intent
            self.oom_target = target
            return
        if self.oom_watermark is None or self.oom_target is None or self.oom_watermark != request.get("journal_watermark"):
            raise HarnessError("OOM evidence does not retain the pre-pressure kernel cursor/target")
        if self.pressure_started_at is None:
            raise HarnessError("OOM evidence has no pressure start timestamp")
        target = self._terrabase_target()
        if request.get("oom_target") != target:
            raise HarnessError("OOM fault target differs from the latest accepted native process witness")
        fault_requested = request.get("phase") == "during" and request.get("wait_for_event") is True
        if fault_requested and (self.oom_restore_intent is None or
                                request.get("oom_restore_intent") != self.oom_restore_intent):
            raise HarnessError("OOM mutation is missing its durable pre-mutation restore obligation")
        if fault_requested:
            report_observed = parse_timestamp(request.get("target_report_observed_at_utc"),
                                              "OOM target report observed_at_utc")
            request_sent = parse_timestamp(request.get("sent_at_utc"), "OOM fault request sent_at_utc")
            witness_age_ms = (request_sent - report_observed).total_seconds() * 1000
            if witness_age_ms < 0 or witness_age_ms > self.contract["target_witness_max_age_ms"]:
                raise HarnessError("OOM fault accepted host report/process witness is stale")
        threshold = self.pressure_started_at + dt.timedelta(
            seconds=self.pressure["scenario_event_after_seconds"])
        collected = parse_timestamp(observed_at, "OOM evidence observed_at_utc")
        max_window = self.contract["oom_event_window_seconds"]
        target_identity = {key: target[key] for key in (
            "kind", "pid", "process_start", "process_nonce", "cgroup", "host_boot_id",
        )}
        if fault_requested:
            memory_receipt = require_object(evidence.get("memory_limit_receipt"), "OOM memory limit receipt")
        else:
            memory_receipt = None
        receipt_fields = {
            "target", "prior_memory_max_bytes", "temporary_memory_max_bytes",
            "observed_memory_current_bytes", "target_cgroup_members_before",
            "target_child_cgroups_before", "target_cgroup_inode_before",
            "restored_memory_max_bytes", "restore_method", "restore_verified",
        }
        if fault_requested and set(memory_receipt) != receipt_fields:
            raise HarnessError("OOM memory limit receipt does not match the bounded native-role fault schema")
        fault = self.pressure["oom_fault"]
        if fault_requested and (memory_receipt.get("target") != target_identity or
                memory_receipt.get("prior_memory_max_bytes") != self.qualification["database_memory_max_bytes"] or
                memory_receipt.get("temporary_memory_max_bytes") != fault["target_memory_max_bytes"] or
                type(memory_receipt.get("observed_memory_current_bytes")) is not int or
                memory_receipt["observed_memory_current_bytes"] <= fault["target_memory_max_bytes"] or
                memory_receipt.get("target_cgroup_members_before") != [target["pid"]] or
                memory_receipt.get("target_child_cgroups_before") != [] or
                type(memory_receipt.get("target_cgroup_inode_before")) is not int or
                memory_receipt["target_cgroup_inode_before"] <= 0 or
                self.oom_restore_intent is None or
                memory_receipt["target_cgroup_inode_before"] != self.oom_restore_intent["cgroup_inode"] or
                memory_receipt.get("restored_memory_max_bytes") != self.qualification["database_memory_max_bytes"] or
                memory_receipt.get("restore_method") not in {"same_cgroup_fd", "native_role_recreated"} or
                memory_receipt.get("restore_verified") is not True):
            raise HarnessError("OOM memory cap was not safely lowered and restored on the exact native role")
        if fault_requested:
            self.oom_restore_receipt = memory_receipt
        expected_cgroup = _cgroup_file_path(target["cgroup"])
        matches = []
        for index, event in enumerate(events):
            row = require_object(event, f"OOM event {index}")
            raw = require_text(row.get("raw_record"), f"OOM event {index}.raw_record")
            _verify_wire_hash(raw, row.get("raw_record_sha256"), f"OOM event {index}", 65536)
            parsed = parse_kernel_oom_record(raw)
            event_at = parse_timestamp(parsed["event_at_utc"], f"OOM event {index} timestamp")
            if (row.get("source") == "kernel" and parsed["boot_id"] == self.oom_watermark["boot_id"] and
                    parsed["journal_cursor"] != self.oom_watermark["cursor"] and
                    parsed["victim_pid"] == target["pid"] and
                    parsed["cgroup_path"] == str(expected_cgroup) and
                    threshold <= event_at <= collected and
                    (event_at - threshold).total_seconds() <= max_window):
                matches.append(parsed)
        if matches:
            self.failure_injection_at = parse_timestamp(matches[0]["event_at_utc"], "matched OOM timestamp")
            self.failure_observed = True
            self.oom_observed = True
        elif request["phase"] == "after":
            raise HarnessError("kernel OOM records do not identify the exact pre-pressure TerraBase process/cgroup")

    def _terrabase_target(self) -> dict[str, Any]:
        if self.host_snapshot is None:
            raise HarnessError("TerraBase failure target needs an accepted current host report")
        row = self.host_snapshot["members"]["source"]
        witness = self.host_snapshot["process_witnesses"]["source"]
        managed = row["report"]["managed"]
        return {
            "kind": "terrabase", "node": self.member["source"]["node"],
            "pid": managed["process_pid"], "process_start": managed["process_start"],
            "process_nonce": managed["process_boot_id"], "cgroup": managed["process_cgroup"],
            "host_boot_id": witness["host_boot_id"],
            "stat_raw": witness["stat_raw"], "cgroup_raw": witness["cgroup_raw"],
        }

    def _failure_target(self) -> dict[str, Any]:
        scenario = self.pressure["scenario"]
        if scenario in {"terrabase_process", "terrabase_oom"}:
            if self.host_snapshot is None:
                raise HarnessError("TerraBase injection lacks a current accepted host report")
            report_age = (dt.datetime.now(dt.timezone.utc) -
                          self.host_snapshot["members"]["source"]["report_time"]).total_seconds()
            if report_age < 0 or report_age * 1000 > self.contract["target_witness_max_age_ms"]:
                raise HarnessError("accepted TerraBase report/process witness is stale before SIGKILL")
            target = self._terrabase_target()
            if scenario == "terrabase_oom":
                raise HarnessError("TerraBase OOM is observed from the kernel; pressure workers are not injected victims")
            if self.native_runner_path is None or self.database_cgroup_path is None:
                raise HarnessError("TerraBase SIGKILL lacks the qualifier-pinned native role cgroup")
            managed = self.host_snapshot["members"]["source"]["report"]["managed"]
            native, database, _role = _qualified_role_cgroups(
                str(self.native_runner_path), managed["process_cgroup"],
            )
            if native != self.native_runner_path or database != self.database_cgroup_path:
                raise HarnessError("TerraBase SIGKILL target differs from the qualifier-pinned native role cgroup")
            return target
        if scenario != "host_manager_sigkill" or SOURCE_UNIT not in self.service_snapshot:
            raise HarnessError("failure target is not an approved scenario or lacks a current service snapshot")
        unit = self.service_snapshot[SOURCE_UNIT]
        if self.host_snapshot is None:
            raise HarnessError("host-manager injection lacks a current accepted managed report")
        now = dt.datetime.now(dt.timezone.utc)
        unit_age = (now - unit["observed_at"]).total_seconds()
        report_age = (now - self.host_snapshot["members"]["source"]["report_time"]).total_seconds()
        if (unit_age < 0 or report_age < 0 or
                max(unit_age, report_age) * 1000 > self.contract["target_witness_max_age_ms"]):
            raise HarnessError("host manager and accepted managed report witnesses are stale before SIGKILL")
        return {"kind": "host_manager", "unit": SOURCE_UNIT, "pid": unit["main_pid"],
                "process_start": unit["process_start"],
                "cgroup": unit["control_group"].rstrip("/") + "/supervisor",
                "host_boot_id": self.host_snapshot["members"]["source"]["host_boot_id"],
                "stat_raw": unit["process_stat_raw"], "cgroup_raw": unit["process_cgroup_raw"]}

    def _protected_processes(self) -> list[dict[str, Any]]:
        values = []
        if self.host_snapshot:
            row = self.host_snapshot["members"]["source"]
            values.append({"kind": "terrabase:source", **row["managed_identity"]})
        if self.service_snapshot and SOURCE_UNIT in self.service_snapshot:
            row = self.service_snapshot[SOURCE_UNIT]
            values.append({"kind": SOURCE_UNIT, "pid": row["main_pid"],
                           "process_start": row["process_start"],
                           "cgroup": row["control_group"].rstrip("/") + "/supervisor"})
        return values

    def _protected_pids(self) -> set[int]:
        if self.host_snapshot is None:
            return set()
        result = {self.host_snapshot["members"]["source"]["managed_identity"]["pid"]}
        if self.service_snapshot and SOURCE_UNIT in self.service_snapshot:
            result.add(self.service_snapshot[SOURCE_UNIT]["main_pid"])
        return result

    def recovery_observation(self) -> None:
        """Require a replacement accepted report/proof and a renewed peer-visible write."""
        self.call("host_status", "post_recovery", wait_for_running_report=True)
        for guest_role in ("host", "controller"):
            self.call("service_state", "post_recovery", guest_role=guest_role)
        for guest_role in ("host", "controller"):
            self.call("qualify", "post_recovery", guest_role=guest_role)
        self.call("database_progress", "post_recovery")
        self.call("host_status", "after_write", wait_for_running_report=True)
        if self.last_event is not None:
            raise HarnessError("post-recovery database event lacks fresh source/peer ServingProof v1 coverage")
        if self.pressure["scenario"] in {"terrabase_process", "terrabase_oom"}:
            before = self.baseline_host_rows["source"]["managed_identity"]
            after = self.host_snapshot["members"]["source"]["managed_identity"]
            if (before["pid"], before["start"], before["nonce"]) == (after["pid"], after["start"], after["nonce"]):
                raise HarnessError("TerraBase process/OOM recovery did not replace its target PID/start identity")
            if before["cgroup"] != after["cgroup"]:
                raise HarnessError("TerraBase recovery did not return to the exact managed role cgroup")
        self.recovery_observed = True

    def _account(self, count: int, budget: int) -> None:
        if count < 0 or self.adapter_bytes + count > budget:
            raise HarnessError("run adapter request/evidence budget is exhausted")
        self.adapter_bytes += count

    def _write_observation(self, directory: Path, value: dict[str, Any], budget: int) -> None:
        wire = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(wire) > MAX_ADAPTER_OBSERVATION_BYTES:
            raise HarnessError("adapter observation exceeds its fixed metadata bound")
        self._account(len(wire), budget)
        (directory / "observation.json").write_bytes(wire)


def evaluate_run_status(failures: list[str], *, pressure_started: bool,
                        pressure_completed: bool, scenario: str,
                        recovery_observed: bool,
                        memory_sample_phases: set[str]) -> tuple[str, list[str]]:
    """Decide a bounded run from observed outcomes, not floor-origin labels."""
    reasons = list(failures)
    if reasons:
        return "FAIL", reasons
    if not pressure_started:
        return "UNQUALIFIED", ["pressure did not start"]
    if not pressure_completed:
        return "FAIL", ["all load workers did not complete the full configured duration"]
    if scenario != "management_stability" and not recovery_observed:
        return "FAIL", ["recovery evidence is incomplete"]
    required = {f"{guest_role}:{phase}" for guest_role in ("host", "controller")
                for phase in ("before", "during", "after")}
    missing_phases = sorted(required - memory_sample_phases)
    if missing_phases:
        return "UNQUALIFIED", [
            "role-bound guest memory usage samples are missing phases: " + ", ".join(missing_phases),
        ]
    return "PASS", []


def run_qualification(manifest: dict[str, Any], manifest_wire: bytes,
                      manifest_hash: str, evidence_dir: Path) -> int:
    missing = pressure.validate_manifest(manifest, dry_run=True, allow_allocations=True)
    if not missing:
        pressure.validate_manifest(manifest, dry_run=False, allow_allocations=True)
    try:
        evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError as error:
        raise HarnessError(f"evidence directory already exists: {evidence_dir}") from error
    os.chmod(evidence_dir, 0o700)
    if missing:
        summary = {
            "schema": pressure.SCHEMA, "qualification_status": "UNQUALIFIED",
            "started_at_utc": utc_now(), "finished_at_utc": utc_now(),
            "manifest_sha256": manifest_hash, "identity": manifest["identity"],
            "controller_identity": manifest["controller_identity"],
            "managed_member": manifest["managed_member"],
            "memory_floor_evidence": manifest["memory_floor_evidence"],
            "controller_memory_floor_evidence": manifest["controller_memory_floor_evidence"],
            "pressure": manifest["pressure"],
            "missing_or_unqualified": sorted(set(missing)),
            "commands_executed": False, "pressure_started": False,
        }
        write_json(evidence_dir / "summary.json", summary)
        (evidence_dir / "manifest.json").write_bytes(manifest_wire)
        (evidence_dir / "manifest.sha256").write_text(f"{manifest_hash}  manifest.json\n", encoding="ascii")
        write_checksums(evidence_dir)
        print(f"UNQUALIFIED: {evidence_dir / 'summary.json'}")
        return 1

    runner = AdapterRunner(manifest, manifest_hash, evidence_dir)
    run_started = utc_now()
    failures: list[str] = []
    pressure_attempted = False
    pressure_started = False
    try:
        runner.call("target_identity", "preflight")
        runner.call("host_status", "before")
        for guest_role in ("host", "controller"):
            runner.call("service_state", "before", guest_role=guest_role)
        for guest_role in ("host", "controller"):
            runner.call("qualify", "before", guest_role=guest_role)
        runner.call("database_progress", "before")
        runner.call("host_status", "after_write")
        if runner.last_event is not None:
            raise HarnessError("initial ObjectDurable write lacks matching source/peer serving proof")
        if manifest["pressure"]["scenario"] == "terrabase_oom":
            runner.call("kernel_oom_evidence", "before")

        pressure_attempted = True
        runner.call("pressure_start", "start", expires_after_seconds=manifest["pressure"]["duration_seconds"])
        pressure_started = True
        runner.call("pressure_status", "during", sample_number=0, pressure_handle=runner.handle)
        start = time.monotonic()
        deadline = start + manifest["pressure"]["duration_seconds"]
        next_sample = start + manifest["pressure"]["sample_interval_seconds"]
        fault_at = (start + manifest["pressure"]["scenario_event_after_seconds"]
                    if manifest["pressure"]["scenario"] != "management_stability" else None)
        sample_number = 0
        fault_completed = False
        while time.monotonic() < deadline:
            now = time.monotonic()
            due_fault = fault_at is not None and not fault_completed and now >= fault_at
            due_sample = now >= next_sample
            if not due_fault and not due_sample:
                wake = min(deadline, next_sample, fault_at if fault_at is not None and not fault_completed else deadline)
                time.sleep(min(max(0.0, wake - time.monotonic()), 0.25))
                continue
            if due_fault:
                scenario = manifest["pressure"]["scenario"]
                runner.call("pressure_status", "pre_injection", pressure_handle=runner.handle)
                if scenario == "terrabase_oom":
                    for guest_role in ("controller", "host"):
                        runner.call("service_state", "pre_failure", guest_role=guest_role)
                    runner.call("host_status", "pre_failure")
                    runner.call("kernel_oom_evidence", "during", wait_for_event=True)
                    fault_completed = runner.oom_observed
                    if fault_completed:
                        runner.recovery_observation()
                else:
                    for guest_role in ("controller", "host"):
                        runner.call("service_state", "pre_failure", guest_role=guest_role)
                    runner.call("host_status", "pre_failure")
                    runner.call("failure_inject", "during", mode=scenario,
                                pressure_handle=runner.handle)
                    fault_completed = runner.failure_observed
                    runner.recovery_observation()
                if not fault_completed and scenario != "terrabase_oom":
                    raise HarnessError("named failure action was not observed")
                if fault_at is not None:
                    fault_at = None
                if time.monotonic() >= deadline:
                    break
            if due_sample and time.monotonic() < deadline:
                sample_number += 1
                runner.call("pressure_status", "during", sample_number=sample_number,
                            pressure_handle=runner.handle)
                if manifest["pressure"]["scenario"] == "terrabase_oom" and not runner.oom_observed and fault_at is None:
                    runner.call("kernel_oom_evidence", "during", wait_for_event=True)
                    if runner.oom_observed:
                        runner.recovery_observation()
                for guest_role in ("host", "controller"):
                    runner.call("service_state", "during", guest_role=guest_role)
                runner.call("host_status", "during", oom_window_open=(
                    manifest["pressure"]["scenario"] == "terrabase_oom" and
                    runner.pressure_started_at is not None and
                    dt.datetime.now(dt.timezone.utc) >= runner.pressure_started_at + dt.timedelta(
                        seconds=manifest["pressure"]["scenario_event_after_seconds"])))
                for guest_role in ("host", "controller"):
                    runner.call("qualify", "during", guest_role=guest_role)
                runner.call("database_progress", "during")
                runner.call("host_status", "after_write")
                if runner.last_event is not None:
                    raise HarnessError("during-pressure ObjectDurable event lacks alpha source/receiver proof coverage")
                next_sample += manifest["pressure"]["sample_interval_seconds"]
        if time.monotonic() < deadline:
            time.sleep(deadline - time.monotonic())
        runner.call("pressure_status", "complete", pressure_handle=runner.handle,
                    expect_pressure_completed=True)
        if manifest["pressure"]["scenario"] == "terrabase_oom" and not runner.oom_observed:
            runner.call("kernel_oom_evidence", "after", wait_for_event=False)
        if manifest["pressure"]["scenario"] != "management_stability" and not runner.recovery_observed:
            raise HarnessError("named failure did not produce a fresh accepted report/proof and renewed read/write")
    except (HarnessError, OSError, ValueError, subprocess.SubprocessError) as error:
        failures.append(str(error))
    finally:
        if pressure_attempted:
            for role, phase in (("pressure_stop", "cleanup"), ("cleanup_verify", "cleanup")):
                try:
                    runner.call(role, phase, pressure_handle=runner.handle, run_id=runner.run_id)
                except (HarnessError, OSError, ValueError, subprocess.SubprocessError) as error:
                    failures.append(str(error))
                    if (role == "cleanup_verify" and runner.oom_restore_intent is not None and
                            runner.oom_restore_unresolved_reason is None):
                        runner.oom_restore_unresolved_reason = f"cleanup adapter failed: {type(error).__name__}"
            if pressure_started:
                try:
                    for guest_role in ("host", "controller"):
                        runner.call("service_state", "after", guest_role=guest_role)
                    runner.call("host_status", "after", wait_for_running_report=True)
                    for guest_role in ("host", "controller"):
                        runner.call("qualify", "after", guest_role=guest_role)
                    runner.call("database_progress", "after")
                    runner.call("host_status", "after_write", wait_for_running_report=True)
                    if runner.last_event is not None:
                        raise HarnessError("final ObjectDurable operation lacks fresh source/peer serving proof")
                except (HarnessError, OSError, ValueError, subprocess.SubprocessError) as error:
                    failures.append(str(error))
                if manifest["pressure"]["scenario"] == "terrabase_oom":
                    try:
                        runner.call("kernel_oom_evidence", "after", wait_for_event=False)
                    except (HarnessError, OSError, ValueError, subprocess.SubprocessError) as error:
                        failures.append(str(error))

    sample_phases = {f"{sample['guest_role']}:{sample['phase']}"
                     for sample in runner.memory_usage_samples}
    state, status_reasons = evaluate_run_status(
        failures, pressure_started=pressure_started,
        pressure_completed=runner.pressure_completed,
        scenario=manifest["pressure"]["scenario"],
        recovery_observed=runner.recovery_observed,
        memory_sample_phases=sample_phases,
    )
    failures.extend(status_reasons)
    summary = {
        "schema": pressure.SCHEMA, "qualification_status": state,
        "started_at_utc": run_started, "finished_at_utc": utc_now(),
        "repository_revision": manifest.get("repository_revision"),
        "harness_sha256": runner.harness_sha256, "manifest_sha256": manifest_hash,
        "run_id": runner.run_id, "adapter_contract": manifest["adapter_contract"],
        "authorization": manifest["authorization"], "identity": manifest["identity"],
        "controller_identity": manifest["controller_identity"],
        "managed_member": manifest["managed_member"], "qualification": manifest["qualification"],
        "controller_qualification": manifest["controller_qualification"],
        "memory_floor_evidence": manifest["memory_floor_evidence"], "pressure": manifest["pressure"],
        "controller_memory_floor_evidence": manifest["controller_memory_floor_evidence"],
        "memory_usage_sampling": {
            "schema": pressure.MEMORY_USAGE_SAMPLE_SCHEMA,
            "baseline_sample_sha256_by_guest": {
                guest_role: next((sample["sample_sha256"]
                                  for sample in runner.memory_usage_samples
                                  if sample["phase"] == "before" and sample["guest_role"] == guest_role), None)
                for guest_role in ("host", "controller")
            },
            "sample_count": len(runner.memory_usage_samples),
            "sample_phases": sorted(sample_phases),
            "samples": runner.memory_usage_samples,
            "floor_basis_by_scope": {scope: manifest["memory_floor_evidence"][scope]["basis"]
                                      for scope in pressure.FLOOR_SCOPES},
            "controller_floor_basis_by_scope": {
                scope: evidence["basis"]
                for scope, evidence in manifest["controller_memory_floor_evidence"].items()
            },
        },
        "pressure_attempted": pressure_attempted, "pressure_started": pressure_started,
        "pressure_completed": runner.pressure_completed,
        "failure_observed": runner.failure_observed, "recovery_observed": runner.recovery_observed,
        "object_durable_oom_observed": runner.oom_observed,
        "oom_restore_cleanup": {
            "intent": runner.oom_restore_intent,
            "verified": runner.oom_restore_cleanup_verified,
            "unresolved_reason": runner.oom_restore_unresolved_reason,
        } if runner.oom_restore_intent is not None else None,
        "observations": runner.results, "failures": failures,
        "limitations": [
            "operator hosts HostStatus.verified is retained as emitted by the read-only command; it is not a portable report signature.",
            "HostStatus does not expose the signed live_s3_config_sha256; the write receipt must say object_durable and match the exact event/proofs.",
            "Remote transport and HTTPS credentials remain exact owner-supplied, pinned adapter settings; no target is contacted by dry-run.",
        ],
    }
    write_json(evidence_dir / "summary.json", summary)
    (evidence_dir / "manifest.json").write_bytes(manifest_wire)
    (evidence_dir / "manifest.sha256").write_text(f"{manifest_hash}  manifest.json\n", encoding="ascii")
    write_checksums(evidence_dir)
    print(f"{state}: {evidence_dir / 'summary.json'}")
    return 0 if state == "PASS" else 1


def validate_report_evidence_for_previous(snapshot: dict[str, Any], label: str,
                                          previous: dict[str, Any], request: dict[str, Any]) -> None:
    current = snapshot["members"][label]
    scenario = request["pressure"].get("scenario")
    phase = request.get("phase")
    if label == "source" and phase == "post_recovery" and scenario in {
            "terrabase_process", "terrabase_oom"}:
        old = previous["managed_identity"]
        new = current["managed_identity"]
        if (old["pid"], old["start"], old["nonce"]) == (new["pid"], new["start"], new["nonce"]):
            raise HarnessError("TerraBase recovery report did not advance its actual process identity")
        if old["cgroup"] != new["cgroup"]:
            raise HarnessError("TerraBase recovery changed the expected native workload role cgroup")
    elif current["managed_identity"] != previous["managed_identity"]:
        raise HarnessError(f"{label} managed member identity changed outside its named recovery scenario")
