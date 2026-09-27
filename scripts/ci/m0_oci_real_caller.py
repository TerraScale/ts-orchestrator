#!/usr/bin/env python3
"""Verify an already deployed two-member OCI pair through its real callers.

The owner supplies a private-network executor and exact retained artifacts.
This command never creates an OCI instance or installs a database process.
"""

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid


class QualificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def read_json(path: Path, limit: int = 1 << 20) -> dict:
    wire = path.read_bytes()
    require(0 < len(wire) <= limit, "input JSON is empty or oversized")
    value = json.loads(wire)
    require(isinstance(value, dict), "input JSON must be an object")
    return value


def digest_file(path: Path, expected: str) -> str:
    require(len(expected) == 64 and all(c in "0123456789abcdef" for c in expected),
            "expected SHA-256 is malformed")
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    require(digest == expected, f"artifact digest mismatch: {path.name}")
    return digest


def require_elf(path: Path, machine: int) -> None:
    with path.open("rb") as source:
        header = source.read(20)
    require(len(header) == 20 and header[:6] == b"\x7fELF\x02\x01" and
            int.from_bytes(header[18:20], "little") == machine,
            f"retained binary has the wrong ELF target: {path.name}")


def qualification(path: Path, digest: str, schema: str, workflow: str,
                  source_sha: str, artifact: str, artifact_sha: str, artifact_size: int) -> dict:
    digest_file(path, digest)
    record = read_json(path)
    check = record.get("verification", {})
    expected_repository = "TerraScale/ts-orchestrator" if workflow == "ci.yml" else "TerraScale/TerraBase"
    expected_job = "verify/go + artifact/linux-amd64-arm64" if workflow == "ci.yml" else "fast"
    require(len(source_sha) == 40 and all(c in "0123456789abcdef" for c in source_sha) and
            record.get("schema") == schema and record.get("repository") == expected_repository and
            record.get("source_revision") == source_sha and
            isinstance(record.get("source_tree"), str) and len(record["source_tree"]) == 40 and
            check.get("workflow") == workflow and check.get("conclusion") == "success" and
            check.get("job") == expected_job and
            isinstance(check.get("run_id"), int) and check["run_id"] > 0 and
            isinstance(check.get("run_number"), int) and check["run_number"] > 0,
            "qualification source or successful CI run is invalid")
    if workflow == "fast.yml":
        require(record.get("target") == "aarch64-unknown-linux-gnu" and
                record.get("build_profile") == "release", "native qualification target is invalid")
    else:
        require(record.get("go_version") == "go1.27.1" and all(
            isinstance(record.get(key), str) and len(record[key]) == 64 and
            all(c in "0123456789abcdef" for c in record[key])
            for key in ("go_mod_sha256", "go_sum_sha256")),
            "qualified Go module source hashes are invalid")
    matches = [item for item in record.get("artifacts", []) if item.get("name") == artifact]
    require(len(matches) == 1 and matches[0].get("sha256") == artifact_sha and
            matches[0].get("bytes") == artifact_size, "qualification artifact differs from retained bytes")
    return {"sha256": digest, "source_revision": source_sha,
            "source_tree": record.get("source_tree"), "run_id": check["run_id"],
            "run_number": check["run_number"], "artifact_sha256": artifact_sha,
            "go_mod_sha256": record.get("go_mod_sha256"),
            "go_sum_sha256": record.get("go_sum_sha256")}


BOOTSTRAP_RECEIPT_FIELDS = {
    "schema", "repository", "source_revision", "source_tree", "source_clean_before",
    "source_clean_after", "go_version", "go_mod_sha256", "go_sum_sha256", "goos", "goarch",
    "cgo_enabled", "binary_name", "binary_sha256", "binary_bytes", "vcs_revision",
    "vcs_modified", "elf_machine", "has_interp", "has_needed", "build_exit",
    "build_command_sha256", "build_log_sha256", "test_exit", "test_command_sha256",
    "test_log_sha256",
}


def bootstrap_provenance(path: Path, expected_sha: str, binary: Path, binary_sha: str,
                         go_qualification: dict, retained: dict[str, Path]) -> dict:
    digest_file(path, expected_sha)
    require_elf(binary, 62)
    record = read_json(path, 16 << 10)
    require(set(record) == BOOTSTRAP_RECEIPT_FIELDS and
            record["schema"] == "terrascale.bootstrap.local-build.v1" and
            record["repository"] == "TerraScale/ts-orchestrator" and
            record["source_revision"] == go_qualification["source_revision"] and
            record["source_tree"] == go_qualification["source_tree"] and
            record["source_clean_before"] is True and record["source_clean_after"] is True and
            record["go_version"] == "go1.27.1" and
            record["go_mod_sha256"] == go_qualification["go_mod_sha256"] and
            record["go_sum_sha256"] == go_qualification["go_sum_sha256"] and
            record["goos"] == "linux" and record["goarch"] == "amd64" and
            record["cgo_enabled"] is False and record["binary_name"] == "ts-bootstrap" and
            record["binary_sha256"] == binary_sha and
            record["binary_bytes"] == binary.stat().st_size and
            record["vcs_revision"] == record["source_revision"] and
            record["vcs_modified"] is False and
            record["elf_machine"] == "Advanced Micro Devices X86-64" and
            record["has_interp"] is False and record["has_needed"] is False and
            record["build_exit"] == 0 and record["test_exit"] == 0 and
            all(isinstance(record[key], str) and len(record[key]) == 64 and
                all(c in "0123456789abcdef" for c in record[key]) for key in (
                    "go_mod_sha256", "go_sum_sha256", "build_command_sha256", "build_log_sha256",
                    "test_command_sha256", "test_log_sha256")),
            "bootstrap build receipt differs from the qualified Go source or retained binary")
    require(set(retained) == {"build_command", "build_log", "test_command", "test_log"},
            "bootstrap build receipt lacks retained command or log evidence")
    for name, evidence_path in retained.items():
        digest_file(evidence_path, record[f"{name}_sha256"])
    metadata = subprocess.run(["go", "version", "-m", str(binary)], capture_output=True,
                              text=True, timeout=10, check=False)
    require(metadata.returncode == 0 and
            "go1.27.1" in metadata.stdout and
            f"vcs.revision={record['source_revision']}" in metadata.stdout and
            "vcs.modified=false" in metadata.stdout and
            "CGO_ENABLED=0" in metadata.stdout,
            "bootstrap binary Go build metadata differs from clean local receipt")
    elf = subprocess.run(["readelf", "-l", "-d", str(binary)], capture_output=True,
                         text=True, timeout=10, check=False)
    require(elf.returncode == 0 and "INTERP" not in elf.stdout and "(NEEDED)" not in elf.stdout,
            "bootstrap binary is dynamically linked")
    return {"sha256": expected_sha, "source_revision": record["source_revision"],
            "source_tree": record["source_tree"], "binary_sha256": binary_sha,
            "retained_evidence_sha256": {name: record[f"{name}_sha256"] for name in sorted(retained)}}


def catalog_binding(spec: dict, collection_id: str) -> tuple[int, str]:
    rows = [row for row in spec.get("catalogs", []) if row.get("collection_id") == collection_id]
    require(len(rows) == 1, "selected collection is absent or duplicated in signed spec")
    wire = base64.b64decode(rows[0]["canonical_catalog"], validate=True)
    require(len(wire) >= 84 and wire[:8] == b"TBCAT001" and
            int.from_bytes(wire[8:12], "little") == len(wire) and
            wire[12:28] == uuid.UUID(collection_id).bytes, "signed catalog framing is invalid")
    generation = int.from_bytes(wire[28:36], "little")
    schema_digest = wire[44:76].hex()
    schema_len = int.from_bytes(wire[76:80], "little")
    require(generation > 0 and schema_len > 0 and 80 + schema_len + 4 == len(wire) and
            hashlib.sha256(wire[80:-4]).hexdigest() == schema_digest,
            "signed catalog schema binding is invalid")
    return generation, schema_digest


def customer_material(reply: dict, opened: dict) -> tuple[str, str]:
    customer = reply.get("customer", {})
    token, ca = opened.get("token"), opened.get("https_ca_pem")
    require(opened.get("version") == 1 and isinstance(token, str) and isinstance(ca, str),
            "opened customer material is invalid")
    parts = token.split(".")
    require(len(parts) == 3 and parts[0] == "tbk1" and parts[1] == customer.get("token_id"),
            "customer token ID differs from verified preparation reply")
    try:
        token_id = base64.urlsafe_b64decode(parts[1] + "==")
        secret = base64.urlsafe_b64decode(parts[2] + "==")
    except ValueError as error:
        raise QualificationError("customer token encoding is invalid") from error
    require(len(token_id) == 16 and len(secret) == 32, "customer token length is invalid")
    verifier = hashlib.sha256(b"TB-APIKEY-V1\0" + token_id + secret).hexdigest()
    require(verifier == customer.get("verifier_sha256") and
            hashlib.sha256(ca.encode()).hexdigest() == customer.get("https_ca_sha256"),
            "opened customer material differs from verified preparation reply")
    return token, ca


def endpoint(member: dict) -> tuple[str, int]:
    address = ipaddress.ip_address(member["client_ip"])
    port = member["client_port"]
    require(address.is_private and not address.is_loopback and not address.is_link_local and
            isinstance(port, int) and 1 <= port <= 65535,
            "signed member HTTPS endpoint is not a private unicast address")
    return str(address), port


def document_id() -> str:
    # UUIDv7: a fresh point read must be absent before the write.
    millis = time.time_ns() // 1_000_000
    value = (millis << 80) | (7 << 76) | (secrets.randbits(12) << 64) | (2 << 62) | secrets.randbits(62)
    return str(uuid.UUID(int=value))


class ForwardedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, identity: tuple[str, int], connect_to: tuple[str, int],
                 context: ssl.SSLContext):
        super().__init__(*identity, timeout=10, context=context)
        self.connect_to = connect_to

    def connect(self) -> None:
        raw = socket.create_connection(self.connect_to, self.timeout)
        try:
            # The local socket is only a TCP route. The signed member IP remains
            # both the HTTP Host and the certificate identity checked by TLS.
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def request(target: tuple[str, int], connect_to: tuple[str, int], context: ssl.SSLContext,
            token: str, method: str, path: str, body: dict | None = None) -> dict:
    wire = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Authorization": "Bearer " + token}
    if wire is not None:
        headers["Content-Type"] = "application/json"
    connection = ForwardedHTTPSConnection(target, connect_to, context)
    try:
        connection.request(method, path, body=wire, headers=headers)
        response = connection.getresponse()
        data = response.read((64 << 10) + 1)
        require(response.status == 200 and len(data) <= 64 << 10,
                "authenticated member HTTPS request failed or response was oversized")
        value = json.loads(data)
        require(isinstance(value, dict), "member HTTPS response is not a JSON object")
        return value
    finally:
        connection.close()


def parse_forward(raw: str, remote_port: int) -> tuple[tuple[str, int], tuple[str, int]]:
    try:
        source, destination = raw.split("=", 1)
        source_ip, source_port = source.rsplit(":", 1)
        local_ip, local_port = destination.rsplit(":", 1)
        ip = ipaddress.ip_address(source_ip)
        loopback = ipaddress.ip_address(local_ip)
        source_num = int(source_port)
        local_num = int(local_port)
    except (ValueError, TypeError) as error:
        raise QualificationError("forward mapping has invalid syntax") from error
    require(ip.version == 4 and str(ip) == source_ip and ip.is_private and
            not ip.is_loopback and not ip.is_link_local and
            source_num == remote_port and source_port == str(remote_port) and
            loopback == ipaddress.ip_address("127.0.0.1") and local_ip == "127.0.0.1" and
            1 <= local_num <= 65535 and local_port == str(local_num),
            "forward mapping must use a canonical private source and IPv4 loopback port")
    return (source_ip, source_num), (local_ip, local_num)


def forwards(raw_values: list[str], targets: set[tuple[str, int]], remote_port: int,
             required: bool) -> dict[tuple[str, int], tuple[str, int]]:
    require(bool(raw_values) or not required, "required Bastion forwarding mappings are absent")
    mappings = [parse_forward(raw, remote_port) for raw in raw_values]
    routes = dict(mappings)
    require(len(routes) == len(mappings) and set(routes) <= targets and
            len(set(routes.values())) == len(mappings) and
            (not required or set(routes) == targets),
            "forwarding entries are unknown, duplicate, or incomplete")
    for destination in routes.values():
        with socket.create_connection(destination, timeout=2):
            pass
    return routes


def configured_controllers(config: Path) -> set[tuple[str, int]]:
    urls = read_json(config)["nats"]["url"].split(",")
    controllers = set()
    for url in urls:
        require(url.startswith("tls://") and url.count(":") == 2,
                "installed operator config has an unexpected controller URL")
        address, port = url[6:].rsplit(":", 1)
        require(port == "4222" and str(ipaddress.ip_address(address)) == address,
                "installed operator config has a noncanonical controller URL")
        controllers.add((address, 4222))
    require(len(controllers) == len(urls) and len(controllers) == 3,
            "installed operator config lacks three distinct controller URLs")
    return controllers


def hosts(operator: Path, config: Path, nats_forwards: list[str]) -> list:
    command = [str(operator), "operator", "hosts", "--config", str(config)]
    for forward in nats_forwards:
        command.extend(("--nats-forward", forward))
    result = subprocess.run(command,
                            capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 1 << 20,
            "authenticated operator hosts request failed")
    statuses = json.loads(result.stdout)
    require(isinstance(statuses, list), "operator hosts response is invalid")
    return statuses


def member_report(statuses: list, spec: dict, member: dict, peer: dict, cell: str,
                  instance_id: str, artifact_sha: str) -> dict:
    scope = spec["scope"]
    matching = [status for status in statuses
                if status.get("registration", {}).get("managed_member", {}).get("scope", {}).get("member_id") == member["member_id"]]
    require(len(matching) == 1, "expected member has no unique registered host")
    status = matching[0]
    registration = status["registration"]
    binding = registration.get("managed_member", {}).get("scope", {})
    oci = registration.get("managed_oci", {})
    placement = registration.get("managed_placement", {})
    require(registration.get("cell") == cell and
            registration.get("environment") == "production" and
            oci.get("instance_id") == instance_id and oci.get("region") == "GRU" and
            placement.get("database_id") == spec["placement_database_id"] and
            placement.get("partition_id") == spec["partition_id"] and
            placement.get("seat_id") == member["seat_id"] and
            all(binding.get(key) == scope.get(key) for key in ("cluster_id", "tenant_id", "database_id", "shard_id")) and
            binding.get("member_id") == member["member_id"] and
            binding.get("incarnation") == member["incarnation"],
            "registered host differs from signed placement, instance or member")
    reports = [report for report in status.get("reports", []) if report.get("role") == "terrabase"]
    require(len(reports) == 1, "expected member has no unique TerraBase report")
    report = reports[0]
    managed = report.get("managed") or {}
    proof = managed.get("serving_proof") or {}
    replication = proof.get("replication") or {}
    observed = report.get("observed_at", "")
    try:
        from datetime import datetime, timezone
        observed_at = datetime.fromisoformat(observed.replace("Z", "+00:00"))
        session_end = datetime.fromisoformat(status.get("session_expires_at", "").replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        fresh = 0 <= (now - observed_at).total_seconds() < 30 and session_end > now
    except (ValueError, TypeError):
        fresh = False
    require(fresh and report.get("cell") == cell and
            report.get("environment") == registration.get("environment") and
            report.get("node") == registration.get("node") and
            report.get("state") == "running" and report.get("digest") == artifact_sha and
            managed.get("member") == registration.get("managed_member") and
            managed.get("oci") == oci and managed.get("process_pid", 0) > 1 and
            managed.get("storage_recovered") is True and managed.get("listener_ready") is True and
            proof.get("serving") is True and proof.get("listeners") == {"client": True, "replication": True} and
            proof.get("scope") == binding and proof.get("authority") == managed.get("authority") and
            proof.get("process") == {"pid": managed.get("process_pid"),
                                     "start_nonce": managed.get("process_boot_id")} and
            replication.get("peer_member_id") == peer["member_id"] and
            replication.get("peer_incarnation") == peer["incarnation"] and
            replication.get("current_authenticated") is True,
            "current host report lacks the exact running managed process or serving proof")
    return {"instance_id": instance_id, "node": report["node"], "observed_at": observed,
            "artifact_sha256": report["digest"], "process_pid": managed["process_pid"],
            "process_boot_id": managed.get("process_boot_id"),
            "member_id": member["member_id"], "serving_proof": proof}


def run(args: argparse.Namespace) -> dict:
    require(args.cell == "gru", "M0 OCI caller is scoped to the GRU regional cell")
    go_sha = digest_file(args.operator, args.operator_sha256)
    require_elf(args.operator, 62)
    digest_file(args.bootstrap, args.bootstrap_sha256)
    tb_sha = digest_file(args.tb_binary, args.tb_sha256)
    require_elf(args.tb_binary, 183)
    go_qualification = qualification(args.go_qualification, args.go_qualification_sha256,
        "terrascale.release.qualification.v1", "ci.yml", args.go_source_sha,
        "terrascale-orchestrator-linux-amd64", go_sha, args.operator.stat().st_size)
    bootstrap_receipt = bootstrap_provenance(
        args.bootstrap_build_receipt, args.bootstrap_build_receipt_sha256, args.bootstrap,
        args.bootstrap_sha256, go_qualification, {
            "build_command": args.bootstrap_build_command,
            "build_log": args.bootstrap_build_log,
            "test_command": args.bootstrap_test_command,
            "test_log": args.bootstrap_test_log,
        })
    tb_qualification = qualification(args.tb_qualification, args.tb_qualification_sha256,
        "terrascale.terrabase.qualification.v1", "fast.yml", args.tb_source_sha,
        "tb-server-linux-arm64", tb_sha, args.tb_binary.stat().st_size)
    require(args.instance_a != args.instance_b, "two distinct OCI member instances are required")
    spec = read_json(args.spec, 16 << 10)
    reply = read_json(args.reply, 64 << 10)
    require(reply.get("receipt", {}).get("spec") == spec,
            "preparation receipt differs from requested member spec")
    with tempfile.TemporaryDirectory(prefix="ts-m0-customer-") as directory:
        opened_path = Path(directory) / "opened.json"
        command = [str(args.bootstrap), "open-customer-material", "--reply", str(args.reply),
                   "--spec", str(args.spec), "--controller-key", str(args.controller_key),
                   "--cell", args.cell, "--recipient-key", str(args.recipient_key),
                   "--out", str(opened_path)]
        result = subprocess.run(command, capture_output=True, timeout=30, check=False)
        require(result.returncode == 0 and opened_path.is_file() and
                opened_path.stat().st_mode & 0o077 == 0,
                "offline signed customer material opening failed")
        token, ca = customer_material(reply, read_json(opened_path, 16 << 10))
    context = ssl.create_default_context(cadata=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    members = spec["members"]
    require(isinstance(members, list) and len(members) == 2,
            "signed spec does not contain two members")
    a, b = members
    target_a, target_b = endpoint(a), endpoint(b)
    require(target_a != target_b, "signed members share one client endpoint")
    nats_routes = forwards(args.nats_forward, configured_controllers(args.operator_config), 4222, False)
    require(bool(nats_routes), "at least one reviewed controller NATS forward is required")
    https_routes = forwards(args.https_forward, {target_a, target_b}, 9465, True)
    require(set(nats_routes.values()).isdisjoint(https_routes.values()),
            "controller and member forwards share a local port")
    generation, schema_digest = catalog_binding(spec, args.collection_id)
    scope = spec["scope"]
    prefix = (f"/v1/tenants/{scope['tenant_id']}/databases/{scope['database_id']}"
              f"/shards/{scope['shard_id']}")
    point = f"{prefix}/collections/{args.collection_id}/documents/{document_id()}"
    doc_id = point.rsplit("/", 1)[1]
    before = hosts(args.operator, args.operator_config, args.nats_forward)
    a_before = member_report(before, spec, a, b, args.cell, args.instance_a, tb_sha)
    b_before = member_report(before, spec, b, a, args.cell, args.instance_b, tb_sha)
    base_source = a_before["serving_proof"]["replication"]["local_source_sequence"]
    base_inbox = b_before["serving_proof"]["replication"]["local_inbox_applied_sequence"]
    absent = request(target_b, https_routes[target_b], context, token, "GET", point)
    require(absent.get("version") == 1 and absent.get("state") == "absent" and
            absent.get("context") == [] and absent.get("siblings") == [],
            "B did not show a fresh absent document before the write")
    transaction = {"version": 1,
        "transaction_id": {"expires_at_unix_ms": str(int(time.time() * 1000) + 3600000),
                           "nonce": secrets.token_hex(16)},
        "writes": [{"collection": args.collection_id, "document": doc_id,
                    "schema_generation": str(generation), "schema_digest": schema_digest,
                    "observed": [], "value": {"kind": "live", "fields": []}}]}
    receipt = request(target_a, https_routes[target_a], context, token,
                      "POST", prefix + "/transactions", transaction)
    require(receipt.get("durability") == "local_durable" and
            not any(key in receipt for key in ("received", "applied", "remote_ack")),
            "A did not return a bounded local durable write receipt")
    deadline = time.monotonic() + 90
    while True:
        value = request(target_b, https_routes[target_b], context, token, "GET", point)
        siblings = value.get("siblings")
        if (value.get("version") == 1 and value.get("state") == "value" and
                isinstance(siblings, list) and len(siblings) == 1 and
                siblings[0].get("kind") == "live" and siblings[0].get("fields") == [] and
                siblings[0].get("schema_generation") == str(generation) and
                siblings[0].get("schema_digest") == schema_digest):
            break
        require(time.monotonic() < deadline, "B did not read A's authenticated write")
        time.sleep(0.25)
    deadline = time.monotonic() + 30
    while True:
        after = hosts(args.operator, args.operator_config, args.nats_forward)
        a_after = member_report(after, spec, a, b, args.cell, args.instance_a, tb_sha)
        b_after = member_report(after, spec, b, a, args.cell, args.instance_b, tb_sha)
        ap = a_after["serving_proof"]["replication"]
        bp = b_after["serving_proof"]["replication"]
        sequence = ap["local_source_sequence"]
        if (sequence > base_source and ap["peer_durable_sequence"] >= sequence and
                ap["peer_applied_sequence"] >= sequence and
                bp["local_inbox_durable_sequence"] >= sequence and
                bp["local_inbox_applied_sequence"] >= sequence and
                bp["local_inbox_applied_sequence"] > base_inbox):
            break
        require(time.monotonic() < deadline, "current signed reports lack post-write peer ACK frontier")
        time.sleep(0.5)
    return {"result": "scenario_passed", "profile": "m0-oci-real-caller-v1",
            "scope": "authenticated two-member document write/read and current peer ACK reports",
            "external_evidence_required": [
                "current signed ARM64 image receipt binding deployed Go binary and OCI image OCID",
                "retained ts-bootstrap binary source and successful qualification manifest",
                "live OCI image and ownership readback for both member instance IDs",
                "deployed host Go binary admission and approved private caller route"],
            "go_qualification": go_qualification, "tb_qualification": tb_qualification,
            "bootstrap_sha256": args.bootstrap_sha256,
            "bootstrap_build_receipt": bootstrap_receipt,
            "material_receipt_sha256": hashlib.sha256(args.reply.read_bytes()).hexdigest(),
            "spec_sha256": hashlib.sha256(args.spec.read_bytes()).hexdigest(),
            "customer_ca_sha256": reply["customer"]["https_ca_sha256"],
            "instances": {"a": args.instance_a, "b": args.instance_b},
            "endpoints": {"a": f"https://{target_a[0]}:{target_a[1]}",
                          "b": f"https://{target_b[0]}:{target_b[1]}"},
            "document_id": doc_id, "collection_id": args.collection_id,
            "schema_generation": generation, "schema_digest": schema_digest,
            "before": {"a": a_before, "b": b_before, "b_point": absent},
            "write_receipt": receipt, "after": {"a": a_after, "b": b_after, "b_point": value}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("operator", "bootstrap", "tb-binary", "go-qualification", "tb-qualification",
                 "bootstrap-build-receipt", "bootstrap-build-command", "bootstrap-build-log",
                 "bootstrap-test-command", "bootstrap-test-log",
                 "operator-config", "spec", "reply", "controller-key",
                 "recipient-key", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("operator-sha256", "bootstrap-sha256", "tb-sha256",
                 "go-qualification-sha256", "tb-qualification-sha256",
                 "bootstrap-build-receipt-sha256",
                 "go-source-sha", "tb-source-sha", "instance-a", "instance-b",
                 "collection-id", "cell"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--nats-forward", action="append", default=[],
                        help="PRIVATE_IP:4222=127.0.0.1:LOCAL_PORT; repeat for controller HA")
    parser.add_argument("--https-forward", action="append", default=[],
                        help="SIGNED_MEMBER_IP:9465=127.0.0.1:LOCAL_PORT; exactly one per member")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output path must not already exist")
    try:
        evidence = run(args)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            destination.write(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        print(f"M0 OCI document scenario passed; evidence={args.output}")
        return 0
    except (QualificationError, OSError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired, ssl.SSLError, json.JSONDecodeError) as error:
        # No response body, bearer token or operator stderr is printed on failure.
        print(f"M0 OCI real caller failed: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
