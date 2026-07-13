#!/usr/bin/env python3
"""Validate the Phase 0 ADR readiness map without third-party packages."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INDEX = Path(__file__).with_name("readiness-index.yaml")
CANONICAL_LANES = {
    "Integration/contract steward", "Core", "Messaging/security", "Runtime",
    "Cloud", "Storage", "TerraBase", "Delivery", "Operations",
    "Cross-repository cleanup", "Verification",
}
STATUSES = {"draft-ready", "owner-input-required", "evidence-required", "accepted"}
EXPECTED_TITLES = {
    1: "Global versus regional authority and outage mutation policy",
    2: "Dual dedicated regional NATS topology, host co-location isolation, bootstrap, upgrade, and recovery",
    3: "JetStream streams, KV CAS, snapshot/restore, fencing, and audit retention",
    4: "Pulumi/provider ownership and exact resource tags/IAM",
    5: "Direct OCI instances versus instance pools by node class",
    6: "Unified workload schema and systemd/containerd driver contract",
    7: "Host network/port allocation versus namespaced network roadmap",
    8: "Compact co-location performance and promotion to isolated node classes",
    9: "Volume identity, filesystem layout, fencing, expansion, performance, retention, and deletion",
    10: "TerraBase topology, upgrade, backup, replication, and autoscaling controller contract",
    11: "Root/intermediate PKI, workload identity namespace, certificate TTL, revocation, and disconnected renewal",
    12: "Built-in vault backend and disaster recovery",
    13: "Native GitOps schema, fresh typed desired state, historical-behavior review, and complete Flux removal",
    14: "CI trust zones, release graph, bootstrap/recovery path, and artifact signing",
    15: "Service registry, DNS, ingress/LB, region headers, and routing ownership",
    16: "VPN implementation and scalable twenty-region connectivity",
    17: "Operator OIDC/RBAC/break-glass/API and Grafana threat model",
    18: "Project placement versus host scheduling boundary",
    19: "Three-region cost/SLO target and provider portability contract",
    20: "Provider-actuator crash-stop threat model, irreversible-operation fencing/resume, and OCI credential boundary",
    21: "Regional survival bundle, artifact/secret availability, disconnected node replacement, and maximum survival window",
    22: "Golden-image bootstrap, N/N-1 compatibility, and A/B orchestrator self-upgrade/rollback",
    23: "Requirement/error registry, pure decision dependency rules, test toolchain, evidence attestation, and deployment-credential gate",
    24: "Greenfield OCI inventory, stale-resource quarantine/approved cleanup, partial-create recovery, initial trust/NATS/TerraBase seeding, independent regional partial success, Pulumi handoff, cleanup-PR sequencing, ingress activation/withdrawal, and first-production rollback boundaries",
}
OWNER_PLANNING_INPUTS = {
    "team-size", "first-production-date", "maximum-three-region-pre-user-cost",
    "storage-slo", "regional-rpo-rto", "memory-and-density-slo", "security-slo",
    "maximum-survival-window",
}
REQUIRED_FIELDS = {
    "id", "slug", "title", "status", "ownerLane", "controllingInputs",
    "availableEvidence", "missingEvidence", "dependencies", "exitEvidence",
}
LOCAL_ANCHOR = re.compile(r"^(?P<path>[^:]+):(?P<start>[1-9]\d*)-(?P<end>[1-9]\d*)$")


def validate_document(document: dict[str, object], root: Path = ROOT) -> list[str]:
    """Return every readiness-map validation error without mutating the input."""

    errors: list[str] = []
    entries_value = document.get("entries", [])
    if not isinstance(entries_value, list):
        return ["entries must be a list"]
    entries = entries_value
    specification = (root / "ORCHESTRATOR.md").read_text(encoding="utf-8")
    lane_text = specification.split("### Exclusive workstream ownership", 1)[1].split(
        "Each domain lane owns", 1
    )[0]
    specification_lanes = {
        match.group(1).strip()
        for match in re.finditer(r"^\| ([^|]+) \|", lane_text, re.MULTILINE)
        if match.group(1).strip() != "Lane"
    }
    if specification_lanes != CANONICAL_LANES:
        errors.append("validator lane catalog differs from ORCHESTRATOR.md exclusive-workstream table")
    backlog_text = specification.split("## Initial ADR backlog", 1)[1].split("## Definition of complete", 1)[0]
    specification_titles = {
        int(match.group(1)): match.group(2).strip().removesuffix(".")
        for match in re.finditer(r"^(\d+)\. (.+)$", backlog_text, re.MULTILINE)
    }
    if specification_titles != EXPECTED_TITLES:
        errors.append("validator title catalog differs from ORCHESTRATOR.md initial ADR backlog")
    ids = [entry.get("id") for entry in entries if isinstance(entry, dict)]
    expected = list(range(1, 25))
    if ids != expected or len(ids) != len(set(ids)):
        errors.append(f"ADR IDs must be exactly 1..24 once; observed {ids}")
    if set(document.get("canonicalOwnerLanes", [])) != CANONICAL_LANES:
        errors.append("document canonicalOwnerLanes differs from validator canonical lanes")

    for entry in entries:
        if not isinstance(entry, dict):
            errors.append("each ADR entry must be an object")
            continue
        ident = entry.get("id", "?")
        missing_fields = REQUIRED_FIELDS - set(entry)
        if missing_fields:
            errors.append(f"ADR {ident}: missing fields {sorted(missing_fields)}")
            continue
        if entry["ownerLane"] not in CANONICAL_LANES:
            errors.append(f"ADR {ident}: non-canonical owner lane {entry['ownerLane']}")
        if entry["status"] not in STATUSES:
            errors.append(f"ADR {ident}: invalid status {entry['status']}")
        if entry["title"] != EXPECTED_TITLES.get(ident):
            errors.append(f"ADR {ident}: title does not exactly match the backlog")
        for field in ("slug", "title"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                errors.append(f"ADR {ident}: {field} must be non-empty")
        for field in ("controllingInputs", "availableEvidence", "missingEvidence", "dependencies", "exitEvidence"):
            if not isinstance(entry[field], list):
                errors.append(f"ADR {ident}: {field} must be a list")
        if not entry["availableEvidence"] or not entry["missingEvidence"] or not entry["exitEvidence"]:
            errors.append(f"ADR {ident}: evidence, gap, and exit lists must be non-empty")
        precise_specification_anchor = False
        audit_or_ledger_anchor = False
        for citation in entry["availableEvidence"]:
            if not isinstance(citation, str):
                errors.append(f"ADR {ident}: evidence citation must be a string")
                continue
            if citation.startswith(("http://", "https://")):
                errors.append(f"ADR {ident}: URL evidence requires a checked local primary-source capture with line anchors")
                continue
            match = LOCAL_ANCHOR.fullmatch(citation)
            if match is None:
                errors.append(f"ADR {ident}: local evidence must use path:start-end: {citation}")
                continue
            target = match.group("path")
            start = int(match.group("start"))
            end = int(match.group("end"))
            evidence_path = root / target
            if not evidence_path.is_file():
                errors.append(f"ADR {ident}: evidence target does not exist or is not a file: {target}")
                continue
            lines = evidence_path.read_text(encoding="utf-8").splitlines()
            if end < start or end > len(lines):
                errors.append(
                    f"ADR {ident}: evidence anchor is out of bounds: {citation} "
                    f"(file has {len(lines)} lines)"
                )
                continue
            if not any(line.strip() for line in lines[start - 1:end]):
                errors.append(f"ADR {ident}: evidence anchor contains no nonblank text: {citation}")
                continue
            precise_specification_anchor |= target == "ORCHESTRATOR.md"
            audit_or_ledger_anchor |= target.startswith("docs/audits/") or target.startswith("docs/retirement/")
        if entry["status"] == "draft-ready" and not precise_specification_anchor:
            errors.append(f"ADR {ident}: draft-ready requires a precise ORCHESTRATOR.md anchor")
        if entry["status"] == "draft-ready" and not audit_or_ledger_anchor:
            errors.append(f"ADR {ident}: draft-ready requires a checked-in audit or ledger anchor")
        if entry["status"] == "accepted":
            errors.append(f"ADR {ident}: accepted is forbidden while owner/SLO inputs remain open")
        owner_controlled = any(
            value.startswith("owner-question-") or value in OWNER_PLANNING_INPUTS
            for value in entry["controllingInputs"]
        )
        if owner_controlled and entry["status"] != "owner-input-required":
            errors.append(f"ADR {ident}: open owner/SLO input must use owner-input-required")

    known = set(ids)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        unknown = set(entry.get("dependencies", [])) - known
        if unknown:
            errors.append(f"ADR {entry.get('id', '?')}: unknown dependencies {sorted(unknown)}")
        if entry.get("id") in entry.get("dependencies", []):
            errors.append(f"ADR {entry.get('id', '?')}: cannot depend on itself")

    covered_questions = {
        int(value.removeprefix("owner-question-"))
        for entry in entries if isinstance(entry, dict)
        for value in entry.get("controllingInputs", [])
        if value.startswith("owner-question-")
    }
    if covered_questions != set(document.get("openOwnerQuestions", [])):
        errors.append(
            "numbered owner-question coverage differs from openOwnerQuestions: "
            f"observed {sorted(covered_questions)}"
        )

    return errors


def main() -> None:
    document = json.loads(INDEX.read_text(encoding="utf-8"))
    errors = validate_document(document)
    if errors:
        raise SystemExit("\n".join(errors))

    entries = document["entries"]
    counts = {status: sum(e["status"] == status for e in entries) for status in sorted(STATUSES)}
    print(f"validated {len(entries)} ADRs exactly once; status counts: {counts}")


if __name__ == "__main__":
    main()
