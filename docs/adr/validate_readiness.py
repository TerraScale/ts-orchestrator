#!/usr/bin/env python3
"""Validate the Phase 0 ADR readiness map without third-party packages."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INDEX = Path(__file__).with_name("readiness-index.yaml")
CANONICAL_LANES = {
    "integration", "core", "messaging-security", "runtime", "cloud",
    "storage", "terrabase", "delivery", "operations",
    "cross-repository-cleanup", "verification",
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


def main() -> None:
    document = json.loads(INDEX.read_text(encoding="utf-8"))
    entries = document["entries"]
    errors: list[str] = []
    specification = (ROOT / "ORCHESTRATOR.md").read_text(encoding="utf-8")
    backlog_text = specification.split("## Initial ADR backlog", 1)[1].split("## Definition of complete", 1)[0]
    specification_titles = {
        int(match.group(1)): match.group(2).strip().removesuffix(".")
        for match in re.finditer(r"^(\d+)\. (.+)$", backlog_text, re.MULTILINE)
    }
    if specification_titles != EXPECTED_TITLES:
        errors.append("validator title catalog differs from ORCHESTRATOR.md initial ADR backlog")
    ids = [entry.get("id") for entry in entries]
    expected = list(range(1, 25))
    if sorted(ids) != expected or len(ids) != len(set(ids)):
        errors.append(f"ADR IDs must be exactly 1..24 once; observed {ids}")
    if set(document.get("canonicalOwnerLanes", [])) != CANONICAL_LANES:
        errors.append("document canonicalOwnerLanes differs from validator canonical lanes")

    for entry in entries:
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
        for citation in entry["availableEvidence"]:
            target = citation.split(":", 1)[0]
            if target.startswith(("http://", "https://")):
                continue
            if not (ROOT / target).exists():
                errors.append(f"ADR {ident}: evidence target does not exist: {target}")
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
        unknown = set(entry.get("dependencies", [])) - known
        if unknown:
            errors.append(f"ADR {entry.get('id', '?')}: unknown dependencies {sorted(unknown)}")
        if entry.get("id") in entry.get("dependencies", []):
            errors.append(f"ADR {entry.get('id', '?')}: cannot depend on itself")

    covered_questions = {
        int(value.removeprefix("owner-question-"))
        for entry in entries
        for value in entry.get("controllingInputs", [])
        if value.startswith("owner-question-")
    }
    if covered_questions != set(document.get("openOwnerQuestions", [])):
        errors.append(
            "numbered owner-question coverage differs from openOwnerQuestions: "
            f"observed {sorted(covered_questions)}"
        )

    if errors:
        raise SystemExit("\n".join(errors))

    counts = {status: sum(e["status"] == status for e in entries) for status in sorted(STATUSES)}
    print(f"validated {len(entries)} ADRs exactly once; status counts: {counts}")


if __name__ == "__main__":
    main()
