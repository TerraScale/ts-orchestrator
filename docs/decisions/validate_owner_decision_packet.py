#!/usr/bin/env python3
"""Deterministically validate the unset Phase 0 owner-decision packet."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PACKET = Path(__file__).with_name("owner-decision-packet.json")
README = Path(__file__).with_name("README.md")

QUESTION_ADRS = {
    1: [1, 2], 2: [1, 21], 3: [12, 21], 4: [6, 10], 5: [9, 10],
    6: [16, 19], 7: [14], 8: [2, 8], 9: [17], 10: [10],
}
INPUTS = {
    "team-size": ("people", [19], False),
    "first-production-date": ("ISO-8601-date-or-quarter", [19], False),
    "maximum-three-region-pre-user-cost": ("BRL/day", [5, 8, 19, 24], True),
    "storage-minimum-iops-per-member": ("IOPS", [2, 3, 5, 8, 9, 10, 19], True),
    "storage-minimum-throughput-per-member": ("MiB/s", [2, 3, 5, 8, 9, 10, 19], True),
    "storage-p95-read-latency": ("ms", [2, 3, 5, 8, 9, 10, 19], True),
    "storage-p99-read-latency": ("ms", [2, 3, 5, 8, 9, 10, 19], True),
    "storage-p95-write-latency": ("ms", [2, 3, 5, 8, 9, 10, 19], True),
    "storage-p99-write-latency": ("ms", [2, 3, 5, 8, 9, 10, 19], True),
    "regional-rpo": ("seconds", [1, 3, 9, 10, 12, 19, 21, 24], True),
    "regional-rto": ("minutes", [1, 3, 9, 10, 12, 19, 21, 24], True),
    "security-credential-revocation": ("seconds", [11, 17], True),
    "security-workload-certificate-ttl": ("hours", [11], True),
    "security-certificate-renewal-lead": ("hours", [11], True),
    "security-break-glass-session-ttl": ("minutes", [17], True),
    "security-critical-remediation": ("hours", [11, 17], True),
    "memory-orchestrator-rss-per-host": ("MiB", [7, 8], True),
    "density-compact-post-failure-utilization-ceiling": ("percent", [7, 8], True),
    "audit-hot-retention": ("days", [3], True),
    "audit-immutable-retention": ("days", [3], True),
    "maximum-regional-survival-window": ("hours", [11, 12, 21], True),
}
VALIDATIONS = {
    "team-size": {"type": "integer", "minimum": 1},
    "first-production-date": {"type": "string", "pattern": r"^(\d{4}-\d{2}-\d{2}|\d{4}-Q[1-4])$"},
    "maximum-three-region-pre-user-cost": {"type": "number", "exclusiveMinimum": 0},
    "storage-minimum-iops-per-member": {"type": "integer", "minimum": 1},
    "storage-minimum-throughput-per-member": {"type": "number", "exclusiveMinimum": 0},
    "storage-p95-read-latency": {"type": "number", "minimum": 0},
    "storage-p99-read-latency": {"type": "number", "minimum": 0},
    "storage-p95-write-latency": {"type": "number", "minimum": 0},
    "storage-p99-write-latency": {"type": "number", "minimum": 0},
    "regional-rpo": {"type": "integer", "minimum": 0},
    "regional-rto": {"type": "integer", "minimum": 0},
    "security-credential-revocation": {"type": "integer", "minimum": 0},
    "security-workload-certificate-ttl": {"type": "integer", "minimum": 1},
    "security-certificate-renewal-lead": {"type": "integer", "minimum": 1},
    "security-break-glass-session-ttl": {"type": "integer", "minimum": 1},
    "security-critical-remediation": {"type": "integer", "minimum": 0},
    "memory-orchestrator-rss-per-host": {"type": "integer", "minimum": 1},
    "density-compact-post-failure-utilization-ceiling": {"type": "number", "exclusiveMinimum": 0, "maximum": 100},
    "audit-hot-retention": {"type": "integer", "minimum": 1},
    "audit-immutable-retention": {"type": "integer", "minimum": 1},
    "maximum-regional-survival-window": {"type": "integer", "minimum": 1},
}
LATER_SELECTIONS = {
    "artifact-and-evidence-signing": ([14, 23], ["phase-0-exit", "L0"]),
    "dns-implementation": ([15], ["phase-0-exit", "L3S", "L4"]),
    "vpn-implementation": ([16], ["phase-0-exit", "L3S", "L4"]),
    "operator-identity-provider": ([17], ["phase-0-exit", "L3S", "L5"]),
    "regional-artifact-mirror": ([21], ["phase-0-exit", "L3S", "L4"]),
    "arm64-host-image": ([22], ["phase-0-exit", "L1R", "L4"]),
    "nats-n-minus-one-policy": ([22], ["phase-0-exit", "L0C", "L3S"]),
}
GATES = {"phase-0-planning", "contract-freeze", "phase-0-exit", "L0", "L0C", "L1R", "L3S", "L4", "L5"}


def _table_rows(specification: str) -> dict[int, tuple[list[str], int, str]]:
    rows: dict[int, tuple[list[str], int, str]] = {}
    for line_number, line in enumerate(specification.splitlines(), 1):
        match = re.match(r"^\|\s*(10|[1-9])\s*\|", line)
        if match and 87 <= line_number <= 98:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            ident = int(cells[0])
            digest = hashlib.sha256("\x1f".join(cells).encode("utf-8")).hexdigest()
            rows[ident] = (cells, line_number, digest)
    return rows


def validate_document(document: dict[str, Any], root: Path = ROOT, require_unset: bool = True) -> list[str]:
    errors: list[str] = []
    specification = (root / "ORCHESTRATOR.md").read_text(encoding="utf-8")
    rows = _table_rows(specification)
    if set(rows) != set(range(1, 11)):
        errors.append(f"ORCHESTRATOR question rows must be exactly 1..10; observed {sorted(rows)}")

    policy = document.get("decisionPolicy", {})
    if policy.get("recommendationIsNotDefault") is not True or policy.get("unknownRemainsNull") is not True:
        errors.append("decision policy must forbid recommendation defaulting and preserve null unknowns")
    if policy.get("allowedAnswers") != ["A", "B"]:
        errors.append("allowed answers must be exactly A and B")

    questions = document.get("questions")
    if not isinstance(questions, list):
        return errors + ["questions must be a list"]
    ids = [item.get("id") for item in questions if isinstance(item, dict)]
    if ids != list(range(1, 11)) or len(ids) != len(set(ids)):
        errors.append(f"questions must be 1..10 exactly once in order; observed {ids}")
    for item in questions:
        if not isinstance(item, dict) or item.get("id") not in rows:
            continue
        ident = item["id"]
        cells, source_line, digest = rows[ident]
        exact = {"question": cells[1], "optionA": cells[2], "optionB": cells[3]}
        for field, expected in exact.items():
            if item.get(field) != expected:
                errors.append(f"question {ident}: {field} differs from ORCHESTRATOR.md:{source_line}")
        if item.get("sourceLine") != source_line or item.get("semanticSha256") != digest:
            errors.append(f"question {ident}: source line/checksum mismatch")
        if item.get("recommended") != "A":
            errors.append(f"question {ident}: recommendation must reflect the A-recommended source column")
        answer = item.get("answer")
        if answer is not None and answer not in ("A", "B"):
            errors.append(f"question {ident}: answer must be null, A, or B")
        if require_unset and answer is not None:
            errors.append(f"question {ident}: checked-in answer must remain null")
        if item.get("impactedAdrs") != QUESTION_ADRS[ident]:
            errors.append(f"question {ident}: canonical ADR impact mismatch")
        gates = item.get("impactedGates", [])
        if not gates or set(gates) - GATES:
            errors.append(f"question {ident}: invalid or empty gate impact")

    inputs = document.get("inputs")
    if not isinstance(inputs, list):
        return errors + ["inputs must be a list"]
    input_ids = [item.get("id") for item in inputs if isinstance(item, dict)]
    if set(input_ids) != set(INPUTS) or len(input_ids) != len(set(input_ids)):
        errors.append(f"required inputs must occur exactly once; observed {input_ids}")
    for item in inputs:
        if not isinstance(item, dict) or item.get("id") not in INPUTS:
            continue
        ident = item["id"]
        unit, adrs, freeze = INPUTS[ident]
        if item.get("unit") != unit:
            errors.append(f"input {ident}: unit must be {unit}")
        if item.get("impactedAdrs") != adrs:
            errors.append(f"input {ident}: canonical ADR impact mismatch")
        if item.get("requiredBeforeContractFreeze") is not freeze:
            errors.append(f"input {ident}: contract-freeze classification mismatch")
        expected_stage = "contract-freeze" if freeze else "phase-0-planning"
        if item.get("readinessStage") != expected_stage:
            errors.append(f"input {ident}: readiness stage must be {expected_stage}")
        if item.get("validation") != VALIDATIONS[ident]:
            errors.append(f"input {ident}: measurable validation constraints differ from the canonical packet")
        if require_unset and item.get("value") is not None:
            errors.append(f"input {ident}: checked-in value must remain null")
        gates = item.get("impactedGates", [])
        if not gates or set(gates) - GATES:
            errors.append(f"input {ident}: invalid or empty gate impact")

    selections = document.get("laterImplementationSelections")
    if not isinstance(selections, list):
        errors.append("laterImplementationSelections must be a list")
    else:
        selection_ids = [item.get("id") for item in selections if isinstance(item, dict)]
        if set(selection_ids) != set(LATER_SELECTIONS) or len(selection_ids) != len(set(selection_ids)):
            errors.append("later implementation selections must occur exactly once")
        for item in selections:
            if not isinstance(item, dict) or item.get("id") not in LATER_SELECTIONS:
                continue
            expected_adrs, expected_gates = LATER_SELECTIONS[item["id"]]
            if item.get("readinessStage") != "later-phase0-selection":
                errors.append(f"selection {item['id']}: readiness stage must be later-phase0-selection")
            if item.get("requiredBeforeContractFreeze") is not False:
                errors.append(f"selection {item['id']}: must remain segregated from contract-freeze inputs")
            if item.get("impactedAdrs") != expected_adrs:
                errors.append(f"selection {item['id']}: canonical ADR impact mismatch")
            if item.get("impactedGates") != expected_gates:
                errors.append(f"selection {item['id']}: canonical gate impact mismatch")
            if require_unset and item.get("selection") is not None:
                errors.append(f"selection {item['id']}: checked-in selection must remain null")

    response = document.get("compactResponse", "")
    for ident in range(1, 11):
        if len(re.findall(rf"(?<!\d){ident}=_(?!\d)", response)) != 1:
            errors.append(f"compact response must contain question {ident} exactly once")
    if "all A" in response:
        errors.append("compact response must not encourage recommendation defaulting")
    return errors


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else PACKET
    document = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_document(document)
    if not errors and path.resolve() == PACKET.resolve():
        readme = README.read_text(encoding="utf-8")
        for line_number in range(89, 99):
            exact_line = (ROOT / "ORCHESTRATOR.md").read_text(encoding="utf-8").splitlines()[line_number - 1]
            if exact_line not in readme:
                errors.append(f"README is missing exact source table row ORCHESTRATOR.md:{line_number}")
    if errors:
        raise SystemExit("\n".join(errors))
    print("validated 10 unset owner questions, 21 unset inputs, 7 later selections, exact source checksums, and ADR/gate impacts")


if __name__ == "__main__":
    main()
