#!/usr/bin/env python3
"""Deterministically validate the Phase 0 semantic registry audit."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

CANONICAL_OWNERS = {
    "integration", "core", "messaging-security", "runtime", "cloud",
    "storage", "terrabase", "delivery", "operations", "verification",
}
CANONICAL_LAYERS = {"review", "L0", "L0C", "L1S", "L2S", "L3S", "L1R", "L4", "L5"}
ID_RE = re.compile(r"^(?:REQ|INV|ERR|SM|SEC)-[A-Z0-9-]+$")
ENTRY_RE = re.compile(
    r"id:\s*([^, }]+),\s*owner:\s*([^, }]+),\s*acceptanceLayers:\s*\[([^]]*)\]"
)


def parse_registry(path: Path) -> list[dict[str, object]]:
    entries = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = ENTRY_RE.search(line)
        if match:
            entries.append({
                "id": match.group(1),
                "owner": match.group(2),
                "layers": [part.strip() for part in match.group(3).split(",")],
                "line": line_no,
            })
    return entries


def validate(audit: dict[str, object], registry_path: Path, source_path: Path) -> list[str]:
    errors: list[str] = []
    registry = parse_registry(registry_path)
    registry_ids = [str(entry["id"]) for entry in registry]
    source_lines = source_path.read_text(encoding="utf-8").splitlines()

    if len(registry_ids) != len(set(registry_ids)):
        errors.append("registry contains duplicate IDs")
    expected = [f"REQ-O{i:03d}" for i in range(1, 24)] + [f"INV-{i:03d}" for i in range(1, 19)]
    for item_id in expected:
        if item_id not in registry_ids:
            errors.append(f"registry is missing required seeded ID {item_id}")

    for entry in registry:
        for layer in entry["layers"]:
            if layer not in CANONICAL_LAYERS:
                errors.append(f"registry {entry['id']} uses invalid acceptance layer {layer}")

    findings = audit.get("findings", [])
    if not isinstance(findings, list):
        return errors + ["audit findings must be a list"]
    finding_ids = [item.get("id") for item in findings if isinstance(item, dict)]
    if len(finding_ids) != len(set(finding_ids)):
        errors.append("audit contains duplicate finding IDs")

    proposed: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            errors.append("audit finding is not an object")
            continue
        finding_id = str(finding.get("id", "<missing>"))
        status = finding.get("status")
        item_id = finding.get("registryId") or finding.get("proposedId")
        if not isinstance(item_id, str) or not ID_RE.fullmatch(item_id):
            errors.append(f"{finding_id} has invalid or missing registry/proposed ID")
        if status == "missing":
            proposed.append(str(finding.get("proposedId", "")))
            if item_id in registry_ids:
                errors.append(f"{finding_id} calls registered ID {item_id} missing")
        elif status == "id-only":
            if item_id not in registry_ids:
                errors.append(f"{finding_id} references absent registry ID {item_id}")
        else:
            errors.append(f"{finding_id} has unsupported status {status}")
        if finding.get("owner") not in CANONICAL_OWNERS:
            errors.append(f"{finding_id} uses noncanonical owner {finding.get('owner')}")
        layers = finding.get("acceptanceLayers", [])
        if not layers or any(layer not in CANONICAL_LAYERS for layer in layers):
            errors.append(f"{finding_id} has missing/invalid acceptance layers")
        citation = finding.get("citation", {})
        start, end, text = citation.get("start"), citation.get("end"), citation.get("contains")
        if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start or end > len(source_lines):
            errors.append(f"{finding_id} has invalid source line range")
        elif not isinstance(text, str) or not text or text not in "\n".join(source_lines[start - 1:end]):
            errors.append(f"{finding_id} citation text does not match ORCHESTRATOR.md")

    if len(proposed) != len(set(proposed)):
        errors.append("proposed IDs are not unique")
    covered_registry_ids = [
        str(finding.get("registryId"))
        for finding in findings
        if isinstance(finding, dict) and finding.get("status") == "id-only"
    ]
    for item_id in registry_ids:
        count = covered_registry_ids.count(item_id)
        if count == 0:
            errors.append(f"audit does not cover registered ID {item_id}")
        elif count > 1:
            errors.append(f"audit covers registered ID {item_id} more than once")
    summary = audit.get("summary", {})
    expected_counts = {
        "registryEntries": len(registry),
        "idOnly": sum(1 for f in findings if f.get("status") == "id-only"),
        "missing": sum(1 for f in findings if f.get("status") == "missing"),
        "noncanonicalRegistryOwners": sum(1 for entry in registry if entry["owner"] not in CANONICAL_OWNERS),
    }
    for key, value in expected_counts.items():
        if summary.get(key) != value:
            errors.append(f"summary {key} is {summary.get(key)!r}, expected {value}")
    return errors


def apply_mutation(document: dict[str, object], mutation: dict[str, object]) -> None:
    target: object = document
    parts = str(mutation["path"]).strip("/").split("/")
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]  # type: ignore[index]
    final = parts[-1]
    if mutation["op"] == "set":
        if isinstance(target, list):
            target[int(final)] = mutation["value"]
        else:
            target[final] = mutation["value"]  # type: ignore[index]
    elif mutation["op"] == "append-copy":
        assert isinstance(target, list)
        target.append(copy.deepcopy(target[int(final)]))
    else:
        raise ValueError(f"unsupported fixture mutation {mutation['op']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, default=Path(__file__).with_name("registry-audit.json"))
    parser.add_argument("--registry", type=Path, default=Path("requirements/registry.yaml"))
    parser.add_argument("--source", type=Path, default=Path("ORCHESTRATOR.md"))
    parser.add_argument("--negative-fixtures", type=Path)
    args = parser.parse_args()
    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    errors = validate(audit, args.registry, args.source)
    if errors:
        print("FAIL")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    if args.negative_fixtures:
        fixtures = json.loads(args.negative_fixtures.read_text(encoding="utf-8"))["cases"]
        for fixture in fixtures:
            mutated = copy.deepcopy(audit)
            apply_mutation(mutated, fixture["mutation"])
            fixture_errors = validate(mutated, args.registry, args.source)
            if not any(fixture["expected"] in error for error in fixture_errors):
                print(f"FAIL: negative fixture {fixture['name']} did not detect {fixture['expected']!r}")
                return 1
        print(f"PASS: canonical audit plus {len(fixtures)} negative fixtures")
    else:
        print("PASS: canonical audit")
    print(f"registry={len(parse_registry(args.registry))} findings={len(audit['findings'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
