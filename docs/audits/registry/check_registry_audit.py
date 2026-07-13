#!/usr/bin/env python3
"""Deterministically validate the Phase 0 semantic registry audit."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

CANONICAL_OWNERS = {
    "Integration/contract steward", "Core", "Messaging/security", "Runtime",
    "Cloud", "Storage", "TerraBase", "Delivery", "Operations",
    "Cross-repository cleanup", "Verification",
}
CANONICAL_LAYERS = {"review", "L0", "L0C", "L1S", "L2S", "L3S", "L1R", "L4", "L5"}
ID_RE = re.compile(r"^(?:REQ|INV|ERR|SM|SEC)-[A-Z0-9-]+$")


def parse_registry_text(text: str) -> list[dict[str, object]]:
    lines = text.splitlines()
    try:
        entries_line = next(i for i, line in enumerate(lines) if re.fullmatch(r"entries:\s*", line))
    except StopIteration as exc:
        raise ValueError("registry is missing top-level entries") from exc
    blocks: list[tuple[int, list[str]]] = []
    current: tuple[int, list[str]] | None = None
    for index in range(entries_line + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith((" ", "\t")):
            break
        if re.match(r"^\s{2}-\s+", line):
            if current:
                blocks.append(current)
            current = (index + 1, [re.sub(r"^\s{2}-\s+", "", line, count=1)])
        elif current:
            current[1].append(line)
    if current:
        blocks.append(current)
    if not blocks:
        raise ValueError("registry entries contains no list items")
    candidate_id_lines = {
        index + 1
        for index in range(entries_line + 1, len(lines))
        if re.match(r"^\s*-\s+(?:\{\s*)?id:\s*", lines[index])
    }
    parsed_start_lines = {line_no for line_no, _ in blocks}
    skipped = sorted(candidate_id_lines - parsed_start_lines)
    if skipped:
        raise ValueError(f"registry contains skipped/misindented '- id:' entry at line {skipped[0]}")

    entries: list[dict[str, object]] = []
    for line_no, block_lines in blocks:
        block = "\n".join(block_lines).replace("{", "").replace("}", "")
        id_match = re.search(r"(?:^|[,\n])[ \t]*id:[ \t]*([^,\s]+)", block)
        owner_match = re.search(r"(?:^|[,\n])[ \t]*owner:[ \t]*([^,\n]+)", block)
        def scalar(name: str) -> str | None:
            match = re.search(rf"(?:^|\n)\s*{name}:\s*(.+?)\s*$", block, re.MULTILINE)
            if not match:
                return None
            value = match.group(1).strip()
            if value.startswith('"'):
                return str(json.loads(value))
            return value

        def list_value(name: str) -> list[str]:
            inline = re.search(rf"{name}:\s*\[([^]]*)\]", block, re.DOTALL)
            normal = re.search(rf"{name}:\s*\n((?:\s+-\s*[^\n]+\n?)*)", block)
            if inline:
                return [part.strip() for part in inline.group(1).split(",") if part.strip()]
            if normal:
                values = [re.sub(r"^\s+-\s*", "", line).strip() for line in normal.group(1).splitlines()]
                return [str(json.loads(value)) if value.startswith('"') else value for value in values]
            return []
        if not id_match:
            raise ValueError(f"registry entry at line {line_no} is missing id")
        item_id = id_match.group(1).strip()
        if not owner_match:
            raise ValueError(f"registry entry {item_id} at line {line_no} is missing owner")
        layers = list_value("acceptanceLayers")
        if not layers:
            raise ValueError(f"registry entry {item_id} at line {line_no} is missing acceptanceLayers")
        entries.append({
            "id": item_id, "owner": owner_match.group(1).strip(), "layers": layers, "line": line_no,
            "coReviewers": list_value("coReviewers"),
            "kind": scalar("kind"), "contractStatus": scalar("contractStatus"),
            "normativeStatement": scalar("normativeStatement"), "normativeSource": scalar("normativeSource"),
            "normativeStartLine": scalar("normativeStartLine"), "normativeEndLine": scalar("normativeEndLine"),
            "normativeContains": scalar("normativeContains"), "normativeSha256": scalar("normativeSha256"),
            "evidenceState": scalar("evidenceState"), "evidenceTargets": list_value("evidenceTargets"),
        })
    return entries


def parse_registry(path: Path) -> list[dict[str, object]]:
    return parse_registry_text(path.read_text(encoding="utf-8"))


def render_block_registry(entries: list[dict[str, object]]) -> str:
    lines = [
        "schemaVersion: 2", "status: draft", "source: ORCHESTRATOR.md",
        "unresolvedOwnerQuestions: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]",
        "evidenceStateVocabulary: [missing, partial, verified]", "entries:",
    ]
    for entry in entries:
        lines.extend([
            f"  - id: {entry['id']}",
            f"    kind: {entry['kind']}",
            f"    contractStatus: {entry['contractStatus']}",
            f"    owner: {entry['owner']}",
            f"    coReviewers: [{', '.join(entry['coReviewers'])}]",
            f"    normativeStatement: {json.dumps(entry['normativeStatement'])}",
            f"    normativeSource: {entry['normativeSource']}",
            f"    normativeStartLine: {entry['normativeStartLine']}",
            f"    normativeEndLine: {entry['normativeEndLine']}",
            f"    normativeContains: {json.dumps(entry['normativeContains'])}",
            f"    normativeSha256: {entry['normativeSha256']}",
            "    acceptanceLayers:",
            *[f"      - {layer}" for layer in entry["layers"]],
            f"    evidenceState: {entry['evidenceState']}",
            "    evidenceTargets:",
            *[f"      - {json.dumps(target)}" for target in entry["evidenceTargets"]],
        ])
    return "\n".join(lines) + "\n"


def validate(
    audit: dict[str, object], registry_text: str, source_path: Path, owner_mapping: dict[str, str]
) -> list[str]:
    errors: list[str] = []
    try:
        registry = parse_registry_text(registry_text)
    except ValueError as exc:
        return [str(exc)]
    registry_ids = [str(entry["id"]) for entry in registry]
    source_lines = source_path.read_text(encoding="utf-8").splitlines()

    root_expectations = {
        "schemaVersion": "2", "status": "draft", "source": "ORCHESTRATOR.md",
        "unresolvedOwnerQuestions": "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]",
        "evidenceStateVocabulary": "[missing, partial, verified]",
    }
    for key, expected_value in root_expectations.items():
        match = re.search(rf"^{key}:\s*(.+?)\s*$", registry_text, re.MULTILINE)
        if match is None or match.group(1) != expected_value:
            errors.append(f"registry root {key} must be {expected_value}")

    if set(audit.get("canonicalOwners", [])) != CANONICAL_OWNERS:
        errors.append("audit canonicalOwners does not equal the 11 exact workstream lane names")
    if set(owner_mapping.values()) - CANONICAL_OWNERS:
        errors.append("owner mapping contains a noncanonical target")
    for entry in registry:
        if entry["owner"] not in CANONICAL_OWNERS and entry["owner"] not in owner_mapping:
            errors.append(f"registry {entry['id']} has unmapped owner alias {entry['owner']}")
        for layer in entry["layers"]:
            if layer not in CANONICAL_LAYERS:
                errors.append(f"registry {entry['id']} uses invalid acceptance layer {layer}")
        co_reviewers = entry["coReviewers"]
        if len(co_reviewers) != len(set(co_reviewers)) or any(lane not in CANONICAL_OWNERS for lane in co_reviewers):
            errors.append(f"registry {entry['id']} has invalid/duplicate co-reviewers")
        if entry["owner"] in co_reviewers:
            errors.append(f"registry {entry['id']} repeats its primary owner as co-reviewer")
    if len(registry_ids) != len(set(registry_ids)):
        errors.append("registry contains duplicate IDs")
    expected = [f"REQ-O{i:03d}" for i in range(1, 24)] + [f"INV-{i:03d}" for i in range(1, 19)]
    for item_id in expected:
        if item_id not in registry_ids:
            errors.append(f"registry is missing required seeded ID {item_id}")

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
        citation = finding.get("citation", {})
        start, end, text = citation.get("start"), citation.get("end"), citation.get("contains")
        if not isinstance(item_id, str) or not ID_RE.fullmatch(item_id):
            errors.append(f"{finding_id} has invalid or missing registry/proposed ID")
        if status == "missing":
            proposed.append(str(finding.get("proposedId", "")))
            if item_id in registry_ids:
                errors.append(f"{finding_id} calls registered ID {item_id} missing")
        elif status in {"id-only", "semantic"}:
            if item_id not in registry_ids:
                errors.append(f"{finding_id} references absent registry ID {item_id}")
            elif status == "semantic":
                entry = next(entry for entry in registry if entry["id"] == item_id)
                expected_kind = {"REQ": "requirement", "INV": "invariant", "ERR": "error", "SEC": "security", "SM": "state-machine"}[item_id.split("-", 1)[0]]
                if entry["kind"] != expected_kind or entry["contractStatus"] != "proposed":
                    errors.append(f"{finding_id} semantic kind/status mismatch")
                if entry["owner"] != finding.get("owner") or entry["layers"] != finding.get("acceptanceLayers"):
                    errors.append(f"{finding_id} semantic owner/layer parity mismatch")
                if entry["normativeSource"] != "ORCHESTRATOR.md" or entry["normativeStartLine"] != str(start) or entry["normativeEndLine"] != str(end):
                    errors.append(f"{finding_id} semantic source anchor mismatch")
                exact = "\n".join(source_lines[start - 1:end]) if isinstance(start, int) and isinstance(end, int) and 1 <= start <= end <= len(source_lines) else ""
                if entry["normativeContains"] != text or entry["normativeSha256"] != hashlib.sha256(exact.encode()).hexdigest():
                    errors.append(f"{finding_id} semantic source digest mismatch")
                if not entry["normativeStatement"] or len(str(entry["normativeStatement"])) < 20 or entry["evidenceState"] != "missing" or len(entry["evidenceTargets"]) != len(entry["layers"]):
                    errors.append(f"{finding_id} semantic statement/evidence targets incomplete")
                for layer, target in zip(entry["layers"], entry["evidenceTargets"], strict=True):
                    if len(target) < 20 or layer not in target:
                        errors.append(f"{finding_id} semantic evidence target does not identify layer {layer}")
        else:
            errors.append(f"{finding_id} has unsupported status {status}")
        if finding.get("owner") not in CANONICAL_OWNERS:
            errors.append(f"{finding_id} uses noncanonical owner {finding.get('owner')}")
        layers = finding.get("acceptanceLayers", [])
        if not layers or any(layer not in CANONICAL_LAYERS for layer in layers):
            errors.append(f"{finding_id} has missing/invalid acceptance layers")
        if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start or end > len(source_lines):
            errors.append(f"{finding_id} has invalid source line range")
        elif not isinstance(text, str) or not text or text not in "\n".join(source_lines[start - 1:end]):
            errors.append(f"{finding_id} citation text does not match ORCHESTRATOR.md")
    if len(proposed) != len(set(proposed)):
        errors.append("proposed IDs are not unique")
    covered = [
        str(f.get("registryId"))
        for f in findings
        if isinstance(f, dict) and f.get("status") in {"id-only", "semantic"}
    ]
    for item_id in registry_ids:
        if covered.count(item_id) == 0:
            errors.append(f"audit does not cover registered ID {item_id}")
        elif covered.count(item_id) > 1:
            errors.append(f"audit covers registered ID {item_id} more than once")
    summary = audit.get("summary", {})
    expected_counts = {
        "registryEntries": len(registry),
        "idOnly": sum(1 for f in findings if isinstance(f, dict) and f.get("status") == "id-only"),
        "semantic": sum(1 for f in findings if isinstance(f, dict) and f.get("status") == "semantic"),
        "missing": sum(1 for f in findings if isinstance(f, dict) and f.get("status") == "missing"),
        "registryOwnerAliases": sum(1 for entry in registry if entry["owner"] not in CANONICAL_OWNERS),
        "unmappedRegistryOwners": sum(1 for entry in registry if entry["owner"] not in CANONICAL_OWNERS and entry["owner"] not in owner_mapping),
    }
    for key, value in expected_counts.items():
        if summary.get(key) != value:
            errors.append(f"summary {key} is {summary.get(key)!r}, expected {value}")
    return errors


def apply_audit_mutation(document: dict[str, object], mutation: dict[str, object]) -> None:
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
        raise ValueError(f"unsupported audit mutation {mutation['op']}")


def mutate_registry(text: str, fixture: dict[str, object]) -> str:
    mutation = fixture["mutation"]
    if mutation["op"] == "remove-entry":
        item_id = re.escape(str(mutation["id"]))
        return re.sub(rf"^\s{{2}}-\s+.*\bid:\s*{item_id}\b.*\n", "", text, count=1, flags=re.MULTILINE)
    if mutation["op"] == "remove-block-owner":
        block = render_block_registry(parse_registry_text(text))
        item_id = re.escape(str(mutation["id"]))
        return re.sub(
            rf"(^  - id: {item_id}\n(?:(?!^  - id:).)*?)^    owner:[^\n]+\n",
            r"\1", block, count=1, flags=re.MULTILINE | re.DOTALL,
        )
    if mutation["op"] == "misindent-block-entry":
        block = render_block_registry(parse_registry_text(text))
        item_id = re.escape(str(mutation["id"]))
        return re.sub(rf"^  (- id: {item_id})$", r"    \1", block, count=1, flags=re.MULTILINE)
    if mutation["op"] == "set-block-field":
        block = render_block_registry(parse_registry_text(text))
        item_id = re.escape(str(mutation["id"]))
        field = re.escape(str(mutation["field"]))
        value = str(mutation["value"])
        return re.sub(
            rf"(^  - id: {item_id}\n(?:(?!^  - id:).)*?^    {field}:)[^\n]*$",
            rf"\1 {value}", block, count=1, flags=re.MULTILINE | re.DOTALL,
        )
    if mutation["op"] == "set-root-field":
        field = re.escape(str(mutation["field"]))
        return re.sub(rf"^{field}:[^\n]*$", f"{mutation['field']}: {mutation['value']}", text, count=1, flags=re.MULTILINE)
    if mutation["op"] == "replace-text":
        old, new = str(mutation["old"]), str(mutation["new"])
        if text.count(old) != 1:
            raise ValueError(f"registry mutation expected one occurrence of {old!r}")
        return text.replace(old, new)
    if mutation["op"] == "set-block-list-item":
        block = render_block_registry(parse_registry_text(text))
        item_id = re.escape(str(mutation["id"]))
        field = re.escape(str(mutation["field"]))
        index = int(mutation["index"])
        match = re.search(
            rf"(^  - id: {item_id}\n(?:(?!^  - id:).)*?^    {field}:\n)((?:      - [^\n]+\n?)+)",
            block, flags=re.MULTILINE | re.DOTALL,
        )
        if match is None:
            raise ValueError("registry list mutation target not found")
        values = match.group(2).splitlines()
        values[index] = f"      - {json.dumps(str(mutation['value']))}"
        return block[:match.start(2)] + "\n".join(values) + "\n" + block[match.end(2):]
    raise ValueError(f"unsupported registry mutation {mutation['op']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, default=Path(__file__).with_name("registry-audit.json"))
    parser.add_argument("--owner-mapping", type=Path, default=Path(__file__).with_name("owner-mapping.json"))
    parser.add_argument("--registry", type=Path, default=Path("requirements/registry.yaml"))
    parser.add_argument("--source", type=Path, default=Path("ORCHESTRATOR.md"))
    parser.add_argument("--negative-fixtures", type=Path)
    args = parser.parse_args()
    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    owner_mapping = json.loads(args.owner_mapping.read_text(encoding="utf-8"))["aliases"]
    registry_text = args.registry.read_text(encoding="utf-8")
    errors = validate(audit, registry_text, args.source, owner_mapping)
    if errors:
        print("FAIL")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    block_errors = validate(audit, render_block_registry(parse_registry_text(registry_text)), args.source, owner_mapping)
    if block_errors:
        print("FAIL: equivalent block-style registry did not validate")
        print("\n".join(f"- {error}" for error in block_errors))
        return 1
    if args.negative_fixtures:
        fixtures = json.loads(args.negative_fixtures.read_text(encoding="utf-8"))["cases"]
        for fixture in fixtures:
            mutated_audit, mutated_registry = copy.deepcopy(audit), registry_text
            if fixture.get("target", "audit") == "audit":
                apply_audit_mutation(mutated_audit, fixture["mutation"])
            else:
                mutated_registry = mutate_registry(registry_text, fixture)
            fixture_errors = validate(mutated_audit, mutated_registry, args.source, owner_mapping)
            if not any(fixture["expected"] in error for error in fixture_errors):
                print(f"FAIL: negative fixture {fixture['name']} did not detect {fixture['expected']!r}")
                return 1
        print(f"PASS: inline + block registries and {len(fixtures)} negative fixtures")
    else:
        print("PASS: inline + block registries")
    print(f"registry={len(parse_registry_text(registry_text))} findings={len(audit['findings'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
