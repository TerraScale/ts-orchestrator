#!/usr/bin/env python3
"""Generate a deterministic draft requirement-to-C# trace report.

This tool reports lexical references only. It never promotes registry or evidence
state and does not claim that a reference proves an acceptance layer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ID_PATTERN = re.compile(r"\b(?:REQ|INV|ERR|SM|SEC)-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")
ENTRY_START = re.compile(r"^  - id:\s*(\S+)\s*$")


def parse_registry(text: str) -> list[dict[str, object]]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if ENTRY_START.fullmatch(line)]
    entries: list[dict[str, object]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        block = lines[start:end]
        item_id = ENTRY_START.fullmatch(block[0]).group(1)  # type: ignore[union-attr]
        owner = scalar(block, "owner")
        layers = block_list(block, "acceptanceLayers")
        evidence_state = scalar(block, "evidenceState")
        if not ID_PATTERN.fullmatch(item_id) or not owner or not layers or not evidence_state:
            raise ValueError(f"registry entry {item_id} is incomplete")
        entries.append({
            "id": item_id,
            "owner": owner,
            "acceptanceLayers": layers,
            "evidenceState": evidence_state,
        })
    if not entries:
        raise ValueError("registry contains no entries")
    ids = [str(entry["id"]) for entry in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("registry contains duplicate IDs")
    return entries


def scalar(block: list[str], name: str) -> str | None:
    prefix = f"    {name}:"
    for line in block:
        if line.startswith(prefix):
            value = line[len(prefix):].strip()
            return json.loads(value) if value.startswith('"') else value
    return None


def block_list(block: list[str], name: str) -> list[str]:
    marker = f"    {name}:"
    try:
        start = block.index(marker) + 1
    except ValueError:
        return []
    values: list[str] = []
    for line in block[start:]:
        if not line.startswith("      - "):
            break
        value = line.removeprefix("      - ").strip()
        values.append(json.loads(value) if value.startswith('"') else value)
    return values


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for top in (root / "src", root / "tests"):
        if not top.exists():
            continue
        files.extend(path for path in top.rglob("*.cs") if not {"bin", "obj"}.intersection(path.parts))
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def generate(root: Path) -> dict[str, object]:
    registry_path = root / "requirements" / "registry.yaml"
    registry_text = registry_path.read_text(encoding="utf-8")
    registry = parse_registry(registry_text)
    registered = {str(entry["id"]) for entry in registry}
    references: dict[str, dict[str, list[dict[str, object]]]] = {
        item_id: {"production": [], "tests": []} for item_id in registered
    }
    unknown: list[dict[str, object]] = []
    digest = hashlib.sha256()
    digest.update(b"traceability-input-v1\0requirements/registry.yaml\0")
    digest.update(registry_text.encode("utf-8"))

    for path in source_files(root):
        relative = path.relative_to(root).as_posix()
        content = path.read_text(encoding="utf-8")
        digest.update(b"\0")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content.encode("utf-8"))
        bucket = "tests" if relative.startswith("tests/") else "production"
        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in ID_PATTERN.finditer(line):
                location = {"path": relative, "line": line_number}
                item_id = match.group(0)
                if item_id in references:
                    if location not in references[item_id][bucket]:
                        references[item_id][bucket].append(location)
                else:
                    unknown.append({"id": item_id, **location})

    traced: list[dict[str, object]] = []
    counts = {"linked": 0, "production-only": 0, "test-only": 0, "unreferenced": 0}
    for entry in registry:
        item_id = str(entry["id"])
        production = references[item_id]["production"]
        tests = references[item_id]["tests"]
        status = "linked" if production and tests else "production-only" if production else "test-only" if tests else "unreferenced"
        counts[status] += 1
        traced.append({**entry, "traceStatus": status, "productionReferences": production, "testReferences": tests})

    return {
        "schemaVersion": 1,
        "reportKind": "draft-lexical-traceability",
        "claimsAcceptanceEvidence": False,
        "inputSha256": digest.hexdigest(),
        "counts": {"registered": len(registry), **counts, "unknownReferences": len(unknown)},
        "unknownReferences": sorted(unknown, key=lambda item: (str(item["id"]), str(item["path"]), int(item["line"]))),
        "entries": traced,
    }


def render(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, default=Path("docs/audits/traceability/phase1-traceability.json"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    try:
        generated = render(generate(root))
    except (OSError, ValueError) as exc:
        print(f"traceability generation failed: {exc}", file=sys.stderr)
        return 1
    if args.check:
        if not output.exists() or output.read_text(encoding="utf-8") != generated:
            print(f"traceability report is stale: {output}", file=sys.stderr)
            return 1
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(generated, encoding="utf-8")
    report = json.loads(generated)
    if report["unknownReferences"]:
        print("traceability report contains references to unregistered IDs", file=sys.stderr)
        return 1
    print(json.dumps(report["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
