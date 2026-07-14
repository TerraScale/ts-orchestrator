#!/usr/bin/env python3
"""Validate the closed structured trace-link manifest and render a canonical gap report.

The manifest is the JSON-compatible subset of YAML.  This deliberately small
grammar keeps validation dependency-free and rejects YAML tags, anchors, aliases,
implicit typing, duplicate keys, and comments.  The separate lexical report is a
gap-discovery aid only and is never consumed as structured evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

MAX_MANIFEST_BYTES = 1_048_576
MAX_REGISTRY_BYTES = 1_048_576
MAX_LINKED_FILE_BYTES = 4_194_304
MAX_LINKS_PER_KIND = 32
MAX_PATH_LENGTH = 240
MAX_IDENTIFIER_LENGTH = 200
EXPECTED_REGISTRY_ENTRIES = 43
ID_PATTERN = re.compile(r"(?:REQ|INV|ERR|SM|SEC)-[A-Z0-9]+(?:-[A-Z0-9]+)*")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ENTRY_START = re.compile(r"^  - id:\s*(\S+)\s*$")
EVIDENCE_KINDS = {
    "review": "reviewed-contract",
    "L0": "unit-test-report",
    "L0C": "conformance-test-report",
    "L1R": "runtime-test-report",
    "L1S": "survival-test-report",
    "L2S": "integration-test-report",
    "L3S": "staging-test-report",
    "L4": "qualification-report",
    "L5": "production-observation",
}


class TraceValidationError(ValueError):
    """Closed validation failure; messages contain no linked file contents."""


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TraceValidationError(f"duplicate mapping key: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TraceValidationError("manifest is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TraceValidationError("manifest must be a non-symbolic-link regular file")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise TraceValidationError("manifest exceeds the byte bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates,
                           parse_constant=lambda _value: (_ for _ in ()).throw(TraceValidationError("non-finite JSON number")))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TraceValidationError("manifest is not strict JSON-compatible YAML") from exc
    if not isinstance(value, dict):
        raise TraceValidationError("manifest root must be a mapping")
    return value


def parse_registry(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if ENTRY_START.fullmatch(line)]
    entries: list[dict[str, Any]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        block = lines[start:end]
        match = ENTRY_START.fullmatch(block[0])
        if match is None:
            raise TraceValidationError("registry entry is malformed")
        item_id = match.group(1)
        owner = _registry_scalar(block, "owner")
        layers = _registry_list(block, "acceptanceLayers")
        if not ID_PATTERN.fullmatch(item_id) or not owner or not layers:
            raise TraceValidationError(f"registry entry is incomplete: {item_id}")
        entries.append({"id": item_id, "owner": owner, "acceptanceLayers": layers})
    ids = [entry["id"] for entry in entries]
    if not entries or len(ids) != len(set(ids)):
        raise TraceValidationError("registry IDs are empty or duplicated")
    return entries


def _registry_scalar(block: list[str], name: str) -> str | None:
    prefix = f"    {name}:"
    for line in block:
        if line.startswith(prefix):
            value = line[len(prefix):].strip()
            if value.startswith('"'):
                try:
                    decoded = json.loads(value)
                except json.JSONDecodeError as exc:
                    raise TraceValidationError(f"registry scalar is malformed: {name}") from exc
                return decoded if isinstance(decoded, str) else None
            return value
    return None


def _registry_list(block: list[str], name: str) -> list[str]:
    marker = f"    {name}:"
    try:
        start = block.index(marker) + 1
    except ValueError:
        return []
    values: list[str] = []
    for line in block[start:]:
        if not line.startswith("      - "):
            break
        raw = line.removeprefix("      - ").strip()
        if raw.startswith('"'):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise TraceValidationError(f"registry list is malformed: {name}") from exc
        if not isinstance(raw, str) or not raw:
            raise TraceValidationError(f"registry list is malformed: {name}")
        values.append(raw)
    return values


def _exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise TraceValidationError(f"{context} has missing or unknown fields")


def _bounded_string(value: Any, field: str, maximum: int = MAX_IDENTIFIER_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(character) < 32 for character in value):
        raise TraceValidationError(f"{field} is invalid")
    return value


def _safe_file(root: Path, relative: Any) -> tuple[str, Path]:
    value = _bounded_string(relative, "link path", MAX_PATH_LENGTH)
    if "\\" in value or value.startswith("/") or value.endswith("/"):
        raise TraceValidationError("link path is not a canonical relative file path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise TraceValidationError("link path traverses or is non-canonical")
    candidate = root.joinpath(*parts)
    root_real = root.resolve(strict=True)
    current = root
    for part in parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise TraceValidationError("linked file does not exist") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise TraceValidationError("linked path contains a symbolic link")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root_real)
    except ValueError as exc:
        raise TraceValidationError("linked path escapes the repository") from exc
    if not resolved.is_file():
        raise TraceValidationError("linked path is not a regular file")
    if resolved.stat().st_size > MAX_LINKED_FILE_BYTES:
        raise TraceValidationError("linked file exceeds the byte bound")
    return value, resolved


def _strip_csharp_non_code(text: str) -> str:
    """Replace comments and string/character literals while retaining code shape."""
    output: list[str] = []
    index = 0
    state = "code"
    raw_quotes = 0
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if current == "/" and following == "/": state = "line"; output.extend("  "); index += 2; continue
            if current == "/" and following == "*": state = "block"; output.extend("  "); index += 2; continue
            if current == '@' and following == '"': state = "verbatim"; output.extend("  "); index += 2; continue
            if current == '"':
                quote_run = 1
                while index + quote_run < len(text) and text[index + quote_run] == '"': quote_run += 1
                if quote_run >= 3:
                    raw_quotes = quote_run; state = "raw"; output.extend(" " * quote_run); index += quote_run; continue
            if current == '"': state = "string"; output.append(" "); index += 1; continue
            if current == "'": state = "char"; output.append(" "); index += 1; continue
            output.append(current); index += 1; continue
        if state == "line":
            output.append("\n" if current == "\n" else " ")
            if current == "\n": state = "code"
            index += 1; continue
        if state == "block":
            if current == "*" and following == "/": output.extend("  "); index += 2; state = "code"
            else: output.append("\n" if current == "\n" else " "); index += 1
            continue
        if state == "verbatim":
            if current == '"' and following == '"': output.extend("  "); index += 2
            elif current == '"': output.append(" "); index += 1; state = "code"
            else: output.append("\n" if current == "\n" else " "); index += 1
            continue
        if state == "raw":
            if text.startswith('"' * raw_quotes, index):
                output.extend(" " * raw_quotes); index += raw_quotes; state = "code"
            else: output.append("\n" if current == "\n" else " "); index += 1
            continue
        if current == "\\" and following: output.extend("  "); index += 2; continue
        if (state == "string" and current == '"') or (state == "char" and current == "'"): state = "code"
        output.append("\n" if current == "\n" else " "); index += 1
    return "".join(output)


def _validate_code_link(root: Path, value: Any, kind: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise TraceValidationError(f"{kind} link must be a mapping")
    field = "symbol" if kind == "production" else "test"
    _exact_keys(value, {"path", field}, f"{kind} link")
    relative, path = _safe_file(root, value["path"])
    identifier = _bounded_string(value[field], field)
    if not IDENTIFIER_PATTERN.fullmatch(identifier):
        raise TraceValidationError(f"{field} identifier is malformed")
    if kind == "production" and not relative.startswith("src/"):
        raise TraceValidationError("production link must be below src")
    if kind == "test" and not relative.startswith("tests/"):
        raise TraceValidationError("test link must be below tests")
    source = _strip_csharp_non_code(path.read_text(encoding="utf-8"))
    token = identifier.rsplit(".", 1)[-1]
    escaped = re.escape(token)
    if kind == "production":
        type_declaration = rf"\b(?:class|struct|interface|enum|record(?:\s+(?:class|struct))?)\s+{escaped}\b"
        method_declaration = rf"\b(?:public|internal|private|protected)\s+(?:(?:static|virtual|override|abstract|sealed|async|partial)\s+)*[A-Za-z_][A-Za-z0-9_.<>,?\[\]]*\s+{escaped}\s*\("
        declarations = re.findall(rf"(?:{type_declaration}|{method_declaration})", source)
    else:
        test_declaration = rf"\[\s*Test(?:Attribute)?\s*\]\s*(?:\[[^\]]+\]\s*)*\b(?:public|internal|private|protected)\s+(?:(?:static|async)\s+)*[A-Za-z_][A-Za-z0-9_.<>,?\[\]]*\s+{escaped}\s*\("
        declarations = re.findall(test_declaration, source)
    if len(declarations) != 1:
        raise TraceValidationError(f"{field} declared identifier is missing or ambiguous")
    return {"path": relative, field: identifier}


def _validate_evidence_link(root: Path, value: Any, layers: list[str]) -> dict[str, str]:
    if not isinstance(value, dict):
        raise TraceValidationError("evidence link must be a mapping")
    _exact_keys(value, {"path", "kind", "layer", "identifier"}, "evidence link")
    relative, path = _safe_file(root, value["path"])
    kind = _bounded_string(value["kind"], "evidence kind")
    layer = _bounded_string(value["layer"], "evidence layer")
    identifier = _bounded_string(value["identifier"], "evidence identifier")
    if layer not in layers or EVIDENCE_KINDS.get(layer) != kind:
        raise TraceValidationError("evidence kind/layer is not allowed for the registry entry")
    text = path.read_text(encoding="utf-8")
    if text.count(identifier) != 1:
        raise TraceValidationError("evidence identifier is missing or ambiguous")
    return {"path": relative, "kind": kind, "layer": layer, "identifier": identifier}


def validate(root: Path, expected_registry_entries: int | None = EXPECTED_REGISTRY_ENTRIES) -> dict[str, Any]:
    root = root.resolve(strict=True)
    registry_path = root / "requirements" / "registry.yaml"
    manifest_path = root / "requirements" / "trace-links.yaml"
    registry_metadata = registry_path.lstat()
    if stat.S_ISLNK(registry_metadata.st_mode) or not stat.S_ISREG(registry_metadata.st_mode) or registry_metadata.st_size > MAX_REGISTRY_BYTES:
        raise TraceValidationError("registry is symbolic, non-regular, or exceeds the byte bound")
    registry_text = registry_path.read_text(encoding="utf-8")
    registry = parse_registry(registry_text)
    if expected_registry_entries is not None and len(registry) != expected_registry_entries:
        raise TraceValidationError("registry entry count differs from the closed tranche")
    manifest = load_manifest(manifest_path)
    _exact_keys(manifest, {"schemaVersion", "claimsAcceptanceEvidence", "entries"}, "manifest")
    if manifest["schemaVersion"] != 1 or manifest["claimsAcceptanceEvidence"] is not False:
        raise TraceValidationError("manifest version or acceptance claim is forbidden")
    raw_entries = manifest["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) > (expected_registry_entries or len(registry)) + 1:
        raise TraceValidationError("manifest entries are absent or exceed the bound")

    by_id: dict[str, dict[str, Any]] = {}
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise TraceValidationError("manifest entry must be a mapping")
        _exact_keys(raw, {"id", "owner", "acceptanceLayers", "status", "gapReason", "productionLinks", "testLinks", "evidenceLinks"}, "manifest entry")
        item_id = _bounded_string(raw["id"], "entry ID")
        if not ID_PATTERN.fullmatch(item_id) or item_id in by_id:
            raise TraceValidationError("manifest ID is malformed or duplicated")
        by_id[item_id] = raw

    registry_by_id = {entry["id"]: entry for entry in registry}
    if set(by_id) != set(registry_by_id):
        raise TraceValidationError("manifest has missing or unknown registry IDs")

    seen_links: set[tuple[str, str]] = set()
    canonical_entries: list[dict[str, Any]] = []
    linked_files: set[str] = set()
    counts = {"registered": len(registry), "gap": 0, "linked": 0, "acceptanceSatisfied": 0}
    for registered in registry:
        raw = by_id[registered["id"]]
        if raw["owner"] != registered["owner"] or raw["acceptanceLayers"] != registered["acceptanceLayers"]:
            raise TraceValidationError("manifest owner or acceptance layers drift from registry")
        status_value = raw["status"]
        if not isinstance(status_value, str) or status_value not in {"gap", "linked"}:
            raise TraceValidationError("entry status is outside the closed vocabulary")
        collections = []
        for name in ("productionLinks", "testLinks", "evidenceLinks"):
            collection = raw[name]
            if not isinstance(collection, list) or len(collection) > MAX_LINKS_PER_KIND:
                raise TraceValidationError(f"{name} exceeds its closed bound")
            collections.append(collection)
        production_raw, tests_raw, evidence_raw = collections
        gap_reason = raw["gapReason"]
        if status_value == "gap":
            _bounded_string(gap_reason, "gap reason")
            if production_raw or tests_raw or evidence_raw:
                raise TraceValidationError("gap entries cannot carry orphan links")
            production: list[dict[str, str]] = []
            tests: list[dict[str, str]] = []
            evidence: list[dict[str, str]] = []
        else:
            if gap_reason is not None or not production_raw or not tests_raw or not evidence_raw:
                raise TraceValidationError("linked status requires production, test, and evidence links")
            production = [_validate_code_link(root, item, "production") for item in production_raw]
            tests = [_validate_code_link(root, item, "test") for item in tests_raw]
            evidence = [_validate_evidence_link(root, item, registered["acceptanceLayers"]) for item in evidence_raw]
            production.sort(key=lambda item: (item["path"], item["symbol"]))
            tests.sort(key=lambda item: (item["path"], item["test"]))
            evidence.sort(key=lambda item: (item["layer"], item["kind"], item["path"], item["identifier"]))
        for link_kind, links in (("production", production), ("test", tests), ("evidence", evidence)):
            for link in links:
                identity = (link["path"], link.get("symbol") or link.get("test") or link["identifier"])
                if identity in seen_links:
                    raise TraceValidationError("structured link identity is duplicated or reused")
                seen_links.add(identity)
                linked_files.add(link["path"])
        counts[status_value] += 1
        canonical_entries.append({
            "id": registered["id"], "owner": registered["owner"],
            "acceptanceLayers": registered["acceptanceLayers"], "status": status_value,
            "gapReason": gap_reason, "productionLinks": production, "testLinks": tests,
            "evidenceLinks": evidence, "acceptanceSatisfied": False,
        })

    digest = hashlib.sha256()
    digest.update(b"structured-trace-input-v1\0requirements/registry.yaml\0")
    digest.update(registry_text.encode("utf-8"))
    digest.update(b"\0requirements/trace-links.yaml\0")
    canonical_manifest = {
        "schemaVersion": 1, "claimsAcceptanceEvidence": False,
        "entries": [{key: value for key, value in entry.items() if key != "acceptanceSatisfied"} for entry in canonical_entries],
    }
    digest.update(json.dumps(canonical_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    for relative in sorted(linked_files):
        digest.update(b"\0" + relative.encode("utf-8") + b"\0")
        digest.update((root / relative).read_bytes())
    return {
        "schemaVersion": 1,
        "reportKind": "structured-traceability-foundation",
        "claimsAcceptanceEvidence": False,
        "inputSha256": digest.hexdigest(),
        "counts": counts,
        "entries": canonical_entries,
    }


def render(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True, separators=(",", ": ")) + "\n"


def _safe_output_path(root: Path, output: Path) -> Path:
    root = root.resolve(strict=True)
    candidate = output if output.is_absolute() else root / output
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise TraceValidationError("report output escapes the repository") from exc
    parts = relative.parts
    if any(part in {"", ".", ".."} for part in parts) or parts[:3] != ("docs", "audits", "traceability") or len(parts) != 4 or not parts[-1].endswith(".json"):
        raise TraceValidationError("report output is outside the closed audit directory")
    current = root
    for part in parts[:-1]:
        current = current / part
        if not current.exists() and not current.is_symlink():
            continue
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise TraceValidationError("report output parent is symbolic or non-directory")
    if candidate.exists() or candidate.is_symlink():
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise TraceValidationError("existing report output is symbolic or non-regular")
    resolved_parent = candidate.parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(root)
    except ValueError as exc:
        raise TraceValidationError("report output parent escapes the repository") from exc
    return candidate


def write_or_check(root: Path, output: Path, check: bool, expected_registry_entries: int | None = EXPECTED_REGISTRY_ENTRIES) -> dict[str, Any]:
    output = _safe_output_path(root, output)
    report = validate(root, expected_registry_entries)
    generated = render(report)
    if check:
        if not output.exists() or output.is_symlink() or output.read_text(encoding="utf-8") != generated:
            raise TraceValidationError("structured report is stale")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(generated, encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, default=Path("docs/audits/traceability/phase1-structured-traceability.json"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    try:
        report = write_or_check(root, output, args.check)
        print(json.dumps(report["counts"], sort_keys=True))
        return 0
    except (OSError, UnicodeError, TraceValidationError) as exc:
        print(f"structured trace validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
