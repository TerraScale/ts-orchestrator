#!/usr/bin/env python3
"""Fail-closed validator for Phase 0 supply-chain candidate evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST = ROOT / "testlab/pins/supply-chain-candidates.json"

TOP_KEYS = {
    "schemaVersion", "asOf", "status", "productionQualified",
    "artifactSigningSelection", "evidenceSigningSelection",
    "attestationToolSelection", "existingBaselinePins", "requiredCategories", "entries", "gaps",
}
BASELINE_KEYS = {
    "status", "globalJsonSource", "centralPackagesSource", "testLockSource",
    "sdk", "packages", "lockProvenance", "lockProvenanceStatus",
}
SDK_KEYS = {"version", "rollForward", "rollForwardSemanticsSource", "testRunner", "exactClosure", "closureGap"}
BASELINE_PACKAGE_KEYS = {
    "name", "declaredVersion", "lockType", "lockRequested", "resolvedVersion", "contentHash",
}
LOCK_PROVENANCE_KEYS = {"path", "sha256"}
EXPECTED_SDK = {
    "version": "10.0.301",
    "rollForward": "latestFeature",
    "testRunner": "Microsoft.Testing.Platform",
}
EXPECTED_BASELINE_PACKAGES = {
    "TUnit": {
        "declaredVersion": "1.56.18", "lockType": "Direct",
        "lockRequested": "[1.56.18, )", "resolvedVersion": "1.56.18",
    },
    "Microsoft.Testing.Platform": {
        "declaredVersion": None, "lockType": "Transitive",
        "lockRequested": None, "resolvedVersion": "2.2.3",
    },
}
ENTRY_KEYS = {
    "id", "category", "name", "candidateVersion", "status", "distribution",
    "versionSource", "evidenceSources", "license", "licenseSource", "platforms",
    "upstreamIntegrity", "upstreamProvenance", "mirrorRequired", "mirrorStatus",
    "locallyObserved", "productionQualified", "qualificationGaps",
}
GAP_KEYS = {"id", "capability", "reason", "exitEvidence"}
REQUIRED_CATEGORIES = {
    "build", "coverage", "fuzz", "mutation", "oci-artifact", "property-test",
    "runtime", "sbom", "signing", "vulnerability",
}
ENTRY_STATUSES = {"candidate-unselected", "reviewed-alternative"}
INTEGRITY_STATES = {
    "registry-metadata-only", "checksums-sbom-provenance-sigstore",
    "checksums-attestation", "checksums-signatures", "checksums-sigstore-bundles",
    "checksums-cert-signature-sbom", "checksums-sbom-sigstore",
}
BINARY_DISTRIBUTIONS = {"release-archive", "release-binary"}
ALLOWED_SOURCE_HOSTS = {"github.com", "www.nuget.org"}
SECRET_NAME = re.compile(r"(?i)(secret|token|password|private.?key|credential)")
VERSION_BAD = re.compile(r"(?i)(latest|snapshot|nightly|\*|[<>=~^]|\.x(?:\b|$))")
ID_PATTERN = re.compile(r"^(?:PIN|ALT|GAP)-[A-Z0-9-]+$")


def _object_keys(value: object, expected: set[str], where: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{where}: expected object")
        return
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        errors.append(f"{where}: missing keys {missing}")
    if unknown:
        errors.append(f"{where}: unknown keys {unknown}")


def _nonempty_text(value: object, where: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{where}: expected non-empty string")


def _source(value: object, where: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        errors.append(f"{where}: expected exact HTTPS primary-source URL")
        return
    parts = urlsplit(value)
    if parts.scheme != "https" or parts.netloc not in ALLOWED_SOURCE_HOSTS:
        errors.append(f"{where}: source must use HTTPS on an allowed primary-source host")
    if parts.query or parts.fragment or parts.username or parts.password:
        errors.append(f"{where}: source URL must not contain query, fragment, or userinfo")
    if "/latest" in parts.path.lower():
        errors.append(f"{where}: source URL must be version-specific, not latest")


def _string_list(value: object, where: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{where}: expected non-empty list")
    elif any(not isinstance(item, str) or not item.strip() for item in value):
        errors.append(f"{where}: entries must be non-empty strings")
    elif len(value) != len(set(value)):
        errors.append(f"{where}: duplicate entries")


def _scan_secret_fields(value: object, where: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_NAME.search(str(key)):
                errors.append(f"{where}.{key}: secret-bearing fields are prohibited")
            _scan_secret_fields(item, f"{where}.{key}", errors)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_secret_fields(item, f"{where}[{index}]", errors)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_existing_baseline(data: dict[str, object], repo_root: Path, errors: list[str]) -> None:
    baseline = data.get("existingBaselinePins")
    _object_keys(baseline, BASELINE_KEYS, "manifest.existingBaselinePins", errors)
    if not isinstance(baseline, dict):
        return
    if baseline.get("status") != "observed-checked-in-not-exact-sdk-closure":
        errors.append("manifest.existingBaselinePins.status: must preserve the observed/unqualified state")

    expected_sources = {
        "globalJsonSource": "global.json",
        "centralPackagesSource": "Directory.Packages.props",
        "testLockSource": "tests/TerraScale.Orchestrator.ContractTests/packages.lock.json",
    }
    for key, expected in expected_sources.items():
        if baseline.get(key) != expected:
            errors.append(f"manifest.existingBaselinePins.{key}: expected {expected}")

    sdk = baseline.get("sdk")
    _object_keys(sdk, SDK_KEYS, "manifest.existingBaselinePins.sdk", errors)
    global_path = repo_root / expected_sources["globalJsonSource"]
    try:
        global_data = load(global_path)
        checked_sdk = global_data["sdk"]  # type: ignore[index]
        checked_runner = global_data["test"]["runner"]  # type: ignore[index]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        errors.append(f"checked-in global.json: unreadable baseline: {exc}")
    else:
        if not isinstance(checked_sdk, dict) or not isinstance(checked_runner, str):
            errors.append("checked-in global.json: baseline fields have invalid types")
        elif isinstance(sdk, dict):
            for key in ("version", "rollForward"):
                if sdk.get(key) != checked_sdk.get(key):
                    errors.append(f"manifest.existingBaselinePins.sdk.{key}: drift from checked-in global.json")
            if sdk.get("testRunner") != checked_runner:
                errors.append("manifest.existingBaselinePins.sdk.testRunner: drift from checked-in global.json")
    if isinstance(sdk, dict):
        for key, expected in EXPECTED_SDK.items():
            if sdk.get(key) != expected:
                errors.append(f"manifest.existingBaselinePins.sdk.{key}: expected frozen baseline {expected}")
        if sdk.get("rollForwardSemanticsSource") != "https://learn.microsoft.com/en-us/dotnet/core/tools/global-json":
            errors.append("manifest.existingBaselinePins.sdk.rollForwardSemanticsSource: expected official .NET documentation")
        if sdk.get("exactClosure") is not False:
            errors.append("manifest.existingBaselinePins.sdk.exactClosure: must be false for latestFeature")
        closure_gap = sdk.get("closureGap")
        if not isinstance(closure_gap, str) or "higher installed feature band" not in closure_gap:
            errors.append("manifest.existingBaselinePins.sdk.closureGap: must disclose higher feature-band roll-forward")

    package_rows = baseline.get("packages")
    if not isinstance(package_rows, list) or len(package_rows) != 2:
        errors.append("manifest.existingBaselinePins.packages: expected exactly TUnit and Microsoft.Testing.Platform")
        package_rows = []
    packages: dict[str, dict[str, object]] = {}
    for index, package in enumerate(package_rows):
        where = f"manifest.existingBaselinePins.packages[{index}]"
        _object_keys(package, BASELINE_PACKAGE_KEYS, where, errors)
        if isinstance(package, dict) and isinstance(package.get("name"), str):
            packages[package["name"]] = package
    if set(packages) != {"TUnit", "Microsoft.Testing.Platform"}:
        errors.append("manifest.existingBaselinePins.packages: baseline package set drift")
    for name, expected_values in EXPECTED_BASELINE_PACKAGES.items():
        row = packages.get(name)
        if row is None:
            continue
        for key, expected in expected_values.items():
            if row.get(key) != expected:
                errors.append(f"manifest.existingBaselinePins.packages.{name}.{key}: expected frozen baseline {expected}")

    central_path = repo_root / expected_sources["centralPackagesSource"]
    try:
        tree = ET.parse(central_path)
        central_versions = {
            node.attrib["Include"]: node.attrib["Version"]
            for node in tree.findall(".//PackageVersion")
            if "Include" in node.attrib and "Version" in node.attrib
        }
    except (OSError, ET.ParseError, KeyError) as exc:
        errors.append(f"checked-in Directory.Packages.props: unreadable baseline: {exc}")
    else:
        tunit = packages.get("TUnit")
        if tunit is not None and tunit.get("declaredVersion") != central_versions.get("TUnit"):
            errors.append("manifest.existingBaselinePins.packages.TUnit.declaredVersion: drift from Directory.Packages.props")

    lock_path = repo_root / expected_sources["testLockSource"]
    try:
        lock_data = load(lock_path)
        locked = lock_data["dependencies"]["net10.0"]  # type: ignore[index]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        errors.append(f"checked-in test lock: unreadable baseline: {exc}")
    else:
        if not isinstance(locked, dict):
            errors.append("checked-in test lock: net10.0 dependency group must be an object")
            locked = {}
        for name in EXPECTED_BASELINE_PACKAGES:
            row = packages.get(name)
            actual = locked.get(name)
            if row is None or not isinstance(actual, dict):
                continue
            expected_values = {
                "lockType": actual.get("type"),
                "lockRequested": actual.get("requested"),
                "resolvedVersion": actual.get("resolved"),
                "contentHash": actual.get("contentHash"),
            }
            for key, expected in expected_values.items():
                if row.get(key) != expected:
                    errors.append(f"manifest.existingBaselinePins.packages.{name}.{key}: drift from checked-in test lock")

    provenance = baseline.get("lockProvenance")
    if not isinstance(provenance, list) or not provenance:
        errors.append("manifest.existingBaselinePins.lockProvenance: expected non-empty lock provenance")
        provenance = []
    recorded: dict[str, str] = {}
    for index, item in enumerate(provenance):
        where = f"manifest.existingBaselinePins.lockProvenance[{index}]"
        _object_keys(item, LOCK_PROVENANCE_KEYS, where, errors)
        if isinstance(item, dict) and isinstance(item.get("path"), str) and isinstance(item.get("sha256"), str):
            recorded[item["path"]] = item["sha256"]
    if len(recorded) != len(provenance):
        errors.append("manifest.existingBaselinePins.lockProvenance: duplicate or invalid path records")
    actual_paths = sorted(path.relative_to(repo_root).as_posix() for path in repo_root.rglob("packages.lock.json"))
    if sorted(recorded) != actual_paths:
        errors.append("manifest.existingBaselinePins.lockProvenance: path set drift from checked-in lock files")
    for relative_path, digest in sorted(recorded.items()):
        path = repo_root / relative_path
        if not path.is_file() or not re.fullmatch(r"[0-9a-f]{64}", digest) or _sha256(path) != digest:
            errors.append(f"manifest.existingBaselinePins.lockProvenance.{relative_path}: SHA-256 drift")

    if baseline.get("lockProvenanceStatus") != "checked-in-lock-files-bound-by-sha256-but-not-yet-qualified-against-an-internal-mirror":
        errors.append("manifest.existingBaselinePins.lockProvenanceStatus: must retain unqualified mirror gap")


def validate(data: object, repo_root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    _object_keys(data, TOP_KEYS, "manifest", errors)
    if not isinstance(data, dict):
        return errors

    if data.get("schemaVersion") != 1:
        errors.append("manifest.schemaVersion: expected 1")
    if data.get("status") != "candidate-review-only":
        errors.append("manifest.status: must remain candidate-review-only")
    if data.get("productionQualified") is not False:
        errors.append("manifest.productionQualified: must be false")
    for key in ("artifactSigningSelection", "evidenceSigningSelection", "attestationToolSelection"):
        if data.get(key) is not None:
            errors.append(f"manifest.{key}: selection must remain null")

    _validate_existing_baseline(data, repo_root, errors)

    categories = data.get("requiredCategories")
    _string_list(categories, "manifest.requiredCategories", errors)
    if isinstance(categories, list) and set(categories) != REQUIRED_CATEGORIES:
        errors.append("manifest.requiredCategories: must equal the complete required category set")

    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("manifest.entries: expected non-empty list")
        entries = []

    ids: list[str] = []
    seen_categories: set[str] = set()
    signing_candidates = 0
    for index, entry in enumerate(entries):
        where = f"manifest.entries[{index}]"
        _object_keys(entry, ENTRY_KEYS, where, errors)
        if not isinstance(entry, dict):
            continue
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not ID_PATTERN.fullmatch(entry_id):
            errors.append(f"{where}.id: invalid stable ID")
        else:
            ids.append(entry_id)
        category = entry.get("category")
        if category not in REQUIRED_CATEGORIES:
            errors.append(f"{where}.category: unknown category")
        else:
            seen_categories.add(category)
            if category == "signing":
                signing_candidates += 1
        for key in ("name", "distribution", "license", "upstreamProvenance"):
            _nonempty_text(entry.get(key), f"{where}.{key}", errors)
        version = entry.get("candidateVersion")
        _nonempty_text(version, f"{where}.candidateVersion", errors)
        if isinstance(version, str) and VERSION_BAD.search(version):
            errors.append(f"{where}.candidateVersion: floating or ranged versions are prohibited")
        if entry.get("status") not in ENTRY_STATUSES:
            errors.append(f"{where}.status: tool must remain unselected")
        _source(entry.get("versionSource"), f"{where}.versionSource", errors)
        if isinstance(version, str) and isinstance(entry.get("versionSource"), str):
            if version.lower() not in entry["versionSource"].lower():
                errors.append(f"{where}.versionSource: URL must contain candidateVersion")
        evidence_sources = entry.get("evidenceSources")
        _string_list(evidence_sources, f"{where}.evidenceSources", errors)
        if isinstance(evidence_sources, list):
            for source_index, source in enumerate(evidence_sources):
                _source(source, f"{where}.evidenceSources[{source_index}]", errors)
            if entry.get("versionSource") not in evidence_sources:
                errors.append(f"{where}.evidenceSources: must include versionSource")
        _source(entry.get("licenseSource"), f"{where}.licenseSource", errors)
        if isinstance(version, str) and isinstance(entry.get("licenseSource"), str):
            if version.lower() not in entry["licenseSource"].lower():
                errors.append(f"{where}.licenseSource: URL must be version-specific")
        platforms = entry.get("platforms")
        _string_list(platforms, f"{where}.platforms", errors)
        if entry.get("distribution") in BINARY_DISTRIBUTIONS and isinstance(platforms, list):
            for platform in ("linux-x64", "linux-arm64"):
                if platform not in platforms:
                    errors.append(f"{where}.platforms: binary candidate lacks {platform}")
        if entry.get("upstreamIntegrity") not in INTEGRITY_STATES:
            errors.append(f"{where}.upstreamIntegrity: unknown evidence state")
        if entry.get("mirrorRequired") is not True:
            errors.append(f"{where}.mirrorRequired: must be true")
        if entry.get("mirrorStatus") != "missing":
            errors.append(f"{where}.mirrorStatus: must remain missing until separate mirror evidence exists")
        if entry.get("locallyObserved") is not False:
            errors.append(f"{where}.locallyObserved: this package did not execute candidate tools")
        if entry.get("productionQualified") is not False:
            errors.append(f"{where}.productionQualified: must be false")
        _string_list(entry.get("qualificationGaps"), f"{where}.qualificationGaps", errors)

    if len(ids) != len(set(ids)):
        errors.append("manifest.entries: duplicate stable IDs")
    missing_categories = sorted(REQUIRED_CATEGORIES - seen_categories)
    if missing_categories:
        errors.append(f"manifest.entries: missing candidate categories {missing_categories}")
    if signing_candidates < 2:
        errors.append("manifest.entries: signing must retain at least two unselected candidates")

    gaps = data.get("gaps")
    if not isinstance(gaps, list) or not gaps:
        errors.append("manifest.gaps: expected non-empty list")
        gaps = []
    gap_ids: list[str] = []
    for index, gap in enumerate(gaps):
        where = f"manifest.gaps[{index}]"
        _object_keys(gap, GAP_KEYS, where, errors)
        if not isinstance(gap, dict):
            continue
        gap_id = gap.get("id")
        if not isinstance(gap_id, str) or not ID_PATTERN.fullmatch(gap_id) or not gap_id.startswith("GAP-"):
            errors.append(f"{where}.id: invalid GAP stable ID")
        else:
            gap_ids.append(gap_id)
        for key in ("capability", "reason", "exitEvidence"):
            _nonempty_text(gap.get(key), f"{where}.{key}", errors)
    if len(gap_ids) != len(set(gap_ids)):
        errors.append("manifest.gaps: duplicate stable IDs")

    _scan_secret_fields(data, "manifest", errors)
    return sorted(set(errors))


def load(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs="?", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args(argv)
    try:
        data = load(args.manifest)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid supply-chain manifest: {exc}", file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"validated {len(data['entries'])} candidate records and {len(data['gaps'])} explicit gaps; no selection or qualification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
