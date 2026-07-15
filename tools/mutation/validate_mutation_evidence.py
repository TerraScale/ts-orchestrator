#!/usr/bin/env python3
"""Validate TerraScale's fail-closed mutation policy and zero-claim report."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = ROOT / "tools/mutation/mutation-policy.json"
DEFAULT_REPORT = ROOT / "tools/mutation/mutation-evidence.json"
SUPPLY_CHAIN = ROOT / "testlab/pins/supply-chain-candidates.json"
MAX_JSON_BYTES = 1024 * 1024
MAX_PROJECTS = 64
MAX_EXCLUSIONS = 64
SHA256 = re.compile(r"^[0-9a-f]{64}$")

POLICY_KEYS = {
    "schemaVersion", "policyId", "scope", "minimumMutationScorePercent",
    "maximumSafetyInvariantSurvivors", "projects", "allowedExclusionCategories",
    "forbiddenExclusionCategories", "exclusions",
}
PROJECT_KEYS = {
    "path", "classification", "mutationRequired", "exclusionProof", "exclusionProofSha256",
}
EXCLUSION_KEYS = {
    "project", "category", "paths", "pathDigests", "proof", "proofSha256",
}
PATH_DIGEST_KEYS = {"path", "sha256"}
REPORT_KEYS = {
    "schemaVersion", "asOf", "validUntil", "status", "policy", "policySha256",
    "toolSelection", "execution", "claims", "blockers",
}
TOOL_KEYS = {
    "candidateId", "candidateVersion", "candidateStatus", "selected",
    "lockedContentHash", "internalMirror",
}
EXECUTION_KEYS = {
    "status", "exactSourceTreeSha256", "startedAt", "finishedAt", "totalMutants",
    "killedMutants", "survivingMutants", "mutationScorePercent",
    "safetyInvariantSurvivors", "normalizedReportSha256",
}
CLAIM_KEYS = {
    "thresholdMet", "safetyInvariantClosure", "fullL0", "fullL0C", "ciEvidence",
    "deploymentEvidence",
}
ALLOWED_EXCLUSIONS = {
    "composition-root-trivial-wiring", "generated-code", "immutable-dto-property-accessor",
}
FORBIDDEN_EXCLUSIONS = {
    "adapter-result-classification", "authority", "compensation", "deletion",
    "fencing", "retry", "state-transition", "validator",
}
REQUIRED_BLOCKERS = {
    "owner-select-mutation-tool-and-version", "lock-tool-content-hash",
    "mirror-selected-tool-internally", "prove-dotnet10-tunit-compatibility",
    "approve-stable-mutant-denominator-and-report-normalization",
}


class DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular non-symlink file: {path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON exceeds {MAX_JSON_BYTES} bytes: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise ValueError(f"top-level JSON must be an object: {path}")
    return value


def _keys(value: Any, expected: set[str], where: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{where}: expected object")
        return False
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        errors.append(f"{where}: missing keys {missing}")
    if unknown:
        errors.append(f"{where}: unknown keys {unknown}")
    return not missing and not unknown


def _safe_path(value: Any, where: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 512:
        errors.append(f"{where}: expected non-empty repository-relative path")
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute() or value != path.as_posix() or ".." in path.parts or "." in path.parts
        or "\\" in value or "\x00" in value or any(not part or len(part) > 255 for part in path.parts)
    ):
        errors.append(f"{where}: unsafe repository-relative path")
        return None
    return value


def _inside_without_symlink(repo_root: Path, relative: str, where: str, errors: list[str]) -> Path | None:
    root = repo_root.resolve()
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            errors.append(f"{where}: symlink path components are forbidden")
            return None
    try:
        current.resolve(strict=False).relative_to(root)
    except ValueError:
        errors.append(f"{where}: path escapes repository root")
        return None
    return current


def _exact_string_list(value: Any, where: str, maximum: int, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        errors.append(f"{where}: expected 1..{maximum} strings")
        return []
    if any(not isinstance(item, str) or not item for item in value):
        errors.append(f"{where}: expected non-empty strings")
        return []
    result = list(value)
    if result != sorted(result):
        errors.append(f"{where}: entries must be sorted")
    if len(result) != len(set(result)):
        errors.append(f"{where}: duplicate entries")
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_policy(policy: dict[str, Any], repo_root: Path, errors: list[str]) -> None:
    _keys(policy, POLICY_KEYS, "policy", errors)
    if policy.get("schemaVersion") != 1:
        errors.append("policy.schemaVersion: expected 1")
    if policy.get("policyId") != "terrascale-orchestrator-mutation-v1":
        errors.append("policy.policyId: unexpected policy identity")
    if policy.get("scope") != "full-correctness-critical-solution":
        errors.append("policy.scope: must cover the full correctness-critical solution")
    if policy.get("minimumMutationScorePercent") != 85:
        errors.append("policy.minimumMutationScorePercent: ORCHESTRATOR requires 85")
    if policy.get("maximumSafetyInvariantSurvivors") != 0:
        errors.append("policy.maximumSafetyInvariantSurvivors: must be zero")

    allowed = _exact_string_list(
        policy.get("allowedExclusionCategories"), "policy.allowedExclusionCategories", 16, errors)
    forbidden = _exact_string_list(
        policy.get("forbiddenExclusionCategories"), "policy.forbiddenExclusionCategories", 32, errors)
    if set(allowed) != ALLOWED_EXCLUSIONS:
        errors.append("policy.allowedExclusionCategories: allowed set drift")
    if set(forbidden) != FORBIDDEN_EXCLUSIONS:
        errors.append("policy.forbiddenExclusionCategories: forbidden safety set drift")
    if set(allowed) & set(forbidden):
        errors.append("policy exclusion categories: allowed and forbidden sets overlap")

    project_rows = policy.get("projects")
    if not isinstance(project_rows, list) or not project_rows or len(project_rows) > MAX_PROJECTS:
        errors.append(f"policy.projects: expected 1..{MAX_PROJECTS} projects")
        project_rows = []
    recorded: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(project_rows):
        where = f"policy.projects[{index}]"
        _keys(row, PROJECT_KEYS, where, errors)
        if not isinstance(row, dict):
            continue
        path = _safe_path(row.get("path"), f"{where}.path", errors)
        if path is None:
            continue
        if path in recorded:
            errors.append(f"{where}.path: duplicate project")
        recorded[path] = row
        full_path = repo_root / path
        checked_path = _inside_without_symlink(repo_root, path, f"{where}.path", errors)
        if checked_path is None or not checked_path.is_file() or checked_path.suffix != ".csproj":
            errors.append(f"{where}.path: project is missing, a symlink, or not a csproj")
        classification = row.get("classification")
        required = row.get("mutationRequired")
        proof = row.get("exclusionProof")
        proof_digest = row.get("exclusionProofSha256")
        if not isinstance(classification, str) or not classification:
            errors.append(f"{where}.classification: expected non-empty string")
        if not isinstance(required, bool):
            errors.append(f"{where}.mutationRequired: expected boolean")
        if required is True and (proof is not None or proof_digest is not None):
            errors.append(f"{where}.exclusionProof: required projects cannot carry exclusions")
        if required is False:
            if classification not in ALLOWED_EXCLUSIONS:
                errors.append(f"{where}: only an allowed trivial/generated classification may be excluded")
            proof_path = _safe_path(proof, f"{where}.exclusionProof", errors)
            if proof_path is not None:
                resolved = _inside_without_symlink(repo_root, proof_path, f"{where}.exclusionProof", errors)
                if resolved is None or not resolved.is_file():
                    errors.append(f"{where}.exclusionProof: proof must be a checked-in regular file")
                elif not isinstance(proof_digest, str) or not SHA256.fullmatch(proof_digest) or proof_digest != _sha256(resolved):
                    errors.append(f"{where}.exclusionProofSha256: proof digest is missing or stale")
        if isinstance(classification, str) and any(token in classification for token in FORBIDDEN_EXCLUSIONS) and required is not True:
            errors.append(f"{where}: correctness-critical classification cannot be excluded")

    actual_projects = sorted(
        path.relative_to(repo_root).as_posix()
        for path in (repo_root / "src").rglob("*.csproj")
        if path.is_file() and not path.is_symlink() and not ({"bin", "obj"} & set(path.parts))
    )
    if sorted(recorded) != actual_projects:
        errors.append("policy.projects: inventory drift from src project set")
    if list(recorded) != sorted(recorded):
        errors.append("policy.projects: projects must be sorted by path")
    for path, row in recorded.items():
        if path != "src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj" and row.get("mutationRequired") is not True:
            errors.append(f"policy.projects.{path}: all non-composition production projects are mandatory")

    exclusions = policy.get("exclusions")
    if not isinstance(exclusions, list) or len(exclusions) > MAX_EXCLUSIONS:
        errors.append(f"policy.exclusions: expected at most {MAX_EXCLUSIONS} exclusions")
        exclusions = []
    seen_paths: set[str] = set()
    for index, exclusion in enumerate(exclusions):
        where = f"policy.exclusions[{index}]"
        _keys(exclusion, EXCLUSION_KEYS, where, errors)
        if not isinstance(exclusion, dict):
            continue
        project = _safe_path(exclusion.get("project"), f"{where}.project", errors)
        category = exclusion.get("category")
        paths = _exact_string_list(exclusion.get("paths"), f"{where}.paths", 256, errors)
        path_digests = exclusion.get("pathDigests")
        if not isinstance(path_digests, list) or len(path_digests) != len(paths):
            errors.append(f"{where}.pathDigests: expected one digest per excluded path")
            path_digests = []
        recorded_digests: dict[str, str] = {}
        for digest_index, path_digest in enumerate(path_digests):
            digest_where = f"{where}.pathDigests[{digest_index}]"
            _keys(path_digest, PATH_DIGEST_KEYS, digest_where, errors)
            if not isinstance(path_digest, dict):
                continue
            digest_path = _safe_path(path_digest.get("path"), f"{digest_where}.path", errors)
            digest_value = path_digest.get("sha256")
            if digest_path is not None and isinstance(digest_value, str):
                if digest_path in recorded_digests:
                    errors.append(f"{digest_where}.path: duplicate digest path")
                recorded_digests[digest_path] = digest_value
        proof = _safe_path(exclusion.get("proof"), f"{where}.proof", errors)
        proof_digest = exclusion.get("proofSha256")
        if category not in ALLOWED_EXCLUSIONS or category in FORBIDDEN_EXCLUSIONS:
            errors.append(f"{where}.category: category is not permitted")
        if project not in recorded or (project is not None and recorded[project].get("mutationRequired") is not False):
            errors.append(f"{where}.project: exclusion must target an explicitly optional project")
        project_row = recorded.get(project) if project is not None else None
        if project_row is not None and (
            proof != project_row.get("exclusionProof")
            or proof_digest != project_row.get("exclusionProofSha256")
        ):
            errors.append(f"{where}.proof: exclusion proof must exactly match the project proof")
        if proof is not None:
            proof_file = _inside_without_symlink(repo_root, proof, f"{where}.proof", errors)
            if proof_file is None or not proof_file.is_file():
                errors.append(f"{where}.proof: proof must be a checked-in regular file")
            elif not isinstance(proof_digest, str) or not SHA256.fullmatch(proof_digest) or proof_digest != _sha256(proof_file):
                errors.append(f"{where}.proofSha256: proof digest is missing or stale")
        for path in paths:
            safe = _safe_path(path, f"{where}.paths", errors)
            if safe is not None:
                if safe in seen_paths:
                    errors.append(f"{where}.paths: path excluded more than once")
                seen_paths.add(safe)
                source = _inside_without_symlink(repo_root, safe, f"{where}.paths", errors)
                if source is None or not source.is_file() or source.suffix != ".cs":
                    errors.append(f"{where}.paths: excluded source must be a regular C# file")
                else:
                    digest_value = recorded_digests.get(safe)
                    if not isinstance(digest_value, str) or not SHA256.fullmatch(digest_value) or digest_value != _sha256(source):
                        errors.append(f"{where}.pathDigests: excluded source digest is missing or stale")
        if set(recorded_digests) != set(paths):
            errors.append(f"{where}.pathDigests: digest path set must exactly match excluded paths")

    composition = recorded.get("src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj")
    if composition is not None and composition.get("mutationRequired") is True:
        if seen_paths:
            errors.append("policy.exclusions: mutation-required runtime project cannot exclude source files")
    else:
        composition_sources = sorted(
            path.relative_to(repo_root).as_posix()
            for path in (repo_root / "src/TerraScale.Orchestrator").rglob("*.cs")
            if path.is_file() and not path.is_symlink() and not ({"bin", "obj"} & set(path.parts))
        )
        if composition_sources != ["src/TerraScale.Orchestrator/Program.cs"] or seen_paths != set(composition_sources):
            errors.append("policy.exclusions: composition-root proof is stale or broader than the exact trivial source set")


def _validate_report(
    report: dict[str, Any], policy_path: Path, supply: dict[str, Any], validation_date: date,
    errors: list[str],
) -> None:
    _keys(report, REPORT_KEYS, "report", errors)
    if report.get("schemaVersion") != 1:
        errors.append("report.schemaVersion: expected 1")
    if report.get("status") != "blocked-unselected-tool":
        errors.append("report.status: must remain blocked while the mutation tool is unselected")
    if report.get("policy") != "tools/mutation/mutation-policy.json":
        errors.append("report.policy: unexpected policy path")
    digest = report.get("policySha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest) or digest != _sha256(policy_path):
        errors.append("report.policySha256: policy digest is missing or stale")

    try:
        as_of = date.fromisoformat(report.get("asOf"))
        valid_until = date.fromisoformat(report.get("validUntil"))
    except (TypeError, ValueError):
        errors.append("report dates: expected ISO calendar dates")
    else:
        if valid_until != as_of + timedelta(days=30):
            errors.append("report.validUntil: expected an exact 30-day review window")
        if validation_date < as_of:
            errors.append("report.asOf: future-dated evidence is invalid")
        if validation_date > valid_until:
            errors.append("report.validUntil: mutation readiness evidence is stale")

    tool = report.get("toolSelection")
    _keys(tool, TOOL_KEYS, "report.toolSelection", errors)
    mutation_candidates = [
        item for item in supply.get("entries", [])
        if isinstance(item, dict) and item.get("category") == "mutation"
    ]
    if len(mutation_candidates) != 1:
        errors.append("supply-chain entries: expected exactly one mutation candidate")
        candidate: dict[str, Any] = {}
    else:
        candidate = mutation_candidates[0]
    if isinstance(tool, dict):
        expected = {
            "candidateId": candidate.get("id"),
            "candidateVersion": candidate.get("candidateVersion"),
            "candidateStatus": candidate.get("status"),
        }
        for key, value in expected.items():
            if tool.get(key) != value:
                errors.append(f"report.toolSelection.{key}: drift from supply-chain candidate audit")
        if tool.get("selected") is not False:
            errors.append("report.toolSelection.selected: candidate audit does not select a tool")
        for key in ("lockedContentHash", "internalMirror"):
            if tool.get(key) is not None:
                errors.append(f"report.toolSelection.{key}: cannot claim closure for an unselected candidate")
    if candidate.get("status") != "candidate-unselected" or candidate.get("productionQualified") is not False:
        errors.append("supply-chain mutation candidate: expected explicit unselected/unqualified state")

    execution = report.get("execution")
    _keys(execution, EXECUTION_KEYS, "report.execution", errors)
    if isinstance(execution, dict):
        if execution.get("status") != "not-run":
            errors.append("report.execution.status: mutation execution cannot be claimed before tool selection")
        for key in EXECUTION_KEYS - {"status"}:
            if execution.get(key) is not None:
                errors.append(f"report.execution.{key}: zero-claim report requires null")

    claims = report.get("claims")
    _keys(claims, CLAIM_KEYS, "report.claims", errors)
    if isinstance(claims, dict):
        for key in sorted(CLAIM_KEYS):
            if claims.get(key) is not False:
                errors.append(f"report.claims.{key}: zero-claim report requires false")

    blockers = _exact_string_list(report.get("blockers"), "report.blockers", 32, errors)
    if set(blockers) != REQUIRED_BLOCKERS:
        errors.append("report.blockers: unresolved selection/qualification blockers drift")


def validate(
    policy: dict[str, Any], report: dict[str, Any], *, repo_root: Path = ROOT,
    validation_date: date = date.today(), policy_path: Path | None = None,
    supply: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    path = policy_path or repo_root / "tools/mutation/mutation-policy.json"
    if supply is None:
        try:
            supply = load_json(repo_root / "testlab/pins/supply-chain-candidates.json")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return [f"supply-chain audit: unreadable: {exc}"]
    _validate_policy(policy, repo_root, errors)
    _validate_report(report, path, supply, validation_date, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    args = parser.parse_args()
    try:
        policy = load_json(args.policy)
        report = load_json(args.report)
        supply = load_json(SUPPLY_CHAIN)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"mutation evidence invalid: {exc}", file=sys.stderr)
        return 1
    errors = validate(
        policy, report, validation_date=args.as_of, policy_path=args.policy, supply=supply)
    if errors:
        for error in errors:
            print(f"mutation evidence invalid: {error}", file=sys.stderr)
        return 1
    print("mutation evidence valid: tool selection unresolved; no mutation result or deployment claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
