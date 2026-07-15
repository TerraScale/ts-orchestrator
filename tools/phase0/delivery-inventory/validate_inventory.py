#!/usr/bin/env python3
"""Fail-closed validation for the pinned delivery descriptor inventory."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
INVENTORY = Path(__file__).parents[3] / "docs/audits/delivery/descriptor-inventory.json"
spec = importlib.util.spec_from_file_location("delivery_inventory_generator", HERE / "generate_inventory.py")
generator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(generator)
CITATION = re.compile(
    r"^(?P<repo>[^@]+)@(?P<commit>[0-9a-f]{40}):(?P<path>.+):(?P<start>[1-9]\d*)-(?P<end>[1-9]\d*)$"
)


def show_lines(repo: str, commit: str, path: str) -> list[str] | None:
    try:
        output = subprocess.check_output(
            ["git", "-C", str(generator.WORKSPACE / repo), "show", f"{commit}:{path}"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return output.splitlines()


def validate_citation(citation: object) -> str | None:
    if not isinstance(citation, str):
        return "citation must be a string"
    match = CITATION.fullmatch(citation)
    if match is None:
        return f"citation lacks exact repo@commit:path:start-end provenance: {citation}"
    repo, commit = match.group("repo"), match.group("commit")
    if generator.PINNED_REPOSITORIES.get(repo) != commit:
        return f"citation does not use the pinned commit: {citation}"
    lines = show_lines(repo, commit, match.group("path"))
    if lines is None:
        return f"citation target is absent from pinned tree: {citation}"
    start, end = int(match.group("start")), int(match.group("end"))
    if end < start or end > len(lines):
        return f"citation line range is out of bounds: {citation}"
    if not any(line.strip() for line in lines[start - 1:end]):
        return f"citation range contains no evidence: {citation}"
    return None


def validate(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    canonical = generator.build_document()
    if document.get("status") != "observed-inventory-not-reconciled-policy":
        errors.append("inventory status must remain observed and unreconciled")
    if document.get("scope") != "pinned sibling commit trees; dirty worktree content excluded and preserved":
        errors.append("inventory scope must exclude and preserve dirty worktree content")

    repositories = document.get("repositories", [])
    if not isinstance(repositories, list):
        return errors + ["repositories must be a list"]
    names = [item.get("name") for item in repositories if isinstance(item, dict)]
    if set(names) != set(generator.PINNED_REPOSITORIES) or len(names) != len(set(names)):
        errors.append("all ten canonical sibling repositories must occur exactly once")
    for repository in repositories:
        if not isinstance(repository, dict) or repository.get("name") not in generator.PINNED_REPOSITORIES:
            continue
        name = repository["name"]
        if repository.get("commit") != generator.PINNED_REPOSITORIES[name]:
            errors.append(f"{name}: commit differs from the audit pin")
        if repository.get("sourceMode") != "immutable-git-tree":
            errors.append(f"{name}: source mode must be immutable-git-tree")
        descriptors = repository.get("descriptors", [])
        paths = [item.get("path") for item in descriptors if isinstance(item, dict)]
        if len(paths) != len(set(paths)) or repository.get("descriptorCount") != len(descriptors):
            errors.append(f"{name}: descriptor paths/count must be unique and exact")
        canonical_repo = next(item for item in canonical["repositories"] if item["name"] == name)
        if descriptors != canonical_repo["descriptors"]:
            errors.append(f"{name}: descriptor inventory differs from the pinned tree")
        scripts = repository.get("referencedLocalScripts", [])
        if repository.get("referencedScriptCount") != len(scripts) or scripts != canonical_repo["referencedLocalScripts"]:
            errors.append(f"{name}: referenced local build-script inventory differs from the pinned delivery/workflow descriptors")
        observation = repository.get("dirtyWorktreeObservation", {})
        if observation.get("excludedFromPinnedTreeInventory") is not True or observation.get("preservation") != "not-inventoried-not-modified-not-cleaned":
            errors.append(f"{name}: dirty worktree preservation boundary is missing")

    if document.get("deploymentDescriptors") != canonical["deploymentDescriptors"]:
        errors.append("deployment descriptor summaries differ from pinned JSON")
    roles = document.get("productionRoles", [])
    role_names = [item.get("role") for item in roles if isinstance(item, dict)]
    if role_names != ["TerraBase", "API", "Authentication", "Dashboard"]:
        errors.append("production runtime roles must be TerraBase, API, Authentication, and Dashboard exactly once")
    for role in roles:
        for citation in role.get("evidence", []):
            error = validate_citation(citation)
            if error:
                errors.append(error)
    authentication = next((item for item in roles if item.get("role") == "Authentication"), {})
    if authentication.get("coverage") != "missing-build-target" or authentication.get("buildTargets") != []:
        errors.append("Authentication build-target gap must remain explicit")

    conflicts = document.get("policyConflicts", [])
    conflict_ids = [item.get("id") for item in conflicts if isinstance(item, dict)]
    if conflict_ids != ["CI-CONFLICT-001", "CI-CONFLICT-002", "CI-CONFLICT-003", "CI-CONFLICT-004"]:
        errors.append("policy conflict IDs must be complete and ordered")
    for conflict in conflicts:
        if conflict.get("status") != "observed-unresolved" or conflict.get("accepted") is not False:
            errors.append(f"{conflict.get('id')}: observed conflict cannot be accepted")
        if not conflict.get("proposedReconciliation"):
            errors.append(f"{conflict.get('id')}: proposed reconciliation is missing")
        for citation in conflict.get("evidence", []):
            error = validate_citation(citation)
            if error:
                errors.append(error)
    gaps = document.get("coverageGaps", [])
    gap_ids = [item.get("id") for item in gaps if isinstance(item, dict)]
    if gap_ids != ["CI-GAP-001", "CI-GAP-002", "CI-GAP-003", "CI-GAP-004"] or any(item.get("status") != "open" for item in gaps):
        errors.append("all four coverage gaps must remain explicit and open")
    if document.get("proposedPolicy", {}).get("status") != "proposal-not-accepted":
        errors.append("proposed reconciliation must not be represented as accepted policy")

    if document != canonical:
        errors.append("inventory differs from deterministic generator output")
    return errors


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else INVENTORY
    errors = validate(json.loads(path.read_text(encoding="utf-8")))
    if errors:
        raise SystemExit("\n".join(dict.fromkeys(errors)))
    document = json.loads(path.read_text(encoding="utf-8"))
    total = sum(repo["descriptorCount"] for repo in document["repositories"])
    print(f"validated 10 pinned repositories, {total} descriptors, 9 delivery summaries, 4 roles, 4 conflicts, and 4 open gaps")


if __name__ == "__main__":
    main()
