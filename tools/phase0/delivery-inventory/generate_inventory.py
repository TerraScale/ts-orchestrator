#!/usr/bin/env python3
"""Generate the deterministic descriptor inventory from immutable sibling commits."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

WORKSPACE = Path("/workspaces/TerraScale")
PINNED_REPOSITORIES = {
    "TerraBase": "349cd1a11e5b252ffc193d3c3cdf059b954828fd",
    "Terrabase.Operator": "b3b105be880e169d62e3cb4506846b8a11342d5c",
    "TerraScale.Deploy": "cacb596cd0f6f25a40e76160554fecc14f047965",
    "TerraScale.DevHost": "dd2b8762beb85199578ee41bdfafc199e977a0b4",
    "TerraScale.DotNet": "9d98e4e3dc3e05eb955ba06f03b05bf462cfb21b",
    "TerraScale.TypeScript": "7d9b629ce5a5d41a3fa457911305b057749e3252",
    "TerraScale.Infrastructure": "3bfdb4ee0124fbcce43e7db57cf00045f374fbcb",
    "TerraScale.Internals": "3643df207f9f1129c9f677148e6890d436339141",
    "Terrascale.Documentation": "ccca078a99f4d0702d4e55ac02d6585277ea08e9",
    "Terrascale.Landingpage": "0a763469d3d086e672be673b080a97dbc31dff26",
}
WORKTREE_OBSERVATIONS = {
    repo: {"observedDirty": repo == "TerraScale.Internals", "statusEntryCount": 13 if repo == "TerraScale.Internals" else 0}
    for repo in PINNED_REPOSITORIES
}
EXCLUDED_SEGMENTS = {"node_modules", "vendor", "bin", "obj"}
DESCRIPTOR_PATTERN = re.compile(
    r"(^|/)(\.terrascale/[^/]+|\.forgejo/workflows/[^/]+|\.github/workflows/[^/]+|"
    r"Dockerfile[^/]*|[^/]*\.service|(?:docker-)?compose[^/]*\.(?:ya?ml)|package\.json|"
    r"[^/]*\.csproj|[^/]*\.fsproj|[^/]*\.slnx?|global\.json|"
    r"Directory\.(?:Build|Packages)\.(?:props|targets)|Pulumi(?:\.[^/]*)?\.ya?ml|"
    r"packages\.lock\.json|package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.ya?ml|yarn\.lock|bun\.lockb?|"
    r"NuGet\.Config|\.config/dotnet-tools\.json|Makefile|GNUmakefile|go\.(?:mod|sum|work|work\.sum)|"
    r"Cargo\.(?:toml|lock)|rust-toolchain(?:\.toml)?|docker-bake[^/]*\.(?:hcl|json|ya?ml)|"
    r"pyproject\.toml)$", re.IGNORECASE,
)
SCRIPT_REFERENCE = re.compile(r"(?<![A-Za-z0-9_.-])((?:\./)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.(?:sh|ps1|py|js|ts))(?![A-Za-z0-9_.-])")


def git(repo: str, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(WORKSPACE / repo), *arguments], text=True
    )


def descriptor_type(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    if path.startswith((".forgejo/workflows/", ".github/workflows/")):
        return "workflow"
    if path.startswith(".terrascale/"):
        return "delivery-descriptor"
    if name.startswith("dockerfile"):
        return "container-build"
    if name.endswith(".service"):
        return "systemd-runtime"
    if "compose" in name and name.endswith((".yml", ".yaml")):
        return "compose-runtime"
    if name == "package.json":
        return "node-build"
    if name in {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb"} or name.startswith("pnpm-lock."):
        return "node-lock"
    if name.endswith((".csproj", ".fsproj")):
        return "dotnet-project"
    if name.endswith((".sln", ".slnx")):
        return "dotnet-solution"
    if name in {"directory.build.props", "directory.build.targets", "directory.packages.props", "directory.packages.targets", "global.json"}:
        return "dotnet-build-policy"
    if name in {"packages.lock.json", "nuget.config", "dotnet-tools.json"}:
        return "dotnet-dependency-lock"
    if name.startswith("pulumi") and name.endswith((".yml", ".yaml")):
        return "pulumi-stack"
    if name in {"go.mod", "go.work"}:
        return "go-build"
    if name in {"go.sum", "go.work.sum"}:
        return "go-lock"
    if name in {"cargo.toml", "rust-toolchain", "rust-toolchain.toml", "pyproject.toml"}:
        return "language-build"
    if name == "cargo.lock":
        return "rust-lock"
    if name in {"makefile", "gnumakefile"}:
        return "make-build"
    if name.startswith("docker-bake"):
        return "container-build-graph"
    raise ValueError(f"unclassified descriptor {path}")


def tree_descriptors(repo: str, commit: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in git(repo, "ls-tree", "-r", commit).splitlines():
        metadata, path = line.split("\t", 1)
        mode, kind, oid = metadata.split()
        if kind != "blob" or EXCLUDED_SEGMENTS.intersection(path.split("/")):
            continue
        if DESCRIPTOR_PATTERN.search(path):
            rows.append({"path": path, "type": descriptor_type(path), "gitBlob": oid, "mode": mode})
    return sorted(rows, key=lambda item: item["path"])


def referenced_scripts(repo: str, commit: str, descriptors: list[dict[str, str]]) -> list[dict[str, str]]:
    all_rows = {
        line.split("\t", 1)[1]: {
            "mode": line.split("\t", 1)[0].split()[0],
            "oid": line.split("\t", 1)[0].split()[2],
        }
        for line in git(repo, "ls-tree", "-r", commit).splitlines()
        if "\t" in line
    }
    references: dict[tuple[str, str], dict[str, str]] = {}
    for descriptor in descriptors:
        if descriptor["type"] not in {"delivery-descriptor", "workflow"}:
            continue
        content = git(repo, "show", f"{commit}:{descriptor['path']}")
        paths = {match.group(1).removeprefix("./") for match in SCRIPT_REFERENCE.finditer(content)}
        paths.update(
            path for path, metadata in all_rows.items()
            if metadata["mode"] == "100755" and path in content
        )
        for path in paths:
            if path in all_rows and not EXCLUDED_SEGMENTS.intersection(path.split("/")):
                references[(descriptor["path"], path)] = {
                    "referencedBy": descriptor["path"], "path": path,
                    "gitBlob": all_rows[path]["oid"], "mode": all_rows[path]["mode"],
                    "classification": "referenced-build-script-or-executable",
                }
    return [references[key] for key in sorted(references)]


def show_json(repo: str, commit: str, path: str) -> dict[str, Any]:
    return json.loads(git(repo, "show", f"{commit}:{path}"))


def dirty_observation(repo: str) -> dict[str, Any]:
    return {
        **WORKTREE_OBSERVATIONS[repo],
        "observedAt": "2026-07-13",
        "excludedFromPinnedTreeInventory": True,
        "preservation": "not-inventoried-not-modified-not-cleaned",
    }


def build_document() -> dict[str, Any]:
    repositories = []
    deployments = []
    for repo, commit in PINNED_REPOSITORIES.items():
        descriptors = tree_descriptors(repo, commit)
        scripts = referenced_scripts(repo, commit, descriptors)
        repositories.append({
            "name": repo,
            "commit": commit,
            "sourceMode": "immutable-git-tree",
            "dirtyWorktreeObservation": dirty_observation(repo),
            "descriptorCount": len(descriptors),
            "descriptors": descriptors,
            "referencedScriptCount": len(scripts),
            "referencedLocalScripts": scripts,
        })
        deploy_path = ".terrascale/deploy.json"
        if any(item["path"] == deploy_path for item in descriptors):
            deploy = show_json(repo, commit, deploy_path)
            deployments.append({
                "repository": repo,
                "source": f"{repo}@{commit}:{deploy_path}:1-{len(git(repo, 'show', f'{commit}:{deploy_path}').splitlines())}",
                "dependencies": deploy.get("dependencies", []),
                "prProfiles": [item["name"] for item in deploy.get("prProfiles", [])],
                "releaseProfiles": [item["name"] for item in deploy.get("releaseProfiles", [])],
                "buildTargets": [item["name"] for item in deploy.get("buildTargets", [])],
                "candidatePackage": deploy.get("candidate", {}).get("genericPackageName"),
                "promotionStrategy": deploy.get("promotion", {}).get("strategy"),
            })

    feature_policy_repos = [
        "Terrabase.Operator", "TerraScale.Deploy", "TerraScale.DotNet",
        "TerraScale.TypeScript", "TerraScale.Infrastructure", "TerraScale.Internals",
        "Terrascale.Documentation", "Terrascale.Landingpage",
    ]
    return {
        "schemaVersion": 1,
        "status": "observed-inventory-not-reconciled-policy",
        "generatedAt": "2026-07-13",
        "scope": "pinned sibling commit trees; dirty worktree content excluded and preserved",
        "descriptorRules": {
            "included": "first-party workflow, delivery, runtime, container/bake, dependency lock/toolchain, language/project/solution/build-policy, Makefile, and Pulumi descriptors",
            "excludedSegments": sorted(EXCLUDED_SEGMENTS),
            "pathPattern": DESCRIPTOR_PATTERN.pattern,
            "scriptBoundary": "local scripts referenced by pinned delivery descriptors or workflows are enumerated; unreferenced standalone scripts are outside this inventory",
        },
        "repositories": repositories,
        "deploymentDescriptors": deployments,
        "productionRoles": [
            {"role": "TerraBase", "runtimeOwner": "TerraBase", "evidence": ["TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:38-74", "TerraBase@349cd1a11e5b252ffc193d3c3cdf059b954828fd:scripts/linux/pkg/deb/assets/terrabase/debian/terrabase.service:1-27"], "buildTargets": ["linux-amd64", "linux-arm64"], "coverage": "present"},
            {"role": "API", "runtimeOwner": "TerraScale.Internals", "evidence": ["TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:44-46", "TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:87-97"], "buildTargets": ["api-amd64", "api-arm64"], "coverage": "present"},
            {"role": "Authentication", "runtimeOwner": "TerraScale.Internals", "evidence": ["TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:41-43", "TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:79-86"], "buildTargets": [], "coverage": "missing-build-target"},
            {"role": "Dashboard", "runtimeOwner": "TerraScale.Internals", "evidence": ["TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:50-55", "TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:98-113"], "buildTargets": ["dashboard"], "coverage": "present"},
        ],
        "policyConflicts": [
            {
                "id": "CI-CONFLICT-001", "status": "observed-unresolved",
                "summary": "Eight repository policies say feature PRs intentionally run no Forgejo automation, while each pinned ci.yml runs policy, static, and build jobs for pull requests targeting develop.",
                "repositories": feature_policy_repos,
                "evidence": [
                    "Terrabase.Operator@b3b105be880e169d62e3cb4506846b8a11342d5c:AGENTS.md:11-12",
                    "TerraScale.Deploy@cacb596cd0f6f25a40e76160554fecc14f047965:AGENTS.md:75-76",
                    "TerraScale.DotNet@9d98e4e3dc3e05eb955ba06f03b05bf462cfb21b:AGENTS.md:83-84",
                    "TerraScale.TypeScript@7d9b629ce5a5d41a3fa457911305b057749e3252:AGENTS.md:25-26",
                    "TerraScale.Infrastructure@3bfdb4ee0124fbcce43e7db57cf00045f374fbcb:AGENTS.md:5-5",
                    "TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:AGENTS.md:19-20",
                    "Terrascale.Documentation@ccca078a99f4d0702d4e55ac02d6585277ea08e9:AGENTS.md:49-50",
                    "Terrascale.Landingpage@0a763469d3d086e672be673b080a97dbc31dff26:AGENTS.md:105-105",
                ] + [f"{repo}@{PINNED_REPOSITORIES[repo]}:.forgejo/workflows/ci.yml:43-103" for repo in feature_policy_repos],
                "proposedReconciliation": "Choose one feature-validation authority and update policies/workflows together; preserve affected-change validation without duplicate execution.",
                "accepted": False,
            },
            {
                "id": "CI-CONFLICT-002", "status": "observed-unresolved",
                "summary": "Internals CI documentation names API, Authentication, and Dashboard image workflows that are absent from the pinned tree, which contains only consolidated ci.yml.",
                "repositories": ["TerraScale.Internals"],
                "evidence": ["TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:docs/ci-setup.md:5-15", "TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:.forgejo/workflows/ci.yml:1-171"],
                "proposedReconciliation": "Make the consolidated descriptor/workflow graph authoritative and remove or regenerate stale per-service workflow documentation after compatibility review.",
                "accepted": False,
            },
            {
                "id": "CI-CONFLICT-003", "status": "observed-unresolved",
                "summary": "Authentication is a production runtime in AppHost and policy, but Internals deploy.json has no Authentication build target or Authentication regression profile.",
                "repositories": ["TerraScale.Internals"],
                "evidence": ["TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:41-43", "TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:79-86", "TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:.terrascale/deploy.json:12-20"],
                "proposedReconciliation": "Add explicit Authentication tests and linux-amd64/linux-arm64 immutable build targets in the future native descriptor revision.",
                "accepted": False,
            },
            {
                "id": "CI-CONFLICT-004", "status": "observed-unresolved",
                "summary": "Several observed promotion/build targets still encode Flux, Helm, or rendered Kubernetes GitOps while the orchestrator contract requires native GitOps and separate cleanup gates.",
                "repositories": ["TerraBase", "Terrabase.Operator", "TerraScale.Infrastructure", "TerraScale.Internals"],
                "evidence": ["TerraBase@349cd1a11e5b252ffc193d3c3cdf059b954828fd:.terrascale/deploy.json:1-30", "Terrabase.Operator@b3b105be880e169d62e3cb4506846b8a11342d5c:.terrascale/deploy.json:1-24", "TerraScale.Infrastructure@3bfdb4ee0124fbcce43e7db57cf00045f374fbcb:.terrascale/deploy.json:1-17", "TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:.terrascale/deploy.json:17-23"],
                "proposedReconciliation": "Port semantic release dependencies and immutable promotion to the native pipeline, then retire Flux/Helm/Kubernetes targets only after replacement gates pass.",
                "accepted": False,
            },
        ],
        "coverageGaps": [
            {"id": "CI-GAP-001", "status": "open", "repository": "TerraScale.Internals", "summary": "Authentication lacks build and release-test targets.", "conflict": "CI-CONFLICT-003"},
            {"id": "CI-GAP-002", "status": "open", "repository": "TerraScale.DevHost", "summary": "No .terrascale descriptor or Forgejo workflow exists; DevHost is local-only and must not be inferred as a production role.", "conflict": None},
            {"id": "CI-GAP-003", "status": "open", "repository": "TerraScale.Internals", "summary": "CI documentation references three absent per-service workflow paths.", "conflict": "CI-CONFLICT-002"},
            {"id": "CI-GAP-004", "status": "open", "repository": "cross-repository", "summary": "Observed generic workflow, repository policy, and historical cleanup targets have no single accepted native pipeline contract yet.", "conflict": "CI-CONFLICT-001"},
        ],
        "proposedPolicy": {
            "status": "proposal-not-accepted",
            "source": "ORCHESTRATOR.md:199,961-1010,1492,1573-1583",
            "rules": ["affected feature validation", "develop-to-main release qualification", "build once", "immutable candidate", "exact candidate promotion", "native GitOps after replacement gate"],
        },
    }


def main() -> None:
    print(json.dumps(build_document(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
