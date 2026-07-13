#!/usr/bin/env python3
"""Deterministically validate the Phase 0 ARM64 runtime candidate record."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_RECORD = ROOT / "testlab/pins/arm64-runtime-candidates.json"
EXPECTED_HOSTS = {
    "oracle-linux-9-aarch64-platform",
    "ubuntu-24.04-lts-aarch64-platform",
}
EXPECTED_FILESYSTEMS = {"ext4-expand-only", "xfs-expand-only"}
EXPECTED_COMPONENTS = {"systemd", "containerd", "runc", "buildkit"}
EXPECTED_HOST_FILESYSTEM_COMBINATIONS = {
    f"{host}|{filesystem}"
    for host in EXPECTED_HOSTS
    for filesystem in EXPECTED_FILESYSTEMS
}
SELECTION_FIELDS = {
    "hostImageCandidateId", "kernelBuild", "glibcBuild",
    "filesystemCandidateId", "systemdBuild", "containerdCandidateId",
    "containerdBuild", "runcCandidateId", "runcBuild",
    "buildkitCandidateId", "buildkitBuild",
}
ALLOWED_SOURCE_HOSTS = {
    "docs.oracle.com", "yum.oracle.com", "ubuntu.com", "packages.ubuntu.com",
    "www.freedesktop.org", "github.com", "git.kernel.org",
}
EXPECTED_SOURCE_URLS = {
    "oci-arm-a1": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/arm.htm",
    "oci-platform-images": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/images.htm",
    "oci-ubuntu2404-images": "https://docs.oracle.com/en-us/iaas/images/ubuntu-2404/",
    "ubuntu-lifecycle": "https://ubuntu.com/about/release-cycle",
    "ubuntu-noble-glibc": "https://packages.ubuntu.com/noble/arm64/libs/",
    "ubuntu-noble-systemd": "https://packages.ubuntu.com/noble/systemd",
    "ubuntu-noble-containerd": "https://packages.ubuntu.com/search?arch=arm64&keywords=containerd",
    "ubuntu-noble-runc": "https://packages.ubuntu.com/noble/runc",
    "oracle-linux9-aarch64": "https://docs.oracle.com/en/operating-systems/oracle-linux/9/relnotes9.3/ol9-AboutOracleLinux9.html",
    "oracle-uek8": "https://docs.oracle.com/en-us/iaas/oracle-linux/uek/8/uek8.0-installation-and-availability.htm",
    "oracle-yum-ol9-aarch64": "https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/aarch64/index.html",
    "systemd-manager": "https://www.freedesktop.org/software/systemd/man/latest/systemd.html",
    "systemd-exec": "https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html",
    "systemd-resource-control": "https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html",
    "containerd-releases": "https://github.com/containerd/containerd/releases",
    "containerd-getting-started": "https://github.com/containerd/containerd/blob/main/docs/getting-started.md",
    "runc-releases": "https://github.com/opencontainers/runc/releases",
    "runc-project": "https://github.com/opencontainers/runc",
    "buildkit-releases": "https://github.com/moby/buildkit/releases",
    "buildkit-project": "https://github.com/moby/buildkit",
    "e2fsprogs-resize2fs": "https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/tree/resize/resize2fs.8.in",
    "xfsprogs-xfs-growfs": "https://git.kernel.org/pub/scm/fs/xfs/xfsprogs-dev.git/tree/man/man8/xfs_growfs.8",
}


def ids(items: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("id", "")) for item in items]


def validate(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("schemaVersion") != 1:
        errors.append("schemaVersion must be 1")
    if document.get("status") != "proposal-unqualified":
        errors.append("status must remain proposal-unqualified")

    target = document.get("target")
    if not isinstance(target, dict):
        errors.append("target must be an object")
    else:
        if target.get("architecture") != "aarch64":
            errors.append("target architecture must be aarch64")
        if target.get("shape") != "VM.Standard.A1.Flex":
            errors.append("target shape must be VM.Standard.A1.Flex")

    selection = document.get("selection")
    if not isinstance(selection, dict):
        errors.append("selection must be an object")
    else:
        if set(selection) != SELECTION_FIELDS:
            errors.append("selection fields differ from the closed unset-selection schema")
        for field in sorted(SELECTION_FIELDS):
            if selection.get(field) is not None:
                errors.append(f"selection.{field} must remain null in Phase 0 readiness evidence")

    local = document.get("localObservation")
    if not isinstance(local, dict):
        errors.append("localObservation must be an object")
    else:
        if local.get("status") != "observed-not-qualified":
            errors.append("local observation must remain observed-not-qualified")
        if local.get("architecture") != "x86_64":
            errors.append("this checked-in local observation must be identified as x86_64")
        if local.get("qualificationLayers") != []:
            errors.append("local x86_64 observation cannot claim a qualification layer")
        if not isinstance(local.get("commands"), list) or not local["commands"]:
            errors.append("local observation requires exact command classes")

    hosts = document.get("hostImageCandidates")
    if not isinstance(hosts, list):
        errors.append("hostImageCandidates must be a list")
        hosts = []
    if set(ids(hosts)) != EXPECTED_HOSTS or len(hosts) != len(EXPECTED_HOSTS):
        errors.append("host candidates must contain Oracle Linux 9 and Ubuntu 24.04 exactly once")
    for item in hosts:
        if item.get("status") != "candidate-unqualified":
            errors.append(f"host {item.get('id')}: status must be candidate-unqualified")
        if item.get("architecture") != "aarch64":
            errors.append(f"host {item.get('id')}: architecture must be aarch64")
        for unset_claim in ("kernelTrack", "glibcTrack", "systemdTrack"):
            if "unset" not in str(item.get(unset_claim, "")).lower():
                errors.append(f"host {item.get('id')}: {unset_claim} must state exact build is unset")
        if not item.get("sourceIds") or not item.get("gaps"):
            errors.append(f"host {item.get('id')}: sources and gaps are required")

    filesystems = document.get("filesystemCandidates")
    if not isinstance(filesystems, list):
        errors.append("filesystemCandidates must be a list")
        filesystems = []
    if set(ids(filesystems)) != EXPECTED_FILESYSTEMS or len(filesystems) != len(EXPECTED_FILESYSTEMS):
        errors.append("filesystem candidates must contain ext4 and XFS exactly once")
    for item in filesystems:
        if item.get("status") != "candidate-unqualified":
            errors.append(f"filesystem {item.get('id')}: status must be candidate-unqualified")
        proof = item.get("requiredProof")
        if not isinstance(proof, list) or not any("crash" in str(x).lower() for x in proof):
            errors.append(f"filesystem {item.get('id')}: crash proof is required")
        if not any("no-format" in str(x).lower() and "shrink" in str(x).lower() for x in proof or []):
            errors.append(f"filesystem {item.get('id')}: no-format and shrink rejection proof is required")

    runtimes = document.get("runtimeCandidates")
    if not isinstance(runtimes, list):
        errors.append("runtimeCandidates must be a list")
        runtimes = []
    components = {str(item.get("component", "")) for item in runtimes}
    if components != EXPECTED_COMPONENTS:
        errors.append("runtime candidates must cover systemd, containerd, runc, and buildkit")
    if len(ids(runtimes)) != len(set(ids(runtimes))) or "" in ids(runtimes):
        errors.append("runtime candidate IDs must be non-empty and unique")
    for item in runtimes:
        if item.get("status") != "candidate-unqualified":
            errors.append(f"runtime {item.get('id')}: status must be candidate-unqualified")
        if not item.get("sourceIds") or not item.get("requiredProof"):
            errors.append(f"runtime {item.get('id')}: sources and required proof are required")
        if "aarch64" not in item.get("architectures", []):
            errors.append(f"runtime {item.get('id')}: aarch64 support must be evaluated")

    qualification = document.get("qualification")
    if not isinstance(qualification, dict) or set(qualification) != {"L1R", "L4"}:
        errors.append("qualification must define exactly L1R and L4")
    else:
        for layer in ("L1R", "L4"):
            entry = qualification[layer]
            if entry.get("status") != "not-run":
                errors.append(f"{layer} status must remain not-run")
            if entry.get("architectureRequired") != "aarch64":
                errors.append(f"{layer} must require aarch64")
            if entry.get("systemdPid1Required") is not True:
                errors.append(f"{layer} must require systemd as PID 1")
            combinations = entry.get("requiredHostFilesystemCombinations")
            if not isinstance(combinations, list):
                errors.append(f"{layer} required host/filesystem combinations must be a list")
            elif (
                set(combinations) != EXPECTED_HOST_FILESYSTEM_COMBINATIONS
                or len(combinations) != len(EXPECTED_HOST_FILESYSTEM_COMBINATIONS)
            ):
                errors.append(
                    f"{layer} must require all four host/filesystem combinations exactly once"
                )
            if not entry.get("requiredEvidence"):
                errors.append(f"{layer} requires exit evidence")
        if qualification["L4"].get("providerRequired") is not True:
            errors.append("L4 must require a real provider")
        if qualification["L4"].get("shapeRequired") != "VM.Standard.A1.Flex":
            errors.append("L4 must require VM.Standard.A1.Flex")

    sources = document.get("primarySources")
    if not isinstance(sources, list) or not sources:
        errors.append("primarySources must be a non-empty list")
        sources = []
    source_ids = ids(sources)
    if len(source_ids) != len(set(source_ids)) or "" in source_ids:
        errors.append("primary source IDs must be non-empty and unique")
    if set(source_ids) != set(EXPECTED_SOURCE_URLS):
        errors.append("primary source IDs differ from the reviewed source set")
    for source in sources:
        url = str(source.get("url", ""))
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_SOURCE_HOSTS:
            errors.append(f"source {source.get('id')}: URL is not an allowlisted primary-source host")
        expected_url = EXPECTED_SOURCE_URLS.get(str(source.get("id", "")))
        if expected_url is not None and url != expected_url:
            errors.append(f"source {source.get('id')}: URL differs from the reviewed primary citation")
        if not source.get("publisher") or not source.get("claim"):
            errors.append(f"source {source.get('id')}: publisher and bounded claim are required")
    known = set(source_ids)
    for collection_name in ("hostImageCandidates", "watchlist", "filesystemCandidates", "runtimeCandidates"):
        for item in document.get(collection_name, []):
            unknown = set(item.get("sourceIds", [])) - known
            if unknown:
                errors.append(f"{collection_name} {item.get('id')}: unknown source IDs {sorted(unknown)}")

    return sorted(set(errors))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("record", nargs="?", type=Path, default=DEFAULT_RECORD)
    args = parser.parse_args()
    document = json.loads(args.record.read_text(encoding="utf-8"))
    errors = validate(document)
    if errors:
        raise SystemExit("\n".join(errors))
    print(
        "validated ARM64 runtime proposal: 2 host candidates, 2 filesystem "
        "candidates, 6 runtime tracks, 4 host/filesystem combinations per layer; "
        "selection unset; L1R/L4 not run"
    )


if __name__ == "__main__":
    main()
