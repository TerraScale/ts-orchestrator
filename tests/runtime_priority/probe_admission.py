#!/usr/bin/env python3
"""Admit a CI-published D15 probe after exact release and job readback."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pressure


PUBLICATION_SCHEMA = "terrascale.d15.probe-publication/v1"
ADMISSION_SCHEMA = "terrascale.d15.probe-admission/v1"
PROBE_ASSET = "terrascale-d15-qualify.py"
JOB_NAME = "verify/go + artifact/linux-amd64-arm64"
MAX_PROBE_BYTES = 262_144
MAX_JOB_LOG_BYTES = 32 << 20
MAX_ARTIFACT_BYTES = 512 << 20


def digest(wire: bytes) -> str:
    return hashlib.sha256(wire).hexdigest()


def read_probe(path: Path) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_PROBE_BYTES:
            raise pressure.HarnessError("downloaded D15 probe is not a bounded regular file")
        wire = path.read_bytes()
    except OSError as error:
        raise pressure.HarnessError(f"cannot read downloaded D15 probe: {error}") from error
    if len(wire) != info.st_size:
        raise pressure.HarnessError("downloaded D15 probe changed during readback")
    return wire


def read_job_log(path: Path) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_JOB_LOG_BYTES:
            raise pressure.HarnessError("D15 producing job log is not a bounded regular file")
        wire = path.read_bytes()
    except OSError as error:
        raise pressure.HarnessError(f"cannot read D15 producing job log: {error}") from error
    if len(wire) != info.st_size:
        raise pressure.HarnessError("D15 producing job log changed during readback")
    return wire


def validate_qualification(qualification: dict[str, Any]) -> None:
    expected = {"schema", "repository", "source_revision", "source_tree", "go_version",
                "go_mod_sha256", "go_sum_sha256", "verification", "artifacts"}
    if (set(qualification) != expected or
            qualification.get("schema") != "terrascale.release.qualification.v1" or
            qualification.get("repository") != "TerraScale/ts-orchestrator" or
            qualification.get("go_version") != "go1.27.1" or
            any(not pressure.HASH_RE.fullmatch(str(qualification.get(key, "")))
                for key in ("go_mod_sha256", "go_sum_sha256"))):
        raise pressure.HarnessError("CI qualification is not a strict v1 two-binary manifest")
    artifacts = qualification["artifacts"]
    if type(artifacts) is not list or len(artifacts) != 2:
        raise pressure.HarnessError("CI qualification requires the two ordered Linux binaries")
    for architecture, artifact in zip(("amd64", "arm64"), artifacts, strict=True):
        if (type(artifact) is not dict or
                set(artifact) != {"architecture", "name", "bytes", "sha256"} or
                artifact.get("architecture") != architecture or
                artifact.get("name") != f"terrascale-orchestrator-linux-{architecture}" or
                not pressure.HASH_RE.fullmatch(str(artifact.get("sha256", "")))):
            raise pressure.HarnessError("CI qualification has an invalid or unordered binary")
        size = pressure.require_int(artifact.get("bytes"), "qualified binary bytes")
        if size > MAX_ARTIFACT_BYTES:
            raise pressure.HarnessError("CI qualification binary exceeds its size bound")


def require_marker(log_wire: bytes, marker: str) -> None:
    count = 0
    for raw_line in log_wire.splitlines():
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            continue
        timestamp, separator, payload = line.rstrip("\r").partition(" ")
        if separator != " " or payload != marker:
            continue
        try:
            observed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as error:
            raise pressure.HarnessError("D15 producing job log marker has an invalid timestamp") from error
        if observed.tzinfo is None:
            raise pressure.HarnessError("D15 producing job log marker lacks a UTC offset")
        count += 1
    if count != 1:
        raise pressure.HarnessError("D15 producing job log lacks one exact CI publication marker")


def admit(probe_path: Path, descriptor_path: Path, qualification_path: Path,
          run_detail_path: Path, job_log_path: Path, release_tag: str) -> dict[str, Any]:
    descriptor, descriptor_wire = pressure.load_json(descriptor_path, 16_384)
    qualification, qualification_wire = pressure.load_json(qualification_path, 65_536)
    run_detail, run_detail_wire = pressure.load_json(run_detail_path, 1 << 20)
    job_log_wire = read_job_log(job_log_path)
    probe_wire = read_probe(probe_path)
    validate_qualification(qualification)
    expected_descriptor = {"schema", "repository", "source_revision", "source_tree",
                           "verification", "probe"}
    if set(descriptor) != expected_descriptor or descriptor.get("schema") != PUBLICATION_SCHEMA or descriptor.get("repository") != "TerraScale/ts-orchestrator":
        raise pressure.HarnessError("D15 probe publication descriptor has an unsupported schema")
    source = pressure.require_text(descriptor.get("source_revision"), "probe source_revision")
    tree = pressure.require_text(descriptor.get("source_tree"), "probe source_tree")
    if not re.fullmatch(r"[0-9a-f]{40}", source) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise pressure.HarnessError("D15 probe descriptor lacks full source and tree identities")
    verification = pressure.require_object(descriptor.get("verification"), "probe verification")
    if set(verification) != {"workflow", "job", "run_id", "run_number"} or verification.get("workflow") != "ci.yml" or verification.get("job") != JOB_NAME:
        raise pressure.HarnessError("D15 probe descriptor lacks the exact CI producer")
    run_id = pressure.require_int(verification.get("run_id"), "probe run_id")
    run_number = pressure.require_int(verification.get("run_number"), "probe run_number")
    expected_tag = f"ci-{source}-run-{run_id}"
    if release_tag != expected_tag:
        raise pressure.HarnessError("D15 probe release tag differs from its source/run identity")
    probe = pressure.require_object(descriptor.get("probe"), "probe asset")
    if set(probe) != {"name", "bytes", "sha256"} or probe.get("name") != PROBE_ASSET:
        raise pressure.HarnessError("D15 probe descriptor names an unsupported asset")
    probe_bytes = pressure.require_int(probe.get("bytes"), "probe bytes")
    probe_sha256 = pressure.require_text(probe.get("sha256"), "probe sha256")
    if probe_bytes > MAX_PROBE_BYTES or not pressure.HASH_RE.fullmatch(probe_sha256) or len(probe_wire) != probe_bytes or digest(probe_wire) != probe_sha256:
        raise pressure.HarnessError("downloaded D15 probe differs from the CI publication descriptor")
    if (qualification.get("repository") != descriptor["repository"] or
            qualification.get("source_revision") != source or
            qualification.get("source_tree") != tree):
        raise pressure.HarnessError("CI qualification source differs from the D15 probe descriptor")
    qualified_run = pressure.require_object(qualification.get("verification"), "CI qualification verification")
    if (set(qualified_run) != {"workflow", "job", "run_id", "run_number", "conclusion"} or
            qualified_run.get("workflow") != "ci.yml" or qualified_run.get("job") != JOB_NAME or
            qualified_run.get("run_id") != run_id or qualified_run.get("run_number") != run_number or
            qualified_run.get("conclusion") != "success"):
        raise pressure.HarnessError("CI qualification run differs from the D15 probe descriptor")
    if (set(run_detail) != {"run_id", "run_number", "head_sha", "workflow", "status", "jobs"} or
            run_detail.get("run_id") != run_id or run_detail.get("run_number") != run_number or
            run_detail.get("head_sha") != source or run_detail.get("workflow") != "ci.yml" or
            run_detail.get("status") != "success"):
        raise pressure.HarnessError("live CI run readback is not successful for the D15 source")
    jobs = run_detail.get("jobs")
    if type(jobs) is not list:
        raise pressure.HarnessError("CI run readback lacks job records")
    if len(jobs) != 1 or type(jobs[0]) is not dict or jobs[0].get("name") != JOB_NAME:
        raise pressure.HarnessError("CI run readback lacks one exact D15-producing job")
    job = jobs[0]
    if (set(job) != {"id", "run_id", "name", "status", "attempt"} or
            job.get("run_id") != run_id or job.get("status") != "success"):
        raise pressure.HarnessError("D15-producing CI job is not successful for this run")
    job_id = pressure.require_int(job.get("id"), "D15-producing job ID")
    attempt = pressure.require_int(job.get("attempt"), "D15-producing job attempt")
    require_marker(job_log_wire, (
        f"TS_D15_PROBE_PUBLICATION_V1 source_sha={source} run_id={run_id} "
        f"run_number={run_number} probe_sha256={probe_sha256} "
        f"descriptor_sha256={digest(descriptor_wire)}"
    ))
    require_marker(job_log_wire, (
        f"TS_RELEASE_QUALIFICATION_V1 source_sha={source} run_id={run_id} "
        f"run_number={run_number} manifest_sha256={digest(qualification_wire)}"
    ))
    return {
        "schema": ADMISSION_SCHEMA,
        "repository": descriptor["repository"],
        "source_revision": source,
        "source_tree": tree,
        "release_tag": release_tag,
        "run_id": run_id,
        "run_number": run_number,
        "workflow": "ci.yml",
        "job": JOB_NAME,
        "job_id": job_id,
        "attempt": attempt,
        "probe_asset": PROBE_ASSET,
        "probe_bytes": probe_bytes,
        "probe_sha256": probe_sha256,
        "publication_sha256": digest(descriptor_wire),
        "qualification_sha256": digest(qualification_wire),
        "run_detail_sha256": digest(run_detail_wire),
        "job_log_sha256": digest(job_log_wire),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--publication", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--run-detail", type=Path, required=True)
    parser.add_argument("--job-log", type=Path, required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = admit(args.probe, args.publication, args.qualification,
                        args.run_detail, args.job_log, args.release_tag)
        wire = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8")
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(wire)
            output.flush()
            os.fsync(output.fileno())
    except (OSError, pressure.HarnessError) as error:
        print(f"D15 probe admission failed: {error}", file=sys.stderr)
        return 1
    print(f"D15 probe admitted: {args.out} sha256={digest(wire)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
