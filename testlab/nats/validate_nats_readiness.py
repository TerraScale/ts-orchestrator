#!/usr/bin/env python3
"""Validate NATS candidates and bounded L0C evidence without network access."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / "testlab/pins/nats-candidates.json"
REPORT = Path(__file__).with_name("local-x64-l0c-report.json")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OFFICIAL_HOSTS = {"github.com", "api.nuget.org", "docs.nats.io"}
CAPABILITIES = {
    "core-pub-sub": (465, "Core pub/sub"), "request-reply": (466, "Request/reply"),
    "service-framework-discovery": (467, "NATS service framework and service discovery"),
    "queue-groups": (468, "Queue groups"), "jetstream-streams": (469, "JetStream streams"),
    "durable-pull-consumers": (470, "Durable pull consumers"),
    "retention-policies": (471, "Retention policies"),
    "deduplication": (472, "Message IDs and duplicate windows"),
    "optimistic-concurrency": (473, "Expected stream/subject sequence and optimistic concurrency"),
    "kv-cas": (474, "JetStream KV"), "kv-watch": (475, "KV watchers"),
    "object-store": (476, "JetStream Object Store"), "accounts": (477, "Accounts"),
    "jwt-nkeys": (478, "JWT operators/accounts/users and NKeys"),
    "imports-exports": (479, "Imports/exports"),
    "subjects-mappings-transforms": (480, "Subject hierarchy, wildcards, mappings, and transforms"),
    "headers-status": (481, "Headers and status messages"),
    "r3-clustering": (482, "Clustering and R3 JetStream"), "gateways": (483, "Gateways"),
    "leaf-nodes": (484, "Leaf nodes"), "mirrors-sources": (485, "Mirrors and sources"),
    "flow-control-limits-backoff": (486, "Flow control, consumer limits, max pending, and backoff"),
    "system-advisories-monitoring": (487, "System account, `$SYS`, advisories, and monitoring endpoints"),
    "reload-lame-duck-rolling": (488, "Configuration reload and lame-duck/rolling behavior"),
    "tls-mtls": (507, "mTLS for clients, routes, and gateways"),
    "snapshot-restore-peer-replacement": ((531, 536), ""),
    "n-minus-one-mixed-version": (1154, "N/N-1 client/server compatibility"),
}
ALLOWED_STATUSES = {
    "passed-local-x64-smoke", "partial-loopback-health-only", "not-executed",
    "blocked-owner-policy-unset",
}


def official_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and parsed.hostname in OFFICIAL_HOSTS


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(pin: dict[str, Any], report: dict[str, Any], root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    if pin.get("status") != "candidate-evidence-not-selected":
        errors.append("pin status must remain candidate-evidence-not-selected")
    if pin.get("nMinusOnePolicy") is not None or pin.get("candidatePairStatus") != "unselected-unexecuted":
        errors.append("owner-controlled N/N-1 policy and candidate pair must remain unset/unexecuted")
    sources = pin.get("primarySources", [])
    if not isinstance(sources, list) or len(sources) < 10 or any(not official_url(url) for url in sources):
        errors.append("primarySources must contain at least ten official HTTPS sources")

    for group, expected_count in (("serverCandidates", 2), ("clientCandidates", 2), ("cliCandidates", 1)):
        candidates = pin.get(group, [])
        if not isinstance(candidates, list) or len(candidates) != expected_count:
            errors.append(f"{group} must contain exactly {expected_count} candidates")
            continue
        for candidate in candidates:
            if candidate.get("selected") is not False:
                errors.append(f"{group} {candidate.get('version')}: selected must remain false")
            for field in ("releaseUrl",):
                if not official_url(candidate.get(field)):
                    errors.append(f"{group} {candidate.get('version')}: {field} lacks official provenance")
            artifacts = candidate.get("artifacts")
            if artifacts is None:
                if (candidate.get("architectureSupport") != "managed-il-anycpu"
                        or not candidate.get("targetFrameworksObserved")
                        or candidate.get("arm64Executed") is not False):
                    errors.append(f"{group} {candidate.get('version')}: managed architecture evidence must be explicit and ARM64 unexecuted")
                artifacts = [{"os": "nuget", "architecture": "any", "url": candidate.get("packageUrl"),
                              "sha256": candidate.get("sha256"), "sizeBytes": candidate.get("sizeBytes")}]
            architectures = {artifact.get("architecture") for artifact in artifacts}
            if group != "clientCandidates" and architectures != {"amd64", "arm64"}:
                errors.append(f"{group} {candidate.get('version')}: linux amd64 and arm64 artifacts are mandatory")
            for artifact in artifacts:
                if not official_url(artifact.get("url")) or not SHA256.fullmatch(str(artifact.get("sha256", ""))):
                    errors.append(f"{group} {candidate.get('version')}: artifact provenance/hash invalid")
                if not isinstance(artifact.get("sizeBytes"), int) or artifact["sizeBytes"] <= 0:
                    errors.append(f"{group} {candidate.get('version')}: artifact size must be positive")

    specification_lines = (root / "ORCHESTRATOR.md").read_text(encoding="utf-8").splitlines()
    capabilities = pin.get("capabilities", [])
    ids = [item.get("id") for item in capabilities if isinstance(item, dict)]
    if set(ids) != set(CAPABILITIES) or len(ids) != len(set(ids)):
        errors.append("capability matrix must contain every canonical capability exactly once")
    for item in capabilities:
        if not isinstance(item, dict) or item.get("id") not in CAPABILITIES:
            continue
        ident = item["id"]
        expected_line, phrase = CAPABILITIES[ident]
        expected_source = (f"ORCHESTRATOR.md:{expected_line[0]}-{expected_line[1]}"
                           if isinstance(expected_line, tuple) else f"ORCHESTRATOR.md:{expected_line}")
        if item.get("source") != expected_source:
            errors.append(f"capability {ident}: specification source mismatch")
        if isinstance(expected_line, tuple):
            source_text = "\n".join(specification_lines[expected_line[0] - 1:expected_line[1]])
        else:
            source_text = specification_lines[expected_line - 1]
        if phrase and phrase not in source_text:
            errors.append(f"capability {ident}: source semantics drifted")
        if not official_url(item.get("primarySource")):
            errors.append(f"capability {ident}: official primary source missing")
        if item.get("localStatus") not in ALLOWED_STATUSES:
            errors.append(f"capability {ident}: invalid local status")

    readiness = pin.get("readiness", {})
    if readiness != {"candidatePinsComplete": True, "architectureAssetsPresent": True,
                     "fullL0CComplete": False, "arm64Qualified": False, "productionQualified": False}:
        errors.append("readiness must fail closed outside candidate pins and architecture asset presence")
    if all(item.get("localStatus") == "passed-local-x64-smoke" for item in capabilities):
        errors.append("capability matrix dishonestly claims a complete local smoke")

    expected_checks = {"corePubSub", "coreRequestReply", "jetStreamCreatePublishGet",
                       "monitoringLoopback", "processCleanup", "temporaryStoreCleanup"}
    if report.get("classification") != "bounded-local-x64-l0c-smoke-not-production-qualification":
        errors.append("local report classification overclaims evidence")
    expected_harness_path = "testlab/nats/run_local_l0c_smoke.py"
    harness_path = report.get("harnessPath")
    if harness_path != expected_harness_path:
        errors.append("local report harness path must be the exact repository-relative smoke harness")
    else:
        harness = root / expected_harness_path
        if not harness.is_file():
            errors.append("local report smoke harness is missing")
        elif report.get("harnessSha256") != file_sha256(harness):
            errors.append("local report harness digest differs from the current smoke procedure")
    if report.get("hostArchitecture") != "x86_64" or report.get("credentials") != "none":
        errors.append("local report must remain credential-free x86_64 evidence")
    checks = report.get("checks", {})
    if set(checks) != expected_checks or any(checks.get(name) is not True for name in expected_checks):
        errors.append("local report checks, including both cleanup checks, must all pass exactly once")
    not_tested = report.get("notTested", [])
    for boundary in ("ARM64", "JWT/NKeys/accounts/permissions", "N/N-1 mixed versions"):
        if boundary not in not_tested:
            errors.append(f"local report must explicitly disclaim {boundary}")
    server = report.get("server", {})
    if server.get("version") != "2.14.3" or not SHA256.fullmatch(str(server.get("binarySha256", ""))):
        errors.append("local report server identity is invalid")
    return errors


def main() -> None:
    pin_path = Path(sys.argv[1]) if len(sys.argv) > 1 else PIN
    report_path = Path(sys.argv[2]) if len(sys.argv) > 2 else REPORT
    errors = validate(json.loads(pin_path.read_text()), json.loads(report_path.read_text()))
    if errors:
        raise SystemExit("\n".join(errors))
    print("validated 5 unselected tool candidates, 27 capability rows, fail-closed readiness, and bounded local cleanup evidence")


if __name__ == "__main__":
    main()
