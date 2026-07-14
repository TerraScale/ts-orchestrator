#!/usr/bin/env python3
"""Offline validation for the non-executing real-NATS L0C foundation."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = Path(__file__).with_name("l0c-cases.json")
REPORT = Path(__file__).with_name("l0c-report.json")
PIN_PATH = ROOT / "testlab/pins/nats-candidates.json"

MAX_INVENTORY_BYTES = 256 * 1024
MAX_REPORT_BYTES = 64 * 1024
MAX_PIN_BYTES = 512 * 1024
MAX_CASES = 128
MAX_LIST_ITEMS = 32
MAX_STRING_BYTES = 160
EXPECTED_CASE_COUNT = 28
EXPECTED_INVENTORY_SHA256 = "a0e075ea6d07ced88951bb44dc02f66ccededfc1ef9d1af51d933be96bfa33cf"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CASE_ID = re.compile(r"^L0C-[A-Z0-9]+-[0-9]{3}$")
REQUIREMENT_ID = re.compile(r"^(?:REQ-O(?:006|007|013|017)|INV-(?:010|018))$")

TOP_KEYS = {"schemaVersion", "classification", "claimsAcceptanceEvidence", "pinManifest",
            "requiredTopologies", "configurationContracts", "cases"}
PIN_REF_KEYS = {"path", "sha256"}
TOPOLOGY_KEYS = {"controlR3", "productR3", "controlGatewayMesh"}
R3_KEYS = {"servers", "jetStreamDomain", "trustPlane"}
GATEWAY_KEYS = {"regions", "fullMesh", "productGatewaysPermitted"}
CONFIG_KEYS = {"controlStream", "productStream", "leadershipKv"}
STREAM_KEYS = {"plane", "replicas", "retention", "acknowledgement", "duplicateWindow",
               "maximumAge", "maximumBytes", "discard", "placement", "syncPolicy",
               "acknowledgedWriteRpo"}
KV_KEYS = {"plane", "replicas", "history", "maximumAge", "placement", "syncPolicy",
           "acknowledgedWriteRpo", "compareAndSwapRequired"}
CASE_KEYS = {"id", "category", "requirementIds", "topology", "versionMode", "fault",
             "expectedOutcome", "assertions"}
REPORT_KEYS = {"schemaVersion", "classification", "claimsAcceptanceEvidence", "fullL0CComplete",
               "arm64Qualified", "productionQualified", "isCurrentForInventory", "inventorySha256",
               "executedCaseCount", "caseResults", "blockers"}
CATEGORIES = {"plane-isolation", "authorization-denial", "jetstream-config", "jetstream-kv",
              "gateway-partition", "delivery-semantics", "r3-recovery",
              "version-compatibility", "snapshot-recovery"}
TOPOLOGIES = {"dual-r3", "control-r3", "product-r3", "control-gateway-mesh"}
VERSION_MODES = {"current", "n-with-n-minus-one-server", "n-minus-one-client-with-n-server",
                 "n-client-with-n-minus-one-server"}
OUTCOMES = {"deny", "pass", "pass-local-hold-global", "deny-stale", "pass-idempotent",
            "hold", "policy-required"}
FAULTS = {"none", "product-credential-on-control-subject", "expired-user-jwt",
          "wrong-account-subject", "publish-outside-allowlist", "subscribe-outside-allowlist",
          "jwt-invalid-issuer-signature", "jwt-revoked-signing-key", "stale-kv-revision",
          "watch-resume-after-disconnect", "gru-sfo-link-partition", "fra-isolated",
          "duplicate-message-id", "reordered-generations", "ack-lost-after-acceptance",
          "consumer-nak-backoff", "one-server-loss", "quorum-loss", "rolling-leader-transfer",
          "n-minus-one-snapshot-restore", "restore-signed-snapshot-and-replay",
          "older-snapshot-over-newer-epoch"}
REQUIRED_ASSERTIONS = {
    "distinct-operator-roots", "distinct-accounts", "distinct-store-domains",
    "cross-plane-publish-denied", "cross-plane-subscribe-denied", "no-product-gateway",
    "jwt-denied", "jwt-signature-denied", "revoked-signing-key-denied", "account-import-denied", "subject-publish-denied", "subject-subscribe-denied",
    "secret-scan-clean", "control-stream-config-exact", "product-stream-config-exact",
    "kv-config-exact", "kv-cas-denied", "kv-watch-ordered", "no-missed-accepted-revision",
    "control-full-mesh-explicit", "regional-work-continues", "global-mutation-held",
    "no-wan-jetstream-quorum", "duplicate-suppressed", "operation-idempotency-required",
    "stale-generation-denied", "authoritative-generation-reread", "redelivery-observed",
    "no-double-terminal-effect", "bounded-backoff", "explicit-ack", "r3-replicas",
    "quorum-retained", "acknowledged-state-retained", "new-mutations-held",
    "running-workloads-independent", "n-minus-one-policy-bound", "mixed-version-read-write",
    "rollback-boundary-tested", "mixed-client-server-protocol", "snapshot-format-compatibility", "snapshot-digest-verified",
    "stream-position-verified", "restored-state-digest-equal", "cross-plane-backup-denied",
    "stale-snapshot-denied", "newer-epoch-retained"
}
EXPECTED_CASE_IDS = {
    "L0C-ISO-001", "L0C-ISO-002",
    "L0C-AUTH-001", "L0C-AUTH-002", "L0C-AUTH-003", "L0C-AUTH-004", "L0C-AUTH-005", "L0C-AUTH-006",
    "L0C-JS-001", "L0C-JS-002", "L0C-KV-001", "L0C-KV-002",
    "L0C-GW-001", "L0C-GW-002",
    "L0C-DEL-001", "L0C-DEL-002", "L0C-DEL-003", "L0C-DEL-004",
    "L0C-R3-001", "L0C-R3-002", "L0C-R3-003",
    "L0C-COMPAT-001", "L0C-COMPAT-002", "L0C-COMPAT-003", "L0C-COMPAT-004",
    "L0C-SNAP-001", "L0C-SNAP-002", "L0C-SNAP-003",
}
REQUIRED_REQUIREMENTS = {"REQ-O006", "REQ-O007", "REQ-O013", "REQ-O017", "INV-010", "INV-018"}
BLOCKERS = [
    "server-candidate-not-selected", "client-candidate-not-selected", "cli-candidate-not-selected",
    "jwt-nkey-toolchain-not-selected", "n-minus-one-policy-unset",
    "snapshot-signing-identity-and-key-unselected", "hermetic-smolvm-test-toolchain-unqualified",
    "internal-mirror-and-verification-receipts-missing",
    "generated-credential-and-configuration-contracts-missing", "sync-rpo-values-unset"
]


class DuplicateKey(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_bounded(path: Path, maximum: int, root: Path = ROOT) -> dict[str, Any]:
    absolute = path.absolute()
    component = absolute
    while True:
        if component.is_symlink():
            raise ValueError(f"input path contains a symlink component: {path}")
        if component == component.parent:
            break
        component = component.parent
    if not path.is_file():
        raise ValueError(f"input must be a non-symlink regular file: {path}")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ValueError(f"input escapes repository root: {path}") from exc
    size = resolved.stat().st_size
    if size <= 0 or size > maximum:
        raise ValueError(f"input byte count outside 1..{maximum}: {path}")
    value = json.loads(resolved.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise ValueError(f"top-level JSON must be an object: {path}")
    return value


def _exact_keys(value: object, expected: set[str], location: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{location} must be an object")
        return False
    if set(value) != expected:
        errors.append(f"{location} has unknown or missing fields")
        return False
    return True


def _bounded_strings(value: object, location: str, errors: list[str], depth: int = 0) -> None:
    if depth > 16:
        errors.append(f"{location} exceeds nesting bound 16")
        return
    if isinstance(value, str):
        if not value or len(value.encode("utf-8")) > MAX_STRING_BYTES or any(ord(c) < 32 for c in value):
            errors.append(f"{location} contains an invalid or oversized string")
    elif isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            errors.append(f"{location} exceeds list bound {MAX_LIST_ITEMS}")
        for index, item in enumerate(value):
            _bounded_strings(item, f"{location}[{index}]", errors, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            _bounded_strings(key, f"{location}.key", errors, depth + 1)
            _bounded_strings(item, f"{location}.{key}", errors, depth + 1)


def validate(inventory: dict[str, Any], report: dict[str, Any], pin: dict[str, Any],
             pin_digest: str) -> list[str]:
    errors: list[str] = []
    _bounded_strings(inventory, "inventory", errors)
    _bounded_strings(report, "report", errors)
    if not _exact_keys(inventory, TOP_KEYS, "inventory", errors):
        return errors
    if inventory["schemaVersion"] != 1 or inventory["classification"] != "planned-real-nats-l0c-not-executed":
        errors.append("inventory schema/classification must remain the non-executing v1 contract")
    if inventory["claimsAcceptanceEvidence"] is not False:
        errors.append("inventory must not claim acceptance evidence")
    if canonical_sha256(inventory) != EXPECTED_INVENTORY_SHA256:
        errors.append("inventory content digest differs from the exact reviewed planned matrix")

    ref = inventory["pinManifest"]
    if _exact_keys(ref, PIN_REF_KEYS, "pinManifest", errors):
        if ref["path"] != "testlab/pins/nats-candidates.json" or ref["sha256"] != pin_digest:
            errors.append("inventory pin manifest path/digest is stale or incorrect")
        if not SHA256.fullmatch(str(ref["sha256"])):
            errors.append("inventory pin digest is not lowercase SHA-256")

    topologies = inventory["requiredTopologies"]
    if _exact_keys(topologies, TOPOLOGY_KEYS, "requiredTopologies", errors):
        for name in ("controlR3", "productR3"):
            item = topologies[name]
            if _exact_keys(item, R3_KEYS, name, errors):
                expected_plane = "control" if name == "controlR3" else "product"
                expected_domain = "control-cell" if name == "controlR3" else "product-cell"
                if item != {"servers": 3, "jetStreamDomain": expected_domain, "trustPlane": expected_plane}:
                    errors.append(f"{name} must declare exactly three servers and its own trust plane")
        gateway = topologies["controlGatewayMesh"]
        if _exact_keys(gateway, GATEWAY_KEYS, "controlGatewayMesh", errors):
            if gateway != {"regions": ["gru", "sfo", "fra"], "fullMesh": True,
                           "productGatewaysPermitted": False}:
                errors.append("gateway topology must be the explicit launch control mesh with no product gateway")

    configs = inventory["configurationContracts"]
    if _exact_keys(configs, CONFIG_KEYS, "configurationContracts", errors):
        for name in ("controlStream", "productStream"):
            item = configs[name]
            if _exact_keys(item, STREAM_KEYS, name, errors):
                expected_plane = "control" if name == "controlStream" else "product"
                if (item["plane"] != expected_plane or item["replicas"] != 3
                        or item["acknowledgement"] != "explicit" or item["placement"] != "same-plane-only"):
                    errors.append(f"{name} must preserve plane, R3, and explicit acknowledgement")
                for field in ("duplicateWindow", "maximumAge", "maximumBytes", "discard", "syncPolicy", "acknowledgedWriteRpo"):
                    if item[field] != "owner-value-required":
                        errors.append(f"{name}.{field} must remain an explicit unresolved owner value")
        kv = configs["leadershipKv"]
        if _exact_keys(kv, KV_KEYS, "leadershipKv", errors):
            if (kv["plane"] != "control" or kv["replicas"] != 3
                    or kv["placement"] != "same-plane-only" or kv["compareAndSwapRequired"] is not True):
                errors.append("leadershipKv must be control-plane R3 with CAS")
            for field in ("history", "maximumAge", "syncPolicy", "acknowledgedWriteRpo"):
                if kv[field] != "owner-value-required":
                    errors.append(f"leadershipKv.{field} must remain an explicit unresolved owner value")

    cases = inventory["cases"]
    if not isinstance(cases, list) or len(cases) != EXPECTED_CASE_COUNT or len(cases) > MAX_CASES:
        errors.append(f"cases must contain exactly {EXPECTED_CASE_COUNT} reviewed entries within bound {MAX_CASES}")
        cases = []
    ids: list[str] = []
    categories: set[str] = set()
    assertions: set[str] = set()
    requirements_seen: set[str] = set()
    faults_seen: set[str] = set()
    topologies_seen: set[str] = set()
    versions_seen: set[str] = set()
    for index, case in enumerate(cases):
        if not _exact_keys(case, CASE_KEYS, f"cases[{index}]", errors):
            continue
        ident = case["id"]
        if not isinstance(ident, str) or not CASE_ID.fullmatch(ident):
            errors.append(f"cases[{index}] has invalid id")
        else:
            ids.append(ident)
        if case["category"] not in CATEGORIES:
            errors.append(f"{ident}: unknown category")
        else:
            categories.add(case["category"])
        if case["topology"] not in TOPOLOGIES or case["versionMode"] not in VERSION_MODES:
            errors.append(f"{ident}: topology/version mode is not closed")
        else:
            topologies_seen.add(case["topology"])
            versions_seen.add(case["versionMode"])
        if case["expectedOutcome"] not in OUTCOMES:
            errors.append(f"{ident}: expected outcome is not closed")
        if case["fault"] not in FAULTS:
            errors.append(f"{ident}: fault is not closed")
        else:
            faults_seen.add(case["fault"])
        requirements = case["requirementIds"]
        if (not isinstance(requirements, list) or not requirements or len(requirements) > 4
                or len(requirements) != len(set(requirements))
                or any(not isinstance(req, str) or not REQUIREMENT_ID.fullmatch(req) for req in requirements)):
            errors.append(f"{ident}: requirement IDs are invalid, duplicate, or unbounded")
        else:
            requirements_seen.update(requirements)
        checks = case["assertions"]
        if (not isinstance(checks, list) or not checks or len(checks) > MAX_LIST_ITEMS
                or len(checks) != len(set(checks)) or any(check not in REQUIRED_ASSERTIONS for check in checks)):
            errors.append(f"{ident}: assertions are invalid, duplicate, or unbounded")
        else:
            assertions.update(checks)
    if len(ids) != len(set(ids)):
        errors.append("case IDs must be unique")
    if set(ids) != EXPECTED_CASE_IDS:
        errors.append("case inventory must contain the exact reviewed case ID catalog")
    if categories != CATEGORIES:
        errors.append("case inventory must cover every mandatory category")
    if assertions != REQUIRED_ASSERTIONS:
        errors.append("case inventory must cover every mandatory assertion exactly by the closed catalog")
    if requirements_seen != REQUIRED_REQUIREMENTS:
        errors.append("case inventory must cover the exact messaging/security requirement catalog")
    if faults_seen != FAULTS or topologies_seen != TOPOLOGIES or versions_seen != VERSION_MODES:
        errors.append("case inventory must exercise every closed fault, topology, and version mode")

    if pin.get("status") != "candidate-evidence-not-selected" or pin.get("nMinusOnePolicy") is not None:
        errors.append("NATS candidates and N/N-1 policy must remain unselected")
    for group in ("serverCandidates", "clientCandidates", "cliCandidates"):
        values = pin.get(group)
        if not isinstance(values, list) or not values or any(item.get("selected") is not False for item in values):
            errors.append(f"{group} must exist and remain entirely unselected")
    readiness = pin.get("readiness", {})
    if any(readiness.get(name) is not False for name in ("fullL0CComplete", "arm64Qualified", "productionQualified")):
        errors.append("candidate manifest must fail closed for L0C, ARM64, and production")

    if _exact_keys(report, REPORT_KEYS, "report", errors):
        expected_scalars = {
            "schemaVersion": 1, "classification": "stale-blocked-no-execution",
            "claimsAcceptanceEvidence": False, "fullL0CComplete": False,
            "arm64Qualified": False, "productionQualified": False,
            "isCurrentForInventory": False, "inventorySha256": None,
            "executedCaseCount": 0, "caseResults": [], "blockers": BLOCKERS,
        }
        if report != expected_scalars:
            errors.append("report must remain the exact deterministic stale, blocked, zero-execution report")
    return errors


def main() -> None:
    try:
        inventory = load_bounded(INVENTORY, MAX_INVENTORY_BYTES)
        report = load_bounded(REPORT, MAX_REPORT_BYTES)
        pin = load_bounded(PIN_PATH, MAX_PIN_BYTES)
        errors = validate(inventory, report, pin, file_sha256(PIN_PATH))
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKey, ValueError, RecursionError) as exc:
        raise SystemExit(str(exc)) from exc
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"validated {len(inventory['cases'])} planned L0C cases; execution and acceptance remain blocked")


if __name__ == "__main__":
    main()
