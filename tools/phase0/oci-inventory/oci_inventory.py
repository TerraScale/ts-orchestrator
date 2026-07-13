#!/usr/bin/env python3
"""Fail-closed, read-only OCI residual inventory.

The OCI CLI is deliberately treated as an untrusted producer of sensitive data:
responses and stderr exist only in memory, while the persisted report contains
counts, coarse error classes, hashes, and documented command templates.
"""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable


ALLOWED_STATES = {
    "observed-empty",
    "observed-present",
    "permission-denied",
    "not-queried",
    "query-failed",
}
OCID_RE = re.compile(r"ocid1\.[a-z0-9.-]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?:\b\d{1,3}\.){3}\d{1,3}\b")
ADDRESS_RE = re.compile(
    r"(?:\b\d{1,3}\.){3}\d{1,3}\b|(?:\b[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}\b",
    re.IGNORECASE,
)

# Only OCI CLI operations in this allowlist may be executed. There are no
# create/update/delete/get-secret-bundle/start/stop/Pulumi operations here.
COMPARTMENT_SCOPED: dict[str, tuple[str, ...]] = {
    "compute-instances": ("compute", "instance", "list"),
    "block-volumes": ("bv", "volume", "list"),
    "boot-volumes": ("bv", "boot-volume", "list"),
    "block-volume-attachments": ("compute", "volume-attachment", "list"),
    "boot-volume-attachments": ("compute", "boot-volume-attachment", "list"),
    "block-volume-backups": ("bv", "backup", "list"),
    "boot-volume-backups": ("bv", "boot-volume-backup", "list"),
    "load-balancers": ("lb", "load-balancer", "list"),
    "network-load-balancers": ("nlb", "network-load-balancer", "list"),
    "public-ips": ("network", "public-ip", "list"),
    "vault-secrets-metadata": ("vault", "secret", "list"),
    "certificates-metadata": ("certs-mgmt", "certificate", "list"),
    "certificate-authorities-metadata": ("certs-mgmt", "certificate-authority", "list"),
    "oke-clusters": ("ce", "cluster", "list"),
    "oke-node-pools": ("ce", "node-pool", "list"),
    "dns-zones": ("dns", "zone", "list"),
}

GLOBAL_COMPARTMENT_SCOPED: dict[str, tuple[str, ...]] = {
    "iam-policies": ("iam", "policy", "list"),
}

ROOT_SCOPED: dict[str, tuple[str, ...]] = {
    "iam-dynamic-groups": ("iam", "dynamic-group", "list"),
}

COMMAND_TEMPLATES = sorted(
    ["oci iam region-subscription list", "oci iam compartment list"]
    + [f"oci {' '.join(command)} --compartment-id <redacted> --all" for command in COMPARTMENT_SCOPED.values()]
    + [f"oci {' '.join(command)} --compartment-id <redacted> --all" for command in GLOBAL_COMPARTMENT_SCOPED.values()]
    + [f"oci {' '.join(command)} --compartment-id <redacted> --all" for command in ROOT_SCOPED.values()]
    + [
        "oci object-storage namespace get",
        "oci object-storage bucket list --namespace-name <redacted> --compartment-id <redacted> --all",
        "oci kms management vault list --compartment-id <redacted> --all",
        "oci dns record zone get --zone-name-or-id <redacted> --all",
        "oci usage-api usage-summary request-summarized-usages --tenant-id <redacted> --query-type COST --granularity DAILY --is-aggregate-by-time false --time-usage-started <utc> --time-usage-ended <utc> --all",
    ]
)


def stable_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def sanitize(value: Any) -> Any:
    """Recursively remove forbidden identifiers/addresses and unsafe keys."""
    forbidden_keys = {
        "id", "ocid", "name", "display-name", "display_name", "hostname",
        "dns-name", "dns_name", "address", "ip-address", "ip_address",
        "key", "key-file", "key_file", "fingerprint", "user", "tenancy",
        "secret", "secret-content", "secret_content", "auth", "authorization",
    }
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = key.lower().replace("_", "-")
            if normalized in {entry.replace("_", "-") for entry in forbidden_keys}:
                result[f"{key}_hash"] = stable_hash(str(item))
            else:
                result[key] = sanitize(item)
        return result
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        value = OCID_RE.sub(lambda match: stable_hash(match.group(0)), value)
        value = ADDRESS_RE.sub("<address-redacted>", value)
        return value
    return value


def assert_sanitized(value: Any) -> None:
    encoded = json.dumps(value, sort_keys=True)
    if OCID_RE.search(encoded) or IPV4_RE.search(encoded):
        raise ValueError("sanitization invariant failed")
    forbidden = ("private_key", "private-key", "auth_token", "authorization")
    if any(token in encoded.lower() for token in forbidden):
        raise ValueError("forbidden secret-bearing field in report")


class OciReadOnly:
    def __init__(self, profile: str, region: str | None = None) -> None:
        self.profile = profile
        self.region = region

    def run(self, parts: Iterable[str]) -> tuple[str, Any]:
        parts_tuple = tuple(parts)
        if not self._allowed(parts_tuple):
            return "query-failed", {"error_class": "command-not-allowlisted"}
        command = ["oci", *parts_tuple, "--profile", self.profile, "--output", "json"]
        if self.region:
            command.extend(("--region", self.region))
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "query-failed", {"error_class": type(exc).__name__}
        if result.returncode != 0:
            lowered = result.stderr.lower()
            if any(marker in lowered for marker in ("notauthorized", "not authorized", "forbidden", "permission", "401", "403")):
                return "permission-denied", {"error_class": "authorization"}
            if any(marker in lowered for marker in ("config", "key_file", "profile", "signing")):
                return "query-failed", {"error_class": "local-auth-configuration"}
            return "query-failed", {"error_class": "oci-cli-or-service"}
        try:
            return "ok", json.loads(result.stdout)
        except json.JSONDecodeError:
            return "query-failed", {"error_class": "invalid-json"}

    @staticmethod
    def _allowed(parts: tuple[str, ...]) -> bool:
        roots = {
            ("iam", "region-subscription", "list"),
            ("iam", "compartment", "list"),
            ("object-storage", "namespace", "get"),
            ("object-storage", "bucket", "list"),
            ("kms", "management", "vault", "list"),
            ("dns", "record", "zone", "get"),
            ("usage-api", "usage-summary", "request-summarized-usages"),
            *COMPARTMENT_SCOPED.values(),
            *GLOBAL_COMPARTMENT_SCOPED.values(),
            *ROOT_SCOPED.values(),
        }
        return len(parts) >= 3 and parts[:3] in roots or len(parts) >= 4 and parts[:4] in roots


def data_items(payload: Any) -> list[Any]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data", [])
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return data["items"]
    return []


def category_result(count: int, attempted: int, succeeded: int, denied: int, failed: int) -> dict[str, Any]:
    if attempted == 0:
        state = "not-queried"
    elif denied:
        state = "permission-denied"
    elif failed:
        state = "query-failed"
    elif succeeded != attempted:
        state = "query-failed"
    else:
        state = "observed-present" if count else "observed-empty"
    return {
        "state": state,
        "minimum_observed_count": count,
        "scopes_attempted": attempted,
        "scopes_succeeded": succeeded,
        "scopes_permission_denied": denied,
        "scopes_failed": failed,
    }


def load_root_id(profile: str) -> str:
    # Read only the tenancy field required to scope list APIs. No config value is
    # printed, hashed into the report, or persisted by this tool.
    config = configparser.ConfigParser(interpolation=None)
    config.read(Path.home() / ".oci" / "config")
    section = "DEFAULT" if profile == "DEFAULT" else profile
    root_id = config[section].get("tenancy", "").strip()
    if not root_id:
        raise RuntimeError("OCI profile lacks tenancy scope")
    return root_id


def discovery_failure_report(
    started: dt.datetime, ended: dt.datetime, discovery: str, state: str
) -> dict[str, Any]:
    names = set(COMPARTMENT_SCOPED) | set(GLOBAL_COMPARTMENT_SCOPED) | set(ROOT_SCOPED) | {
        "object-storage-buckets", "kms-vaults-metadata", "dns-records",
        "nats-streams-consumers", "workload-runtime-inventory",
    }
    categories = {name: category_result(0, 0, 0, 0, 0) for name in sorted(names)}
    report = {
        "schema_version": 1,
        "generated_at_utc": ended.isoformat().replace("+00:00", "Z"),
        "profile": "redacted",
        "scope": {
            "subscribed_region_count": None,
            "accessible_compartment_count": None,
            "region_identifiers": [],
            "discovery": discovery,
            "discovery_state": state if state in ALLOWED_STATES else "query-failed",
        },
        "command_templates": COMMAND_TEMPLATES,
        "categories": categories,
        "oke_absence_proven": False,
        "cost_window": {
            "start_utc": started.isoformat().replace("+00:00", "Z"),
            "end_utc": ended.isoformat().replace("+00:00", "Z"),
            "duration_days": (ended - started).total_seconds() / 86400,
            "state": "not-queried",
            "measured_total": None,
            "currencies": [],
            "seven_day_residual_bill_established": False,
        },
        "safety": {
            "read_only_allowlist_enforced": True,
            "secret_contents_queried": False,
            "raw_identifiers_persisted": False,
            "mutation_commands_present": False,
        },
    }
    assert_sanitized(report)
    return report


def inventory(profile: str, started: dt.datetime, ended: dt.datetime) -> dict[str, Any]:
    root_id = load_root_id(profile)
    bootstrap = OciReadOnly(profile)
    region_status, region_payload = bootstrap.run(("iam", "region-subscription", "list", "--all"))
    if region_status != "ok":
        return discovery_failure_report(started, ended, "region-subscriptions", region_status)
    regions = sorted(
        item.get("region-name") for item in data_items(region_payload)
        if isinstance(item, dict) and isinstance(item.get("region-name"), str)
    )
    compartment_status, compartment_payload = bootstrap.run((
        "iam", "compartment", "list", "--compartment-id", root_id,
        "--compartment-id-in-subtree", "true", "--access-level", "ACCESSIBLE", "--all",
    ))
    if compartment_status != "ok":
        return discovery_failure_report(started, ended, "accessible-compartments", compartment_status)
    compartments = [root_id]
    compartments.extend(
        item["id"] for item in data_items(compartment_payload)
        if isinstance(item, dict) and isinstance(item.get("id"), str)
        and item.get("lifecycle-state") != "DELETED"
    )
    compartments = sorted(set(compartments))

    categories: dict[str, dict[str, Any]] = {}
    for category, operation in COMPARTMENT_SCOPED.items():
        count = attempted = succeeded = denied = failed = 0
        for region in regions:
            client = OciReadOnly(profile, region)
            for compartment_id in compartments:
                attempted += 1
                extra: tuple[str, ...] = ()
                if category == "public-ips":
                    extra = ("--scope", "REGION")
                status, payload = client.run((*operation, "--compartment-id", compartment_id, *extra, "--all"))
                if status == "ok":
                    succeeded += 1
                    count += len(data_items(payload))
                elif status == "permission-denied":
                    denied += 1
                else:
                    failed += 1
        categories[category] = category_result(count, attempted, succeeded, denied, failed)

    for category, operation in ROOT_SCOPED.items():
        status, payload = bootstrap.run((*operation, "--compartment-id", root_id, "--all"))
        categories[category] = category_result(
            len(data_items(payload)) if status == "ok" else 0, 1, int(status == "ok"),
            int(status == "permission-denied"), int(status not in ("ok", "permission-denied")),
        )

    for category, operation in GLOBAL_COMPARTMENT_SCOPED.items():
        count = attempted = succeeded = denied = failed = 0
        for compartment_id in compartments:
            attempted += 1
            status, payload = bootstrap.run((*operation, "--compartment-id", compartment_id, "--all"))
            if status == "ok": succeeded += 1; count += len(data_items(payload))
            elif status == "permission-denied": denied += 1
            else: failed += 1
        categories[category] = category_result(count, attempted, succeeded, denied, failed)

    # Object Storage namespace is used only in memory. Secret contents are never queried.
    namespace_status, namespace_payload = bootstrap.run(("object-storage", "namespace", "get"))
    namespace = namespace_payload.get("data") if namespace_status == "ok" and isinstance(namespace_payload, dict) else None
    count = attempted = succeeded = denied = failed = 0
    if isinstance(namespace, str):
        for region in regions:
            client = OciReadOnly(profile, region)
            for compartment_id in compartments:
                attempted += 1
                status, payload = client.run(("object-storage", "bucket", "list", "--namespace-name", namespace, "--compartment-id", compartment_id, "--all"))
                if status == "ok": succeeded += 1; count += len(data_items(payload))
                elif status == "permission-denied": denied += 1
                else: failed += 1
    categories["object-storage-buckets"] = category_result(count, attempted, succeeded, denied, failed)

    # Vaults are a KMS management list; keys and secret bundles are intentionally absent.
    count = attempted = succeeded = denied = failed = 0
    for region in regions:
        client = OciReadOnly(profile, region)
        for compartment_id in compartments:
            attempted += 1
            status, payload = client.run(("kms", "management", "vault", "list", "--compartment-id", compartment_id, "--all"))
            if status == "ok": succeeded += 1; count += len(data_items(payload))
            elif status == "permission-denied": denied += 1
            else: failed += 1
    categories["kms-vaults-metadata"] = category_result(count, attempted, succeeded, denied, failed)

    # Zone identifiers are consumed only in memory; record names and RDATA are
    # never emitted or persisted.
    count = attempted = succeeded = denied = failed = 0
    for region in regions:
        client = OciReadOnly(profile, region)
        for compartment_id in compartments:
            zone_status, zone_payload = client.run(("dns", "zone", "list", "--compartment-id", compartment_id, "--all"))
            if zone_status == "permission-denied":
                attempted += 1; denied += 1
                continue
            if zone_status != "ok":
                attempted += 1; failed += 1
                continue
            zones = [item.get("id") for item in data_items(zone_payload) if isinstance(item, dict) and isinstance(item.get("id"), str)]
            if not zones:
                attempted += 1; succeeded += 1
            for zone_id in zones:
                attempted += 1
                status, payload = client.run(("dns", "record", "zone", "get", "--zone-name-or-id", zone_id, "--all"))
                if status == "ok": succeeded += 1; count += len(data_items(payload))
                elif status == "permission-denied": denied += 1
                else: failed += 1
    categories["dns-records"] = category_result(count, attempted, succeeded, denied, failed)

    cost_status, cost_payload = bootstrap.run((
        "usage-api", "usage-summary", "request-summarized-usages",
        "--tenant-id", root_id, "--query-type", "COST", "--granularity", "DAILY",
        "--is-aggregate-by-time", "false",
        "--time-usage-started", started.isoformat().replace("+00:00", "Z"),
        "--time-usage-ended", ended.isoformat().replace("+00:00", "Z"), "--all",
    ))
    cost_items = data_items(cost_payload) if cost_status == "ok" else []
    amounts: list[float] = []
    currencies: set[str] = set()
    for item in cost_items:
        if not isinstance(item, dict): continue
        amount = item.get("computed-amount")
        currency = item.get("currency")
        try:
            if amount is not None: amounts.append(float(amount))
        except (TypeError, ValueError):
            pass
        if isinstance(currency, str): currencies.add(currency)
    cost_state = "observed-present" if cost_status == "ok" and amounts else (
        "observed-empty" if cost_status == "ok" else cost_status
    )
    if cost_state not in ALLOWED_STATES: cost_state = "query-failed"

    # These are not OCI control-plane APIs and cannot honestly be inferred here.
    categories["nats-streams-consumers"] = category_result(0, 0, 0, 0, 0)
    categories["workload-runtime-inventory"] = category_result(0, 0, 0, 0, 0)

    report = {
        "schema_version": 1,
        "generated_at_utc": ended.isoformat().replace("+00:00", "Z"),
        "profile": "redacted",
        "scope": {
            "subscribed_region_count": len(regions),
            "accessible_compartment_count": len(compartments),
            "region_identifiers": [stable_hash(region) for region in regions],
        },
        "command_templates": COMMAND_TEMPLATES,
        "categories": categories,
        "oke_absence_proven": all(
            categories[name]["state"] == "observed-empty"
            for name in ("oke-clusters", "oke-node-pools")
        ),
        "cost_window": {
            "start_utc": started.isoformat().replace("+00:00", "Z"),
            "end_utc": ended.isoformat().replace("+00:00", "Z"),
            "duration_days": (ended - started).total_seconds() / 86400,
            "state": cost_state,
            "measured_total": round(sum(amounts), 8) if amounts else None,
            "currencies": sorted(currencies),
            "seven_day_residual_bill_established": cost_status == "ok" and bool(amounts)
                and len(currencies) == 1 and (ended - started) >= dt.timedelta(days=7),
        },
        "safety": {
            "read_only_allowlist_enforced": True,
            "secret_contents_queried": False,
            "raw_identifiers_persisted": False,
            "mutation_commands_present": False,
        },
    }
    assert_sanitized(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="DEFAULT")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--plan", action="store_true", help="print sanitized command templates; perform no API calls")
    parser.add_argument("--live", action="store_true", help="execute the hard-coded read-only allowlist")
    parser.add_argument("--end-utc", help="exclusive UTC window end; default is current whole UTC hour")
    args = parser.parse_args()
    if args.plan == args.live:
        parser.error("select exactly one of --plan or --live")
    if args.plan:
        print(json.dumps({"command_templates": COMMAND_TEMPLATES}, indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--live requires --output")
    ended = (dt.datetime.fromisoformat(args.end_utc.replace("Z", "+00:00")) if args.end_utc
             else dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0))
    if ended.tzinfo is None:
        parser.error("--end-utc must include a timezone")
    ended = ended.astimezone(dt.timezone.utc)
    started = ended - dt.timedelta(days=7)
    report = inventory(args.profile, started, ended)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(args.output, 0o644)
    print("sanitized OCI inventory written; inspect the report for coverage and permission gaps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
