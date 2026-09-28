#!/usr/bin/env python3
"""Read-only manual-region inventory, budget admission, and live foundation inspection.

All prices are explicit estimates, not OCI spending limits. This tool never
creates, updates, or deletes OCI resources. Its live foundation record is a
short-lived authenticated readback, not a Terraform apply receipt or approval.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import email.utils
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import shlex
import subprocess
import sys
import tempfile
from decimal import Decimal


ROOT = pathlib.Path(__file__).resolve().parent
PLAN = ROOT / "plan.json"
UTC = dt.timezone.utc
ACTIVE_COMPARTMENT_STATES = {"ACTIVE", "CREATING"}
ACTIVE_RESOURCE_STATES = {"CREATING", "PROVISIONING", "STARTING", "RUNNING", "STOPPING", "STOPPED", "AVAILABLE", "FAULTY", "UPDATING", "TERMINATING"}
FREE_A1_OCPU_HOURS = Decimal(1500)
FREE_A1_MEMORY_GB_HOURS = Decimal(9000)
FREE_BLOCK_GB = Decimal(200)
FREE_OBJECT_GB = Decimal(10)
MAX_PLAN_BYTES = 64 * 1024
MAX_INVENTORY_BYTES = 4 * 1024 * 1024
MAX_ADMISSION_BYTES = 64 * 1024
MAX_IMPORT_RECEIPT_BYTES = 64 * 1024
MAX_IMPORT_PROJECTION_BYTES = 64 * 1024
MAX_SEED_MANIFEST_BYTES = 30 * 1024
MAX_USER_DATA_BYTES = 32766
MAX_SSH_PUBLIC_KEY_BYTES = 16 * 1024
OCID = re.compile(r"ocid1\.([a-z]+)\.oc1\.([a-z0-9-]*)\.([a-z0-9]+(?:\.[a-z0-9]+)*)\Z")
SAFE_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}\Z")
CELL_REGIONS = {"GRU": "sa-saopaulo-1", "SFO": "us-sanjose-1", "FRA": "eu-frankfurt-1"}


def fail(message: str) -> None:
    raise ValueError(message)


def strict_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(strict_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(strict_equal(a, b) for a, b in zip(left, right))
    return left == right


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            fail("JSON document has duplicate fields")
        value[key] = item
    return value


def read_regular_bytes(path: pathlib.Path, limit: int, label: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > limit:
                fail(f"{label} has invalid size or is not a regular file")
            wire = source.read(limit + 1)
    except OSError as error:
        raise ValueError(f"{label} is unreadable or invalid JSON") from error
    if not wire or len(wire) > limit:
        fail(f"{label} has invalid size")
    return wire


def read_json(path: pathlib.Path, limit: int, label: str) -> dict:
    wire = read_regular_bytes(path, limit, label)
    try:
        value = json.loads(wire, object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is unreadable or invalid JSON") from error
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_ocid(value: object, kind: str, region: str | None = None) -> str:
    match = OCID.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(1) != kind or (region is not None and match.group(2) != region):
        fail(f"manual plan has an invalid {kind} OCID")
    return value


RULE_FIELDS = {"direction", "protocol", "source", "source_type", "destination", "destination_type",
               "tcp_min", "tcp_max", "udp_min", "udp_max", "stateless"}


def validate_rule_specs(value: object, label: str) -> list[dict]:
    if not isinstance(value, list) or any(not isinstance(row, dict) or set(row) != RULE_FIELDS for row in value):
        fail(f"manual plan {label} must declare complete normalized security rules")
    seen = set()
    for rule in value:
        if (rule["direction"] not in {"INGRESS", "EGRESS"} or
                not isinstance(rule["protocol"], str) or
                rule["protocol"] not in {"all", "1", "6", "17", "58"} or
                not isinstance(rule["stateless"], bool)):
            fail(f"manual plan {label} has an unsupported rule")
        for key in ("source", "source_type", "destination", "destination_type"):
            if rule[key] is not None and (not isinstance(rule[key], str) or not rule[key] or len(rule[key]) > 200):
                fail(f"manual plan {label} has an invalid rule {key}")
        for low, high in (("tcp_min", "tcp_max"), ("udp_min", "udp_max")):
            left, right = rule[low], rule[high]
            if (left is None) != (right is None) or (left is not None and
                    (isinstance(left, bool) or isinstance(right, bool) or not 1 <= left <= right <= 65535)):
                fail(f"manual plan {label} has an invalid port range")
        if rule["protocol"] != "6" and (rule["tcp_min"] is not None or rule["tcp_max"] is not None):
            fail(f"manual plan {label} has TCP ports on a non-TCP rule")
        if rule["protocol"] != "17" and (rule["udp_min"] is not None or rule["udp_max"] is not None):
            fail(f"manual plan {label} has UDP ports on a non-UDP rule")
        marker = json.dumps(rule, sort_keys=True, separators=(",", ":"))
        if marker in seen:
            fail(f"manual plan {label} contains duplicate rules")
        seen.add(marker)
    return value


def source_path(plan: dict) -> pathlib.Path:
    path = plan.get("_source_path", PLAN)
    return pathlib.Path(path)


def decimal(value: object) -> Decimal:
    if isinstance(value, bool):
        fail("boolean is not a number")
    return Decimal(str(value))


def load_plan(path: pathlib.Path = PLAN) -> dict:
    plan = read_json(path, MAX_PLAN_BYTES, "manual region plan")
    if plan.get("schema_version") != 2 or plan.get("cell") not in CELL_REGIONS or plan.get("region") != CELL_REGIONS[plan["cell"]]:
        fail("unexpected manual plan schema, cell, or OCI region")
    plan["_source_path"] = path.resolve()
    names = plan.get("preview_compartment_names")
    if (not isinstance(names, dict) or set(names) != {"control", "network", "workload"} or
            any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name)
                for name in names.values()) or len(set(names.values())) != 3):
        fail("manual compartment names must be distinct safe names for control, network, and workload")
    host_rows = plan.get("hosts")
    if not isinstance(host_rows, list) or not host_rows:
        fail("manual plan must define at least one host")
    slots = [host.get("slot") for host in host_rows if isinstance(host, dict)]
    if len(slots) != len(host_rows) or len(set(slots)) != len(slots):
        fail("manual host slots must be unique objects")
    controllers = [host for host in host_rows if host.get("slot", "").startswith("controller-")]
    members = [host for host in host_rows if host.get("slot", "").startswith("member-")]
    if (len(controllers) != plan.get("controller_replicas") or
            len(members) != plan.get("database_members") or len(controllers) + len(members) != len(host_rows)):
        fail("manual host roster differs from its controller and database member counts")
    for host in host_rows:
        if (not re.fullmatch(r"(?:controller|member)-[a-z][a-z0-9-]{0,30}", host["slot"]) or
                host.get("shape") != "VM.Standard.A1.Flex" or
                decimal(host.get("ocpus")) <= 0 or decimal(host.get("memory_gb")) < decimal(host["ocpus"]) or
                decimal(host.get("boot_gb")) < 50 or decimal(host.get("data_gb")) < 0 or
                (host["slot"].startswith("controller-") and decimal(host["data_gb"]) != 0) or
                (host["slot"].startswith("member-") and decimal(host["data_gb"]) <= 0)):
            fail(f"unexpected manual shape or size for {host['slot']}")
    network = ipaddress.ip_network(plan["network_cidr"], strict=True)
    subnet = ipaddress.ip_network(plan["subnet_cidr"], strict=True)
    if not network.is_private or not subnet.is_private or not subnet.subnet_of(network):
        fail("manual VCN and subnet must be nested private CIDRs")
    host_ips = [ipaddress.ip_address(host["private_ip"]) for host in host_rows]
    if len(set(host_ips)) != len(host_ips) or any(address not in subnet for address in host_ips):
        fail("manual host addresses must be unique and inside the private subnet")
    ids = plan.get("resource_ids")
    id_keys = {"control_compartment", "network_compartment", "workload_compartment", "vault", "key", "vcn",
               "subnet", "network_security_group", "seed_ssh_network_security_group", "security_list",
               "route_table", "service_gateway", "controller_dynamic_group", "controller_policy",
               "objectstorage_key_policy", "host_dynamic_group", "host_policy",
               "instances", "boot_volumes", "data_volumes"}
    if not isinstance(ids, dict) or set(ids) != id_keys:
        fail("manual plan must bind the exact foundation and host resource ID map")
    for key, kind in (("control_compartment", "compartment"), ("network_compartment", "compartment"),
                      ("workload_compartment", "compartment"), ("vault", "vault"), ("key", "key"),
                      ("vcn", "vcn"), ("subnet", "subnet"), ("network_security_group", "networksecuritygroup"),
                      ("seed_ssh_network_security_group", "networksecuritygroup"), ("security_list", "securitylist"),
                      ("route_table", "routetable"), ("service_gateway", "servicegateway"),
                      ("controller_dynamic_group", "dynamicgroup"), ("controller_policy", "policy"),
                      ("objectstorage_key_policy", "policy"), ("host_dynamic_group", "dynamicgroup"),
                      ("host_policy", "policy")):
        if ids[key] is not None:
            require_ocid(ids[key], kind, plan["region"] if key in {"vault", "key", "vcn", "subnet",
                                                                     "network_security_group",
                                                                     "seed_ssh_network_security_group",
                                                                     "security_list", "route_table", "service_gateway"} else None)
    expected_slots = set(slots)
    for key, allowed in (("instances", expected_slots), ("boot_volumes", expected_slots),
                         ("data_volumes", {host["slot"] for host in members})):
        value = ids[key]
        if not isinstance(value, dict) or set(value) != allowed:
            fail(f"manual {key} must map every planned slot to an exact OCID or null")
        kind = "instance" if key == "instances" else ("bootvolume" if key == "boot_volumes" else "volume")
        seen = set()
        for resource_id in value.values():
            if resource_id is not None:
                require_ocid(resource_id, kind, plan["region"])
                if resource_id in seen:
                    fail(f"manual {key} OCIDs must be unique")
                seen.add(resource_id)
    create_identity = plan.get("seed_a_create_identity")
    if create_identity is not None and (not isinstance(create_identity, str) or
            not SAFE_IDENTITY.fullmatch(create_identity)):
        fail("manual seed-A create identity is invalid")
    budget = plan.get("budget", {})
    if budget.get("currency") != "USD" or not Decimal(0) < decimal(budget.get("monthly_limit")) <= Decimal(100):
        fail("manual monthly budget must be positive USD and no more than $100")
    if budget.get("replacement_hosts_max") != 1 or decimal(budget.get("replacement_overlap_hours_max")) > 72:
        fail("replacement allowance exceeds the bounded plan")
    if (decimal(budget.get("snapshot_gb_max")) > 350 or
            not Decimal(0) <= decimal(budget.get("object_storage_gb_max")) <= Decimal(10) or
            not Decimal(0) <= decimal(budget.get("staging_object_storage_gb_max")) <= Decimal(10)):
        fail("storage allowance exceeds the bounded plan")
    existing = plan["existing_forgejo"]
    if existing["expected_volume_gb"] != 50 or existing["expected_volume_vpus_per_gb"] != 10:
        fail("existing Forgejo data volume differs from the bounded cost model")
    network_security = plan.get("network_security")
    if not isinstance(network_security, dict) or set(network_security) != {
            "nsg_rules", "seed_ssh_nsg_rules", "security_list_ingress_rules", "security_list_egress_rules",
            "route_rules", "service_gateway_service_id", "service_gateway_cidr_block"}:
        fail("manual plan must declare exact network and security state")
    for key in ("nsg_rules", "seed_ssh_nsg_rules", "security_list_ingress_rules", "security_list_egress_rules"):
        validate_rule_specs(network_security[key], key)
    if (not isinstance(network_security["route_rules"], list) or any(
            not isinstance(rule, dict) or set(rule) != {"destination", "destination_type", "network_entity_id"}
            or any(not isinstance(rule[key], str) or not rule[key] for key in rule)
            for rule in network_security["route_rules"])):
        fail("manual plan route_rules must declare exact destination, type, and target triples")
    gateway_service_id = network_security["service_gateway_service_id"]
    gateway_cidr = network_security["service_gateway_cidr_block"]
    if (gateway_service_id is None) != (gateway_cidr is None):
        fail("manual service gateway ID and service CIDR must be configured together")
    if gateway_service_id is not None:
        require_ocid(gateway_service_id, "service", plan["region"])
        if (len(network_security["route_rules"]) != 1 or
                network_security["route_rules"][0] != {
                    "destination": gateway_cidr, "destination_type": "SERVICE_CIDR_BLOCK",
                    "network_entity_id": "{service_gateway_id}"}):
            fail("manual service gateway route must target the exact declared service CIDR and gateway")
    elif ids["service_gateway"] is not None or ids["route_table"] is not None or network_security["route_rules"]:
        fail("manual plan has route resources without a service gateway declaration")
    identity = plan.get("identity")
    identity_keys = {"controller_dynamic_group_name", "controller_policy_name", "objectstorage_key_policy_name",
                     "host_dynamic_group_name", "host_policy_name"}
    if not isinstance(identity, dict) or set(identity) != identity_keys:
        fail("manual plan must declare exact live controller IAM readiness expectations")
    for key in ("controller_dynamic_group_name", "controller_policy_name", "objectstorage_key_policy_name",
                "host_dynamic_group_name", "host_policy_name"):
        if not isinstance(identity[key], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", identity[key]):
            fail(f"manual IAM {key} is invalid")
    host_secret = plan.get("host_credential_secret")
    if not isinstance(host_secret, dict) or set(host_secret) != {"compartment_id", "secret_id"}:
        fail("manual plan must bind the exact host LiveS3Credential secret and compartment")
    if any(value is not None for value in host_secret.values()):
        require_ocid(host_secret["compartment_id"], "compartment")
        require_ocid(host_secret["secret_id"], "vaultsecret", plan["region"])
    if ids["instances"]["controller-a"] is not None and plan.get("seed_a_create_identity") is None:
        fail("manual controller-a OCID requires its preserved seed-A create identity")
    retention = plan.get("bucket_retention_days")
    if isinstance(retention, bool) or not isinstance(retention, int) or not 1 <= retention <= 3650:
        fail("manual ledger and backup retention must be a bounded whole-day duration")
    return plan


def oci(*args: str, region: str | None = None) -> object:
    command = ["oci", *args]
    if region:
        command += ["--region", region]
    command += ["--output", "json"]
    process = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    if process.returncode:
        # OCI errors may include private request details. Only the operation is reported.
        fail(f"OCI read failed: {' '.join(args[:3])} (exit {process.returncode})")
    object_storage_list = args[:3] in (("os", "object", "list"),
                                       ("os", "object", "list-object-versions"))
    if not process.stdout.strip() and "--all" in args and not object_storage_list:
        return []
    try:
        response = json.loads(process.stdout)
        if object_storage_list and "--all" in args and response == {"prefixes": []}:
            # OCI CLI 3.92.1's renderer omits `data` for an empty Object
            # Storage list but retains its empty prefixes metadata.
            return []
        return response["data"]
    except (ValueError, KeyError) as error:
        raise ValueError(f"invalid OCI response for {' '.join(args[:3])}") from error


def slim(resource: dict, kind: str, region: str) -> dict:
    fields = ("id", "display-name", "name", "compartment-id", "lifecycle-state", "availability-domain",
              "fault-domain", "shape", "shape-config", "size-in-gbs", "vpus-per-gb", "freeform-tags",
              "cidr-block", "is-public", "prohibit-public-ip-on-vnic", "prohibit-internet-ingress",
              "ip-address", "unique-size-in-gbs", "scope", "time-created")
    return {"kind": kind, "region": region, **{key: resource[key] for key in fields if key in resource}}


def rows(value: object) -> list[dict]:
    if isinstance(value, dict) and "items" in value:
        value = value["items"]
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        fail("OCI list response has an unexpected shape")
    return value


def collect_scoped_images(regions: list[str], compartments: list[str]) -> list[dict]:
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for region in regions:
            for compartment in compartments:
                tasks.append((region, compartment, pool.submit(
                    oci, "compute", "image", "list", "--compartment-id", compartment, "--all", region=region)))
        images = []
        seen_images = set()
        for region, compartment, future in tasks:
            for row in rows(future.result()):
                # ListImages also returns platform images. Only images owned by the
                # requested compartment are charged to this scoped inventory.
                owner = row.get("compartment-id")
                if owner is None:
                    continue
                if owner != compartment:
                    fail("image list returned an unexpected owning compartment")
                image_id = row.get("id")
                if not isinstance(image_id, str) or not image_id or image_id in seen_images:
                    fail("duplicate or missing scoped image identity")
                seen_images.add(image_id)
                images.append({"region": region, "id": image_id, "compartment_id": compartment,
                               "display_name": row.get("display-name"),
                               "lifecycle_state": row.get("lifecycle-state"),
                               "billable_size_in_gbs": row.get("billable-size-in-gbs")})
    verify_scoped_images(regions, compartments, images)
    return images


def verify_scoped_images(regions: list[str], compartments: list[str], images: object) -> None:
    if not isinstance(images, list):
        fail("inventory lacks scoped custom images")
    seen_images = set()
    for image in images:
        if not isinstance(image, dict):
            fail("invalid scoped custom image entry")
        identity = (image.get("region"), image.get("id"))
        if (set(image) != {"region", "id", "compartment_id", "display_name", "lifecycle_state",
                           "billable_size_in_gbs"} or
                not all(isinstance(value, str) and value for value in identity) or
                image["id"] in seen_images or image["region"] not in regions or
                image["compartment_id"] not in compartments or
                not isinstance(image["display_name"], str) or not image["display_name"] or
                not isinstance(image["lifecycle_state"], str) or not image["lifecycle_state"]):
            fail("duplicate or incomplete scoped custom image identity")
        seen_images.add(image["id"])
        if image["billable_size_in_gbs"] is None:
            fail("scoped custom image has no billed GiB size")
        positive_gib(image["billable_size_in_gbs"], "scoped image size")


def collect_inventory(plan: dict) -> dict:
    subscriptions = oci("iam", "region-subscription", "list", "--tenancy-id", plan["tenancy_id"], "--all")
    regions = sorted(row["region-name"] for row in subscriptions if row["status"] == "READY")
    if plan["region"] not in regions:
        fail(f"{plan['region']} is not a ready subscribed region")
    children = oci("iam", "compartment", "list", "--compartment-id", plan["parent_compartment_id"], "--all")
    preview_ids = {}
    for role, name in plan["preview_compartment_names"].items():
        matches = [row for row in children if row["name"] == name
                   and row["lifecycle-state"] in ACTIVE_COMPARTMENT_STATES]
        if len(matches) > 1 or any(row["lifecycle-state"] == "CREATING" for row in matches):
            fail(f"preview {role} compartment is duplicated or still creating")
        preview_ids[role] = matches[0]["id"] if matches else None
        planned_id = plan["resource_ids"][f"{role}_compartment"]
        if planned_id and planned_id != preview_ids[role]:
            fail(f"recorded preview {role} compartment OCID differs from live inventory")
    if len({resource_id for resource_id in preview_ids.values() if resource_id}) != sum(bool(value) for value in preview_ids.values()):
        fail("preview compartments overlap")
    compartment_ids = [plan["tenancy_id"], plan["parent_compartment_id"], plan["shared_compartment_id"]]
    compartment_ids.extend(resource_id for resource_id in preview_ids.values() if resource_id)
    images = collect_scoped_images(regions, compartment_ids)
    resources: list[dict] = []
    buckets: list[dict] = []
    namespace = oci("os", "ns", "get", region=plan["region"])
    list_tasks: list[tuple[str, str, tuple[str, ...]]] = []
    for region in regions:
        domains = rows(oci("iam", "availability-domain", "list", "--compartment-id", plan["tenancy_id"], region=region))
        for compartment_id in compartment_ids:
            for kind, command in (
                ("instance", ("compute", "instance", "list")),
                ("volume", ("bv", "volume", "list")),
                ("vcn", ("network", "vcn", "list")),
                ("subnet", ("network", "subnet", "list")),
                ("network-security-group", ("network", "nsg", "list")),
                ("security-list", ("network", "security-list", "list")),
                ("route-table", ("network", "route-table", "list")),
                ("service-gateway", ("network", "service-gateway", "list")),
                ("nat-gateway", ("network", "nat-gateway", "list")),
                ("load-balancer", ("lb", "load-balancer", "list")),
                ("network-load-balancer", ("nlb", "network-load-balancer", "list")),
                ("volume-backup", ("bv", "backup", "list")),
                ("boot-volume-backup", ("bv", "boot-volume-backup", "list")),
            ):
                list_tasks.append((kind, region, (*command, "--compartment-id", compartment_id, "--all")))
            for domain in domains:
                list_tasks.append(("boot-volume", region,
                                   ("bv", "boot-volume", "list", "--compartment-id", compartment_id,
                                    "--availability-domain", domain["name"], "--all")))
            list_tasks.append(("bucket", region, ("os", "bucket", "list", "--compartment-id", compartment_id, "--all")))
            list_tasks.append(("public-ip", region, ("network", "public-ip", "list", "--scope", "REGION",
                                                     "--compartment-id", compartment_id, "--all")))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [(kind, region, pool.submit(oci, *command, region=region)) for kind, region, command in list_tasks]
        bucket_tasks: list[tuple[str, dict]] = []
        for kind, region, future in futures:
            for row in rows(future.result()):
                if kind == "bucket":
                    bucket_tasks.append((region, row))
                else:
                    resources.append(slim(row, kind, region))
        object_futures = [(region, bucket, pool.submit(oci, "os", "object", "list", "--namespace-name",
                                                        namespace, "--bucket-name", bucket["name"],
                                                        "--fields", "size", "--all", region=region))
                          for region, bucket in bucket_tasks]
        for region, bucket, future in object_futures:
            objects = rows(future.result())
            properties = oci("os", "bucket", "get", "--namespace-name", namespace,
                             "--bucket-name", bucket["name"], region=region)
            versioned = (region == plan["region"] and
                    bucket["compartment-id"] == preview_ids["control"] and
                    bucket["name"] in (plan["foundation_buckets"]["head"], plan["foundation_buckets"]["material"]))
            expected_versioning = "Enabled" if versioned else "Disabled"
            if properties.get("versioning") != expected_versioning or properties.get("storage-tier") != "Standard":
                fail("bucket versioning or tier is outside the cost model")
            if properties.get("public-access-type") != "NoPublicAccess":
                fail("bucket public access is outside the private storage model")
            if versioned:
                versions = rows(oci("os", "object", "list-object-versions", "--namespace-name", namespace,
                                    "--bucket-name", bucket["name"], "--fields", "size", "--all", region=region))
                objects = versions
            buckets.append({"region": region, "compartment_id": bucket["compartment-id"], "name": bucket["name"],
                            "object_count": len(objects), "bytes": sum(row.get("size", 0) or 0 for row in objects),
                            "versioning": properties["versioning"], "storage_tier": properties["storage-tier"],
                            "public_access_type": properties["public-access-type"],
                            "kms_key_id": properties.get("kms-key-id")})
    return {"schema_version": 2, "captured_at": dt.datetime.now(UTC).isoformat(),
            "plan_sha256": sha256(source_path(plan)), "tenancy_id": plan["tenancy_id"], "regions": regions,
            "preview_compartment_ids": preview_ids, "resources": resources, "buckets": buckets,
            "images": images}


def active(resources: list[dict], kind: str) -> list[dict]:
    return [row for row in resources if row["kind"] == kind and row.get("lifecycle-state") in ACTIVE_RESOURCE_STATES]


def replacement_within_window(resources: list[dict], plan: dict,
                              now: dt.datetime | None = None) -> bool:
    if not resources:
        return False
    try:
        newest = max(dt.datetime.fromisoformat(row["time-created"]) for row in resources)
    except (KeyError, ValueError):
        return False
    if newest.tzinfo is None:
        return False
    age = (now or dt.datetime.now(UTC)) - newest
    return dt.timedelta(0) <= age <= dt.timedelta(hours=plan["budget"]["replacement_overlap_hours_max"])


def verify_inventory(plan: dict, inventory: dict, max_age_minutes: int = 15,
                     plan_path: pathlib.Path | None = None,
                     now: dt.datetime | None = None) -> None:
    if inventory.get("schema_version") != 2 or inventory.get("tenancy_id") != plan["tenancy_id"]:
        fail("inventory belongs to another tenancy or schema")
    if inventory.get("plan_sha256") != sha256(plan_path or source_path(plan)):
        fail("inventory was captured against another plan revision")
    preview_ids = inventory.get("preview_compartment_ids")
    if not isinstance(preview_ids, dict) or set(preview_ids) != {"control", "network", "workload"}:
        fail("inventory lacks the three planned preview compartment identities")
    for role, resource_id in preview_ids.items():
        planned = plan["resource_ids"][f"{role}_compartment"]
        if planned and planned != resource_id:
            fail(f"preview {role} compartment differs from the recorded resource identity")
    regions = inventory.get("regions")
    if not isinstance(regions, list) or any(not isinstance(region, str) or not region for region in regions):
        fail("inventory lacks subscribed region scope")
    image_compartments = [plan["tenancy_id"], plan["parent_compartment_id"], plan["shared_compartment_id"]]
    image_compartments.extend(resource_id for resource_id in preview_ids.values() if resource_id)
    verify_scoped_images(regions, image_compartments, inventory.get("images"))
    for bucket in inventory["buckets"]:
        if (preview_ids["control"] and bucket.get("compartment_id") == preview_ids["control"] and
                bucket.get("name") not in plan["foundation_buckets"].values()):
            fail("control compartment has an unplanned object bucket")
        versioned = (bucket.get("region") == plan["region"] and bucket.get("compartment_id") == preview_ids["control"]
                and bucket.get("name") in (plan["foundation_buckets"]["head"], plan["foundation_buckets"]["material"]))
        if bucket.get("versioning") != ("Enabled" if versioned else "Disabled") or bucket.get("storage_tier") != "Standard":
            fail("inventory contains an unpriced object storage tier or versioning mode")
        if bucket.get("public_access_type") != "NoPublicAccess":
            fail("inventory contains a public object storage bucket")
        if (preview_ids["control"] and bucket.get("compartment_id") == preview_ids["control"] and
                bucket.get("name") in plan["foundation_buckets"].values() and
                plan["resource_ids"].get("key") is not None and
                bucket.get("kms_key_id") != plan["resource_ids"]["key"]):
            fail("inventory bucket encryption differs from the exact control KMS key")
    captured = dt.datetime.fromisoformat(inventory["captured_at"])
    age = (now or dt.datetime.now(UTC)) - captured
    if captured.tzinfo is None or age.total_seconds() < -30 or age > dt.timedelta(minutes=max_age_minutes):
        fail("inventory is stale or has an invalid timestamp")
    existing = plan["existing_forgejo"]
    for kind, key in (("instance", "instance_id"), ("boot-volume", "boot_volume_id"), ("volume", "data_volume_id")):
        rows = [row for row in active(inventory["resources"], kind) if row.get("id") == existing[key]]
        if len(rows) != 1 or rows[0].get("compartment-id") != plan["shared_compartment_id"]:
            fail(f"existing Forgejo {kind} identity changed")
    instances = active(inventory["resources"], "instance")
    known_instance_ids = {existing["instance_id"]}
    control_id = preview_ids["control"]
    workload_id = preview_ids["workload"]
    seed_instance_id = plan["resource_ids"]["instances"]["controller-a"]
    seed_create_identity = plan.get("seed_a_create_identity")
    seed_candidates = [row for row in instances
                       if row.get("id") == seed_instance_id or
                       "BootstrapCreateKey" in (row.get("freeform-tags") or {})]
    if seed_instance_id is not None:
        if (not seed_create_identity or len(seed_candidates) != 1 or seed_candidates[0].get("id") != seed_instance_id or
                (seed_candidates[0].get("freeform-tags") or {}).get("BootstrapCreateKey") != seed_create_identity):
            fail("plan-bound controller-a OCID or BootstrapCreateKey differs from live inventory")
    elif seed_candidates:
        fail("controller-a must be recorded by exact OCID and seed create identity before admission")
    preview_controller_count = 0
    preview_member_count = 0
    for row in instances:
        if row["id"] in known_instance_ids:
            if row.get("shape") != "VM.Standard.A1.Flex" or decimal(row["shape-config"]["ocpus"]) != 2 or decimal(row["shape-config"]["memory-in-gbs"]) != 4:
                fail("Forgejo A1 dimensions changed")
            continue
        compartment = row.get("compartment-id")
        if compartment not in {control_id, workload_id}:
            fail(f"unbudgeted instance found: {row['id']}")
        tags = row.get("freeform-tags") or {}
        if (compartment == workload_id and tags.get("terrascale-managed-by") == "ts-orchestrator" and
                tags.get("terrascale-owner") == plan["orchestrator_owner"] and
                tags.get("terrascale-resource") == "member-host"):
            preview_member_count += 1
        elif compartment == control_id and row.get("id") == seed_instance_id:
            preview_controller_count += 1
        elif compartment == control_id and row.get("display-name") in {"controller-b", "controller-c"}:
            preview_controller_count += 1
        else:
            fail(f"preview instance has no approved owner: {row['id']}")
        if row.get("shape") != "VM.Standard.A1.Flex" or decimal(row["shape-config"]["ocpus"]) != 1 or decimal(row["shape-config"]["memory-in-gbs"]) != 6:
            fail("preview instance dimensions exceed the plan")
    preview_instances = [row for row in instances if row.get("compartment-id") in {control_id, workload_id}]
    if (preview_controller_count > 4 or preview_member_count > 3 or len(preview_instances) > 6 or
            (len(preview_instances) > 5 and not replacement_within_window(preview_instances, plan, now))):
        fail("preview controller or member count exceeds the plan")
    known_volumes = {existing["boot_volume_id"], existing["data_volume_id"]}
    for kind in ("boot-volume", "volume"):
        for row in active(inventory["resources"], kind):
            if row["id"] not in known_volumes and row.get("compartment-id") not in {control_id, workload_id}:
                fail(f"unbudgeted {kind} found: {row['id']}")
            expected_size = (existing["expected_volume_gb"]
                             if kind == "volume" and row["id"] == existing["data_volume_id"] else 50)
            expected_vpus = (existing["expected_volume_vpus_per_gb"]
                             if kind == "volume" and row["id"] == existing["data_volume_id"] else 10)
            if decimal(row["size-in-gbs"]) != expected_size or decimal(row["vpus-per-gb"]) != expected_vpus:
                fail(f"unexpected {kind} size or performance: {row['id']}")
    boot_volumes = active(inventory["resources"], "boot-volume")
    data_volumes = active(inventory["resources"], "volume")
    if (len(boot_volumes) > 7 or len(data_volumes) > 4 or
            (len(boot_volumes) > 6 and not replacement_within_window(boot_volumes, plan, now)) or
            (len(data_volumes) > 3 and not replacement_within_window(data_volumes, plan, now))):
        fail("live volumes exceed the five-host plan")
    public_ips = [row for row in inventory["resources"] if row["kind"] == "public-ip"]
    if {row.get("id") for row in public_ips} != {existing["public_ip_id"]}:
        fail("public IP inventory differs from the unrelated Forgejo baseline")
    backups = [row for row in inventory["resources"] if row["kind"] in ("volume-backup", "boot-volume-backup")
               and row.get("lifecycle-state") in ACTIVE_RESOURCE_STATES]
    if any(row.get("unique-size-in-gbs") is None and row.get("size-in-gbs") is None for row in backups):
        fail("retained volume backup size is unavailable")
    backup_gb = sum(decimal(row.get("unique-size-in-gbs") or row.get("size-in-gbs") or 0) for row in backups)
    if backup_gb > decimal(plan["budget"]["snapshot_gb_max"]):
        fail("retained volume backups exceed the 350 GB reserve")
    if any(active(inventory["resources"], kind) for kind in ("nat-gateway", "load-balancer", "network-load-balancer")):
        fail("unpriced gateway or load balancer is present")


def estimate(plan: dict, inventory: dict, plan_path: pathlib.Path | None = None,
             now: dt.datetime | None = None, max_age_minutes: int = 15) -> dict:
    verify_inventory(plan, inventory, max_age_minutes=max_age_minutes, plan_path=plan_path, now=now)
    budget = plan["budget"]
    rates = {key: decimal(value) for key, value in budget["rates"].items()}
    hours = decimal(budget["month_hours"])
    ocpus = sum(decimal(host["ocpus"]) for host in plan["hosts"]) + 2
    memory = sum(decimal(host["memory_gb"]) for host in plan["hosts"]) + 4
    compute = max(Decimal(0), ocpus * hours - FREE_A1_OCPU_HOURS) * rates["a1_ocpu_hour"]
    compute += max(Decimal(0), memory * hours - FREE_A1_MEMORY_GB_HOURS) * rates["a1_memory_gb_hour"]
    forgejo_storage_gb = 50 + decimal(plan["existing_forgejo"]["expected_volume_gb"])
    storage_gb = sum(decimal(host["boot_gb"] + host["data_gb"]) for host in plan["hosts"]) + forgejo_storage_gb
    billed_storage = max(Decimal(0), storage_gb - FREE_BLOCK_GB)
    storage = billed_storage * (rates["block_gb_month"] + decimal(plan["volume_vpus_per_gb"]) * rates["block_vpu_gb_month"])
    custom_image_gib = sum((positive_gib(image["billable_size_in_gbs"], "scoped image size")
                            for image in inventory["images"]), Decimal(0))
    custom_image_storage = custom_image_gib * rates["object_gb_month"]
    overlap_hours = decimal(budget["replacement_overlap_hours_max"])
    overlap_compute = overlap_hours * (rates["a1_ocpu_hour"] + 6 * rates["a1_memory_gb_hour"])
    overlap_storage = decimal(100) * overlap_hours / hours * (rates["block_gb_month"] + 10 * rates["block_vpu_gb_month"])
    live_object_gb = sum(decimal(bucket["bytes"]) for bucket in inventory["buckets"]) / decimal(1024 ** 3)
    object_gb = (max(live_object_gb, decimal(budget["baseline_object_storage_gb"])) +
                 decimal(budget["object_storage_gb_max"]) + decimal(budget["staging_object_storage_gb_max"]))
    object_storage = max(Decimal(0), object_gb - FREE_OBJECT_GB) * rates["object_gb_month"]
    object_requests = decimal(budget["object_requests_max"]) / 10000 * rates["object_10000_requests"]
    object_requests += decimal(budget["baseline_object_requests_usd"])
    egress = decimal(budget["egress_gb_max"]) * rates["egress_gb"]
    # This is a conservative reserve. OCI's current catalog does not provide a
    # separate volume-backup SKU, so the exact backup bill must be reconciled.
    snapshot_reserve = decimal(budget["snapshot_gb_max"]) * rates["block_gb_month"]
    items = {"compute": compute, "block_storage": storage, "replacement_compute": overlap_compute,
             "replacement_storage": overlap_storage, "object_storage": object_storage,
             "custom_image_storage": custom_image_storage, "object_requests": object_requests, "egress": egress,
             "snapshot_reserve": snapshot_reserve, "misc_reserve": decimal(budget["misc_reserve_usd"])}
    total = sum(items.values(), Decimal(0))
    if total > decimal(budget["monthly_limit"]):
        fail(f"projected USD {total:.2f} exceeds the monthly ceiling")
    return {"currency": "USD", "items": {key: str(value.quantize(Decimal("0.0001"))) for key, value in items.items()},
            "total": str(total.quantize(Decimal("0.01"))), "limit": str(budget["monthly_limit"]),
            "headroom": str((decimal(budget["monthly_limit"]) - total).quantize(Decimal("0.01"))),
            "assumptions": {"a1_free_ocpu_hours": 1500, "a1_free_memory_gb_hours": 9000,
                            "free_block_gb": 200, "free_object_gb": 10,
                            "object_growth_reserve_gb": str(budget["object_storage_gb_max"]),
                            "object_staging_reserve_gb": str(budget["staging_object_storage_gb_max"]),
                            "backup_reserve_pricing": "350 GB at block capacity rate; provisional",
                            "custom_image_storage_rate": str(rates["object_gb_month"]),
                            "custom_image_size_source": "OCI billableSizeInGBs for scoped custom images"}}



def current_object_head(namespace: str, bucket: str, name: str, region: str) -> dict:
    """Read the unqualified object key that OCI import-from-object will consume."""
    command = ["oci", "os", "object", "head", "--namespace-name", namespace,
               "--bucket-name", bucket, "--name", name, "--region", region, "--output", "json"]
    process = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    if process.returncode:
        fail("OCI current object HEAD failed or key is deleted")
    try:
        headers = json.loads(process.stdout)
    except ValueError as error:
        raise ValueError("OCI current object HEAD response is invalid") from error
    if not isinstance(headers, dict):
        fail("OCI current object HEAD response is invalid")
    version_id = headers.get("version-id")
    modified = headers.get("last-modified")
    try:
        size = int(headers["content-length"])
        modified_at = email.utils.parsedate_to_datetime(modified)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("OCI current object HEAD lacks size or timestamp") from error
    if (not isinstance(version_id, str) or not version_id or
            type(headers["content-length"]) not in (str, int) or size < 0 or
            modified_at.tzinfo is None):
        fail("OCI current object HEAD lacks version identity, size, or timestamp")
    return {"region": region, "bucket": bucket, "name": name, "version_id": version_id,
            "size": size, "last_modified": modified, "head_at": dt.datetime.now(UTC).isoformat()}


def import_inventory(plan: dict, projection_path: pathlib.Path | None = None,
                     staged_path: pathlib.Path | None = None,
                     previous_projection_path: pathlib.Path | None = None) -> dict:
    """Collect an opt-in detailed snapshot without changing the v2 recovery inventory."""
    snapshot = collect_inventory(plan)
    namespace = oci("os", "ns", "get", region=plan["region"])
    if not isinstance(namespace, str) or not namespace:
        fail("object namespace is missing")
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for bucket in snapshot["buckets"]:
            command = ("os", "object", "list-object-versions" if bucket["versioning"] == "Enabled" else "list",
                       "--namespace-name", namespace, "--bucket-name", bucket["name"],
                       "--fields", "name,size,storageTier,archivalState", "--all")
            tasks.append((bucket, pool.submit(oci, *command, region=bucket["region"])))
        for bucket, future in tasks:
            result = rows(future.result())
            bucket["versions"] = [object_version(row, bucket["versioning"] == "Enabled") for row in result]
            bucket["object_count"] = len(bucket["versions"])
            bucket["bytes"] = sum(row["size"] for row in bucket["versions"] if not row["is_delete_marker"])
    snapshot.update({"schema_version": 3, "object_namespace": namespace, "current_objects": []})
    if staged_path is not None:
        if projection_path is None:
            fail("current object HEAD requires the reviewed import projection")
        imports = reviewed_imports(plan, snapshot, projection_path)
        receipt = read_json(staged_path, MAX_IMPORT_RECEIPT_BYTES, "staged object version receipt")
        roles = set(receipt.get("versions", {})) if isinstance(receipt, dict) and isinstance(
            receipt.get("versions"), dict) else set()
        if roles not in ({"base"}, {"base", "final"}):
            fail("current object HEAD requires base or both staged version IDs")
        receipt_projection_hash = sha256(projection_path)
        if previous_projection_path is not None and roles == {"base"}:
            old_imports = reviewed_imports(plan, snapshot, previous_projection_path)
            full_imports = imports
            if set(old_imports) != {"base"} or set(full_imports) != {"base", "final"} or not strict_equal(
                    old_imports["base"], full_imports["base"]):
                fail("full import projection base row differs from the staged base-only projection")
            receipt_projection_hash = sha256(previous_projection_path)
        staged = import_receipt(staged_path, "versions", receipt_projection_hash, roles)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [(role, pool.submit(current_object_head, namespace, imports[role]["object"]["bucket"],
                                          imports[role]["object"]["key"], plan["region"])) for role in staged]
            snapshot["current_objects"] = [future.result() for _, future in futures]
    return snapshot


def object_version(row: dict, versioned: bool) -> dict:
    name = row.get("name")
    version_id = row.get("version-id")
    marker = row.get("is-delete-marker", False)
    size = row.get("size")
    tier = row.get("storage-tier")
    if (not isinstance(name, str) or not name or type(marker) is not bool or
            (versioned and ("is-delete-marker" not in row or not isinstance(version_id, str) or
                            not version_id or type(marker) is not bool)) or
            (not versioned and version_id not in (None, "")) or
            (not marker and (type(size) is not int or size < 0)) or tier != "Standard"):
        fail("object version has missing identity, size, or priced tier")
    return {"name": name, "version_id": version_id if versioned else None,
            "is_delete_marker": marker, "size": size, "storage_tier": tier,
            "archival_state": row.get("archival-state")}


def positive_gib(value: object, label: str) -> Decimal:
    if type(value) is not int or value <= 0:
        fail(f"{label} must be a positive integer billed GiB amount")
    return Decimal(value)


def verify_import_inventory(plan: dict, inventory: dict, plan_path: pathlib.Path | None = None,
                            now: dt.datetime | None = None, max_age_minutes: int = 15) -> None:
    if inventory.get("schema_version") != 3:
        fail("import inventory requires schema v3")
    verify_inventory(plan, {**inventory, "schema_version": 2}, max_age_minutes=max_age_minutes,
                     plan_path=plan_path, now=now)
    if not isinstance(inventory.get("object_namespace"), str) or not inventory["object_namespace"]:
        fail("import inventory lacks object namespace")
    if not isinstance(inventory.get("regions"), list):
        fail("import inventory lacks region scope")
    seen_buckets = set()
    seen_versions = set()
    for bucket in inventory["buckets"]:
        identity = (bucket.get("region"), bucket.get("name"))
        if not all(isinstance(value, str) and value for value in identity) or identity in seen_buckets:
            fail("duplicate or missing bucket identity")
        seen_buckets.add(identity)
        versions = bucket.get("versions")
        if not isinstance(versions, list):
            fail("import inventory lacks object versions")
        total = 0
        for version in versions:
            if not isinstance(version, dict):
                fail("invalid object version")
            normalized = object_version({"name": version.get("name"), "version-id": version.get("version_id"),
                                         "is-delete-marker": version.get("is_delete_marker"),
                                         "size": version.get("size"), "storage-tier": version.get("storage_tier"),
                                         "archival-state": version.get("archival_state")},
                                        bucket["versioning"] == "Enabled")
            if version != normalized:
                fail("object version detail was altered")
            version_identity = (*identity, normalized["name"], normalized["version_id"])
            if version_identity in seen_versions:
                fail("duplicate object version identity")
            seen_versions.add(version_identity)
            if not normalized["is_delete_marker"]:
                total += normalized["size"]
        if bucket.get("object_count") != len(versions) or bucket.get("bytes") != total:
            fail("object version totals disagree with bucket")
    current_objects = inventory.get("current_objects")
    if not isinstance(current_objects, list):
        fail("import inventory lacks current object HEAD evidence")
    seen_current = set()
    captured = dt.datetime.fromisoformat(inventory["captured_at"])
    for current in current_objects:
        if not isinstance(current, dict):
            fail("current object HEAD evidence is malformed")
        identity = (current.get("region"), current.get("bucket"), current.get("name"))
        if (not all(isinstance(value, str) and value for value in identity) or
                identity in seen_current or current.get("region") not in inventory["regions"] or
                not isinstance(current.get("version_id"), str) or not current["version_id"] or
                type(current.get("size")) is not int or current["size"] < 0):
            fail("current object HEAD identity or size is invalid")
        seen_current.add(identity)
        try:
            modified = email.utils.parsedate_to_datetime(current["last_modified"])
            head_at = dt.datetime.fromisoformat(current["head_at"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("current object HEAD timestamp is invalid") from error
        if (modified.tzinfo is None or head_at.tzinfo is None or
                head_at < captured - dt.timedelta(seconds=30) or
                head_at > (now or dt.datetime.now(UTC)) + dt.timedelta(seconds=30)):
            fail("current object HEAD timestamp is stale or invalid")
        matches = [row for bucket in inventory["buckets"] if
                   (bucket["region"], bucket["name"]) == identity[:2] and
                   bucket["versioning"] == "Enabled" for row in bucket["versions"] if
                   row["name"] == identity[2] and row["version_id"] == current["version_id"] and
                   not row["is_delete_marker"] and row["size"] == current["size"]]
        if len(matches) != 1:
            fail("current object HEAD differs from retained version inventory")
def reviewed_imports(plan: dict, inventory: dict, projection_path: pathlib.Path) -> dict[str, dict]:
    projection = read_json(projection_path, MAX_IMPORT_PROJECTION_BYTES, "import projection")
    if not isinstance(projection, dict):
        fail("import projection must be an object")
    imports = projection.get("imports")
    if (projection.get("schema_version") != 1 or not isinstance(imports, list) or
            len(imports) not in (1, 2)):
        fail("import projection requires a base-only or base-and-final schema v1 import list")
    by_role = {}
    object_keys = set()
    image_names = set()
    control = inventory["preview_compartment_ids"]["control"]
    if not control:
        fail("import projection requires the live control compartment")
    for entry in imports:
        if not isinstance(entry, dict) or set(entry) != {"role", "local_file", "sha256", "bytes", "object", "image"}:
            fail("import projection entry has missing or unexpected fields")
        role = entry["role"]
        if role not in {"base", "final"} or role in by_role:
            fail("import projection requires distinct base and final roles")
        object_ref, image_ref = entry["object"], entry["image"]
        if (not isinstance(object_ref, dict) or set(object_ref) != {"bucket", "key"} or
                not isinstance(image_ref, dict) or set(image_ref) !=
                {"display_name", "compartment_id", "max_billable_size_in_gbs", "evidence"}):
            fail("import projection object or image identity is incomplete")
        bucket, key = object_ref["bucket"], object_ref["key"]
        name, compartment = image_ref["display_name"], image_ref["compartment_id"]
        if (not isinstance(bucket, str) or not bucket or not isinstance(key, str) or not key or
                not isinstance(name, str) or not name or compartment != control or
                not isinstance(image_ref["evidence"], str) or not image_ref["evidence"].strip()):
            fail("import projection lacks reviewed object or image identity and evidence")
        if (bucket, key) in object_keys or (compartment, name) in image_names:
            fail("import projection has duplicate object keys or image names")
        object_keys.add((bucket, key))
        image_names.add((compartment, name))
        matches = [row for row in inventory["buckets"] if row["region"] == plan["region"] and
                   row["compartment_id"] == control and row["name"] == bucket]
        if len(matches) != 1 or matches[0]["versioning"] != "Enabled":
            fail("import object bucket must be a priced versioned control bucket")
        positive_gib(image_ref["max_billable_size_in_gbs"], f"{role} reviewed maximum")
        digest = entry["sha256"]
        size = entry["bytes"]
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or
                type(size) is not int or size <= 0 or
                not isinstance(entry["local_file"], str) or not entry["local_file"]):
            fail("import projection lacks exact local file bytes and SHA-256")
        local_file = pathlib.Path(entry["local_file"])
        if (not local_file.is_absolute() or not local_file.is_file() or
                local_file.stat().st_size != size or sha256(local_file) != digest):
            fail(f"{role} local file bytes or SHA-256 changed")
        by_role[role] = entry
    if set(by_role) not in ({"base"}, {"base", "final"}):
        fail("import projection requires the base role and optional final role")
    return by_role


def import_receipt(path: pathlib.Path, field: str, projection_hash: str,
                   expected_roles: set[str]) -> dict[str, str]:
    receipt = read_json(path, MAX_IMPORT_RECEIPT_BYTES, f"import {field} receipt")
    if not isinstance(receipt, dict):
        fail("import receipt must be an object")
    values = receipt.get(field)
    if (receipt.get("schema_version") != 1 or receipt.get("projection_sha256") != projection_hash or
            not isinstance(values, dict) or set(values) != expected_roles or
            any(not isinstance(value, str) or not value for value in values.values()) or
            len(set(values.values())) != len(expected_roles)):
        fail(f"import {field} receipt is incomplete or bound to another projection")
    if field == "images" and any(not value.startswith("ocid1.image.") for value in values.values()):
        fail("import image receipt lacks OCI image OCIDs")
    return values


def verify_previous_import_admission(path: pathlib.Path, phase: str, projection_hash: str,
                                     plan_path: pathlib.Path, staged_hash: str | None = None,
                                     imported_hash: str | None = None) -> dict:
    previous = read_json(path, MAX_ADMISSION_BYTES, "previous import admission")
    if not isinstance(previous, dict):
        fail("previous import admission must be an object")
    if (previous.get("schema_version") != 3 or previous.get("phase") != phase or
            previous.get("plan_sha256") != sha256(plan_path) or
            previous.get("projection_sha256") != projection_hash or
            (staged_hash is not None and previous.get("staged_versions_sha256") != staged_hash) or
            (imported_hash is not None and previous.get("imported_images_sha256") != imported_hash) or
            not isinstance(previous.get("estimate"), dict)):
        fail("previous import admission does not bind this projection and stage")
    try:
        admitted = dt.datetime.fromisoformat(previous["admitted_at"])
        expires = dt.datetime.fromisoformat(previous["expires_at"])
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("previous import admission has invalid timestamps") from error
    if (admitted.tzinfo is None or expires.tzinfo is None or expires <= admitted or
            expires > admitted + dt.timedelta(minutes=15, seconds=30) or
            admitted > dt.datetime.now(UTC) + dt.timedelta(seconds=30)):
        fail("previous import admission has invalid timestamps")
    return previous


def carried_base_lineage(value: object, plan_hash: str) -> dict:
    fields = {"schema_version", "plan_sha256", "projection_sha256", "admission_sha256",
              "inventory_sha256", "staged_versions_sha256", "imported_images_sha256",
              "base_version_id", "base_image_id", "estimate"}
    hashes = ("plan_sha256", "projection_sha256", "admission_sha256", "inventory_sha256",
              "staged_versions_sha256", "imported_images_sha256")
    if (not isinstance(value, dict) or set(value) != fields or
            type(value.get("schema_version")) is not int or value.get("schema_version") != 1 or
            value.get("plan_sha256") != plan_hash or
            any(not isinstance(value.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", value[field])
                for field in hashes) or
            not isinstance(value.get("base_version_id"), str) or not value["base_version_id"] or
            not isinstance(value.get("base_image_id"), str) or
            not value["base_image_id"].startswith("ocid1.image.") or
            not isinstance(value.get("estimate"), dict)):
        fail("full import projection lacks valid base-only admission lineage")
    return value


def require_matching_base_projection(plan: dict, inventory: dict, full_projection_path: pathlib.Path,
                                    base_projection_path: pathlib.Path) -> None:
    full_imports = reviewed_imports(plan, inventory, full_projection_path)
    base_imports = reviewed_imports(plan, inventory, base_projection_path)
    if (set(base_imports) != {"base"} or set(full_imports) != {"base", "final"} or
            not strict_equal(base_imports["base"], full_imports["base"])):
        fail("full import projection base row differs from the admitted base-only input")


def establish_base_lineage(plan: dict, full_projection_path: pathlib.Path,
                           base_projection_path: pathlib.Path, base_inventory_path: pathlib.Path,
                           base_admission_path: pathlib.Path, base_staged_path: pathlib.Path,
                           base_images_path: pathlib.Path, plan_path: pathlib.Path) -> dict:
    base_inventory = read_json(base_inventory_path, MAX_INVENTORY_BYTES, "base-only import inventory")
    require_matching_base_projection(plan, base_inventory, full_projection_path, base_projection_path)

    base_projection_hash = sha256(base_projection_path)
    staged_hash = sha256(base_staged_path)
    images_hash = sha256(base_images_path)
    previous = verify_previous_import_admission(base_admission_path, "pre-import", base_projection_hash,
                                                plan_path, staged_hash, images_hash)
    if previous.get("inventory_sha256") != sha256(base_inventory_path):
        fail("base-only admission does not bind the supplied inventory")
    admitted = dt.datetime.fromisoformat(previous["admitted_at"])
    if admitted.utcoffset() != dt.timedelta(0):
        fail("base-only admission timestamp is not UTC")
    expected = import_estimate(plan, base_inventory, base_projection_path, "pre-import",
                               base_staged_path, base_images_path, plan_path,
                               now=admitted, max_age_minutes=10 * 365 * 24 * 60)
    if not strict_equal(previous["estimate"], expected):
        fail("base-only admission cost differs from its exact inventory and receipts")
    versions = import_receipt(base_staged_path, "versions", base_projection_hash, {"base"})
    images = import_receipt(base_images_path, "images", base_projection_hash, {"base"})
    return carried_base_lineage({
        "schema_version": 1,
        "plan_sha256": sha256(plan_path),
        "projection_sha256": base_projection_hash,
        "admission_sha256": sha256(base_admission_path),
        "inventory_sha256": sha256(base_inventory_path),
        "staged_versions_sha256": staged_hash,
        "imported_images_sha256": images_hash,
        "base_version_id": versions["base"],
        "base_image_id": images["base"],
        "estimate": expected,
    }, sha256(plan_path))


def import_estimate(plan: dict, inventory: dict, projection_path: pathlib.Path, phase: str,
                    staged_path: pathlib.Path | None = None,
                    imported_path: pathlib.Path | None = None,
                    plan_path: pathlib.Path | None = None,
                    now: dt.datetime | None = None,
                    max_age_minutes: int = 15,
                    base_lineage: dict | None = None) -> dict:
    if phase not in {"pre-stage", "pre-import", "post-import"}:
        fail("unknown import admission phase")
    verify_import_inventory(plan, inventory, plan_path, now, max_age_minutes)
    imports = reviewed_imports(plan, inventory, projection_path)
    projection_hash = sha256(projection_path)
    staged = None
    if phase != "pre-stage" and staged_path is None:
        fail("staged object version receipt is required")
    if staged_path is not None:
        expected_roles = {"base"} if phase == "pre-stage" else set(imports)
        staged = import_receipt(staged_path, "versions", projection_hash, expected_roles)
    imported = None
    if phase == "post-import" and imported_path is None:
        fail("imported image OCID receipt is required")
    if imported_path is not None:
        expected_roles = set(imports) if phase == "post-import" else {"base"}
        if phase == "pre-stage":
            fail("pre-stage cannot bind imported images")
        imported = import_receipt(imported_path, "images", projection_hash, expected_roles)

    if set(imports) == {"base", "final"} and base_lineage is not None:
        base_lineage = carried_base_lineage(base_lineage, sha256(plan_path or source_path(plan)))
        if ((staged is not None and "base" in staged and
             staged["base"] != base_lineage["base_version_id"]) or
                (imported is not None and "base" in imported and
                 imported["base"] != base_lineage["base_image_id"])):
            fail("full import receipt changed the admitted base object version or image OCID")
        if staged is None:
            staged = {"base": base_lineage["base_version_id"]}
        if imported is None:
            imported = {"base": base_lineage["base_image_id"]}

    projected_bytes = 0
    for role, entry in imports.items():
        bucket_name, object_name = entry["object"]["bucket"], entry["object"]["key"]
        bucket = next(row for row in inventory["buckets"] if row["region"] == plan["region"] and
                      row["name"] == bucket_name)
        if staged is None or role not in staged:
            projected_bytes += entry["bytes"]
        else:
            matches = [row for row in bucket["versions"] if row["name"] == object_name and
                       row["version_id"] == staged[role] and not row["is_delete_marker"]]
            if len(matches) != 1 or matches[0]["size"] != entry["bytes"]:
                fail(f"{role} staged object version is absent or has different bytes")
            current = [row for row in inventory["current_objects"] if
                       (row["region"], row["bucket"], row["name"]) ==
                       (plan["region"], bucket_name, object_name)]
            if len(current) != 1 or current[0]["version_id"] != staged[role] or current[0]["size"] != entry["bytes"]:
                fail(f"{role} staged object is not the current import source version")
        matching_images = [row for row in inventory["images"] if row["region"] == plan["region"] and
                           row["compartment_id"] == entry["image"]["compartment_id"] and
                           row["display_name"] == entry["image"]["display_name"]]
        if (imported is None or role not in imported) and matching_images:
            fail(f"{role} image name already exists before import")
        if imported is not None and role in imported:
            exact = [row for row in matching_images if row["id"] == imported[role]]
            if len(matching_images) != 1 or len(exact) != 1 or exact[0]["lifecycle_state"] != "AVAILABLE":
                fail(f"{role} imported image identity is absent, duplicated, or unavailable")
            if positive_gib(exact[0]["billable_size_in_gbs"], f"{role} billed size") > positive_gib(
                    entry["image"]["max_billable_size_in_gbs"], f"{role} reviewed maximum"):
                fail(f"{role} imported image exceeds reviewed billed GiB maximum")

    baseline = estimate(plan, {**inventory, "schema_version": 2}, plan_path, now, max_age_minutes)
    rates = plan["budget"]["rates"]
    rate = decimal(rates["object_gb_month"])
    budget = plan["budget"]
    live_bytes = sum(bucket["bytes"] for bucket in inventory["buckets"])
    object_gb = (max((decimal(live_bytes + projected_bytes) / Decimal(1_000_000_000)),
                     decimal(budget["baseline_object_storage_gb"])) +
                 decimal(budget["object_storage_gb_max"]) +
                 decimal(budget["staging_object_storage_gb_max"]))
    object_cost = max(Decimal(0), object_gb - FREE_OBJECT_GB) * rate
    imported_ids = set(imported.values()) if imported else set()
    existing_gib = sum((positive_gib(row["billable_size_in_gbs"], "scoped image size")
                        for row in inventory["images"] if row["id"] not in imported_ids), Decimal(0))
    expected_gib = sum((positive_gib(next(row for row in inventory["images"] if row["id"] == imported[role])[
                       "billable_size_in_gbs"], f"{role} billed size") if imported and role in imported else
                        positive_gib(entry["image"]["max_billable_size_in_gbs"], f"{role} reviewed maximum")
                        for role, entry in imports.items()), Decimal(0))
    image_cost = (existing_gib + expected_gib) * rate
    items = {key: decimal(value) for key, value in baseline["items"].items()}
    items["object_storage"] = object_cost
    items["custom_image_storage"] = image_cost
    total = sum(items.values(), Decimal(0))
    if total > decimal(budget["monthly_limit"]):
        fail(f"projected USD {total:.2f} exceeds the monthly ceiling")
    return {"currency": "USD", "items": {key: str(value.quantize(Decimal("0.0001"))) for key, value in items.items()},
            "total": str(total.quantize(Decimal("0.01"))), "limit": str(budget["monthly_limit"]),
            "headroom": str((decimal(budget["monthly_limit"]) - total).quantize(Decimal("0.01"))),
            "object_projected_bytes": projected_bytes, "existing_image_billed_gib": str(existing_gib),
            "import_image_billed_gib": str(expected_gib),
            "assumptions": {"object_free_gb": 10, "custom_image_free_gib": 0,
                            "object_growth_reserve_gb": str(budget["object_storage_gb_max"]),
                            "object_staging_reserve_gb": str(budget["staging_object_storage_gb_max"]),
                            "custom_image_rate": str(rate), "object_gb_bytes": 1_000_000_000,
                            "custom_image_size_source": "reviewed maxima plus OCI billableSizeInGBs for completed roles"}}


def write_json(path: pathlib.Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)


def rfc3339_utc(value: dt.datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != dt.timedelta(0):
        fail("budget admission timestamps must be UTC RFC3339 values")
    value = value.astimezone(UTC)
    base = value.strftime("%Y-%m-%dT%H:%M:%S")
    fraction = f"{value.microsecond:06d}".rstrip("0")
    return base + (f".{fraction}" if fraction else "") + "Z"


def canonical_manual_seed_plan(value: dict) -> bytes:
    fields = (
        "schema_version", "slot", "shape", "ocpus", "memory_gb", "boot_gb", "boot_vpus_per_gb",
        "assign_public_ip", "compartment_id", "availability_domain", "fault_domain", "subnet_id",
        "network_security_group_ids", "image_id", "anchor_sha256", "manifest_sha256",
        "image_receipt_sha256", "admission_sha256", "inventory_sha256", "admission_admitted_at",
        "admission_expires_at", "monthly_estimate_usd", "create_identity",
    )
    if set(value) != set(fields):
        fail("manual seed plan has an unexpected producer schema")
    return json.dumps({field: value[field] for field in fields}, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def write_canonical_seed_plan(path: pathlib.Path, value: dict) -> str:
    wire = canonical_manual_seed_plan(value)
    if len(wire) > 16 * 1024:
        fail("manual seed plan exceeds the bounded Go consumer input")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(wire)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return hashlib.sha256(wire).hexdigest()


def create_identity(plan: dict, plan_path: pathlib.Path, manifest_summary: dict) -> str:
    configured = plan.get("seed_a_create_identity")
    if configured is not None:
        return configured
    binding = "\0".join((sha256(plan_path), manifest_summary["anchorSha256"],
                         manifest_summary["manifestSha256"], manifest_summary["releaseReceiptSha256"]))
    return "seed-a-" + hashlib.sha256(binding.encode("ascii")).hexdigest()[:32]


def validate_seed_manifest(path: pathlib.Path, expected_cell: str) -> bytes:
    wire = read_regular_bytes(path, MAX_SEED_MANIFEST_BYTES, "signed seed manifest")
    envelope = read_json(path, MAX_SEED_MANIFEST_BYTES, "signed seed manifest")
    scope = envelope.get("scope")
    payload = envelope.get("payload")
    if (envelope.get("schemaVersion") != 1 or not isinstance(envelope.get("keyId"), str) or
            not envelope["keyId"] or not isinstance(envelope.get("signature"), str) or
            not envelope["signature"] or not isinstance(scope, dict) or not isinstance(payload, dict) or
            scope.get("domain") != "terrascale.bootstrap.manifest" or
            scope.get("role") != "controller" or scope.get("slot") != "controller-a" or
            scope.get("cell") != expected_cell or payload.get("cell") != expected_cell or
            payload.get("schemaVersion") != 2 or
            payload.get("slot") != "controller-a" or payload.get("seedSlot") != "controller-a"):
        fail("signed manifest is not a controller-a seed envelope")
    try:
        raw = wire.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("signed seed manifest is not UTF-8 JSON") from error
    if "\x00" in raw:
        fail("signed seed manifest contains an invalid NUL byte")
    return wire


def validate_ssh_ed25519_public_key(path: pathlib.Path) -> str:
    try:
        wire = path.read_bytes()
    except OSError as error:
        raise ValueError("owner SSH public key is unreadable") from error
    if not wire or len(wire) > MAX_SSH_PUBLIC_KEY_BYTES:
        fail("owner SSH public key has invalid size")
    try:
        text_value = wire.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("owner SSH public key must be ASCII") from error
    lines = text_value.splitlines()
    if len(lines) != 1 or text_value.endswith(("\n\n", "\r\n\r\n")):
        fail("owner SSH public key must contain exactly one OpenSSH key line")
    parts = lines[0].strip().split()
    if len(parts) not in (2, 3) or parts[0] != "ssh-ed25519":
        fail("owner SSH key must be one OpenSSH Ed25519 public key")
    try:
        encoded = base64.b64decode(parts[1], validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("owner SSH Ed25519 key encoding is invalid") from error
    if len(encoded) != 4 + 11 + 4 + 32 or encoded[:4] != (11).to_bytes(4, "big") or encoded[4:15] != b"ssh-ed25519":
        fail("owner SSH key is not a canonical Ed25519 public key")
    if int.from_bytes(encoded[15:19], "big") != 32 or len(encoded[19:]) != 32:
        fail("owner SSH key has an invalid Ed25519 public key length")
    if len(parts) == 3 and (not re.fullmatch(r"[A-Za-z0-9._@+-]{1,128}", parts[2])):
        fail("owner SSH public key comment contains unsafe characters")
    return " ".join(parts)


def seed_user_data(manifest_path: pathlib.Path, owner_key_path: pathlib.Path | None,
                   expected_cell: str) -> bytes:
    manifest_wire = validate_seed_manifest(manifest_path, expected_cell)
    try:
        manifest_text = manifest_wire.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("signed seed manifest is not UTF-8 JSON") from error
    bootcmd = (
        "set -eu; umask 077; install -d -o root -g root -m 0755 /etc/terrascale-orchestrator; "
        f"printf '%s' {shlex.quote(manifest_text)} > /run/terrascale-controller-seed-manifest; "
        "install -o root -g root -m 0644 /run/terrascale-controller-seed-manifest "
        "/etc/terrascale-orchestrator/controller-seed-manifest.json; "
        "rm -f /run/terrascale-controller-seed-manifest"
    )
    console_key = (
        "set -eu; IFS=' ' read -r key_type key_data key_comment < /etc/ssh/ssh_host_ed25519_key.pub; "
        "test \"$key_type\" = ssh-ed25519; test -n \"$key_data\"; "
        "printf '\\nTERASCALE_SEED_A_HOST_KEY_BEGIN\\n%s %s\\nTERASCALE_SEED_A_HOST_KEY_END\\n' "
        "\"$key_type\" \"$key_data\" > /dev/console"
    )
    config: dict[str, object] = {
        "bootcmd": [bootcmd],
        "allow_public_ssh_keys": False,
        "runcmd": [console_key],
    }
    if owner_key_path is not None:
        config["ssh_authorized_keys"] = [validate_ssh_ed25519_public_key(owner_key_path)]
    wire = ("#cloud-config\n" + json.dumps(config, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    if len(wire) > MAX_USER_DATA_BYTES:
        fail("generated seed user-data exceeds the OCI metadata transport limit")
    return wire


def write_output_bytes(path: pathlib.Path, wire: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(wire)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def verify_seed_preflight(plan: dict, inventory_path: pathlib.Path, admission_path: pathlib.Path,
                          manifest_summary: dict, image_receipt_path: pathlib.Path,
                          image_verification: str, plan_path: pathlib.Path | None = None) -> dict:
    """Check exact seed launch facts; this command never creates OCI resources."""
    inventory = read_json(inventory_path, MAX_INVENTORY_BYTES, "manual region inventory")
    admission = read_json(admission_path, MAX_ADMISSION_BYTES, "manual budget admission")
    cost = estimate(plan, inventory, plan_path)
    now = dt.datetime.now(UTC)
    try:
        admitted_at = dt.datetime.fromisoformat(admission["admitted_at"])
        expires_at = dt.datetime.fromisoformat(admission["expires_at"])
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("budget admission has invalid timestamps") from error
    if (admission.get("schema_version") != 2 or admitted_at.tzinfo is None or expires_at.tzinfo is None or
            admitted_at.utcoffset() != dt.timedelta(0) or expires_at.utcoffset() != dt.timedelta(0) or
            admitted_at > now + dt.timedelta(seconds=30) or not admitted_at <= now < expires_at or
            expires_at > admitted_at + dt.timedelta(minutes=15, seconds=30) or
            admission.get("plan_sha256") != sha256(plan_path or source_path(plan)) or
            admission.get("inventory_sha256") != sha256(inventory_path) or
            admission.get("preview_compartment_ids") != inventory["preview_compartment_ids"] or
            admission.get("estimate") != cost):
        fail("budget admission is stale or does not match the current plan and inventory")
    ids = plan["resource_ids"]
    compartments = inventory["preview_compartment_ids"]
    control = ids.get("control_compartment")
    network = ids.get("network_compartment")
    workload = ids.get("workload_compartment")
    if not control or not network or not workload or compartments != {"control": control, "network": network,
                                                                      "workload": workload}:
        fail("seed preflight requires exact plan-bound control, network, and workload compartments")
    foundation = {}
    for kind, key in (("vcn", "vcn"), ("subnet", "subnet"),
                      ("network-security-group", "network_security_group")):
        resource_id = ids.get(key)
        matches = [row for row in active(inventory["resources"], kind)
                   if row.get("id") == resource_id and row.get("compartment-id") == network]
        if not resource_id or len(matches) != 1:
            fail(f"seed preflight requires the exact recorded live {kind}")
        foundation[kind] = matches[0]
    if (foundation["vcn"].get("cidr-block") != plan["network_cidr"] or
            foundation["subnet"].get("cidr-block") != plan["subnet_cidr"] or
            foundation["subnet"].get("prohibit-public-ip-on-vnic") is not True or
            foundation["subnet"].get("prohibit-internet-ingress") is not True):
        fail("seed preflight requires the exact private preview network")
    for role, name in plan["foundation_buckets"].items():
        matches = [bucket for bucket in inventory["buckets"]
                   if bucket.get("compartment_id") == control and bucket.get("region") == plan["region"]
                   and bucket.get("name") == name and bucket.get("storage_tier") == "Standard"
                   and bucket.get("versioning") == ("Enabled" if role in ("head", "material") else "Disabled")]
        if len(matches) != 1:
            fail(f"seed preflight requires the exact {role} control bucket")
    live_ids = required_resource_ids(plan)
    check_live_compartments(plan, live_ids)
    check_live_vault(plan, live_ids)
    check_live_network(plan, live_ids)
    check_live_buckets(plan, live_ids)
    check_live_iam(plan, live_ids)
    seed = next(host for host in plan["hosts"] if host["slot"] == "controller-a")
    profile = manifest_summary.get("profile")
    if (manifest_summary.get("schemaVersion") != 2 or manifest_summary.get("cell") != plan["cell"] or
            manifest_summary.get("ociRegion") != plan["region"] or
            manifest_summary.get("slot") != seed["slot"] or
            manifest_summary.get("imageArchitecture") != "linux-arm64" or
            not isinstance(profile, dict) or profile.get("slot") != seed["slot"] or
            profile.get("compartmentOcid") != control or
            profile.get("availabilityDomain") != plan["availability_domain"] or
            profile.get("faultDomain") != seed["fault_domain"] or
            profile.get("subnetOcid") != ids["subnet"] or
            profile.get("networkSecurityGroupOcids") != sorted([ids["network_security_group"], *(
                [ids["seed_ssh_network_security_group"]] if ids.get("seed_ssh_network_security_group") else [])]) or
            profile.get("shape") != seed["shape"] or
            not re.fullmatch(r"[0-9a-f]{64}", manifest_summary.get("anchorSha256", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", manifest_summary.get("manifestSha256", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", manifest_summary.get("releaseReceiptSha256", ""))):
        fail("verified seed manifest differs from the recorded controller-a profile")
    if sha256(image_receipt_path) != manifest_summary["releaseReceiptSha256"]:
        fail("verified image receipt bytes differ from the signed seed manifest")
    image_ocid = manifest_summary.get("imageOcid", "")
    if (not re.fullmatch(r"ocid1\.image\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9-]+", image_ocid) or
            not image_verification.startswith(f"verified OCI image={image_ocid} region={plan['cell']} ") or
            " arch=arm64 " not in image_verification):
        fail("verified ARM image candidate differs from the signed seed manifest")
    seed_instance_id = ids["instances"]["controller-a"]
    seed_create_identity = plan.get("seed_a_create_identity")
    if any(row.get("id") == seed_instance_id or "BootstrapCreateKey" in (row.get("freeform-tags") or {})
           for row in active(inventory["resources"], "instance")):
        fail("seed controller already exists in the preview inventory")
    return {"schema_version": 2, "slot": seed["slot"], "shape": seed["shape"],
            "ocpus": seed["ocpus"], "memory_gb": seed["memory_gb"],
            "boot_gb": seed["boot_gb"], "boot_vpus_per_gb": plan["volume_vpus_per_gb"],
            "assign_public_ip": False, "compartment_id": control,
            "availability_domain": profile["availabilityDomain"], "fault_domain": profile["faultDomain"],
            "subnet_id": profile["subnetOcid"], "network_security_group_ids": profile["networkSecurityGroupOcids"],
            "image_id": image_ocid, "anchor_sha256": manifest_summary["anchorSha256"],
            "manifest_sha256": manifest_summary["manifestSha256"],
            "image_receipt_sha256": manifest_summary["releaseReceiptSha256"],
            "admission_sha256": sha256(admission_path), "inventory_sha256": sha256(inventory_path),
            "admission_admitted_at": admission["admitted_at"],
            "admission_expires_at": admission["expires_at"], "monthly_estimate_usd": cost["total"]}


def checked_tool(*command: str) -> str:
    process = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    if process.returncode:
        fail(f"verification tool {pathlib.Path(command[0]).name} rejected its inputs (exit {process.returncode})")
    return process.stdout.strip()


def seed_preflight(args: argparse.Namespace, plan: dict, plan_path: pathlib.Path) -> dict:
    if not args.bootstrap_root:
        fail("seed preflight requires at least one bootstrap trust root")
    manifest_summary = json.loads(checked_tool(
        str(args.bootstrap_tool), "verify-manifest", "--anchor", str(args.anchor),
        "--manifest", str(args.manifest), "--identity", str(args.identity),
        "--slot", "controller-a", "--image-ocid", args.image_ocid,
        *(argument for root in args.bootstrap_root for argument in ("--root-key", str(root)))))
    image_verification = checked_tool(
        str(args.release_tool), "verify-image", "--receipt", str(args.image_receipt),
        "--delegation", str(args.release_delegation), "--root-key", str(args.release_root),
        "--image-file", str(args.image_file), "--base-image-file", str(args.base_image_file),
        "--kernel-file", str(args.kernel_file), "--region", plan["cell"],
        "--environment", manifest_summary["environment"])
    reviewed = verify_seed_preflight(plan, args.inventory, args.admission, manifest_summary,
                                     args.image_receipt, image_verification, plan_path)
    reviewed["create_identity"] = create_identity(plan, plan_path, manifest_summary)
    return reviewed


def normalized_security_rule(rule: dict, default_direction: str | None = None) -> dict:
    def get(name: str, default: object = None) -> object:
        return rule.get(name, rule.get(name.replace("_", "-"), default))

    def port_range(protocol: str) -> tuple[object, object]:
        options = get(f"{protocol}_options")
        if options is None:
            return None, None
        if not isinstance(options, dict) or options.get("source-port-range") not in (None, {}):
            fail("live security rule uses unsupported port options")
        value = options.get("destination-port-range")
        if value is None:
            return None, None
        if not isinstance(value, dict) or set(value) != {"min", "max"}:
            fail("live security rule has an unsupported destination port range")
        return value["min"], value["max"]

    if not isinstance(rule, dict) or get("icmp_options") not in (None, {}):
        fail("live security rule uses an unsupported shape")
    protocol = str(get("protocol"))
    tcp_min, tcp_max = port_range("tcp")
    udp_min, udp_max = port_range("udp")
    return {"direction": get("direction", default_direction), "protocol": protocol,
            "source": get("source"), "source_type": get("source_type"),
            "destination": get("destination"), "destination_type": get("destination_type"),
            "tcp_min": tcp_min, "tcp_max": tcp_max, "udp_min": udp_min, "udp_max": udp_max,
            "stateless": get("is_stateless", False)}


def compare_security_rules(actual: object, expected: list[dict], label: str,
                           default_direction: str | None = None) -> None:
    actual_rows = rows(actual)
    normalized = [normalized_security_rule(rule, default_direction) for rule in actual_rows]
    canonical = lambda rule: json.dumps(rule, sort_keys=True, separators=(",", ":"))
    if sorted(map(canonical, normalized)) != sorted(map(canonical, expected)):
        fail(f"live {label} rules differ from the exact plan")


def require_planned_route_ids(plan: dict, ids: dict) -> None:
    network_security = plan["network_security"]
    route_table_id = ids.get("route_table")
    service_gateway_id = ids.get("service_gateway")
    route_required = bool(network_security["service_gateway_service_id"] or network_security["route_rules"])
    if (bool(route_table_id) != bool(service_gateway_id) or
            bool(route_required) != bool(route_table_id)):
        fail("foundation inspection requires the exact route table and service gateway IDs declared by the plan")


def required_resource_ids(plan: dict) -> dict:
    ids = plan["resource_ids"]
    required = ("control_compartment", "network_compartment", "workload_compartment", "vault", "key", "vcn",
                "subnet", "network_security_group", "security_list", "controller_dynamic_group", "controller_policy",
                "objectstorage_key_policy", "host_dynamic_group", "host_policy")
    if any(not ids.get(key) for key in required):
        fail("foundation inspection requires every plan-bound compartment, network, Vault, key, and IAM OCID")
    host_secret = plan["host_credential_secret"]
    if not host_secret.get("compartment_id") or not host_secret.get("secret_id"):
        fail("foundation inspection requires the operator-selected host LiveS3Credential secret OCIDs")
    require_planned_route_ids(plan, ids)
    return ids


def require_live_id(resource: dict, resource_id: str, label: str) -> dict:
    if not isinstance(resource, dict) or resource.get("id") != resource_id:
        fail(f"live {label} identity differs from the exact plan")
    return resource


def check_live_compartments(plan: dict, ids: dict) -> None:
    for role in ("control", "network", "workload"):
        compartment_id = ids[f"{role}_compartment"]
        compartment = require_live_id(oci("iam", "compartment", "get", "--compartment-id", compartment_id),
                                      compartment_id, f"{role} compartment")
        if (compartment.get("lifecycle-state") != "ACTIVE" or
                compartment.get("compartment-id") != plan["parent_compartment_id"] or
                compartment.get("name") != plan["preview_compartment_names"][role]):
            fail(f"live {role} compartment is not active under the plan parent")


def check_live_network(plan: dict, ids: dict) -> None:
    expected = plan["network_security"]
    require_planned_route_ids(plan, ids)
    region = plan["region"]
    vcn = require_live_id(oci("network", "vcn", "get", "--vcn-id", ids["vcn"], region=region),
                          ids["vcn"], "VCN")
    if (vcn.get("lifecycle-state") != "AVAILABLE" or vcn.get("compartment-id") != ids["network_compartment"] or
            vcn.get("cidr-block") != plan["network_cidr"]):
        fail("live VCN state or CIDR differs from the plan")
    subnet = require_live_id(oci("network", "subnet", "get", "--subnet-id", ids["subnet"], region=region),
                             ids["subnet"], "subnet")
    if (subnet.get("lifecycle-state") != "AVAILABLE" or
            subnet.get("compartment-id") != ids["network_compartment"] or
            subnet.get("vcn-id") != ids["vcn"] or subnet.get("cidr-block") != plan["subnet_cidr"] or
            subnet.get("prohibit-public-ip-on-vnic") is not True or
            subnet.get("prohibit-internet-ingress") is not True or
            subnet.get("security-list-ids") != [ids["security_list"]] or
            subnet.get("route-table-id") != ids.get("route_table")):
        fail("live subnet security, route, compartment, or CIDR differs from the plan")
    nsg = require_live_id(oci("network", "nsg", "get", "--nsg-id", ids["network_security_group"], region=region),
                          ids["network_security_group"], "network security group")
    if nsg.get("compartment-id") != ids["network_compartment"] or nsg.get("vcn-id") != ids["vcn"]:
        fail("live network security group is attached to an unexpected compartment or VCN")
    rules = oci("network", "nsg", "rules", "list", "--nsg-id",
                ids["network_security_group"], region=region)
    compare_security_rules(rules, expected["nsg_rules"], "controller network security group")
    seed_nsg_id = ids.get("seed_ssh_network_security_group")
    if seed_nsg_id:
        seed_nsg = require_live_id(oci("network", "nsg", "get", "--nsg-id", seed_nsg_id, region=region),
                                   seed_nsg_id, "seed-A SSH network security group")
        if seed_nsg.get("compartment-id") != ids["network_compartment"] or seed_nsg.get("vcn-id") != ids["vcn"]:
            fail("live seed-A SSH network security group is attached to an unexpected compartment or VCN")
        seed_rules = oci("network", "nsg", "rules", "list", "--nsg-id",
                         seed_nsg_id, region=region)
        compare_security_rules(seed_rules, expected["seed_ssh_nsg_rules"], "seed-A SSH network security group")
    elif expected["seed_ssh_nsg_rules"]:
        fail("plan declares a seed-A SSH exception without its exact network security group OCID")
    security_list = require_live_id(oci("network", "security-list", "get", "--security-list-id",
                                        ids["security_list"], region=region), ids["security_list"], "security list")
    if (security_list.get("compartment-id") != ids["network_compartment"] or
            security_list.get("vcn-id") != ids["vcn"]):
        fail("live security list is attached to an unexpected compartment or VCN")
    compare_security_rules(security_list.get("ingress-security-rules"), expected["security_list_ingress_rules"],
                           "subnet security-list ingress", "INGRESS")
    compare_security_rules(security_list.get("egress-security-rules"), expected["security_list_egress_rules"],
                           "subnet security-list egress", "EGRESS")
    if expected["route_rules"]:
        route_table = require_live_id(oci("network", "route-table", "get", "--rt-id", ids["route_table"],
                                          region=region), ids["route_table"], "route table")
        if (route_table.get("compartment-id") != ids["network_compartment"] or
                route_table.get("vcn-id") != ids["vcn"]):
            fail("live route table is attached to an unexpected compartment or VCN")
        actual_routes = route_table.get("route-rules")
        routes = rows(actual_routes)
        normalized_routes = [{"destination": row.get("destination"),
                              "destination_type": row.get("destination-type"),
                              "network_entity_id": row.get("network-entity-id")} for row in routes]
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
        expected_routes = [dict(rule, network_entity_id=ids["service_gateway"])
                           for rule in expected["route_rules"]]
        if sorted(map(canonical, normalized_routes)) != sorted(map(canonical, expected_routes)):
            fail("live route table rules differ from the exact plan")
        gateway_id = ids["service_gateway"]
        gateway = require_live_id(oci("network", "service-gateway", "get", "--service-gateway-id",
                                       gateway_id, region=region), gateway_id, "service gateway")
        service_ids = sorted(service.get("service-id") for service in gateway.get("services", [])
                             if isinstance(service, dict))
        if (gateway.get("compartment-id") != ids["network_compartment"] or gateway.get("vcn-id") != ids["vcn"] or
                gateway.get("lifecycle-state") != "AVAILABLE" or
                service_ids != [expected["service_gateway_service_id"]]):
            fail("live service gateway services differ from the exact plan")


def controller_storage_statements(plan: dict, ids: dict) -> list[str]:
    identity = plan["identity"]
    dynamic_group = identity["controller_dynamic_group_name"]
    control_name = plan["preview_compartment_names"]["control"]
    buckets = plan["foundation_buckets"]
    prefix = plan.get("bootstrap_object_prefix", "bootstrap/v1/*")
    return [
        f"Allow dynamic-group {dynamic_group} to manage objects in compartment {control_name} where all "
        f"{{target.bucket.name='{buckets['ledger']}', target.object.name='{prefix}', any "
        "{request.permission='OBJECT_READ', request.permission='OBJECT_CREATE'}}",
        f"Allow dynamic-group {dynamic_group} to manage objects in compartment {control_name} where all "
        f"{{target.bucket.name='{buckets['head']}', target.object.name='{prefix}', any "
        "{request.permission='OBJECT_READ', request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}",
        f"Allow dynamic-group {dynamic_group} to manage objects in compartment {control_name} where all "
        f"{{target.bucket.name='{buckets['material']}', target.object.name='material/v1/*', any "
        "{request.permission='OBJECT_READ', request.permission='OBJECT_CREATE'}}",
        f"Allow dynamic-group {dynamic_group} to use keys in compartment {control_name} where all "
        f"{{target.key.id='{ids['key']}', any {{request.permission='KEY_ENCRYPT', request.permission='KEY_DECRYPT'}}}}",
    ]


def required_controller_statements(plan: dict, ids: dict) -> list[str]:
    identity = plan["identity"]
    dynamic_group = identity["controller_dynamic_group_name"]
    control = plan["preview_compartment_names"]["control"]
    network = plan["preview_compartment_names"]["network"]
    workload = plan["preview_compartment_names"]["workload"]
    return [
        f"Allow dynamic-group {dynamic_group} to manage instance-family in compartment {control}",
        f"Allow dynamic-group {dynamic_group} to manage instance-family in compartment {workload}",
        f"Allow dynamic-group {dynamic_group} to read instance-images in compartment {control}",
        f"Allow dynamic-group {dynamic_group} to use virtual-network-family in compartment {network}",
        f"Allow dynamic-group {dynamic_group} to manage volume-family in compartment {control}",
        f"Allow dynamic-group {dynamic_group} to manage volume-family in compartment {workload}",
        f"Allow dynamic-group {dynamic_group} to read secret-bundles in compartment {control}",
        *controller_storage_statements(plan, ids),
    ]


def check_live_iam(plan: dict, ids: dict) -> None:
    identity = plan["identity"]
    rule = f"ALL {{instance.compartment.id = '{ids['control_compartment']}'}}"
    group = require_live_id(oci("iam", "dynamic-group", "get", "--dynamic-group-id",
                                 ids["controller_dynamic_group"]), ids["controller_dynamic_group"],
                            "controller dynamic group")
    if (group.get("lifecycle-state") != "ACTIVE" or
            group.get("name") != identity["controller_dynamic_group_name"] or
            group.get("matching-rule") != rule):
        fail("live controller dynamic group does not exactly isolate controller instances")
    policy = require_live_id(oci("iam", "policy", "get", "--policy-id", ids["controller_policy"]),
                             ids["controller_policy"], "controller IAM policy")
    expected_statements = required_controller_statements(plan, ids)
    if (policy.get("lifecycle-state") != "ACTIVE" or
            policy.get("name") != identity["controller_policy_name"] or
            policy.get("compartment-id") != plan["parent_compartment_id"] or
            policy.get("statements") != expected_statements):
        fail("live controller IAM policy differs from exact reviewed statements")
    key_policy = require_live_id(oci("iam", "policy", "get", "--policy-id", ids["objectstorage_key_policy"]),
                                 ids["objectstorage_key_policy"], "Object Storage key IAM policy")
    if (key_policy.get("lifecycle-state") != "ACTIVE" or
            key_policy.get("name") != identity["objectstorage_key_policy_name"] or
            key_policy.get("compartment-id") != ids["control_compartment"]):
        fail("live Object Storage key policy differs from exact reviewed statements")
    key_statement = (f"Allow service objectstorage-{plan['region']} to use keys in compartment "
                     f"{plan['preview_compartment_names']['control']} where all {{target.key.id='{ids['key']}', "
                     "any {request.permission='KEY_READ', request.permission='KEY_ENCRYPT', "
                     "request.permission='KEY_DECRYPT'}}")
    if key_policy["statements"] != [key_statement]:
        fail("Object Storage key policy is not limited to the reviewed region and key")
    host_secret = plan["host_credential_secret"]
    secret_compartment = host_secret.get("compartment_id")
    secret_id = host_secret.get("secret_id")
    if not secret_compartment or not secret_id:
        fail("foundation inspection requires the operator-selected host LiveS3Credential secret OCIDs")
    host_group_rule = f"ALL {{instance.compartment.id = '{ids['workload_compartment']}'}}"
    host_group = require_live_id(oci("iam", "dynamic-group", "get", "--dynamic-group-id",
                                     ids["host_dynamic_group"]), ids["host_dynamic_group"],
                                "workload host dynamic group")
    if (host_group.get("lifecycle-state") != "ACTIVE" or
            host_group.get("name") != identity["host_dynamic_group_name"] or
            host_group.get("matching-rule") != host_group_rule):
        fail("live workload host dynamic group does not exactly isolate workload instances")
    host_policy = require_live_id(oci("iam", "policy", "get", "--policy-id", ids["host_policy"]),
                                  ids["host_policy"], "host LiveS3Credential IAM policy")
    secret_statement = (f"Allow dynamic-group {identity['host_dynamic_group_name']} to read secret-bundles "
                        f"in compartment id {secret_compartment} where target.secret.id = '{secret_id}'")
    if (host_policy.get("lifecycle-state") != "ACTIVE" or
            host_policy.get("name") != identity["host_policy_name"] or
            host_policy.get("compartment-id") != secret_compartment or
            host_policy.get("statements") != [secret_statement]):
        fail("host LiveS3Credential policy is not limited to the selected secret and compartment")
    secret = require_live_id(oci("vault", "secret", "get", "--secret-id", secret_id,
                                 region=plan["region"]), secret_id, "host LiveS3Credential secret")
    if (secret.get("lifecycle-state") != "ACTIVE" or
            secret.get("compartment-id") != secret_compartment):
        fail("live host LiveS3Credential secret is not active in its selected compartment")


def check_live_vault(plan: dict, ids: dict) -> None:
    vault = require_live_id(oci("kms", "management", "vault", "get", "--vault-id", ids["vault"],
                                region=plan["region"]), ids["vault"], "Vault")
    if (vault.get("lifecycle-state") != "ACTIVE" or vault.get("vault-type") != "DEFAULT" or
            vault.get("compartment-id") != ids["control_compartment"]):
        fail("live Vault is not active in the plan control compartment")
    endpoint = vault.get("management-endpoint")
    if not isinstance(endpoint, str) or not endpoint.startswith("https://") or len(endpoint) > 512:
        fail("live Vault management endpoint is invalid")
    key = require_live_id(oci("kms", "management", "key", "get", "--key-id", ids["key"],
                              "--endpoint", endpoint, region=plan["region"]), ids["key"], "KMS key")
    key_state = key.get("lifecycle-state", key.get("key-state"))
    shape = key.get("key-shape") or {}
    if (key_state != "ENABLED" or key.get("compartment-id") != ids["control_compartment"] or
            key.get("vault-id") != ids["vault"] or key.get("protection-mode") != "HSM" or
            shape.get("algorithm") != "AES" or shape.get("length") != 32):
        fail("live KMS key state or cryptographic shape differs from the plan")


def check_live_buckets(plan: dict, ids: dict) -> None:
    namespace = oci("os", "ns", "get", region=plan["region"])
    names = plan["foundation_buckets"]
    properties = {
        "ledger": ("Disabled", "ledger-retention"),
        "head": ("Enabled", None),
        "backup": ("Disabled", "backup-retention"),
        "material": ("Enabled", None),
    }
    for role, name in names.items():
        bucket = oci("os", "bucket", "get", "--namespace-name", namespace, "--bucket-name", name,
                     region=plan["region"])
        versioning, retention_name = properties[role]
        if (bucket.get("name") != name or bucket.get("compartment-id") != ids["control_compartment"] or
                bucket.get("public-access-type") != "NoPublicAccess" or bucket.get("storage-tier") != "Standard" or
                bucket.get("versioning") != versioning or bucket.get("kms-key-id") != ids["key"]):
            fail(f"live {role} bucket privacy, KMS, tier, compartment, or versioning differs from the plan")
        retention = rows(oci("os", "retention-rule", "list", "--namespace-name", namespace,
                             "--bucket-name", name, "--all", region=plan["region"]))
        if retention_name is None:
            if retention:
                fail(f"live {role} bucket has an unplanned retention rule")
        elif len(retention) != 1 or retention[0].get("display-name") != retention_name:
            fail(f"live {role} bucket retention differs from the exact plan")
        else:
            duration = retention[0].get("duration") or {}
            try:
                duration_days = decimal(duration.get("time-amount"))
            except Exception as error:
                raise ValueError(f"live {role} bucket retention duration is invalid") from error
            if duration.get("time-unit") != "DAYS" or duration_days != Decimal(plan["bucket_retention_days"]):
                fail(f"live {role} bucket retention differs from the exact plan")


def verify_current_admission(plan: dict, inventory: dict, inventory_path: pathlib.Path,
                             admission_path: pathlib.Path, plan_path: pathlib.Path) -> tuple[dict, dict, dt.datetime]:
    cost = estimate(plan, inventory, plan_path)
    admission = read_json(admission_path, MAX_ADMISSION_BYTES, "manual budget admission")
    now = dt.datetime.now(UTC)
    try:
        admitted_at = dt.datetime.fromisoformat(admission["admitted_at"])
        expires_at = dt.datetime.fromisoformat(admission["expires_at"])
        inventory_captured_at = dt.datetime.fromisoformat(inventory["captured_at"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("budget admission has invalid timestamps") from error
    if (admission.get("schema_version") != 2 or admitted_at.tzinfo is None or expires_at.tzinfo is None or
            admitted_at.utcoffset() != dt.timedelta(0) or expires_at.utcoffset() != dt.timedelta(0) or
            admitted_at > now + dt.timedelta(seconds=30) or not admitted_at <= now < expires_at or
            expires_at > admitted_at + dt.timedelta(minutes=15, seconds=30) or
            inventory_captured_at.tzinfo is None or inventory_captured_at > admitted_at or
            admission.get("plan_sha256") != sha256(plan_path) or
            admission.get("inventory_sha256") != sha256(inventory_path) or
            admission.get("preview_compartment_ids") != inventory.get("preview_compartment_ids") or
            admission.get("estimate") != cost):
        fail("budget admission is stale or does not match the exact current plan and inventory")
    return cost, admission, admitted_at


def inspect_foundation(plan: dict, plan_path: pathlib.Path, inventory_path: pathlib.Path,
                       admission_path: pathlib.Path) -> dict:
    inventory = read_json(inventory_path, MAX_INVENTORY_BYTES, "manual region inventory")
    verify_inventory(plan, inventory, plan_path=plan_path)
    cost, admission, admitted_at = verify_current_admission(plan, inventory, inventory_path, admission_path, plan_path)
    if Decimal(cost["total"]) > Decimal("100"):
        fail("live foundation inspection exceeds the USD 100 monthly ceiling")
    ids = required_resource_ids(plan)
    check_live_compartments(plan, ids)
    check_live_vault(plan, ids)
    check_live_network(plan, ids)
    check_live_buckets(plan, ids)
    check_live_iam(plan, ids)
    inspected_at = dt.datetime.now(UTC)
    expires_at = dt.datetime.fromisoformat(admission["expires_at"])
    if inspected_at < admitted_at:
        fail("local clock precedes the current budget admission")
    if inspected_at >= expires_at:
        fail("budget admission expired during live foundation inspection")
    return {"schema_version": 1, "plan_sha256": sha256(plan_path),
            "inventory_sha256": sha256(inventory_path), "inspected_at": rfc3339_utc(inspected_at),
            "tenancy_id": plan["tenancy_id"], "cell": plan["cell"], "oci_region": plan["region"],
            "control_compartment_id": ids["control_compartment"],
            "network_compartment_id": ids["network_compartment"],
            "workload_compartment_id": ids["workload_compartment"],
            "vault_id": ids["vault"], "key_id": ids["key"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "admit", "estimate", "seed-preflight", "seed-user-data",
                                            "inspect-foundation", "import-inventory", "import-admit",
                                            "import-reconcile"))
    parser.add_argument("--plan", type=pathlib.Path, default=PLAN)
    parser.add_argument("--inventory", type=pathlib.Path, default=ROOT / "inventory.json")
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument("--admission", type=pathlib.Path, default=ROOT / "admission.json")
    parser.add_argument("--bootstrap-tool", type=pathlib.Path)
    parser.add_argument("--anchor", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--identity", type=pathlib.Path)
    parser.add_argument("--bootstrap-root", type=pathlib.Path, action="append")
    parser.add_argument("--image-ocid")
    parser.add_argument("--release-tool", type=pathlib.Path)
    parser.add_argument("--image-receipt", type=pathlib.Path)
    parser.add_argument("--release-delegation", type=pathlib.Path)
    parser.add_argument("--release-root", type=pathlib.Path)
    parser.add_argument("--image-file", type=pathlib.Path)
    parser.add_argument("--base-image-file", type=pathlib.Path)
    parser.add_argument("--kernel-file", type=pathlib.Path)
    parser.add_argument("--owner-ssh-public-key", type=pathlib.Path)
    parser.add_argument("--projection", type=pathlib.Path)
    parser.add_argument("--phase", choices=("pre-stage", "pre-import"))
    parser.add_argument("--staged-versions", type=pathlib.Path)
    parser.add_argument("--imported-images", type=pathlib.Path)
    parser.add_argument("--previous-admission", type=pathlib.Path)
    parser.add_argument("--previous-projection", type=pathlib.Path)
    parser.add_argument("--previous-inventory", type=pathlib.Path)
    parser.add_argument("--previous-imported-images", type=pathlib.Path)
    parser.add_argument("--previous-staged-versions", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "seed-user-data":
        if args.manifest is None or args.out is None:
            fail("seed user-data requires --manifest and --out")
        plan = load_plan(args.plan)
        wire = seed_user_data(args.manifest, args.owner_ssh_public_key, plan["cell"])
        write_output_bytes(args.out, wire)
        print(f"wrote seed user-data bytes={len(wire)} sha256={hashlib.sha256(wire).hexdigest()}")
        return
    plan = load_plan(args.plan)
    if args.command == "seed-preflight":
        required = ("bootstrap_tool", "anchor", "manifest", "identity", "image_ocid", "release_tool",
                    "image_receipt", "release_delegation", "release_root", "image_file", "base_image_file",
                    "kernel_file", "out")
        if any(getattr(args, key) is None for key in required):
            fail("seed preflight requires signed bootstrap, release image, and exact image candidate inputs")
        result = seed_preflight(args, plan, args.plan.resolve())
        output_sha = write_canonical_seed_plan(args.out, result)
        print(f"wrote reviewed manual seed plan slot=controller-a sha256={output_sha}")
        return
    if args.command == "inventory":
        snapshot = collect_inventory(plan)
        write_json(args.out or args.inventory, snapshot)
        print(f"captured {len(snapshot['resources'])} OCI resources and {len(snapshot['buckets'])} buckets")
        return
    if args.command == "import-inventory":
        snapshot = import_inventory(plan, args.projection, args.staged_versions, args.previous_projection)
        verify_import_inventory(plan, snapshot, args.plan.resolve())
        write_json(args.out or args.inventory, snapshot)
        print(f"captured {len(snapshot['images'])} scoped images and {len(snapshot['buckets'])} detailed buckets")
        return
    if args.command == "inspect-foundation":
        if args.out is None:
            fail("foundation inspection requires --out")
        result = inspect_foundation(plan, args.plan.resolve(), args.inventory, args.admission)
        write_json(args.out, result)
        print(f"foundation readback PASS region={plan['region']} inventory={result['inventory_sha256']}")
        return
    if args.command in {"import-admit", "import-reconcile"}:
        if not args.projection or not args.out:
            fail("import admission requires --projection and --out")
        phase = args.phase if args.command == "import-admit" else "post-import"
        if phase is None:
            fail("import-admit requires --phase")
        inventory = read_json(args.inventory, MAX_INVENTORY_BYTES, "manual region import inventory")
        imports = reviewed_imports(plan, inventory, args.projection)
        base_lineage = None
        if set(imports) == {"base", "final"}:
            if args.previous_projection:
                if (phase != "pre-stage" or args.staged_versions or not args.previous_admission or
                        not args.previous_inventory or not args.previous_staged_versions or
                        not args.previous_imported_images):
                    fail("base-only lineage requires the first full pre-stage admission and all prior evidence")
                base_lineage = establish_base_lineage(
                    plan, args.projection, args.previous_projection, args.previous_inventory,
                    args.previous_admission, args.previous_staged_versions, args.previous_imported_images,
                    args.plan.resolve())
            elif args.previous_admission:
                if phase == "pre-stage" and not args.staged_versions:
                    fail("first full pre-stage admission requires the exact previous base-only projection")
                previous_value = read_json(args.previous_admission, MAX_ADMISSION_BYTES,
                                           "previous import admission")
                base_lineage = carried_base_lineage(previous_value.get("base_lineage"), sha256(args.plan))
            else:
                fail("full import projection requires a verified base-only admission lineage")
        elif args.previous_projection or args.previous_inventory:
            fail("base-only projection cannot accept a prior base projection lineage")
        if phase == "pre-stage" and args.staged_versions:
            preceding = "pre-stage"
        elif phase == "pre-import" and not args.imported_images:
            preceding = "pre-stage"
        elif phase in {"pre-import", "post-import"}:
            preceding = "pre-import"
        else:
            preceding = None
        if preceding is not None:
            if not args.staged_versions or not args.previous_admission:
                fail("later import admission requires staged versions and previous admission")
            previous = verify_previous_import_admission(
                args.previous_admission, preceding, sha256(args.projection), args.plan.resolve(),
                sha256(args.previous_staged_versions) if args.previous_staged_versions else
                (sha256(args.staged_versions) if preceding == "pre-import" else None))
            if set(imports) == {"base", "final"}:
                base_lineage = carried_base_lineage(previous.get("base_lineage"), sha256(args.plan))
            if phase == "pre-import" and not args.imported_images:
                if previous.get("staged_versions_sha256") is not None:
                    if not args.previous_staged_versions:
                        fail("pre-import requires the preceding base object version receipt")
                    if previous.get("staged_versions_sha256") != sha256(args.previous_staged_versions):
                        fail("preceding base object receipt changed")
                    base = import_receipt(args.previous_staged_versions, "versions", sha256(args.projection), {"base"})
                    current = import_receipt(args.staged_versions, "versions", sha256(args.projection), set(imports))
                    if base["base"] != current["base"]:
                        fail("staged receipt changed the admitted base object version")
            if phase == "pre-import" and args.imported_images and previous.get("imported_images_sha256") is not None:
                fail("base readback requires the preceding two-maximum pre-import admission")
            if phase == "post-import":
                if set(imports) == {"base"}:
                    if not args.previous_imported_images or not previous.get("imported_images_sha256"):
                        fail("base reconciliation requires the preceding image readback admission and receipt")
                    if sha256(args.previous_imported_images) != previous["imported_images_sha256"]:
                        fail("preceding base image receipt changed")
                    base = import_receipt(args.previous_imported_images, "images", sha256(args.projection), {"base"})
                    final = import_receipt(args.imported_images, "images", sha256(args.projection), {"base"})
                    if base["base"] != final["base"]:
                        fail("final image receipt changed the admitted base image OCID")
                elif base_lineage is None:
                    fail("final reconciliation lacks the carried base image readback")
        if set(imports) == {"base", "final"} and base_lineage is None:
            fail("full import admission lacks the carried base-only lineage")
        result = import_estimate(plan, inventory, args.projection, phase,
                                 args.staged_versions, args.imported_images, args.plan.resolve(),
                                 base_lineage=base_lineage)
        now = dt.datetime.now(UTC)
        admission = {"schema_version": 3, "phase": phase, "admitted_at": now.isoformat(),
                     "expires_at": (now + dt.timedelta(minutes=15)).isoformat(),
                     "plan_sha256": sha256(args.plan), "inventory_sha256": sha256(args.inventory),
                     "projection_sha256": sha256(args.projection),
                     "staged_versions_sha256": sha256(args.staged_versions) if args.staged_versions else None,
                     "imported_images_sha256": sha256(args.imported_images) if args.imported_images else None,
                     "previous_admission_sha256": sha256(args.previous_admission) if args.previous_admission else None,
                     "base_lineage": base_lineage,
                     "estimate": result}
        write_json(args.out, admission)
        print(json.dumps(admission, indent=2, sort_keys=True))
        return
    inventory = read_json(args.inventory, MAX_INVENTORY_BYTES, "manual region inventory")
    result = estimate(plan, inventory, args.plan.resolve())
    if args.command == "admit":
        if not args.out:
            fail("admit requires --out")
        result = {"schema_version": 2, "admitted_at": dt.datetime.now(UTC).isoformat(),
                  "expires_at": (dt.datetime.now(UTC) + dt.timedelta(minutes=15)).isoformat(),
                  "plan_sha256": sha256(args.plan), "inventory_sha256": sha256(args.inventory),
                  "preview_compartment_ids": inventory["preview_compartment_ids"], "estimate": result}
        write_json(args.out, result)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"oci-preview: {error}", file=sys.stderr)
        sys.exit(1)
