#!/usr/bin/env python3
"""Read-only OCI preview inventory and fail-closed monthly cost admission.

All prices are explicit estimates, not OCI spending limits. OCI mutations use
the separately qualified founder and placement callers; this tool records the
live resource boundary that those callers must satisfy before every create.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
import re
import subprocess
import sys
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


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decimal(value: object) -> Decimal:
    if isinstance(value, bool):
        fail("boolean is not a number")
    return Decimal(str(value))


def load_plan(path: pathlib.Path = PLAN) -> dict:
    plan = json.loads(path.read_text(encoding="utf-8"))
    if plan.get("schema_version") != 2 or plan.get("region") != "sa-saopaulo-1":
        fail("unexpected preview plan schema or region")
    if plan.get("preview_compartment_names") != {"control": "terrascale-control", "network": "terrascale-network",
                                                  "workload": "terrascale-workload"}:
        fail("preview compartments differ from the ts-infra ownership boundary")
    if (plan.get("controller_replicas"), plan.get("database_members")) != (3, 2):
        fail("preview requires three controllers and two database members")
    slots = {host["slot"] for host in plan["hosts"]}
    if slots != {"controller-a", "controller-b", "controller-c", "member-a", "member-b"}:
        fail("preview host slots differ from the bounded five-host plan")
    for host in plan["hosts"]:
        if (host["shape"], host["ocpus"], host["memory_gb"], host["boot_gb"]) != ("VM.Standard.A1.Flex", 1, 6, 50):
            fail(f"unexpected shape or size for {host['slot']}")
        if host["data_gb"] != (0 if host["slot"].startswith("controller-") else 50):
            fail(f"unexpected data volume for {host['slot']}")
    cidr = ipaddress.ip_network(plan["network_cidr"], strict=True)
    host_ips = [ipaddress.ip_address(host["private_ip"]) for host in plan["hosts"]]
    if len(set(host_ips)) != 5 or any(address not in cidr for address in host_ips):
        fail("host addresses must be unique private IPs inside the preview subnet")
    budget = plan["budget"]
    if budget["currency"] != "USD" or decimal(budget["monthly_limit"]) != 100:
        fail("preview budget must match the authorized USD 100 monthly ceiling")
    if budget["replacement_hosts_max"] != 1 or budget["replacement_overlap_hours_max"] > 72:
        fail("replacement allowance exceeds the bounded plan")
    if budget["snapshot_gb_max"] > 350 or budget["object_storage_gb_max"] > 10:
        fail("storage allowance exceeds the bounded plan")
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
    if not process.stdout.strip() and "--all" in args:
        return []
    try:
        return json.loads(process.stdout)["data"]
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


def collect_inventory(plan: dict) -> dict:
    subscriptions = oci("iam", "region-subscription", "list", "--tenancy-id", plan["tenancy_id"], "--all")
    regions = sorted(row["region-name"] for row in subscriptions if row["status"] == "READY")
    if plan["region"] not in regions:
        fail("GRU is not a ready subscribed region")
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
            if versioned:
                versions = rows(oci("os", "object", "list-object-versions", "--namespace-name", namespace,
                                    "--bucket-name", bucket["name"], "--fields", "size", "--all", region=region))
                objects = versions
            buckets.append({"region": region, "compartment_id": bucket["compartment-id"], "name": bucket["name"],
                            "object_count": len(objects), "bytes": sum(row.get("size", 0) or 0 for row in objects),
                            "versioning": properties["versioning"], "storage_tier": properties["storage-tier"]})
    return {"schema_version": 2, "captured_at": dt.datetime.now(UTC).isoformat(),
            "plan_sha256": sha256(PLAN), "tenancy_id": plan["tenancy_id"], "regions": regions,
            "preview_compartment_ids": preview_ids, "resources": resources, "buckets": buckets}


def active(resources: list[dict], kind: str) -> list[dict]:
    return [row for row in resources if row["kind"] == kind and row.get("lifecycle-state") in ACTIVE_RESOURCE_STATES]


def replacement_within_window(resources: list[dict], plan: dict) -> bool:
    if not resources:
        return False
    try:
        newest = max(dt.datetime.fromisoformat(row["time-created"]) for row in resources)
    except (KeyError, ValueError):
        return False
    if newest.tzinfo is None:
        return False
    age = dt.datetime.now(UTC) - newest
    return dt.timedelta(0) <= age <= dt.timedelta(hours=plan["budget"]["replacement_overlap_hours_max"])


def verify_inventory(plan: dict, inventory: dict, max_age_minutes: int = 15) -> None:
    if inventory.get("schema_version") != 2 or inventory.get("tenancy_id") != plan["tenancy_id"]:
        fail("inventory belongs to another tenancy or schema")
    if inventory.get("plan_sha256") != sha256(PLAN):
        fail("inventory was captured against another plan revision")
    preview_ids = inventory.get("preview_compartment_ids")
    if not isinstance(preview_ids, dict) or set(preview_ids) != {"control", "network", "workload"}:
        fail("inventory lacks the three ts-infra preview compartment identities")
    for role, resource_id in preview_ids.items():
        planned = plan["resource_ids"][f"{role}_compartment"]
        if planned and planned != resource_id:
            fail(f"preview {role} compartment differs from the recorded resource identity")
    for bucket in inventory["buckets"]:
        if (preview_ids["control"] and bucket.get("compartment_id") == preview_ids["control"] and
                bucket.get("name") not in plan["foundation_buckets"].values()):
            fail("control compartment has an unplanned object bucket")
        versioned = (bucket.get("region") == plan["region"] and bucket.get("compartment_id") == preview_ids["control"]
                and bucket.get("name") in (plan["foundation_buckets"]["head"], plan["foundation_buckets"]["material"]))
        if bucket.get("versioning") != ("Enabled" if versioned else "Disabled") or bucket.get("storage_tier") != "Standard":
            fail("inventory contains an unpriced object storage tier or versioning mode")
    captured = dt.datetime.fromisoformat(inventory["captured_at"])
    age = dt.datetime.now(UTC) - captured
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
        elif (compartment == control_id and row.get("display-name") == "terrascale-orchestrator-gru" and
              tags.get("ManagedBy") == "ts-infra" and tags.get("Role") == "initial-controller"):
            preview_controller_count += 1
        elif compartment == control_id and row.get("display-name") in {"controller-b", "controller-c"}:
            preview_controller_count += 1
        else:
            fail(f"preview instance has no approved owner: {row['id']}")
        if row.get("shape") != "VM.Standard.A1.Flex" or decimal(row["shape-config"]["ocpus"]) != 1 or decimal(row["shape-config"]["memory-in-gbs"]) != 6:
            fail("preview instance dimensions exceed the plan")
    preview_instances = [row for row in instances if row.get("compartment-id") in {control_id, workload_id}]
    if (preview_controller_count > 4 or preview_member_count > 3 or len(preview_instances) > 6 or
            (len(preview_instances) > 5 and not replacement_within_window(preview_instances, plan))):
        fail("preview controller or member count exceeds the plan")
    known_volumes = {existing["boot_volume_id"], existing["data_volume_id"]}
    for kind in ("boot-volume", "volume"):
        for row in active(inventory["resources"], kind):
            if row["id"] not in known_volumes and row.get("compartment-id") not in {control_id, workload_id}:
                fail(f"unbudgeted {kind} found: {row['id']}")
            if decimal(row["size-in-gbs"]) != 50 or decimal(row["vpus-per-gb"]) != 10:
                fail(f"unexpected {kind} size or performance: {row['id']}")
    boot_volumes = active(inventory["resources"], "boot-volume")
    data_volumes = active(inventory["resources"], "volume")
    if (len(boot_volumes) > 7 or len(data_volumes) > 4 or
            (len(boot_volumes) > 6 and not replacement_within_window(boot_volumes, plan)) or
            (len(data_volumes) > 3 and not replacement_within_window(data_volumes, plan))):
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


def estimate(plan: dict, inventory: dict) -> dict:
    verify_inventory(plan, inventory)
    budget = plan["budget"]
    rates = {key: decimal(value) for key, value in budget["rates"].items()}
    hours = decimal(budget["month_hours"])
    ocpus = sum(decimal(host["ocpus"]) for host in plan["hosts"]) + 2
    memory = sum(decimal(host["memory_gb"]) for host in plan["hosts"]) + 4
    compute = max(Decimal(0), ocpus * hours - FREE_A1_OCPU_HOURS) * rates["a1_ocpu_hour"]
    compute += max(Decimal(0), memory * hours - FREE_A1_MEMORY_GB_HOURS) * rates["a1_memory_gb_hour"]
    storage_gb = sum(decimal(host["boot_gb"] + host["data_gb"]) for host in plan["hosts"]) + 100
    billed_storage = max(Decimal(0), storage_gb - FREE_BLOCK_GB)
    storage = billed_storage * (rates["block_gb_month"] + decimal(plan["volume_vpus_per_gb"]) * rates["block_vpu_gb_month"])
    overlap_hours = decimal(budget["replacement_overlap_hours_max"])
    overlap_compute = overlap_hours * (rates["a1_ocpu_hour"] + 6 * rates["a1_memory_gb_hour"])
    overlap_storage = decimal(100) * overlap_hours / hours * (rates["block_gb_month"] + 10 * rates["block_vpu_gb_month"])
    live_object_gb = sum(decimal(bucket["bytes"]) for bucket in inventory["buckets"]) / decimal(1024 ** 3)
    object_gb = max(live_object_gb, decimal(budget["baseline_object_storage_gb"])) + decimal(budget["object_storage_gb_max"])
    object_storage = max(Decimal(0), object_gb - FREE_OBJECT_GB) * rates["object_gb_month"]
    object_requests = decimal(budget["object_requests_max"]) / 10000 * rates["object_10000_requests"]
    object_requests += decimal(budget["baseline_object_requests_usd"])
    egress = decimal(budget["egress_gb_max"]) * rates["egress_gb"]
    # This is a conservative reserve. OCI's current catalog does not provide a
    # separate volume-backup SKU, so the exact backup bill must be reconciled.
    snapshot_reserve = decimal(budget["snapshot_gb_max"]) * rates["block_gb_month"]
    items = {"compute": compute, "block_storage": storage, "replacement_compute": overlap_compute,
             "replacement_storage": overlap_storage, "object_storage": object_storage,
             "object_requests": object_requests, "egress": egress,
             "snapshot_reserve": snapshot_reserve, "misc_reserve": decimal(budget["misc_reserve_usd"])}
    total = sum(items.values(), Decimal(0))
    if total > decimal(budget["monthly_limit"]):
        fail(f"projected USD {total:.2f} exceeds the monthly ceiling")
    return {"currency": "USD", "items": {key: str(value.quantize(Decimal("0.0001"))) for key, value in items.items()},
            "total": str(total.quantize(Decimal("0.01"))), "limit": str(budget["monthly_limit"]),
            "headroom": str((decimal(budget["monthly_limit"]) - total).quantize(Decimal("0.01"))),
            "assumptions": {"a1_free_ocpu_hours": 1500, "a1_free_memory_gb_hours": 9000,
                            "free_block_gb": 200, "free_object_gb": 10,
                            "backup_reserve_pricing": "350 GB at block capacity rate; provisional"}}


def write_json(path: pathlib.Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)


def verify_seed_preflight(plan: dict, inventory_path: pathlib.Path, admission_path: pathlib.Path,
                          manifest_summary: dict, image_receipt_path: pathlib.Path,
                          image_verification: str) -> dict:
    """Check exact seed launch facts; this command never creates OCI resources."""
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    cost = estimate(plan, inventory)
    admission = json.loads(admission_path.read_text(encoding="utf-8"))
    now = dt.datetime.now(UTC)
    try:
        admitted_at = dt.datetime.fromisoformat(admission["admitted_at"])
        expires_at = dt.datetime.fromisoformat(admission["expires_at"])
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("budget admission has invalid timestamps") from error
    if (admission.get("schema_version") != 2 or admitted_at.tzinfo is None or expires_at.tzinfo is None or
            admitted_at > now + dt.timedelta(seconds=30) or not admitted_at <= now < expires_at or
            expires_at > admitted_at + dt.timedelta(minutes=15, seconds=30) or
            admission.get("plan_sha256") != sha256(PLAN) or
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
        fail("seed preflight requires the exact recorded ts-infra compartments")
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
            foundation["subnet"].get("cidr-block") != "10.251.0.0/25" or
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
    seed = next(host for host in plan["hosts"] if host["slot"] == "controller-a")
    profile = manifest_summary.get("profile")
    if (manifest_summary.get("schemaVersion") != 2 or manifest_summary.get("cell") != "GRU" or
            manifest_summary.get("ociRegion") != plan["region"] or
            manifest_summary.get("slot") != seed["slot"] or
            manifest_summary.get("imageArchitecture") != "linux-arm64" or
            not isinstance(profile, dict) or profile.get("slot") != seed["slot"] or
            profile.get("compartmentOcid") != control or
            profile.get("availabilityDomain") != plan["availability_domain"] or
            profile.get("faultDomain") != seed["fault_domain"] or
            profile.get("subnetOcid") != ids["subnet"] or
            profile.get("networkSecurityGroupOcids") != [ids["network_security_group"]] or
            profile.get("shape") != seed["shape"] or
            not re.fullmatch(r"[0-9a-f]{64}", manifest_summary.get("anchorSha256", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", manifest_summary.get("manifestSha256", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", manifest_summary.get("releaseReceiptSha256", ""))):
        fail("verified seed manifest differs from the recorded controller-a profile")
    if sha256(image_receipt_path) != manifest_summary["releaseReceiptSha256"]:
        fail("verified image receipt bytes differ from the signed seed manifest")
    image_ocid = manifest_summary.get("imageOcid", "")
    if (not re.fullmatch(r"ocid1\.image\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9-]+", image_ocid) or
            not image_verification.startswith(f"verified OCI image={image_ocid} region=GRU ") or
            " arch=arm64 " not in image_verification):
        fail("verified ARM image candidate differs from the signed seed manifest")
    if any(row.get("display-name") == "terrascale-orchestrator-gru"
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
            "admission_expires_at": admission["expires_at"], "monthly_estimate_usd": cost["total"]}


def checked_tool(*command: str) -> str:
    process = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    if process.returncode:
        fail(f"verification tool {pathlib.Path(command[0]).name} rejected its inputs (exit {process.returncode})")
    return process.stdout.strip()


def seed_preflight(args: argparse.Namespace, plan: dict) -> dict:
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
        "--kernel-file", str(args.kernel_file), "--region", "GRU",
        "--environment", manifest_summary["environment"])
    return verify_seed_preflight(plan, args.inventory, args.admission, manifest_summary,
                                 args.image_receipt, image_verification)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inventory", "admit", "estimate", "seed-preflight"))
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
    args = parser.parse_args()
    plan = load_plan()
    if args.command == "seed-preflight":
        required = ("bootstrap_tool", "anchor", "manifest", "identity", "image_ocid", "release_tool",
                    "image_receipt", "release_delegation", "release_root", "image_file", "base_image_file",
                    "kernel_file")
        if any(getattr(args, key) is None for key in required):
            fail("seed preflight requires signed bootstrap, release image, and exact image candidate inputs")
        print(json.dumps(seed_preflight(args, plan), indent=2, sort_keys=True))
        return
    if args.command == "inventory":
        snapshot = collect_inventory(plan)
        write_json(args.out or args.inventory, snapshot)
        print(f"captured {len(snapshot['resources'])} OCI resources and {len(snapshot['buckets'])} buckets")
        return
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    result = estimate(plan, inventory)
    if args.command == "admit":
        if not args.out:
            fail("admit requires --out")
        result = {"schema_version": 2, "admitted_at": dt.datetime.now(UTC).isoformat(),
                  "expires_at": (dt.datetime.now(UTC) + dt.timedelta(minutes=15)).isoformat(),
                  "plan_sha256": sha256(PLAN), "inventory_sha256": sha256(args.inventory),
                  "preview_compartment_ids": inventory["preview_compartment_ids"], "estimate": result}
        write_json(args.out, result)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"oci-preview: {error}", file=sys.stderr)
        sys.exit(1)
