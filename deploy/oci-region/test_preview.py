import datetime as dt
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from decimal import Decimal
from email.utils import format_datetime
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oci_preview", ROOT / "preview.py")
preview = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preview)


class PreviewAdmissionTests(unittest.TestCase):
    def test_empty_object_lists_use_exact_oci_cli_empty_shape(self):
        for operation in ("list", "list-object-versions"):
            with self.subTest(operation=operation):
                command = ("os", "object", operation, "--bucket-name", "empty", "--all")
                with mock.patch.object(preview.subprocess, "run") as run:
                    run.return_value.returncode = 0
                    run.return_value.stdout = '{"prefixes": []}'
                    self.assertEqual(preview.oci(*command), [])
                    run.assert_called_once()
        for response in ('{"prefixes": ["hidden/"]}', '{"prefixes": [], "next-start-with": "next"}',
                         '{}', '{"objects": []}'):
            with self.subTest(response=response):
                with mock.patch.object(preview.subprocess, "run") as run:
                    run.return_value.returncode = 0
                    run.return_value.stdout = response
                    with self.assertRaisesRegex(ValueError, "invalid OCI response"):
                        preview.oci("os", "object", "list", "--all")
        with mock.patch.object(preview.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"prefixes": []}'
            with self.assertRaisesRegex(ValueError, "invalid OCI response"):
                preview.oci("os", "object", "list")
            with self.assertRaisesRegex(ValueError, "invalid OCI response"):
                preview.oci("network", "vcn", "list", "--all")
        with mock.patch.object(preview.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            self.assertEqual(preview.oci("network", "vcn", "list", "--all"), [])
            for operation in ("list", "list-object-versions"):
                with self.subTest(blank_object_storage_operation=operation):
                    with self.assertRaisesRegex(ValueError, "invalid OCI response"):
                        preview.oci("os", "object", operation, "--all")

    def setUp(self):
        self.plan = preview.load_plan()
        existing = self.plan["existing_forgejo"]
        shared = self.plan["shared_compartment_id"]
        self.inventory = {
            "schema_version": 2,
            "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "plan_sha256": preview.sha256(preview.PLAN),
            "tenancy_id": self.plan["tenancy_id"],
            "regions": [self.plan["region"]],
            "preview_compartment_ids": {"control": None, "network": None, "workload": None},
            "images": [],
            "buckets": [
                {"name": "ts-forgejo", "bytes": 30 * 1024**3,
                 "versioning": "Disabled", "storage_tier": "Standard",
                 "public_access_type": "NoPublicAccess"},
                {"name": "ts-forgejo-backup", "bytes": 28 * 1024**3,
                 "versioning": "Disabled", "storage_tier": "Standard",
                 "public_access_type": "NoPublicAccess"},
            ],
            "resources": [
                {"kind": "instance", "id": existing["instance_id"], "compartment-id": shared,
                 "lifecycle-state": "RUNNING", "shape": "VM.Standard.A1.Flex",
                 "shape-config": {"ocpus": 2, "memory-in-gbs": 4}},
                {"kind": "boot-volume", "id": existing["boot_volume_id"], "compartment-id": shared,
                 "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
                {"kind": "volume", "id": existing["data_volume_id"], "compartment-id": shared,
                 "lifecycle-state": "AVAILABLE", "size-in-gbs": existing["expected_volume_gb"],
                 "vpus-per-gb": existing["expected_volume_vpus_per_gb"]},
                {"kind": "public-ip", "id": existing["public_ip_id"], "compartment-id": shared,
                 "lifecycle-state": "ASSIGNED"},
            ],
        }

    def bound_plan_and_inventory(self, directory):
        plan_value = json.loads(preview.PLAN.read_text())
        ids = plan_value["resource_ids"]
        ids.update({
            "control_compartment": "ocid1.compartment.oc1..control",
            "network_compartment": "ocid1.compartment.oc1..network",
            "workload_compartment": "ocid1.compartment.oc1..workload",
            "vault": "ocid1.vault.oc1.sa-saopaulo-1.testvault",
            "key": "ocid1.key.oc1.sa-saopaulo-1.testkey",
            "vcn": "ocid1.vcn.oc1.sa-saopaulo-1.testvcn",
            "subnet": "ocid1.subnet.oc1.sa-saopaulo-1.testsubnet",
            "network_security_group": "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.testnsg",
            "security_list": "ocid1.securitylist.oc1.sa-saopaulo-1.testsecuritylist",
            "route_table": "ocid1.routetable.oc1.sa-saopaulo-1.testroute",
            "service_gateway": "ocid1.servicegateway.oc1.sa-saopaulo-1.testgateway",
            "controller_dynamic_group": "ocid1.dynamicgroup.oc1..testcontroller",
            "controller_policy": "ocid1.policy.oc1..testcontroller",
            "objectstorage_key_policy": "ocid1.policy.oc1..testobjectstorage",
            "host_dynamic_group": "ocid1.dynamicgroup.oc1..testhosts",
            "host_policy": "ocid1.policy.oc1..testhostsecret",
        })
        plan_value["host_credential_secret"] = {
            "compartment_id": "ocid1.compartment.oc1..secretstore",
            "secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }
        plan_path = directory / "plan.json"
        plan_path.write_text(json.dumps(plan_value))
        plan = preview.load_plan(plan_path)
        inventory = deepcopy(self.inventory)
        inventory["plan_sha256"] = preview.sha256(plan_path)
        inventory["preview_compartment_ids"] = {
            role: ids[f"{role}_compartment"] for role in ("control", "network", "workload")}
        for role, name in plan["foundation_buckets"].items():
            inventory["buckets"].append({
                "region": plan["region"], "compartment_id": ids["control_compartment"], "name": name,
                "bytes": 0, "versioning": "Enabled" if role in {"head", "material"} else "Disabled",
                "storage_tier": "Standard", "public_access_type": "NoPublicAccess", "kms_key_id": ids["key"],
            })
        inventory_path = directory / "inventory.json"
        inventory_path.write_text(json.dumps(inventory))
        cost = preview.estimate(plan, inventory, plan_path)
        now = dt.datetime.now(dt.timezone.utc)
        admission = {
            "schema_version": 2, "admitted_at": now.isoformat(),
            "expires_at": (now + dt.timedelta(minutes=15)).isoformat(),
            "plan_sha256": preview.sha256(plan_path), "inventory_sha256": preview.sha256(inventory_path),
            "preview_compartment_ids": inventory["preview_compartment_ids"], "estimate": cost,
        }
        admission_path = directory / "admission.json"
        admission_path.write_text(json.dumps(admission))
        return plan, plan_path, inventory, inventory_path, admission, admission_path

    def test_fixed_cell_mapping_rejects_unmapped_region(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = json.loads(preview.PLAN.read_text())
            plan["cell"] = "SFO"
            path = pathlib.Path(directory) / "plan.json"
            path.write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError, "cell, or OCI region"):
                preview.load_plan(path)

    def test_host_credential_requires_vaultsecret_ocid_kind(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "plan.json"
            plan = json.loads(preview.PLAN.read_text())
            secret = "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            plan["host_credential_secret"] = {
                "compartment_id": "ocid1.compartment.oc1..secretstore",
                "secret_id": secret,
            }
            path.write_text(json.dumps(plan))
            self.assertEqual(preview.load_plan(path)["host_credential_secret"]["secret_id"], secret)

            plan["host_credential_secret"]["secret_id"] = "ocid1.secret.oc1.sa-saopaulo-1.synthetic"
            path.write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError, "invalid vaultsecret OCID"):
                preview.load_plan(path)

    def test_inspection_readback_binds_fresh_plan_inventory_and_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, plan_path, inventory, inventory_path, admission, admission_path = self.bound_plan_and_inventory(
                pathlib.Path(directory))
            with mock.patch.multiple(preview, check_live_compartments=mock.DEFAULT,
                                     check_live_vault=mock.DEFAULT, check_live_network=mock.DEFAULT,
                                     check_live_buckets=mock.DEFAULT, check_live_iam=mock.DEFAULT):
                result = preview.inspect_foundation(plan, plan_path, inventory_path, admission_path)
            self.assertEqual(result["cell"], "GRU")
            self.assertEqual(result["oci_region"], "sa-saopaulo-1")
            self.assertEqual(result["plan_sha256"], preview.sha256(plan_path))
            self.assertEqual(result["inventory_sha256"], preview.sha256(inventory_path))
            self.assertEqual(set(result), {
                "schema_version", "plan_sha256", "inventory_sha256", "inspected_at", "tenancy_id", "cell",
                "oci_region", "control_compartment_id", "network_compartment_id", "workload_compartment_id",
                "vault_id", "key_id",
            })
            admission["plan_sha256"] = "0" * 64
            admission_path.write_text(json.dumps(admission))
            with self.assertRaisesRegex(ValueError, "stale or does not match"):
                preview.inspect_foundation(plan, plan_path, inventory_path, admission_path)

    def test_inspection_rejects_admission_that_expires_during_live_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, plan_path, inventory, inventory_path, admission, admission_path = self.bound_plan_and_inventory(
                pathlib.Path(directory))
            admission["expires_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
            admission_path.write_text(json.dumps(admission))
            with self.assertRaisesRegex(ValueError, "stale or does not match"):
                preview.inspect_foundation(plan, plan_path, inventory_path, admission_path)

    def test_host_secret_policy_is_exact_and_attached_to_selected_compartment(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, _, _, _, _, _ = self.bound_plan_and_inventory(pathlib.Path(directory))
            ids = plan["resource_ids"]
            control = ids["control_compartment"]
            workload = ids["workload_compartment"]
            secret_scope = plan["host_credential_secret"]
            controller_rule = f"ALL {{instance.compartment.id = '{control}'}}"
            host_rule = f"ALL {{instance.compartment.id = '{workload}'}}"
            key_statement = (f"Allow service objectstorage-{plan['region']} to use keys in compartment "
                             f"{plan['preview_compartment_names']['control']} where all {{target.key.id='{ids['key']}', "
                             "any {request.permission='KEY_READ', request.permission='KEY_ENCRYPT', "
                             "request.permission='KEY_DECRYPT'}}")
            host_statement = (f"Allow dynamic-group {plan['identity']['host_dynamic_group_name']} to read "
                              f"secret-bundles in compartment id {secret_scope['compartment_id']} where "
                              f"target.secret.id = '{secret_scope['secret_id']}'")
            resources = {
                ids["controller_dynamic_group"]: {"id": ids["controller_dynamic_group"], "name":
                    plan["identity"]["controller_dynamic_group_name"], "lifecycle-state": "ACTIVE",
                    "matching-rule": controller_rule},
                ids["host_dynamic_group"]: {"id": ids["host_dynamic_group"], "name":
                    plan["identity"]["host_dynamic_group_name"], "lifecycle-state": "ACTIVE",
                    "matching-rule": host_rule},
                ids["controller_policy"]: {"id": ids["controller_policy"], "name":
                    plan["identity"]["controller_policy_name"], "compartment-id": plan["parent_compartment_id"],
                    "lifecycle-state": "ACTIVE", "statements": preview.required_controller_statements(plan, ids)},
                ids["objectstorage_key_policy"]: {"id": ids["objectstorage_key_policy"], "name":
                    plan["identity"]["objectstorage_key_policy_name"], "compartment-id": control,
                    "lifecycle-state": "ACTIVE", "statements": [key_statement]},
                ids["host_policy"]: {"id": ids["host_policy"], "name": plan["identity"]["host_policy_name"],
                    "compartment-id": secret_scope["compartment_id"], "lifecycle-state": "ACTIVE",
                    "statements": [host_statement]},
                secret_scope["secret_id"]: {"id": secret_scope["secret_id"], "compartment-id":
                    secret_scope["compartment_id"], "lifecycle-state": "ACTIVE"},
            }

            def fake_oci(*args, region=None):
                if args[:3] == ("iam", "dynamic-group", "get"):
                    return resources[args[args.index("--dynamic-group-id") + 1]]
                if args[:3] == ("iam", "policy", "get"):
                    return resources[args[args.index("--policy-id") + 1]]
                if args[:3] == ("vault", "secret", "get"):
                    return resources[args[args.index("--secret-id") + 1]]
                self.fail(f"unexpected OCI command: {args}")

            with mock.patch.object(preview, "oci", side_effect=fake_oci):
                preview.check_live_iam(plan, ids)
            resources[ids["host_policy"]]["statements"] = [host_statement.replace(
                secret_scope["secret_id"], "ocid1.secret.oc1.sa-saopaulo-1.other")]
            with mock.patch.object(preview, "oci", side_effect=fake_oci):
                with self.assertRaisesRegex(ValueError, "selected secret and compartment"):
                    preview.check_live_iam(plan, ids)

    def test_live_network_rules_and_route_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, _, _, _, _, _ = self.bound_plan_and_inventory(pathlib.Path(directory))
            ids = plan["resource_ids"]
            ids["seed_ssh_network_security_group"] = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.seednsg"
            plan["network_security"]["seed_ssh_nsg_rules"] = deepcopy(plan["network_security"]["nsg_rules"])
            drift = False
            rule_commands = []

            def live_rules(expected):
                result = []
                for row in expected:
                    live = {"direction": row["direction"], "protocol": row["protocol"],
                            "is-stateless": row["stateless"]}
                    for key in ("source", "source_type", "destination", "destination_type"):
                        if row[key] is not None:
                            live[key.replace("_", "-")] = row[key]
                    for protocol in ("tcp", "udp"):
                        if row[f"{protocol}_min"] is not None:
                            live[f"{protocol}-options"] = {"destination-port-range": {
                                "min": row[f"{protocol}_min"], "max": row[f"{protocol}_max"]}}
                    result.append(live)
                return result

            def fake_oci(*args, region=None):
                command = args[:3]
                if command == ("network", "vcn", "get"):
                    return {"id": ids["vcn"], "lifecycle-state": "AVAILABLE",
                            "compartment-id": ids["network_compartment"], "cidr-block": plan["network_cidr"]}
                if command == ("network", "subnet", "get"):
                    return {"id": ids["subnet"], "lifecycle-state": "AVAILABLE",
                            "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"],
                            "cidr-block": plan["subnet_cidr"], "prohibit-public-ip-on-vnic": True,
                            "prohibit-internet-ingress": True, "security-list-ids": [ids["security_list"]],
                            "route-table-id": ids["route_table"]}
                if command == ("network", "nsg", "get"):
                    return {"id": args[args.index("--nsg-id") + 1],
                            "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"]}
                if command == ("network", "nsg", "rules"):
                    self.assertIn("--nsg-id", args)
                    self.assertNotIn("--network-security-group-id", args)
                    rule_commands.append(args)
                    group = args[args.index("--nsg-id") + 1]
                    role = "seed_ssh_nsg_rules" if group == ids["seed_ssh_network_security_group"] else "nsg_rules"
                    rules = live_rules(plan["network_security"][role])
                    if drift and role == "nsg_rules":
                        rules[0]["tcp-options"]["destination-port-range"]["max"] += 1
                    return rules
                if command == ("network", "security-list", "get"):
                    return {"id": ids["security_list"], "compartment-id": ids["network_compartment"],
                            "vcn-id": ids["vcn"],
                            "ingress-security-rules": live_rules(plan["network_security"]["security_list_ingress_rules"]),
                            "egress-security-rules": live_rules(plan["network_security"]["security_list_egress_rules"])}
                if command == ("network", "route-table", "get"):
                    routes = [{"destination": row["destination"], "destination-type": row["destination_type"],
                               "network-entity-id": ids["service_gateway"]}
                              for row in plan["network_security"]["route_rules"]]
                    return {"id": ids["route_table"], "compartment-id": ids["network_compartment"],
                            "vcn-id": ids["vcn"], "route-rules": routes}
                if command == ("network", "service-gateway", "get"):
                    return {"id": ids["service_gateway"], "compartment-id": ids["network_compartment"],
                            "vcn-id": ids["vcn"], "lifecycle-state": "AVAILABLE",
                            "services": [{"service-id": plan["network_security"]["service_gateway_service_id"]}]}
                self.fail(f"unexpected OCI command: {args}")

            with mock.patch.object(preview, "oci", side_effect=fake_oci):
                preview.check_live_network(plan, ids)
            self.assertEqual(len(rule_commands), 2)
            self.assertEqual({command[command.index("--nsg-id") + 1] for command in rule_commands},
                             {ids["network_security_group"], ids["seed_ssh_network_security_group"]})
            drift = True
            with mock.patch.object(preview, "oci", side_effect=fake_oci):
                with self.assertRaisesRegex(ValueError, "network security group rules differ"):
                    preview.check_live_network(plan, ids)

    def test_live_network_requires_every_planned_route_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, _, _, _, _, _ = self.bound_plan_and_inventory(pathlib.Path(directory))
            cases = ({"route_table": None, "service_gateway": None},
                     {"route_table": None}, {"service_gateway": None})
            for missing in cases:
                with self.subTest(missing=missing):
                    ids = dict(plan["resource_ids"])
                    ids.update(missing)
                    with self.assertRaisesRegex(ValueError, "exact route table and service gateway IDs"):
                        preview.check_live_network(plan, ids)
                    changed_plan = {**plan, "resource_ids": ids}
                    with self.assertRaisesRegex(ValueError, "exact route table and service gateway IDs"):
                        preview.required_resource_ids(changed_plan)

    def test_kms_key_must_be_enabled_not_merely_active(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, _, _, _, _, _ = self.bound_plan_and_inventory(pathlib.Path(directory))
            ids = plan["resource_ids"]
            state = "ENABLED"

            def fake_oci(*args, region=None):
                if args[:3] == ("kms", "management", "vault"):
                    return {"id": ids["vault"], "lifecycle-state": "ACTIVE", "vault-type": "DEFAULT",
                            "compartment-id": ids["control_compartment"], "management-endpoint": "https://kms.example"}
                if args[:3] == ("kms", "management", "key"):
                    return {"id": ids["key"], "lifecycle-state": state,
                            "compartment-id": ids["control_compartment"], "vault-id": ids["vault"],
                            "protection-mode": "HSM", "key-shape": {"algorithm": "AES", "length": 32}}
                self.fail(f"unexpected OCI command: {args}")

            with mock.patch.object(preview, "oci", side_effect=fake_oci):
                preview.check_live_vault(plan, ids)
            state = "ACTIVE"
            with mock.patch.object(preview, "oci", side_effect=fake_oci):
                with self.assertRaisesRegex(ValueError, "KMS key state"):
                    preview.check_live_vault(plan, ids)

    def test_seed_create_identity_survives_recording_the_launched_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "plan.json"
            path.write_bytes(preview.PLAN.read_bytes())
            plan = preview.load_plan(path)
            summary = {"anchorSha256": "a" * 64, "manifestSha256": "b" * 64,
                       "releaseReceiptSha256": "c" * 64}
            identity = preview.create_identity(plan, path, summary)
            value = json.loads(path.read_text())
            value["seed_a_create_identity"] = identity
            value["resource_ids"]["instances"]["controller-a"] = \
                "ocid1.instance.oc1.sa-saopaulo-1.controllera"
            path.write_text(json.dumps(value))
            updated = preview.load_plan(path)
            self.assertEqual(preview.create_identity(updated, path, summary), identity)
            changed_without_preserving = json.loads(path.read_text())
            changed_without_preserving["seed_a_create_identity"] = None
            changed_without_preserving["resource_ids"]["instances"]["controller-a"] = None
            path.write_text(json.dumps(changed_without_preserving))
            changed = preview.load_plan(path)
            self.assertNotEqual(preview.create_identity(changed, path, summary), identity)

    def test_seed_user_data_rejects_wrong_scope_and_transport_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = pathlib.Path(directory) / "manifest.json"
            envelope = {"schemaVersion": 1, "keyId": "root", "signature": "signed",
                        "scope": {"domain": "terrascale.bootstrap.manifest", "role": "controller",
                                  "slot": "controller-a", "cell": "GRU"},
                        "payload": {"schemaVersion": 2, "slot": "controller-a",
                                    "seedSlot": "controller-a", "cell": "GRU"}}
            manifest_path.write_text(json.dumps(envelope))
            wire = preview.seed_user_data(manifest_path, None, "GRU")
            self.assertTrue(wire.startswith(b"#cloud-config\n"))
            self.assertIn(b"allow_public_ssh_keys", wire)
            self.assertNotIn(b"ssh_authorized_keys", wire)
            self.assertIn(b"/etc/terrascale-orchestrator/controller-seed-manifest.json", wire)
            envelope["scope"]["cell"] = "FRA"
            manifest_path.write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError, "not a controller-a seed envelope"):
                preview.seed_user_data(manifest_path, None, "GRU")
            envelope["scope"]["cell"] = "GRU"
            envelope["signature"] = "s" * 1200
            manifest_path.write_text(json.dumps(envelope))
            with mock.patch.object(preview, "MAX_USER_DATA_BYTES", 1000):
                with self.assertRaisesRegex(ValueError, "exceeds the OCI metadata transport limit"):
                    preview.seed_user_data(manifest_path, None, "GRU")

    def test_five_host_budget_includes_existing_resources_and_reserves(self):
        cost = preview.estimate(self.plan, self.inventory)
        self.assertEqual(cost["items"]["compute"], "58.6200")
        self.assertEqual(cost["items"]["block_storage"], "10.6250")
        self.assertEqual(cost["items"]["snapshot_reserve"], "8.9250")
        self.assertEqual(cost["assumptions"]["object_growth_reserve_gb"], "10")
        self.assertEqual(cost["assumptions"]["object_staging_reserve_gb"], "10")
        self.assertLess(float(cost["total"]), 100)

    def test_object_growth_and_staging_reserves_are_separate_and_bounded(self):
        expected_gb = Decimal(58) + Decimal(10) + Decimal(10)
        expected = ((expected_gb - Decimal(10)) * Decimal("0.0255")).quantize(Decimal("0.0001"))
        cost = preview.estimate(self.plan, self.inventory)
        self.assertEqual(cost["items"]["object_storage"], str(expected))
        for key in ("object_storage_gb_max", "staging_object_storage_gb_max"):
            with self.subTest(key=key):
                changed = json.loads(preview.PLAN.read_text())
                changed["budget"][key] = 11
                with tempfile.TemporaryDirectory() as directory:
                    path = pathlib.Path(directory) / "plan.json"
                    path.write_text(json.dumps(changed))
                    with self.assertRaisesRegex(ValueError, "storage allowance"):
                        preview.load_plan(path)

    def test_normal_estimate_prices_scoped_custom_images(self):
        image = {"region": self.plan["region"], "id": "ocid1.image.existing",
                 "compartment_id": self.plan["shared_compartment_id"], "display_name": "existing-custom",
                 "lifecycle_state": "AVAILABLE", "billable_size_in_gbs": 8}
        self.inventory["images"].append(image)
        cost = preview.estimate(self.plan, self.inventory)
        self.assertEqual(cost["items"]["custom_image_storage"], "0.2040")
        image["billable_size_in_gbs"] = None
        with self.assertRaisesRegex(ValueError, "no billed GiB"):
            preview.estimate(self.plan, self.inventory)

    def test_image_collection_excludes_platform_images(self):
        region = self.plan["region"]
        compartment = self.plan["shared_compartment_id"]
        rows = [
            {"id": "ocid1.image.platform", "compartment-id": None},
            {"id": "ocid1.image.custom", "compartment-id": compartment,
             "display-name": "custom", "lifecycle-state": "AVAILABLE", "billable-size-in-gbs": 6},
        ]
        with mock.patch.object(preview, "oci", return_value=rows) as oci:
            images = preview.collect_scoped_images([region], [compartment])
        self.assertEqual(images, [{"region": region, "id": "ocid1.image.custom", "compartment_id": compartment,
                                  "display_name": "custom", "lifecycle_state": "AVAILABLE",
                                  "billable_size_in_gbs": 6}])
        oci.assert_called_once_with("compute", "image", "list", "--compartment-id", compartment,
                                    "--all", region=region)

    def test_forgejo_data_volume_and_preview_volumes_use_exact_plan_sizes(self):
        existing_volume = self.inventory["resources"][2]
        existing_volume["size-in-gbs"] = 100
        with self.assertRaisesRegex(ValueError, "unexpected volume size"):
            preview.estimate(self.plan, self.inventory)
        existing_volume["size-in-gbs"] = 50
        control = "ocid1.compartment.control"
        self.inventory["preview_compartment_ids"]["control"] = control
        self.inventory["resources"].append({"kind": "volume", "id": "ocid1.volume.unplanned",
                                            "compartment-id": control, "lifecycle-state": "AVAILABLE",
                                            "size-in-gbs": 100, "vpus-per-gb": 10})
        with self.assertRaisesRegex(ValueError, "unexpected volume size"):
            preview.estimate(self.plan, self.inventory)

    def test_forgejo_data_volume_expectation_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "plan.json"
            changed = json.loads(preview.PLAN.read_text())
            changed["existing_forgejo"]["expected_volume_gb"] = 100
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "bounded cost model"):
                preview.load_plan(path)

    def test_unbudgeted_instance_fails_closed(self):
        self.inventory["resources"].append({"kind": "instance", "id": "ocid1.instance.other",
                                            "compartment-id": self.plan["tenancy_id"],
                                            "lifecycle-state": "RUNNING"})
        with self.assertRaisesRegex(ValueError, "unbudgeted instance"):
            preview.estimate(self.plan, self.inventory)

    def test_unknown_paid_network_resource_fails_closed(self):
        self.inventory["resources"].append({"kind": "nat-gateway", "id": "ocid1.natgateway.other",
                                            "lifecycle-state": "AVAILABLE"})
        with self.assertRaisesRegex(ValueError, "unpriced gateway"):
            preview.estimate(self.plan, self.inventory)

    def test_stale_inventory_fails_closed(self):
        self.inventory["captured_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=16)).isoformat()
        with self.assertRaisesRegex(ValueError, "stale"):
            preview.estimate(self.plan, self.inventory)

    def test_versioned_bucket_fails_closed(self):
        self.inventory["buckets"][0]["versioning"] = "Enabled"
        with self.assertRaisesRegex(ValueError, "unpriced object storage"):
            preview.estimate(self.plan, self.inventory)

    def test_object_growth_can_exceed_budget(self):
        self.inventory["buckets"][0]["bytes"] = 550 * 1024**3
        with self.assertRaisesRegex(ValueError, "exceeds the monthly ceiling"):
            preview.estimate(self.plan, self.inventory)

    def test_extra_public_ip_or_backups_fail_closed(self):
        self.inventory["resources"].append({"kind": "public-ip", "id": "ocid1.publicip.unplanned"})
        with self.assertRaisesRegex(ValueError, "public IP inventory"):
            preview.estimate(self.plan, self.inventory)
        self.inventory["resources"].pop()
        self.inventory["resources"].append({"kind": "volume-backup", "id": "ocid1.volumebackup.unplanned",
                                            "lifecycle-state": "AVAILABLE", "unique-size-in-gbs": 351})
        with self.assertRaisesRegex(ValueError, "backups exceed"):
            preview.estimate(self.plan, self.inventory)

    def test_one_replacement_overlap_expires_after_72_hours(self):
        control = "ocid1.compartment.control"
        workload = "ocid1.compartment.workload"
        self.inventory["preview_compartment_ids"] = {"control": control, "network": None,
                                                      "workload": workload}
        now = dt.datetime.now(dt.timezone.utc)
        self.plan["seed_a_create_identity"] = "seed-a-fixture-identity"
        self.plan["resource_ids"]["instances"]["controller-a"] = "ocid1.instance.oc1.sa-saopaulo-1.preview0"
        for index in range(6):
            row = {"kind": "instance", "id": ("ocid1.instance.oc1.sa-saopaulo-1.preview0" if index == 0 else
                                                  f"ocid1.instance.preview-{index}"),
                   "compartment-id": control if index < 3 else workload, "lifecycle-state": "RUNNING",
                   "shape": "VM.Standard.A1.Flex", "shape-config": {"ocpus": 1, "memory-in-gbs": 6},
                   "time-created": (now - dt.timedelta(hours=73 if index < 5 else 1)).isoformat()}
            if index == 0:
                row["display-name"] = "user-started-seed-a"
                row["freeform-tags"] = {"BootstrapCreateKey": self.plan["seed_a_create_identity"]}
            elif index < 3:
                row["display-name"] = f"controller-{'bc'[index - 1]}"
            else:
                row["freeform-tags"] = {"terrascale-managed-by": "ts-orchestrator",
                                        "terrascale-owner": self.plan["orchestrator_owner"],
                                        "terrascale-resource": "member-host"}
            self.inventory["resources"].append(row)
        self.assertLess(float(preview.estimate(self.plan, self.inventory)["total"]), 100)
        self.inventory["resources"][-1]["time-created"] = (now - dt.timedelta(hours=73)).isoformat()
        with self.assertRaisesRegex(ValueError, "count exceeds"):
            preview.estimate(self.plan, self.inventory)

    def test_seed_a_requires_exact_plan_ocid_and_bootstrap_create_key(self):
        control = "ocid1.compartment.control"
        self.inventory["preview_compartment_ids"]["control"] = control
        seed_id = "ocid1.instance.oc1.sa-saopaulo-1.controller-a"
        self.plan["seed_a_create_identity"] = "seed-a-exact-create-key"
        self.plan["resource_ids"]["instances"]["controller-a"] = seed_id
        self.inventory["resources"].append({
            "kind": "instance", "id": seed_id, "compartment-id": control, "lifecycle-state": "RUNNING",
            "shape": "VM.Standard.A1.Flex", "shape-config": {"ocpus": 1, "memory-in-gbs": 6},
            "freeform-tags": {"BootstrapCreateKey": "different-create-key"},
        })
        with self.assertRaisesRegex(ValueError, "plan-bound controller-a OCID or BootstrapCreateKey"):
            preview.estimate(self.plan, self.inventory)

    def test_seed_preflight_binds_foundation_and_signed_image(self):
        ids = self.plan["resource_ids"]
        ids.update({"control_compartment": "ocid1.compartment.control", "network_compartment": "ocid1.compartment.network",
                    "workload_compartment": "ocid1.compartment.workload", "vcn": "ocid1.vcn.gru",
                    "subnet": "ocid1.subnet.gru", "network_security_group": "ocid1.networksecuritygroup.gru",
                    "security_list": "ocid1.securitylist.gru", "vault": "ocid1.vault.gru",
                    "key": "ocid1.key.gru", "route_table": "ocid1.routetable.gru",
                    "service_gateway": "ocid1.servicegateway.gru",
                    "controller_dynamic_group": "ocid1.dynamicgroup.oc1..controller",
                    "controller_policy": "ocid1.policy.oc1..controller",
                    "objectstorage_key_policy": "ocid1.policy.oc1..objectstorage",
                    "host_dynamic_group": "ocid1.dynamicgroup.oc1..host",
                    "host_policy": "ocid1.policy.oc1..host"})
        self.plan["host_credential_secret"] = {
            "compartment_id": "ocid1.compartment.oc1..secretstore",
            "secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }
        self.inventory["preview_compartment_ids"] = {"control": ids["control_compartment"],
                                                      "network": ids["network_compartment"],
                                                      "workload": ids["workload_compartment"]}
        for kind, key in (("vcn", "vcn"), ("subnet", "subnet"),
                          ("network-security-group", "network_security_group")):
            resource = {"kind": kind, "id": ids[key], "compartment-id": ids["network_compartment"],
                        "lifecycle-state": "AVAILABLE"}
            if kind == "vcn":
                resource["cidr-block"] = self.plan["network_cidr"]
            if kind == "subnet":
                resource.update({"cidr-block": "10.251.0.0/25", "prohibit-public-ip-on-vnic": True,
                                 "prohibit-internet-ingress": True})
            self.inventory["resources"].append(resource)
        for role, name in self.plan["foundation_buckets"].items():
            self.inventory["buckets"].append({"region": self.plan["region"],
                                              "compartment_id": ids["control_compartment"],
                                              "name": name, "bytes": 0, "storage_tier": "Standard",
                                              "public_access_type": "NoPublicAccess",
                                              "kms_key_id": ids["key"] if ids["key"] is not None else
                                              "ocid1.key.oc1.sa-saopaulo-1.fixture",
                                              "versioning": "Enabled" if role in ("head", "material") else "Disabled"})
        image_ocid = "ocid1.image.oc1.sa-saopaulo-1.seedimage"
        receipt = b"signed image receipt fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            inventory_path, admission_path, receipt_path = (root / "inventory.json", root / "admission.json",
                                                            root / "receipt.json")
            inventory_path.write_text(json.dumps(self.inventory))
            receipt_path.write_bytes(receipt)
            cost = preview.estimate(self.plan, self.inventory)
            now = dt.datetime.now(dt.timezone.utc)
            admission = {"schema_version": 2, "admitted_at": now.isoformat(),
                         "expires_at": (now + dt.timedelta(minutes=15)).isoformat(),
                         "plan_sha256": preview.sha256(preview.PLAN),
                         "inventory_sha256": preview.sha256(inventory_path),
                         "preview_compartment_ids": self.inventory["preview_compartment_ids"], "estimate": cost}
            admission_path.write_text(json.dumps(admission))
            summary = {"schemaVersion": 2, "cell": "GRU", "ociRegion": self.plan["region"],
                       "slot": "controller-a", "imageOcid": image_ocid, "imageArchitecture": "linux-arm64",
                       "anchorSha256": "a" * 64, "manifestSha256": "b" * 64,
                       "releaseReceiptSha256": preview.sha256(receipt_path),
                       "profile": {"slot": "controller-a", "compartmentOcid": ids["control_compartment"],
                                   "availabilityDomain": self.plan["availability_domain"],
                                   "faultDomain": "FAULT-DOMAIN-1", "subnetOcid": ids["subnet"],
                                   "networkSecurityGroupOcids": [ids["network_security_group"]],
                                   "shape": "VM.Standard.A1.Flex"}}
            verified = f"verified OCI image={image_ocid} region=GRU revision=abc arch=arm64 sha256=abc"
            with mock.patch.multiple(preview, check_live_compartments=mock.DEFAULT,
                                     check_live_vault=mock.DEFAULT, check_live_network=mock.DEFAULT,
                                     check_live_buckets=mock.DEFAULT, check_live_iam=mock.DEFAULT):
                result = preview.verify_seed_preflight(self.plan, inventory_path, admission_path, summary,
                                                       receipt_path, verified)
            self.assertEqual(result["compartment_id"], ids["control_compartment"])
            self.assertFalse(result["assign_public_ip"])
            self.assertEqual(result["admission_admitted_at"], admission["admitted_at"])
            self.assertEqual(result["admission_expires_at"], admission["expires_at"])
            result["create_identity"] = preview.create_identity(self.plan, preview.PLAN, summary)
            seed_wire = preview.canonical_manual_seed_plan(result)
            self.assertEqual(json.loads(seed_wire)["create_identity"], result["create_identity"])
            summary["profile"]["compartmentOcid"] = ids["workload_compartment"]
            with self.assertRaisesRegex(ValueError, "recorded controller-a profile"):
                with mock.patch.multiple(preview, check_live_compartments=mock.DEFAULT,
                                         check_live_vault=mock.DEFAULT, check_live_network=mock.DEFAULT,
                                         check_live_buckets=mock.DEFAULT, check_live_iam=mock.DEFAULT):
                    preview.verify_seed_preflight(self.plan, inventory_path, admission_path, summary,
                                                  receipt_path, verified)
            summary["profile"]["compartmentOcid"] = ids["control_compartment"]
            admission["expires_at"] = (now - dt.timedelta(seconds=1)).isoformat()
            admission_path.write_text(json.dumps(admission))
            with self.assertRaisesRegex(ValueError, "stale"):
                preview.verify_seed_preflight(self.plan, inventory_path, admission_path, summary,
                                              receipt_path, verified)


    def import_case(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = pathlib.Path(temporary.name)
        control = "ocid1.compartment.control"
        self.inventory["schema_version"] = 3
        self.inventory["regions"] = [self.plan["region"]]
        self.inventory["preview_compartment_ids"]["control"] = control
        self.inventory["object_namespace"] = "test-namespace"
        self.inventory["images"] = []
        self.inventory["current_objects"] = []
        for bucket in self.inventory["buckets"]:
            bucket.update({"region": self.plan["region"], "compartment_id": self.plan["shared_compartment_id"],
                           "object_count": 1, "versions": [{"name": bucket["name"], "version_id": None,
                                                               "is_delete_marker": False, "size": bucket["bytes"],
                                                               "storage_tier": "Standard", "archival_state": None}]})
        head = self.plan["foundation_buckets"]["head"]
        old = {"name": "import/base.qcow2", "version_id": "old-base", "is_delete_marker": False,
               "size": 9, "storage_tier": "Standard", "archival_state": None}
        self.inventory["buckets"].append({"region": self.plan["region"], "compartment_id": control,
                                          "name": head, "object_count": 1, "bytes": 9,
                                          "versioning": "Enabled", "storage_tier": "Standard",
                                          "public_access_type": "NoPublicAccess", "versions": [old]})
        entries = []
        for role in ("base", "final"):
            image_file = directory / f"{role}.qcow2"
            image_file.write_bytes((role * 10).encode())
            entries.append({"role": role, "local_file": str(image_file), "sha256": preview.sha256(image_file),
                            "bytes": image_file.stat().st_size,
                            "object": {"bucket": head, "key": f"import/{role}.qcow2"},
                            "image": {"display_name": f"preview-{role}", "compartment_id": control,
                                      "max_billable_size_in_gbs": 3 if role == "base" else 4,
                                      "evidence": "Reviewed OCI custom image storage maximum"}})
        projection = directory / "projection.json"
        projection.write_text(json.dumps({"schema_version": 1, "imports": entries}))
        return directory, projection, entries

    def add_staged_versions(self, entries):
        head = self.inventory["buckets"][-1]
        head["versions"].append({"name": "import/base.qcow2", "version_id": "marker-base",
                                 "is_delete_marker": True, "size": None,
                                 "storage_tier": "Standard", "archival_state": None})
        for entry in entries:
            if not any(row["version_id"] == f"new-{entry['role']}" for row in head["versions"]):
                head["versions"].append({"name": entry["object"]["key"], "version_id": f"new-{entry['role']}",
                                         "is_delete_marker": False, "size": entry["bytes"],
                                         "storage_tier": "Standard", "archival_state": None})
        head["object_count"] = len(head["versions"])
        head["bytes"] = sum(row["size"] for row in head["versions"] if not row["is_delete_marker"])
        self.inventory["current_objects"] = [self.current_head(entry) for entry in entries]

    def current_head(self, entry):
        now = dt.datetime.now(dt.timezone.utc)
        return {"region": self.plan["region"], "bucket": entry["object"]["bucket"],
                "name": entry["object"]["key"], "version_id": f"new-{entry['role']}",
                "size": entry["bytes"], "last_modified": format_datetime(now, usegmt=True),
                "head_at": now.isoformat()}

    def test_base_only_pre_import_cli_accepts_uploaded_base_receipt(self):
        directory, _, entries = self.import_case()
        base_projection = directory / "base-projection.json"
        base_projection.write_text(json.dumps({"schema_version": 1, "imports": [entries[0]]}))
        projection_hash = preview.sha256(base_projection)
        staged = directory / "base-staged.json"
        staged.write_text(json.dumps({"schema_version": 1, "projection_sha256": projection_hash,
                                      "versions": {"base": "new-base"}}))

        bucket = self.inventory["buckets"][-1]
        bucket["versions"].append({"name": entries[0]["object"]["key"], "version_id": "new-base",
                                   "is_delete_marker": False, "size": entries[0]["bytes"],
                                   "storage_tier": "Standard", "archival_state": None})
        bucket["object_count"] += 1
        bucket["bytes"] += entries[0]["bytes"]
        self.inventory["current_objects"] = [self.current_head(entries[0])]
        inventory_path = directory / "import-inventory.json"
        inventory_path.write_text(json.dumps(self.inventory))
        estimate = preview.import_estimate(self.plan, self.inventory, base_projection, "pre-stage",
                                           staged, plan_path=preview.PLAN)
        admitted = dt.datetime.now(dt.timezone.utc)
        previous = {"schema_version": 3, "phase": "pre-stage", "admitted_at": admitted.isoformat(),
                    "expires_at": (admitted + dt.timedelta(minutes=15)).isoformat(),
                    "plan_sha256": preview.sha256(preview.PLAN),
                    "inventory_sha256": preview.sha256(inventory_path),
                    "projection_sha256": projection_hash,
                    "staged_versions_sha256": preview.sha256(staged),
                    "imported_images_sha256": None, "estimate": estimate}
        previous_path = directory / "upload-readback-admission.json"
        previous_path.write_text(json.dumps(previous))
        output_path = directory / "pre-import-admission.json"
        result = subprocess.run([
            sys.executable, str(preview.ROOT / "preview.py"), "import-admit",
            "--plan", str(preview.PLAN), "--inventory", str(inventory_path),
            "--projection", str(base_projection), "--phase", "pre-import",
            "--staged-versions", str(staged), "--previous-staged-versions", str(staged),
            "--previous-admission", str(previous_path), "--out", str(output_path),
        ], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        admitted_value = json.loads(output_path.read_text())
        self.assertEqual(admitted_value["phase"], "pre-import")
        self.assertEqual(admitted_value["staged_versions_sha256"], preview.sha256(staged))
        self.assertEqual(admitted_value["estimate"]["object_projected_bytes"], 0)

        self.inventory["images"].append({"region": self.plan["region"], "id": "ocid1.image.base",
                                          "compartment_id": "ocid1.compartment.control",
                                          "display_name": entries[0]["image"]["display_name"],
                                          "lifecycle_state": "AVAILABLE", "billable_size_in_gbs": 2})
        inventory_path.write_text(json.dumps(self.inventory))
        images = directory / "base-images.json"
        images.write_text(json.dumps({"schema_version": 1, "projection_sha256": projection_hash,
                                      "images": {"base": "ocid1.image.base"}}))
        image_readback = preview.import_estimate(self.plan, self.inventory, base_projection, "pre-import",
                                                 staged, images, preview.PLAN)
        readback_at = dt.datetime.now(dt.timezone.utc)
        readback = {"schema_version": 3, "phase": "pre-import", "admitted_at": readback_at.isoformat(),
                    "expires_at": (readback_at + dt.timedelta(minutes=15)).isoformat(),
                    "plan_sha256": preview.sha256(preview.PLAN),
                    "inventory_sha256": preview.sha256(inventory_path),
                    "projection_sha256": projection_hash,
                    "staged_versions_sha256": preview.sha256(staged),
                    "imported_images_sha256": preview.sha256(images), "estimate": image_readback}
        readback_path = directory / "base-image-readback-admission.json"
        readback_path.write_text(json.dumps(readback))
        reconcile_path = directory / "base-post-import-admission.json"
        result = subprocess.run([
            sys.executable, str(preview.ROOT / "preview.py"), "import-reconcile",
            "--plan", str(preview.PLAN), "--inventory", str(inventory_path),
            "--projection", str(base_projection), "--staged-versions", str(staged),
            "--imported-images", str(images), "--previous-imported-images", str(images),
            "--previous-admission", str(readback_path), "--out", str(reconcile_path),
        ], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        reconciled = json.loads(reconcile_path.read_text())
        self.assertEqual(reconciled["phase"], "post-import")
        self.assertEqual(reconciled["estimate"]["import_image_billed_gib"], "2")

    def test_full_projection_carries_exact_base_only_admission_lineage(self):
        directory, full_projection, entries = self.import_case()
        unapproved_inventory = directory / "unapproved-inventory.json"
        unapproved_inventory.write_text(json.dumps(self.inventory))
        with mock.patch.object(preview.sys, "argv", ["preview.py", "import-admit", "--plan",
                                                       str(preview.PLAN), "--inventory",
                                                       str(unapproved_inventory), "--projection",
                                                       str(full_projection), "--phase", "pre-stage", "--out",
                                                       str(directory / "unapproved.json")]):
            with self.assertRaisesRegex(ValueError, "requires a verified base-only admission lineage"):
                preview.main()
        base_projection = directory / "base-projection.json"
        base_projection.write_text(json.dumps({"schema_version": 1, "imports": [entries[0]]}))
        base_hash = preview.sha256(base_projection)
        base_staged = directory / "base-staged.json"
        base_staged.write_text(json.dumps({"schema_version": 1, "projection_sha256": base_hash,
                                           "versions": {"base": "new-base"}}))
        base_images = directory / "base-images.json"
        base_images.write_text(json.dumps({"schema_version": 1, "projection_sha256": base_hash,
                                           "images": {"base": "ocid1.image.base"}}))

        bucket = self.inventory["buckets"][-1]
        bucket["versions"].append({"name": entries[0]["object"]["key"], "version_id": "new-base",
                                   "is_delete_marker": False, "size": entries[0]["bytes"],
                                   "storage_tier": "Standard", "archival_state": None})
        bucket["object_count"] += 1
        bucket["bytes"] += entries[0]["bytes"]
        self.inventory["current_objects"] = [self.current_head(entries[0])]
        self.inventory["images"].append({"region": self.plan["region"], "id": "ocid1.image.base",
                                         "compartment_id": "ocid1.compartment.control",
                                         "display_name": "preview-base", "lifecycle_state": "AVAILABLE",
                                         "billable_size_in_gbs": 2})
        inventory_path = directory / "base-inventory.json"
        inventory_path.write_text(json.dumps(self.inventory))
        cost = preview.import_estimate(self.plan, self.inventory, base_projection, "pre-import",
                                       base_staged, base_images, preview.PLAN)
        admitted = dt.datetime.now(dt.timezone.utc)
        admission = {"schema_version": 3, "phase": "pre-import", "admitted_at": admitted.isoformat(),
                     "expires_at": (admitted + dt.timedelta(minutes=15)).isoformat(),
                     "plan_sha256": preview.sha256(preview.PLAN),
                     "inventory_sha256": preview.sha256(inventory_path),
                     "projection_sha256": base_hash,
                     "staged_versions_sha256": preview.sha256(base_staged),
                     "imported_images_sha256": preview.sha256(base_images), "estimate": cost}
        admission_path = directory / "base-admission.json"
        admission_path.write_text(json.dumps(admission))

        lineage = preview.establish_base_lineage(
            self.plan, full_projection, base_projection, inventory_path, admission_path,
            base_staged, base_images, preview.PLAN)
        self.assertEqual(lineage["base_version_id"], "new-base")
        self.assertEqual(lineage["base_image_id"], "ocid1.image.base")
        self.assertEqual(lineage["estimate"], cost)
        full_pre_stage = preview.import_estimate(self.plan, self.inventory, full_projection, "pre-stage",
                                                 plan_path=preview.PLAN, base_lineage=lineage)
        self.assertEqual(full_pre_stage["object_projected_bytes"], entries[1]["bytes"])
        self.assertEqual(full_pre_stage["import_image_billed_gib"], "6")

        full_staged = directory / "full-staged.json"
        full_staged.write_text(json.dumps({"schema_version": 1,
                                           "projection_sha256": preview.sha256(full_projection),
                                           "versions": {"base": "changed-base", "final": "new-final"}}))
        with self.assertRaisesRegex(ValueError, "changed the admitted base object version"):
            preview.import_estimate(self.plan, self.inventory, full_projection, "pre-import",
                                    full_staged, plan_path=preview.PLAN, base_lineage=lineage)

        full_value = json.loads(full_projection.read_text())
        full_value["imports"][0]["image"]["evidence"] = "different evidence"
        full_projection.write_text(json.dumps(full_value))
        with self.assertRaisesRegex(ValueError, "base row differs"):
            preview.establish_base_lineage(
                self.plan, full_projection, base_projection, inventory_path, admission_path,
                base_staged, base_images, preview.PLAN)

        full_value["imports"][0]["image"]["evidence"] = entries[0]["image"]["evidence"]
        full_projection.write_text(json.dumps(full_value))
        admission["estimate"]["total"] = "0.00"
        admission_path.write_text(json.dumps(admission))
        with self.assertRaisesRegex(ValueError, "cost differs"):
            preview.establish_base_lineage(
                self.plan, full_projection, base_projection, inventory_path, admission_path,
                base_staged, base_images, preview.PLAN)

    def test_import_three_gates_count_versions_and_actual_image_gib(self):
        directory, projection, entries = self.import_case()
        self.inventory["images"].append({"region": self.plan["region"], "id": "ocid1.image.existing",
                                         "compartment_id": self.plan["shared_compartment_id"],
                                         "display_name": "existing-custom", "lifecycle_state": "AVAILABLE",
                                         "billable_size_in_gbs": 4})
        first = preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        self.assertEqual(first["object_projected_bytes"], sum(row["bytes"] for row in entries))
        self.assertEqual(first["import_image_billed_gib"], "7")
        exact_object_gb = Decimal(sum(row["bytes"] for row in self.inventory["buckets"]) +
                                  first["object_projected_bytes"]) / Decimal(1_000_000_000)
        object_gb = max(exact_object_gb, Decimal("57.93")) + Decimal(10) + Decimal(10)
        expected_object_cost = ((object_gb - Decimal(10)) * Decimal("0.0255")).quantize(Decimal("0.0001"))
        self.assertEqual(first["items"]["object_storage"], str(expected_object_cost))
        head = self.inventory["buckets"][-1]
        head["versions"].append({"name": entries[0]["object"]["key"], "version_id": "new-base",
                                 "is_delete_marker": False, "size": entries[0]["bytes"],
                                 "storage_tier": "Standard", "archival_state": None})
        head["object_count"] += 1
        head["bytes"] += entries[0]["bytes"]
        self.inventory["current_objects"] = [self.current_head(entries[0])]
        base_staged = directory / "base-staged.json"
        base_staged.write_text(json.dumps({"schema_version": 1, "projection_sha256": preview.sha256(projection),
                                           "versions": {"base": "new-base"}}))
        middle = preview.import_estimate(self.plan, self.inventory, projection, "pre-stage", base_staged)
        self.assertEqual(middle["object_projected_bytes"], entries[1]["bytes"])
        self.assertEqual(first["items"]["object_storage"], middle["items"]["object_storage"])
        self.add_staged_versions(entries)
        staged = directory / "staged.json"
        staged.write_text(json.dumps({"schema_version": 1, "projection_sha256": preview.sha256(projection),
                                      "versions": {"base": "new-base", "final": "new-final"}}))
        second = preview.import_estimate(self.plan, self.inventory, projection, "pre-import", staged)
        self.assertEqual(second["object_projected_bytes"], 0)
        self.assertEqual(first["items"]["object_storage"], second["items"]["object_storage"])
        old = self.inventory["buckets"][-1]["versions"][0]
        self.inventory["buckets"][-1]["bytes"] += entries[0]["bytes"] - old["size"]
        old["size"] = entries[0]["bytes"]
        old_receipt = directory / "old-staged.json"
        old_receipt.write_text(json.dumps({"schema_version": 1, "projection_sha256": preview.sha256(projection),
                                           "versions": {"base": "old-base", "final": "new-final"}}))
        with self.assertRaisesRegex(ValueError, "not the current import source"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-import", old_receipt)
        old["size"] = 9
        self.inventory["buckets"][-1]["bytes"] -= entries[0]["bytes"] - 9
        self.inventory["current_objects"][0]["version_id"] = "old-base"
        self.inventory["current_objects"][0]["size"] = 9
        with self.assertRaisesRegex(ValueError, "not the current import source"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-import", staged)
        self.inventory["current_objects"][0] = self.current_head(entries[0])
        self.inventory["current_objects"].pop(0)
        with self.assertRaisesRegex(ValueError, "not the current import source"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-import", staged)
        self.inventory["current_objects"].insert(0, self.current_head(entries[0]))
        self.inventory["current_objects"][0]["version_id"] = "marker-base"
        self.inventory["current_objects"][0]["size"] = 0
        with self.assertRaisesRegex(ValueError, "differs from retained"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-import", staged)
        self.inventory["current_objects"][0] = self.current_head(entries[0])
        self.assertEqual(self.inventory["buckets"][-1]["bytes"], 9 + sum(row["bytes"] for row in entries))
        base = directory / "base-images.json"
        base.write_text(json.dumps({"schema_version": 1, "projection_sha256": preview.sha256(projection),
                                    "images": {"base": "ocid1.image.base"}}))
        self.inventory["images"].append({"region": self.plan["region"], "id": "ocid1.image.base",
                                         "compartment_id": "ocid1.compartment.control", "display_name": "preview-base",
                                         "lifecycle_state": "AVAILABLE", "billable_size_in_gbs": 2})
        third = preview.import_estimate(self.plan, self.inventory, projection, "pre-import", staged, base)
        self.assertEqual(third["import_image_billed_gib"], "6")
        both = directory / "both-images.json"
        both.write_text(json.dumps({"schema_version": 1, "projection_sha256": preview.sha256(projection),
                                    "images": {"base": "ocid1.image.base", "final": "ocid1.image.final"}}))
        self.inventory["images"].append({"region": self.plan["region"], "id": "ocid1.image.final",
                                         "compartment_id": "ocid1.compartment.control", "display_name": "preview-final",
                                         "lifecycle_state": "AVAILABLE", "billable_size_in_gbs": 3})
        final = preview.import_estimate(self.plan, self.inventory, projection, "post-import", staged, both)
        self.assertEqual(final["import_image_billed_gib"], "5")
        self.assertEqual(final["object_projected_bytes"], 0)
        post_import = preview.estimate(self.plan, {**self.inventory, "schema_version": 2})
        self.assertEqual(final["existing_image_billed_gib"], "4")
        self.assertEqual(final["items"]["custom_image_storage"], "0.2295")
        self.assertEqual(final["items"]["custom_image_storage"], post_import["items"]["custom_image_storage"])
        self.inventory["images"][-1]["billable_size_in_gbs"] = None
        with self.assertRaisesRegex(ValueError, "no billed GiB"):
            preview.import_estimate(self.plan, self.inventory, projection, "post-import", staged, both)
        self.inventory["images"][-1]["billable_size_in_gbs"] = 5
        with self.assertRaisesRegex(ValueError, "exceeds reviewed"):
            preview.import_estimate(self.plan, self.inventory, projection, "post-import", staged, both)
        self.inventory["images"][-1]["billable_size_in_gbs"] = 3
        self.inventory["images"][-1]["id"] = "ocid1.image.unrelated"
        with self.assertRaisesRegex(ValueError, "identity is absent"):
            preview.import_estimate(self.plan, self.inventory, projection, "post-import", staged, both)
        self.inventory["images"][-1]["id"] = "ocid1.image.final"
        self.inventory["images"][-1]["lifecycle_state"] = "IMPORTING"
        with self.assertRaisesRegex(ValueError, "unavailable"):
            preview.import_estimate(self.plan, self.inventory, projection, "post-import", staged, both)
        self.inventory["images"][-1]["lifecycle_state"] = "AVAILABLE"
        self.inventory["buckets"][-1]["versions"][-1]["size"] += 1
        self.inventory["buckets"][-1]["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "differs from retained"):
            preview.import_estimate(self.plan, self.inventory, projection, "post-import", staged, both)

    def test_import_fails_closed_on_missing_or_duplicate_storage_facts(self):
        directory, projection, entries = self.import_case()
        self.inventory["buckets"][-1]["versions"].append({"name": "x", "version_id": "x", "is_delete_marker": False,
                                                           "size": None, "storage_tier": "Standard", "archival_state": None})
        with self.assertRaisesRegex(ValueError, "size"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        self.inventory["buckets"][-1]["versions"].clear()
        self.add_staged_versions(entries)
        self.inventory["buckets"][-1]["versions"].append(dict(self.inventory["buckets"][-1]["versions"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate object version"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        self.inventory["buckets"][-1]["versions"].pop()
        self.inventory["buckets"][-1]["versions"][0]["storage_tier"] = "Archive"
        with self.assertRaisesRegex(ValueError, "tier"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        self.inventory["buckets"][-1]["versions"][0]["storage_tier"] = "Standard"
        self.inventory["images"] = [{"region": self.plan["region"], "id": "ocid1.image.old",
                                     "compartment_id": self.plan["shared_compartment_id"], "display_name": "old",
                                     "lifecycle_state": "IMPORTING", "billable_size_in_gbs": None}]
        with self.assertRaisesRegex(ValueError, "no billed GiB"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        self.inventory["images"][0]["billable_size_in_gbs"] = 1
        self.inventory["images"].append(dict(self.inventory["images"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")

    def test_import_overbound_size_and_stale_inventory_deny(self):
        directory, projection, entries = self.import_case()
        entries[0]["image"]["max_billable_size_in_gbs"] = 500
        projection.write_text(json.dumps({"schema_version": 1, "imports": entries}))
        with self.assertRaisesRegex(ValueError, "exceeds the monthly ceiling"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        entries[0]["image"]["max_billable_size_in_gbs"] = 3
        projection.write_text(json.dumps({"schema_version": 1, "imports": entries}))
        entries[0]["image"]["max_billable_size_in_gbs"] = 3.5
        projection.write_text(json.dumps({"schema_version": 1, "imports": entries}))
        with self.assertRaisesRegex(ValueError, "positive integer"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        entries[0]["image"]["max_billable_size_in_gbs"] = 3
        projection.write_text(json.dumps({"schema_version": 1, "imports": entries}))
        entries[0]["local_file"] = str(directory / "missing.qcow2")
        projection.write_text(json.dumps({"schema_version": 1, "imports": entries}))
        with self.assertRaisesRegex(ValueError, "local file"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        entries[0]["local_file"] = str(directory / "base.qcow2")
        projection.write_text(json.dumps({"schema_version": 1, "imports": entries}))
        self.inventory["captured_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=16)).isoformat()
        with self.assertRaisesRegex(ValueError, "stale"):
            preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")

    def test_expired_prior_admission_remains_lineage_only(self):
        directory, projection, _ = self.import_case()
        now = dt.datetime.now(dt.timezone.utc)
        admitted = now - dt.timedelta(hours=1)
        prior = {"schema_version": 3, "phase": "pre-stage", "plan_sha256": preview.sha256(preview.PLAN),
                 "projection_sha256": preview.sha256(projection), "staged_versions_sha256": None,
                 "admitted_at": admitted.isoformat(),
                 "expires_at": (admitted + dt.timedelta(minutes=15)).isoformat(),
                 "estimate": preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")}
        prior_path = directory / "prior.json"
        prior_path.write_text(json.dumps(prior))
        self.assertEqual(preview.verify_previous_import_admission(
            prior_path, "pre-stage", preview.sha256(projection), preview.PLAN), prior)
        with self.assertRaisesRegex(ValueError, "does not bind"):
            preview.verify_previous_import_admission(prior_path, "pre-stage", "0" * 64, preview.PLAN)
        prior["expires_at"] = (admitted + dt.timedelta(minutes=30)).isoformat()
        prior_path.write_text(json.dumps(prior))
        with self.assertRaisesRegex(ValueError, "invalid timestamps"):
            preview.verify_previous_import_admission(prior_path, "pre-stage", preview.sha256(projection), preview.PLAN)

    def test_current_head_uses_oci_cli_version_header_and_requires_it(self):
        response = {"version-id": "c1e5a9ab-ec20-428f-a7b2-ebe560b2bd5e",
                    "content-length": "620224512", "last-modified": "Sun, 27 Sep 2026 23:56:25 GMT"}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(response), stderr="")
        with mock.patch.object(preview.subprocess, "run", return_value=completed) as run:
            current = preview.current_object_head("namespace", "bucket", "key", self.plan["region"])
            self.assertEqual(current["version_id"], "c1e5a9ab-ec20-428f-a7b2-ebe560b2bd5e")
            self.assertEqual(current["size"], 620224512)
            self.assertNotIn("--version-id", run.call_args.args[0])
        completed.stdout = json.dumps({"opc-version-id": "unsupported-alias", "content-length": "123",
                                       "last-modified": "Sun, 27 Sep 2026 23:56:25 GMT"})
        with mock.patch.object(preview.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "version identity"):
                preview.current_object_head("namespace", "bucket", "key", self.plan["region"])


if __name__ == "__main__":
    unittest.main()
