import datetime as dt
import importlib.util
import base64
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from decimal import Decimal
from email.utils import format_datetime
from types import SimpleNamespace
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
        self.plan["bootstrap_object_prefix"] = "fixture-deployment"
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
                {"kind": "internet-gateway", "id": existing["internet_gateway_id"], "compartment-id": shared,
                 "vcn-id": existing["vcn_id"], "lifecycle-state": "AVAILABLE"},
            ],
        }

    def bound_plan_and_inventory(self, directory):
        plan_value = json.loads(preview.PLAN.read_text())
        plan_value["bootstrap_object_prefix"] = "fixture-deployment"
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
            "seed_ssh_network_security_group": "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.testseednsg",
            "workload_network_security_group": "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.testworkloadnsg",
            "security_list": "ocid1.securitylist.oc1.sa-saopaulo-1.testsecuritylist",
            "route_table": "ocid1.routetable.oc1.sa-saopaulo-1.testroute",
            "service_gateway": "ocid1.servicegateway.oc1.sa-saopaulo-1.testgateway",
            "local_peering_gateway": "ocid1.localpeeringgateway.oc1.sa-saopaulo-1.testcellpeering",
            "internet_gateway": "ocid1.internetgateway.oc1.sa-saopaulo-1.testpublicgateway",
            "public_subnet": "ocid1.subnet.oc1.sa-saopaulo-1.testpublicsubnet",
            "public_route_table": "ocid1.routetable.oc1.sa-saopaulo-1.testpublicroute",
            "public_security_list": "ocid1.securitylist.oc1.sa-saopaulo-1.testpublicsecuritylist",
            "network_load_balancer": "ocid1.networkloadbalancer.oc1.sa-saopaulo-1.testpublicbalancer",
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
        plan_value["operator_gateway"]["local_peering_gateway_id"] = (
            "ocid1.localpeeringgateway.oc1.sa-saopaulo-1.testforgejopeering")
        plan_path = directory / "plan.json"
        plan_path.write_text(json.dumps(plan_value))
        plan = preview.load_plan(plan_path)
        inventory = deepcopy(self.inventory)
        inventory["plan_sha256"] = preview.sha256(plan_path)
        inventory["preview_compartment_ids"] = {
            role: ids[f"{role}_compartment"] for role in ("control", "network", "workload")}
        inventory["resources"] += [
            {"kind": "local-peering-gateway", "id": ids["local_peering_gateway"], "lifecycle-state": "AVAILABLE",
             "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"]},
            {"kind": "local-peering-gateway", "id": plan["operator_gateway"]["local_peering_gateway_id"],
             "lifecycle-state": "AVAILABLE", "compartment-id": plan["shared_compartment_id"],
             "vcn-id": plan["existing_forgejo"]["vcn_id"]},
            {"kind": "internet-gateway", "id": ids["internet_gateway"], "lifecycle-state": "AVAILABLE",
             "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"]},
            {"kind": "network-load-balancer", "id": ids["network_load_balancer"], "lifecycle-state": "ACTIVE",
             "compartment-id": ids["network_compartment"], "subnet-id": ids["public_subnet"]},
        ]
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

    def assert_plan_rejected(self, change, message):
        with tempfile.TemporaryDirectory() as directory:
            plan = json.loads(preview.PLAN.read_text())
            change(plan)
            path = pathlib.Path(directory) / "plan.json"
            path.write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError, message):
                preview.load_plan(path)

    def test_checked_in_plan_pins_reconciled_private_ports(self):
        network_security = self.plan["network_security"]
        pinned = lambda key: {(rule["tcp_min"], rule["source"]) for rule in network_security[key]}
        gateway = "10.250.10.155/32"
        self.assertEqual(pinned("nsg_rules"), {(4222, "10.251.0.0/25"), (4222, gateway),
                                               (6222, "10.251.0.0/25"), (8443, "10.251.0.0/25")})
        self.assertEqual(pinned("seed_ssh_nsg_rules"), {(22, "10.251.0.18/32"), (22, gateway)})
        self.assertEqual(pinned("workload_nsg_rules"), {(9443, "10.251.0.21/32"), (9443, "10.251.0.22/32"),
                                                        (9465, "10.251.0.18/32"), (9465, gateway),
                                                        (9465, "10.251.0.128/26")})
        self.assertEqual(self.plan["public_api"], {"subnet_cidr": "10.251.0.128/26", "listener_port": 443,
                                                   "client_port": 9465})
        self.assertEqual(network_security["security_list_ingress_rules"], [])
        self.assertEqual(self.plan["operator_gateway"], {"private_ip": "10.250.10.155", "vcn_cidr": "10.250.0.0/16",
                                                         "local_peering_gateway_id": None})

    def test_operator_gateway_private_outside_cell_inside_its_vcn(self):
        def gateway(**fields):
            return lambda plan: plan["operator_gateway"].update(fields)

        for name, change, message in (
                ("public address", gateway(private_ip="163.176.73.79"), "operator gateway"),
                ("inside the cell", gateway(private_ip="10.251.0.40", vcn_cidr="10.251.0.0/16"), "operator gateway"),
                ("outside its VCN", gateway(private_ip="10.9.0.4"), "operator gateway"),
                ("public VCN", gateway(private_ip="163.176.73.79", vcn_cidr="163.176.0.0/16"), "operator gateway"),
                ("noncanonical address", gateway(private_ip="10.250.010.155"), "operator gateway"),
                ("integer address", gateway(private_ip=180000000), "operator gateway"),
                ("host bits in VCN", gateway(vcn_cidr="10.250.10.0/16"), "operator gateway"),
                ("wrong peering kind", gateway(local_peering_gateway_id="ocid1.drg.oc1.sa-saopaulo-1.x"),
                 "invalid localpeeringgateway OCID"),
                ("extra field", gateway(public_ip="163.176.73.79"), "operator gateway"),
                ("missing declaration", lambda plan: plan.pop("operator_gateway"), "operator gateway")):
            with self.subTest(case=name):
                self.assert_plan_rejected(change, message)

    def test_public_api_subnet_inside_cell_outside_private_subnet(self):
        def public(**fields):
            return lambda plan: plan["public_api"].update(fields)

        def ids_without_public_api(plan):
            plan["public_api"] = None
            plan["resource_ids"]["network_load_balancer"] = "ocid1.networkloadbalancer.oc1.sa-saopaulo-1.x"

        for name, change, message in (
                ("overlaps private subnet", public(subnet_cidr="10.251.0.64/26"), "outside the private subnet"),
                ("outside the VCN", public(subnet_cidr="10.9.0.0/26"), "inside the cell VCN"),
                ("host bits", public(subnet_cidr="10.251.0.130/26"), "inside the cell VCN"),
                ("boolean port", public(client_port=True), "exactly its subnet CIDR"),
                ("port zero", public(listener_port=0), "exactly its subnet CIDR"),
                ("extra field", public(public_ip="150.230.93.187"), "exactly its subnet CIDR"),
                ("missing declaration", lambda plan: plan.pop("public_api"), "public TerraBase API or null"),
                ("resources without API", ids_without_public_api, "require a declared public API")):
            with self.subTest(case=name):
                self.assert_plan_rejected(change, message)

    def test_public_subnet_reaches_members_only_on_client_port(self):
        def rule(port, source):
            return {"direction": "INGRESS", "protocol": "6", "source": source, "source_type": "CIDR_BLOCK",
                    "destination": None, "destination_type": None, "tcp_min": port, "tcp_max": port,
                    "udp_min": None, "udp_max": None, "stateless": False}

        def add(key, value):
            return lambda plan: plan["network_security"][key].append(value)

        for name, change in (
                ("controller NATS from the whole VCN", add("nsg_rules", rule(4222, "10.251.0.0/24"))),
                ("controller enrollment from public subnet", add("nsg_rules", rule(8443, "10.251.0.128/26"))),
                ("member replication from public subnet", add("workload_nsg_rules", rule(9443, "10.251.0.128/26"))),
                ("SSH from part of public subnet", add("seed_ssh_nsg_rules", rule(22, "10.251.0.160/27")))):
            with self.subTest(case=name):
                self.assert_plan_rejected(change, "public API subnet beyond the member client port")

    def test_rule_sources_limited_to_cell_or_gateway(self):
        def rule(port, source, **fields):
            return {"direction": "INGRESS", "protocol": "6", "source": source, "source_type": "CIDR_BLOCK",
                    "destination": None, "destination_type": None, "tcp_min": port, "tcp_max": port,
                    "udp_min": None, "udp_max": None, "stateless": False, **fields}

        def add(key, value):
            return lambda plan: plan["network_security"][key].append(value)

        def without_gateway(plan):
            plan["operator_gateway"] = None
            plan["network_security"]["route_rules"] = plan["network_security"]["route_rules"][:1]

        for name, change, message in (
                ("internet source", add("nsg_rules", rule(4222, "0.0.0.0/0")), "outside the private cell"),
                ("whole gateway subnet", add("nsg_rules", rule(4222, "10.250.10.0/24")), "outside the private cell"),
                ("gateway on enrollment", add("nsg_rules", rule(8443, "10.250.10.155/32")), "single allowed port"),
                ("gateway on replication", add("workload_nsg_rules", rule(9443, "10.250.10.155/32")),
                 "single allowed port"),
                ("gateway in security list", add("security_list_ingress_rules", rule(4222, "10.250.10.155/32")),
                 "single allowed port"),
                ("stateless gateway rule", add("nsg_rules", rule(6222, "10.250.10.155/32", stateless=True)),
                 "stateful CIDR ingress"),
                ("NSG egress", add("nsg_rules", rule(4222, None, direction="EGRESS", source_type=None,
                                                      destination="0.0.0.0/0", destination_type="CIDR_BLOCK")),
                 "stateful CIDR ingress"),
                ("service source", add("nsg_rules", rule(4222, "all-gru-services-in-oracle-services-network",
                                                          source_type="SERVICE_CIDR_BLOCK")),
                 "stateful CIDR ingress"),
                ("egress to gateway", add("security_list_egress_rules", rule(
                    4222, None, direction="EGRESS", source_type=None, destination="10.250.10.155/32",
                    destination_type="CIDR_BLOCK")), "egress leaves the private cell"),
                ("egress to internet", add("security_list_egress_rules", rule(
                    443, None, direction="EGRESS", source_type=None, destination="0.0.0.0/0",
                    destination_type="CIDR_BLOCK")), "egress leaves the private cell"),
                ("link-local TCP", add("security_list_egress_rules", rule(
                    123, None, direction="EGRESS", source_type=None, destination="169.254.169.254/32",
                    destination_type="CIDR_BLOCK")), "egress leaves the private cell"),
                ("gateway rules without gateway", without_gateway, "outside the private cell")):
            with self.subTest(case=name):
                self.assert_plan_rejected(change, message)

    def test_route_rules_service_gateway_plus_single_gateway_peering(self):
        peering = {"destination": "10.250.10.155/32", "destination_type": "CIDR_BLOCK",
                   "network_entity_id": "{local_peering_gateway_id}"}

        def routes(*rows):
            return lambda plan: plan["network_security"].update(
                route_rules=[plan["network_security"]["route_rules"][0], *rows] if rows else
                plan["network_security"]["route_rules"][:1])

        def unplanned_cell_peering(plan):
            plan["operator_gateway"] = None
            plan["network_security"]["route_rules"] = plan["network_security"]["route_rules"][:1]
            for key in ("nsg_rules", "seed_ssh_nsg_rules", "workload_nsg_rules"):
                plan["network_security"][key] = [rule for rule in plan["network_security"][key]
                                                 if rule["source"] != "10.250.10.155/32"]
            plan["resource_ids"]["local_peering_gateway"] = "ocid1.localpeeringgateway.oc1.sa-saopaulo-1.x"

        for name, change, message in (
                ("missing peering route", routes(), "exact service gateway route"),
                ("duplicate peering route", routes(peering, peering), "exact service gateway route"),
                ("whole gateway VCN", routes(dict(peering, destination="10.250.0.0/16")),
                 "exact service gateway route"),
                ("default route", routes(dict(peering, destination="0.0.0.0/0")), "exact service gateway route"),
                ("wrong placeholder", routes(dict(peering, network_entity_id="{service_gateway_id}")),
                 "exact service gateway route"),
                ("peering without gateway", unplanned_cell_peering, "requires a declared operator gateway")):
            with self.subTest(case=name):
                self.assert_plan_rejected(change, message)
        def without_service_gateway(plan):
            network_security = plan["network_security"]
            network_security.update(route_rules=[], service_gateway_service_id=None, service_gateway_cidr_block=None)
            network_security["security_list_egress_rules"] = [
                rule for rule in network_security["security_list_egress_rules"]
                if rule["destination_type"] != "SERVICE_CIDR_BLOCK"]

        self.assert_plan_rejected(without_service_gateway, "route resources without a service gateway")

    def test_inventory_admits_only_recorded_gateways_and_balancer(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, plan_path, inventory, _, _, _ = self.bound_plan_and_inventory(pathlib.Path(directory))
            preview.verify_inventory(plan, inventory, plan_path=plan_path)
            ids = plan["resource_ids"]
            forgejo_igw = plan["existing_forgejo"]["internet_gateway_id"]

            def extra(row):
                return lambda resources: resources + [row]

            def without(kind, resource_id):
                return lambda resources: [row for row in resources
                                          if row["kind"] != kind or row["id"] != resource_id]

            def moved(kind, resource_id, **fields):
                return lambda resources: [dict(row, **fields) if row["kind"] == kind and row["id"] == resource_id
                                          else row for row in resources]

            for name, change, message in (
                    ("cell internet gateway", extra({"kind": "internet-gateway", "id": "ocid1.internetgateway.x",
                                                     "compartment-id": ids["network_compartment"],
                                                     "vcn-id": ids["vcn"], "lifecycle-state": "AVAILABLE"}),
                     "internet gateway inventory"),
                    ("missing Forgejo internet gateway", without("internet-gateway", forgejo_igw),
                     "internet gateway inventory"),
                    ("Forgejo gateway in another VCN", moved("internet-gateway", forgejo_igw, **{"vcn-id": "x"}),
                     "internet gateway inventory"),
                    ("missing public API gateway", without("internet-gateway", ids["internet_gateway"]),
                     "internet gateway inventory"),
                    ("second balancer", extra({"kind": "network-load-balancer", "id": "ocid1.networkloadbalancer.x",
                                               "compartment-id": ids["network_compartment"],
                                               "subnet-id": ids["subnet"], "lifecycle-state": "ACTIVE"}),
                     "network load balancer inventory"),
                    ("balancer in the private subnet", moved("network-load-balancer", ids["network_load_balancer"],
                                                             **{"subnet-id": ids["subnet"]}),
                     "network load balancer inventory"),
                    ("classic load balancer", extra({"kind": "load-balancer", "id": "ocid1.loadbalancer.x",
                                                     "compartment-id": ids["network_compartment"],
                                                     "lifecycle-state": "ACTIVE"}), "unpriced gateway"),
                    ("unrecorded peering", extra({"kind": "local-peering-gateway", "id": "ocid1.localpeeringgateway.x",
                                                  "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"],
                                                  "lifecycle-state": "AVAILABLE"}), "local peering gateway"),
                    ("missing cell peering", without("local-peering-gateway", ids["local_peering_gateway"]),
                     "local peering gateway"),
                    ("cell peering in workload", moved("local-peering-gateway", ids["local_peering_gateway"],
                                                       **{"compartment-id": ids["workload_compartment"]}),
                     "local peering gateway")):
                with self.subTest(case=name):
                    changed = dict(inventory, resources=change(deepcopy(inventory["resources"])))
                    with self.assertRaisesRegex(ValueError, message):
                        preview.verify_inventory(plan, changed, plan_path=plan_path)
            deleted = dict(inventory, resources=[*inventory["resources"], {
                "kind": "network-load-balancer", "id": "ocid1.networkloadbalancer.x", "lifecycle-state": "DELETED",
                "compartment-id": ids["network_compartment"], "subnet-id": ids["public_subnet"]}])
            preview.verify_inventory(plan, deleted, plan_path=plan_path)

    def test_collect_inventory_lists_gateway_kinds(self):
        region = self.plan["region"]
        compartments = [self.plan["tenancy_id"], self.plan["parent_compartment_id"], self.plan["shared_compartment_id"]]
        commands = []
        forgejo_igw = {"id": self.plan["existing_forgejo"]["internet_gateway_id"], "lifecycle-state": "AVAILABLE",
                       "compartment-id": self.plan["shared_compartment_id"],
                       "vcn-id": self.plan["existing_forgejo"]["vcn_id"]}

        def fake_oci(*args, region=None):
            commands.append(args)
            if args[:3] == ("iam", "region-subscription", "list"):
                return [{"region-name": self.plan["region"], "status": "READY"}]
            if args[:3] == ("os", "ns", "get"):
                return "namespace"
            if (args[:3] == ("network", "internet-gateway", "list") and
                    args[args.index("--compartment-id") + 1] == self.plan["shared_compartment_id"]):
                return [forgejo_igw]
            return []

        with mock.patch.object(preview, "oci", side_effect=fake_oci):
            inventory = preview.collect_inventory(self.plan)
        for command_prefix in (("network", "internet-gateway", "list"), ("network", "local-peering-gateway", "list"),
                               ("nlb", "network-load-balancer", "list")):
            kind = command_prefix[1]
            listed = [command[command.index("--compartment-id") + 1] for command in commands
                      if command[:3] == command_prefix and "--all" in command]
            self.assertEqual(sorted(listed), sorted(compartments), kind)
        self.assertIn({"kind": "internet-gateway", "region": region, **forgejo_igw}, inventory["resources"])

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
                    "lifecycle-state": "ACTIVE", "statements": preview.required_controller_statements(
                        plan, ids, preview.required_plan_bootstrap_prefix(plan))},
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
                preview.check_live_iam(plan, ids, preview.required_plan_bootstrap_prefix(plan))
            resources[ids["host_policy"]]["statements"] = [host_statement.replace(
                secret_scope["secret_id"], "ocid1.secret.oc1.sa-saopaulo-1.other")]
            with mock.patch.object(preview, "oci", side_effect=fake_oci):
                with self.assertRaisesRegex(ValueError, "selected secret and compartment"):
                    preview.check_live_iam(plan, ids, preview.required_plan_bootstrap_prefix(plan))

    def test_controller_storage_grants_only_signed_scope_versions_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, _, _, _, _, _ = self.bound_plan_and_inventory(pathlib.Path(directory))
            plan["bootstrap_object_prefix"] = "tenant-a/deployment-29"
            ids = plan["resource_ids"]
            group = plan["identity"]["controller_dynamic_group_name"]
            control = plan["preview_compartment_names"]["control"]
            ledger = plan["foundation_buckets"]["ledger"]
            head = plan["foundation_buckets"]["head"]
            common = f"Allow dynamic-group {group} to manage objects in compartment {control} where all "
            actual = preview.controller_storage_statements(plan, ids, preview.required_plan_bootstrap_prefix(plan))
            self.assertEqual(actual[:4], [
                common + f"{{target.bucket.name='{ledger}', target.object.name='tenant-a/deployment-29/bootstrap/v1/*', "
                "any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE'}}",
                common + f"{{target.bucket.name='{ledger}', target.object.name='tenant-a/deployment-29/bootstrap/v2/*', "
                "any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE'}}",
                common + f"{{target.bucket.name='{head}', target.object.name='tenant-a/deployment-29/bootstrap/v1/*', "
                "any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE', "
                "request.permission='OBJECT_OVERWRITE'}}",
                common + f"{{target.bucket.name='{head}', target.object.name='tenant-a/deployment-29/bootstrap/v2/*', "
                "any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE', "
                "request.permission='OBJECT_OVERWRITE'}}",
            ])
            self.assertEqual(len(actual), 7)
            self.assertIn("target.object.name='material/v2/*'", actual[4])
            self.assertIn(f"target.key.id='{ids['key']}'", actual[5])
            self.assertEqual(actual[6], f"Allow dynamic-group {group} to use key-delegate in compartment {control} "
                                        f"where target.key.id='{ids['key']}'")
            self.assertFalse(any("OBJECT_LIST" in row or "OBJECT_INSPECT" in row for row in actual))

            plan["bootstrap_object_prefix"] = ""
            unprefixed = preview.controller_storage_statements(
                plan, ids, preview.required_plan_bootstrap_prefix(plan))
            self.assertIn("target.object.name='bootstrap/v1/*'", unprefixed[0])
            self.assertIn("target.object.name='bootstrap/v2/*'", unprefixed[1])

            missing = deepcopy(plan)
            del missing["bootstrap_object_prefix"]
            with self.assertRaisesRegex(ValueError, "explicit bootstrap storage prefix"):
                preview.inspect_foundation(missing, pathlib.Path(directory) / "plan.json",
                                           pathlib.Path(directory) / "inventory.json",
                                           pathlib.Path(directory) / "admission.json")
            for invalid in (None, "/tenant", "tenant/", "tenant//deployment", "tenant/../deployment",
                            "tenant/*", "a" * 129):
                with self.subTest(invalid=invalid):
                    plan["bootstrap_object_prefix"] = invalid
                    with self.assertRaisesRegex(ValueError, "not canonical"):
                        preview.required_plan_bootstrap_prefix(plan)

    def test_seed_preflight_uses_verified_anchor_command(self):
        args = SimpleNamespace(bootstrap_root=[pathlib.Path("/root.pub")],
                               bootstrap_tool=pathlib.Path("/ts-bootstrap"),
                               anchor=pathlib.Path("/anchor.json"), identity=pathlib.Path("/identity.json"),
                               manifest=pathlib.Path("/manifest.json"), image_ocid="ocid1.image.oc1.test",
                               release_tool=pathlib.Path("/ts-release"), image_receipt=pathlib.Path("/receipt.json"),
                               release_delegation=pathlib.Path("/delegation.json"),
                               release_root=pathlib.Path("/release-root.pub"),
                               image_file=pathlib.Path("/image.qcow2"),
                               base_image_file=pathlib.Path("/base.qcow2"), kernel_file=pathlib.Path("/kernel"),
                               inventory=pathlib.Path("/inventory.json"), admission=pathlib.Path("/admission.json"))
        anchor = {"schemaVersion": 3, "anchorSha256": "a" * 64,
                  "storageDomain": {"prefix": "fixture-deployment"}}
        manifest = {"anchorSha256": "a" * 64, "environment": "canary"}
        with mock.patch.object(preview, "checked_tool", side_effect=(json.dumps(anchor), json.dumps(manifest),
                                                                      "verified image")) as checked, \
             mock.patch.object(preview, "verify_seed_preflight", return_value={}) as verify, \
             mock.patch.object(preview, "create_identity", return_value="create-key"):
            result = preview.seed_preflight(args, self.plan, preview.PLAN)
        self.assertEqual(result["create_identity"], "create-key")
        self.assertEqual(checked.call_args_list[0].args[:2], ("/ts-bootstrap", "verify-anchor"))
        self.assertIn("--root-key", checked.call_args_list[0].args)
        self.assertEqual(checked.call_args_list[1].args[:2], ("/ts-bootstrap", "verify-manifest"))
        self.assertEqual(verify.call_args.args[3:5], (anchor, manifest))

    def live_rules(self, expected):
        result = []
        for row in expected:
            live = {"direction": row["direction"], "protocol": row["protocol"], "is-stateless": row["stateless"]}
            for key in ("source", "source_type", "destination", "destination_type"):
                if row[key] is not None:
                    live[key.replace("_", "-")] = row[key]
            for protocol in ("tcp", "udp"):
                if row[f"{protocol}_min"] is not None:
                    live[f"{protocol}-options"] = {"destination-port-range": {
                        "min": row[f"{protocol}_min"], "max": row[f"{protocol}_max"]}}
            result.append(live)
        return result

    def live_network_oci(self, plan, ids, drift, rule_commands):
        network_security = plan["network_security"]
        gateway = plan["operator_gateway"]
        public = plan["public_api"]
        existing = plan["existing_forgejo"]
        rule_roles = {ids["network_security_group"]: "nsg_rules",
                      ids["seed_ssh_network_security_group"]: "seed_ssh_nsg_rules",
                      ids["workload_network_security_group"]: "workload_nsg_rules"}
        peerings = {
            ids["local_peering_gateway"]: {
                "id": ids["local_peering_gateway"], "lifecycle-state": "AVAILABLE", "peering-status": "PEERED",
                "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"],
                "peer-id": gateway["local_peering_gateway_id"], "is-cross-tenancy-peering": False,
                "route-table-id": None, "peer-advertised-cidr": gateway["vcn_cidr"],
                "peer-advertised-cidr-details": [gateway["vcn_cidr"]]},
            gateway["local_peering_gateway_id"]: {
                "id": gateway["local_peering_gateway_id"], "lifecycle-state": "AVAILABLE",
                "peering-status": "PEERED", "compartment-id": plan["shared_compartment_id"],
                "vcn-id": existing["vcn_id"], "peer-id": ids["local_peering_gateway"],
                "is-cross-tenancy-peering": False, "route-table-id": None,
                "peer-advertised-cidr": plan["network_cidr"], "peer-advertised-cidr-details": [plan["network_cidr"]]},
        }

        def fake_oci(*args, region=None):
            command = args[:3]
            if command == ("network", "vcn", "get"):
                return {"id": ids["vcn"], "lifecycle-state": "AVAILABLE",
                        "compartment-id": ids["network_compartment"], "cidr-block": plan["network_cidr"]}
            if command == ("network", "subnet", "get") and args[args.index("--subnet-id") + 1] == ids["public_subnet"]:
                return drift.get("public_subnet", lambda value: value)({
                    "id": ids["public_subnet"], "lifecycle-state": "AVAILABLE",
                    "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"],
                    "cidr-block": public["subnet_cidr"], "prohibit-public-ip-on-vnic": False,
                    "route-table-id": ids["public_route_table"], "security-list-ids": [ids["public_security_list"]]})
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
                role = rule_roles[args[args.index("--nsg-id") + 1]]
                return drift.get(role, lambda rules: rules)(self.live_rules(network_security[role]))
            if command == ("network", "internet-gateway", "get"):
                return drift.get("internet_gateway", lambda value: value)({
                    "id": ids["internet_gateway"], "lifecycle-state": "AVAILABLE", "is-enabled": True,
                    "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"], "route-table-id": None})
            if (command == ("network", "security-list", "get") and
                    args[args.index("--security-list-id") + 1] == ids["public_security_list"]):
                return {"id": ids["public_security_list"], "compartment-id": ids["network_compartment"],
                        "vcn-id": ids["vcn"],
                        "ingress-security-rules": drift.get("public_ingress", lambda value: value)([{
                            "protocol": "6", "source": "0.0.0.0/0", "source-type": "CIDR_BLOCK",
                            "is-stateless": False, "tcp-options": {"destination-port-range": {
                                "min": public["listener_port"], "max": public["listener_port"]}}}]),
                        "egress-security-rules": [{
                            "protocol": "6", "destination": plan["subnet_cidr"], "destination-type": "CIDR_BLOCK",
                            "is-stateless": False, "tcp-options": {"destination-port-range": {
                                "min": public["client_port"], "max": public["client_port"]}}}]}
            if (command == ("network", "route-table", "get") and
                    args[args.index("--rt-id") + 1] == ids["public_route_table"]):
                return {"id": ids["public_route_table"], "compartment-id": ids["network_compartment"],
                        "vcn-id": ids["vcn"], "route-rules": drift.get("public_routes", lambda value: value)([{
                            "destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK",
                            "network-entity-id": ids["internet_gateway"]}])}
            if command == ("nlb", "network-load-balancer", "get"):
                members = [host["private_ip"] for host in plan["hosts"] if host["slot"].startswith("member-")]
                return drift.get("balancer", lambda value: value)({
                    "id": ids["network_load_balancer"], "lifecycle-state": "ACTIVE",
                    "compartment-id": ids["network_compartment"], "subnet-id": ids["public_subnet"],
                    "is-private": False, "is-preserve-source-destination": False, "network-security-group-ids": [],
                    "listeners": {"https": {"name": "https", "protocol": "TCP", "port": public["listener_port"],
                                            "default-backend-set-name": "terrabase-https"}},
                    "backend-sets": {"terrabase-https": {"name": "terrabase-https", "is-preserve-source": False,
                                                         "backends": [{"ip-address": address,
                                                                       "port": public["client_port"]}
                                                                      for address in members]}}})
            if command == ("network", "security-list", "get"):
                return {"id": ids["security_list"], "compartment-id": ids["network_compartment"],
                        "vcn-id": ids["vcn"],
                        "ingress-security-rules": self.live_rules(network_security["security_list_ingress_rules"]),
                        "egress-security-rules": self.live_rules(network_security["security_list_egress_rules"])}
            if command == ("network", "route-table", "get"):
                routes = [{"destination": row["destination"], "destination-type": row["destination_type"],
                           "network-entity-id": ids[preview.ROUTE_TARGET_IDS[row["network_entity_id"]]]}
                          for row in network_security["route_rules"]]
                return {"id": ids["route_table"], "compartment-id": ids["network_compartment"],
                        "vcn-id": ids["vcn"], "route-rules": drift.get("routes", lambda value: value)(routes)}
            if command == ("network", "service-gateway", "get"):
                return {"id": ids["service_gateway"], "compartment-id": ids["network_compartment"],
                        "vcn-id": ids["vcn"], "lifecycle-state": "AVAILABLE",
                        "services": [{"service-id": network_security["service_gateway_service_id"]}]}
            if command == ("network", "local-peering-gateway", "get"):
                peering = deepcopy(peerings[args[args.index("--local-peering-gateway-id") + 1]])
                return drift.get("peering", lambda value: value)(peering)
            if command == ("compute", "instance", "list-vnics"):
                self.assertEqual(args[args.index("--instance-id") + 1], existing["instance_id"])
                self.assertIn("--all", args)
                vnic = {"lifecycle-state": "AVAILABLE", "is-primary": True,
                        "private-ip": gateway["private_ip"], "skip-source-dest-check": False}
                return drift.get("vnics", lambda value: value)([vnic])
            self.fail(f"unexpected OCI command: {args}")

        return fake_oci

    def test_live_network_rules_routes_and_operator_gateway_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, _, _, _, _, _ = self.bound_plan_and_inventory(pathlib.Path(directory))
            ids = plan["resource_ids"]
            rule_commands = []
            with mock.patch.object(preview, "oci", side_effect=self.live_network_oci(plan, ids, {}, rule_commands)):
                preview.check_live_network(plan, ids)
            self.assertEqual({command[command.index("--nsg-id") + 1] for command in rule_commands},
                             {ids["network_security_group"], ids["seed_ssh_network_security_group"],
                              ids["workload_network_security_group"]})

            def widen_port(rules):
                rules[0]["tcp-options"]["destination-port-range"]["max"] += 1
                return rules

            def set_field(key, value):
                def change(resource):
                    resource[key] = value
                    return resource
                return change

            def vnic_field(key, value):
                def change(vnics):
                    vnics[0][key] = value
                    return vnics
                return change

            def backend(key, value):
                def change(balancer):
                    balancer["backend-sets"]["terrabase-https"]["backends"][0][key] = value
                    return balancer
                return change

            def peering_to_service_gateway(routes):
                for route in routes:
                    route["network-entity-id"] = ids["service_gateway"]
                return routes

            for name, drift, message in (
                    ("controller port", {"nsg_rules": widen_port}, "controller network security group rules differ"),
                    ("member port", {"workload_nsg_rules": widen_port}, "member workload network security group"),
                    ("peering pending", {"peering": set_field("peering-status", "PENDING")}, "peering differs"),
                    ("foreign peer", {"peering": set_field("peer-id", "ocid1.localpeeringgateway.oc1..x")},
                     "peering differs"),
                    ("extra advertised CIDR", {"peering": set_field("peer-advertised-cidr-details",
                                                                    ["10.250.0.0/16", "10.9.0.0/16"])},
                     "peering differs"),
                    ("transit route table", {"peering": set_field("route-table-id", "ocid1.routetable.oc1..x")},
                     "peering differs"),
                    ("wrong VCN", {"peering": set_field("vcn-id", "ocid1.vcn.oc1..other")}, "peering differs"),
                    ("peering route retargeted", {"routes": peering_to_service_gateway}, "route table rules differ"),
                    ("gateway address", {"vnics": vnic_field("private-ip", "10.250.10.156")}, "gateway VNIC"),
                    ("source check skipped", {"vnics": vnic_field("skip-source-dest-check", True)}, "gateway VNIC"),
                    ("secondary VNIC", {"vnics": lambda vnics: vnics * 2}, "gateway VNIC"),
                    ("public gateway disabled", {"internet_gateway": set_field("is-enabled", False)},
                     "public API internet gateway"),
                    ("public subnet sealed", {"public_subnet": set_field("prohibit-public-ip-on-vnic", True)},
                     "public API subnet"),
                    ("public default route retargeted", {"public_routes": lambda routes: [
                        dict(routes[0], **{"network-entity-id": ids["service_gateway"]})]}, "public API route table"),
                    ("public SSH opened", {"public_ingress": lambda rules: rules + [dict(
                        rules[0], **{"tcp-options": {"destination-port-range": {"min": 22, "max": 22}}})]},
                     "public API security-list ingress"),
                    ("source preserved", {"balancer": set_field("is-preserve-source-destination", True)},
                     "network load balancer"),
                    ("private balancer", {"balancer": set_field("is-private", True)}, "network load balancer"),
                    ("controller backend", {"balancer": backend("ip-address", "10.251.0.11")},
                     "network load balancer"),
                    ("replication backend", {"balancer": backend("port", 9443)}, "network load balancer"),
                    ("second listener", {"balancer": lambda balancer: dict(balancer, listeners={
                        **balancer["listeners"], "ssh": {"name": "ssh", "protocol": "TCP", "port": 22,
                                                         "default-backend-set-name": "terrabase-https"}})},
                     "network load balancer")):
                with self.subTest(drift=name):
                    fake = self.live_network_oci(plan, ids, drift, [])
                    with mock.patch.object(preview, "oci", side_effect=fake):
                        with self.assertRaisesRegex(ValueError, message):
                            preview.check_live_network(plan, ids)

    def test_live_network_without_gateway_reads_no_peering(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, _, _, _, _, _ = self.bound_plan_and_inventory(pathlib.Path(directory))
            plan["operator_gateway"] = None
            plan["network_security"]["route_rules"] = plan["network_security"]["route_rules"][:1]
            ids = dict(plan["resource_ids"], local_peering_gateway=None)
            for key in ("nsg_rules", "seed_ssh_nsg_rules", "workload_nsg_rules"):
                plan["network_security"][key] = [rule for rule in plan["network_security"][key]
                                                 if rule["source"] != "10.250.10.155/32"]
            commands = []
            fake = self.live_network_oci({**plan, "operator_gateway": {"local_peering_gateway_id": None,
                                                                      "vcn_cidr": None, "private_ip": None}},
                                         ids, {}, [])

            def recording_oci(*args, region=None):
                commands.append(args[:3])
                return fake(*args, region=region)

            with mock.patch.object(preview, "oci", side_effect=recording_oci):
                preview.check_live_network(plan, ids)
            self.assertNotIn(("network", "local-peering-gateway", "get"), commands)
            self.assertNotIn(("compute", "instance", "list-vnics"), commands)

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
            for name, changed_plan in (
                    ("cell", {**plan, "resource_ids": dict(plan["resource_ids"], local_peering_gateway=None)}),
                    ("forgejo", {**plan, "operator_gateway": dict(plan["operator_gateway"],
                                                                  local_peering_gateway_id=None)})):
                with self.subTest(missing_peering=name):
                    with self.assertRaisesRegex(ValueError, "exact cell and operator gateway local peering gateway"):
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

    def test_seed_launch_carries_launch_material_and_rejects_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            envelope = {"schemaVersion": 1, "keyId": "root", "signature": "signed",
                        "scope": {"domain": "terrascale.bootstrap.manifest", "role": "controller",
                                  "slot": "controller-a", "cell": "GRU"},
                        "payload": {"schemaVersion": 2, "slot": "controller-a",
                                    "seedSlot": "controller-a", "cell": "GRU"}}
            paths = {name: root / f"{name}.json" for name in ("manifest", "identity", "anchor", "enrollment")}
            paths["manifest"].write_text(json.dumps(envelope))
            paths["identity"].write_text('{"schemaVersion":1,"deploymentId":"ts-preview-gru-r6",'
                                         '"environment":"canary","cell":"GRU"}')
            paths["anchor"].write_text('{"schemaVersion":1,"payload":{}}')
            paths["enrollment"].write_text('{"schema_version":1}')
            reviewed = {"availability_domain": "AD-1", "fault_domain": "FAULT-DOMAIN-1",
                        "compartment_id": "ocid1.compartment.oc1..control", "shape": "VM.Standard.A1.Flex",
                        "ocpus": 1, "memory_gb": 6, "image_id": "ocid1.image.oc1..image", "boot_gb": 50,
                        "boot_vpus_per_gb": 10, "subnet_id": "ocid1.subnet.oc1..subnet",
                        "network_security_group_ids": ["ocid1.networksecuritygroup.oc1..a"],
                        "assign_public_ip": False, "create_identity": "seed-a-r6",
                        "manifest_sha256": preview.sha256(paths["manifest"]),
                        "anchor_sha256": preview.sha256(paths["anchor"])}
            reviewed_path = root / "reviewed.json"
            reviewed_path.write_text(json.dumps(reviewed))
            launch = preview.seed_launch(self.plan, reviewed_path, paths["manifest"], paths["identity"],
                                         paths["anchor"], paths["enrollment"], None)
            metadata = launch["metadata"]
            self.assertEqual(metadata["terrascale-bootstrap"], '{"schemaVersion":1,"slot":"controller-a"}')
            self.assertEqual(metadata["terrascale-controller-manifest-v1"], paths["manifest"].read_text())
            self.assertEqual(metadata["terrascale-bootstrap-anchor-v1"], paths["anchor"].read_text())
            self.assertEqual(metadata["terrascale-bootstrap-identity-v1"], paths["identity"].read_text())
            self.assertEqual(metadata["terrascale-host-enrollment-v1"], '{"schema_version":1}')
            user_data = base64.b64decode(metadata["user_data"])
            self.assertTrue(user_data.startswith(b"#cloud-config\n"))
            self.assertNotIn(b"ssh_authorized_keys", user_data)
            self.assertEqual(launch["freeformTags"], {"BootstrapCreateKey": "seed-a-r6"})
            self.assertEqual(launch["displayName"], "ts-preview-gru-r6-controller-a")
            self.assertEqual(launch["privateIp"], "10.251.0.11")

            paths["anchor"].write_text('{"schemaVersion":1,"payload":{"other":1}}')
            with self.assertRaisesRegex(ValueError, "differs from the reviewed seed plan"):
                preview.seed_launch(self.plan, reviewed_path, paths["manifest"], paths["identity"],
                                    paths["anchor"], paths["enrollment"], None)
            paths["anchor"].write_text('{"schemaVersion":1,"payload":{}}')
            envelope["scope"]["cell"] = "FRA"
            paths["manifest"].write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError, "not a controller-a seed envelope"):
                preview.seed_launch(self.plan, reviewed_path, paths["manifest"], paths["identity"],
                                    paths["anchor"], paths["enrollment"], None)
            envelope["scope"]["cell"] = "GRU"
            paths["manifest"].write_text(json.dumps(envelope))
            paths["anchor"].write_text(json.dumps({"schemaVersion": 1, "signature": "s" * 32000}))
            reviewed["anchor_sha256"] = preview.sha256(paths["anchor"])
            reviewed_path.write_text(json.dumps(reviewed))
            with self.assertRaisesRegex(ValueError, "exceeds the OCI instance metadata limit"):
                preview.seed_launch(self.plan, reviewed_path, paths["manifest"], paths["identity"],
                                    paths["anchor"], paths["enrollment"], None)

    def test_five_host_budget_includes_existing_resources_and_reserves(self):
        cost = preview.estimate(self.plan, self.inventory)
        self.assertEqual(cost["items"]["compute"], "58.6200")
        self.assertEqual(cost["items"]["block_storage"], "10.6250")
        self.assertEqual(cost["items"]["snapshot_reserve"], "8.9250")
        self.assertEqual(cost["assumptions"]["object_growth_reserve_gb"], "10")
        self.assertEqual(cost["assumptions"]["object_staging_reserve_gb"], "10")
        self.assertLess(float(cost["total"]), 100)

    def test_monthly_ceiling_accepts_200_and_rejects_more(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = json.loads(preview.PLAN.read_text())
            path = pathlib.Path(directory) / "plan.json"
            self.assertEqual(plan["budget"]["monthly_limit"], 200)
            for limit in ("100", "200"):
                with self.subTest(limit=limit):
                    plan["budget"]["monthly_limit"] = limit
                    path.write_text(json.dumps(plan))
                    self.assertEqual(preview.load_plan(path)["budget"]["monthly_limit"], limit)
            plan["budget"]["monthly_limit"] = "200.01"
            path.write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError, "no more than \\$200"):
                preview.load_plan(path)

        baseline = preview.estimate(self.plan, self.inventory)
        self.plan["budget"]["misc_reserve_usd"] = (
            Decimal(self.plan["budget"]["misc_reserve_usd"]) + Decimal("200") - Decimal(baseline["total"]))
        admitted = preview.estimate(self.plan, self.inventory)
        self.assertEqual(admitted["total"], "200.00")
        self.assertEqual(admitted["headroom"], "0.00")
        self.plan["budget"]["misc_reserve_usd"] += Decimal("0.01")
        with self.assertRaisesRegex(ValueError, "exceeds the monthly ceiling"):
            preview.estimate(self.plan, self.inventory)

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
        self.inventory["buckets"][0]["bytes"] = 6000 * 1024**3
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
                    "local_peering_gateway": "ocid1.localpeeringgateway.gru",
                    "internet_gateway": "ocid1.internetgateway.gru", "public_subnet": "ocid1.subnet.grupublic",
                    "public_route_table": "ocid1.routetable.grupublic",
                    "public_security_list": "ocid1.securitylist.grupublic",
                    "network_load_balancer": "ocid1.networkloadbalancer.gru",
                    "controller_dynamic_group": "ocid1.dynamicgroup.oc1..controller",
                    "controller_policy": "ocid1.policy.oc1..controller",
                    "objectstorage_key_policy": "ocid1.policy.oc1..objectstorage",
                    "host_dynamic_group": "ocid1.dynamicgroup.oc1..host",
                    "host_policy": "ocid1.policy.oc1..host"})
        self.plan["host_credential_secret"] = {
            "compartment_id": "ocid1.compartment.oc1..secretstore",
            "secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }
        self.plan["operator_gateway"]["local_peering_gateway_id"] = "ocid1.localpeeringgateway.forgejo"
        self.inventory["preview_compartment_ids"] = {"control": ids["control_compartment"],
                                                      "network": ids["network_compartment"],
                                                      "workload": ids["workload_compartment"]}
        self.inventory["resources"] += [
            {"kind": "local-peering-gateway", "id": ids["local_peering_gateway"], "lifecycle-state": "AVAILABLE",
             "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"]},
            {"kind": "local-peering-gateway", "id": "ocid1.localpeeringgateway.forgejo",
             "lifecycle-state": "AVAILABLE", "compartment-id": self.plan["shared_compartment_id"],
             "vcn-id": self.plan["existing_forgejo"]["vcn_id"]},
            {"kind": "internet-gateway", "id": ids["internet_gateway"], "lifecycle-state": "AVAILABLE",
             "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"]},
            {"kind": "network-load-balancer", "id": ids["network_load_balancer"], "lifecycle-state": "ACTIVE",
             "compartment-id": ids["network_compartment"], "subnet-id": ids["public_subnet"]},
        ]
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
            anchor_summary = {
                "schemaVersion": 3, "anchorSha256": summary["anchorSha256"],
                "cell": self.plan["cell"], "ociRegion": self.plan["region"],
                "storageDomain": {
                    "prefix": self.plan["bootstrap_object_prefix"],
                    "namespace": "fixture-namespace",
                    "ledgerBucket": self.plan["foundation_buckets"]["ledger"],
                    "headBucket": self.plan["foundation_buckets"]["head"],
                    "ledgerKmsKeyOcid": ids["key"], "headKmsKeyOcid": ids["key"],
                },
            }
            verified = f"verified OCI image={image_ocid} region=GRU revision=abc arch=arm64 sha256=abc"
            with mock.patch.multiple(preview, check_live_compartments=mock.DEFAULT,
                                     check_live_vault=mock.DEFAULT, check_live_network=mock.DEFAULT,
                                     check_live_buckets=mock.DEFAULT, check_live_iam=mock.DEFAULT) as live:
                live["check_live_buckets"].return_value = "fixture-namespace"
                result = preview.verify_seed_preflight(self.plan, inventory_path, admission_path,
                                                       anchor_summary, summary, receipt_path, verified)
                live["check_live_iam"].assert_called_once_with(
                    self.plan, ids, self.plan["bootstrap_object_prefix"])
            self.assertEqual(result["compartment_id"], ids["control_compartment"])
            self.assertFalse(result["assign_public_ip"])
            self.assertEqual(result["admission_admitted_at"], admission["admitted_at"])
            self.assertEqual(result["admission_expires_at"], admission["expires_at"])
            result["create_identity"] = preview.create_identity(self.plan, preview.PLAN, summary)
            seed_wire = preview.canonical_manual_seed_plan(result)
            self.assertEqual(json.loads(seed_wire)["create_identity"], result["create_identity"])
            signed_mismatches = (
                ("storageDomain", "prefix", "other-deployment"),
                ("storageDomain", "namespace", "other-namespace"),
                ("storageDomain", "ledgerBucket", "other-ledger"),
                ("storageDomain", "headBucket", "other-head"),
                ("storageDomain", "ledgerKmsKeyOcid", "ocid1.key.gru.other"),
                ("storageDomain", "headKmsKeyOcid", "ocid1.key.gru.other"),
                (None, "ociRegion", "us-ashburn-1"),
                (None, "cell", "IAD"),
                (None, "anchorSha256", "c" * 64),
                (None, "schemaVersion", 2),
            )
            for section, field, value in signed_mismatches:
                with self.subTest(section=section, field=field):
                    mismatched_anchor = deepcopy(anchor_summary)
                    target = mismatched_anchor if section is None else mismatched_anchor[section]
                    target[field] = value
                    with mock.patch.multiple(preview, check_live_compartments=mock.DEFAULT,
                                             check_live_vault=mock.DEFAULT, check_live_network=mock.DEFAULT,
                                             check_live_buckets=mock.DEFAULT, check_live_iam=mock.DEFAULT) as live:
                        live["check_live_buckets"].return_value = "fixture-namespace"
                        with self.assertRaisesRegex(ValueError, "anchor storage domain differs"):
                            preview.verify_seed_preflight(self.plan, inventory_path, admission_path,
                                                          mismatched_anchor, summary, receipt_path, verified)
                        live["check_live_iam"].assert_not_called()
            summary["profile"]["compartmentOcid"] = ids["workload_compartment"]
            with self.assertRaisesRegex(ValueError, "recorded controller-a profile"):
                with mock.patch.multiple(preview, check_live_compartments=mock.DEFAULT,
                                         check_live_vault=mock.DEFAULT, check_live_network=mock.DEFAULT,
                                         check_live_buckets=mock.DEFAULT, check_live_iam=mock.DEFAULT) as live:
                    live["check_live_buckets"].return_value = "fixture-namespace"
                    preview.verify_seed_preflight(self.plan, inventory_path, admission_path,
                                                  anchor_summary, summary, receipt_path, verified)
            summary["profile"]["compartmentOcid"] = ids["control_compartment"]
            admission["expires_at"] = (now - dt.timedelta(seconds=1)).isoformat()
            admission_path.write_text(json.dumps(admission))
            with self.assertRaisesRegex(ValueError, "stale"):
                preview.verify_seed_preflight(self.plan, inventory_path, admission_path,
                                              anchor_summary, summary, receipt_path, verified)


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
        entries[0]["image"]["max_billable_size_in_gbs"] = 6000
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
