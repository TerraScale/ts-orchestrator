import datetime as dt
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from copy import deepcopy
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oci_preview_private_peer", ROOT / "preview.py")
preview = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preview)


class PrivatePeerInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.regions = {
            "GRU": ("sa-saopaulo-1", "10.251.0.0/24", "10.251.0.0/25"),
            "SFO": ("us-sanjose-1", "10.252.0.0/24", "10.252.0.0/25"),
        }
        self.plans = {}
        self.plan_paths = {}
        self.inventories = {}
        self.inventory_paths = {}
        self.admissions = {}
        self.admission_paths = {}
        self.network_ids = {}
        self.intent_path = self.directory / "pair-intent.json"
        self.receipt_path = self.directory / "pair-readback.json"
        for cell, (region, vcn_cidr, subnet_cidr) in self.regions.items():
            plan, plan_path = self.make_plan(cell, region, vcn_cidr, subnet_cidr)
            self.plans[cell] = plan
            self.plan_paths[cell] = plan_path
            inventory, inventory_path = self.make_inventory(plan, plan_path)
            self.inventories[cell] = inventory
            self.inventory_paths[cell] = inventory_path
            admission, admission_path = self.make_admission(plan, plan_path, inventory, inventory_path)
            self.admissions[cell] = admission
            self.admission_paths[cell] = admission_path
            self.network_ids[cell] = self.make_peer_network_ids(cell, region)
        self.intent = self.make_intent()
        self.write_json(self.intent_path, self.intent)
        self.drift = None
        self.calls = []

    def write_json(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True) + "\n")

    def make_plan(self, cell, region, vcn_cidr, subnet_cidr):
        plan = json.loads(preview.PLAN.read_text())
        # Another cell has no Forgejo-hosted operator gateway, public API, or GRU seat rules.
        plan["operator_gateway"] = None
        plan["netbird"] = None
        plan["public_api"] = None
        plan["network_security"]["nsg_rules"] = [
            rule for rule in plan["network_security"]["nsg_rules"] if rule["source"] != "10.250.10.155/32"]
        plan["network_security"]["seed_ssh_nsg_rules"] = []
        plan["network_security"]["workload_nsg_rules"] = []
        plan["cell"] = cell
        plan["region"] = region
        plan["network_cidr"] = vcn_cidr
        plan["subnet_cidr"] = subnet_cidr
        prefix = vcn_cidr.split(".")[1]
        plan["hosts"] = [{
            "slot": "controller-a", "shape": "VM.Standard.A1.Flex", "ocpus": 1, "memory_gb": 6,
            "boot_gb": 50, "data_gb": 0, "private_ip": f"10.{prefix}.0.10",
        }]
        plan["controller_replicas"] = 1
        plan["database_members"] = 0
        plan["resource_ids"].update({
            "control_compartment": f"ocid1.compartment.oc1..{cell.lower()}control",
            "network_compartment": f"ocid1.compartment.oc1..{cell.lower()}network",
            "workload_compartment": f"ocid1.compartment.oc1..{cell.lower()}workload",
            "vault": f"ocid1.vault.oc1.{region}.{cell.lower()}vault",
            "key": f"ocid1.key.oc1.{region}.{cell.lower()}key",
            "vcn": f"ocid1.vcn.oc1.{region}.{cell.lower()}vcn",
            "subnet": f"ocid1.subnet.oc1.{region}.{cell.lower()}subnet",
            "network_security_group": f"ocid1.networksecuritygroup.oc1.{region}.{cell.lower()}nsg",
            "seed_ssh_network_security_group": None,
            "security_list": f"ocid1.securitylist.oc1.{region}.{cell.lower()}sl",
            "route_table": f"ocid1.routetable.oc1.{region}.{cell.lower()}rt",
            "service_gateway": f"ocid1.servicegateway.oc1.{region}.{cell.lower()}sgw",
            "local_peering_gateway": None,
            "controller_dynamic_group": f"ocid1.dynamicgroup.oc1..{cell.lower()}controller",
            "controller_policy": f"ocid1.policy.oc1..{cell.lower()}controller",
            "objectstorage_key_policy": f"ocid1.policy.oc1..{cell.lower()}storage",
            "host_dynamic_group": f"ocid1.dynamicgroup.oc1..{cell.lower()}hosts",
            "host_policy": f"ocid1.policy.oc1..{cell.lower()}host",
            "instances": {"controller-a": None},
            "boot_volumes": {"controller-a": None},
            "data_volumes": {},
        })
        plan["host_credential_secret"] = {
            "compartment_id": f"ocid1.compartment.oc1..{cell.lower()}secrets",
            "secret_id": f"ocid1.vaultsecret.oc1.{region}.{cell.lower()}secret",
        }
        service = f"all-{cell.lower()}-services-in-oracle-services-network"
        plan["network_security"]["service_gateway_service_id"] = (
            f"ocid1.service.oc1.{region}.{cell.lower()}service")
        plan["network_security"]["service_gateway_cidr_block"] = service
        plan["network_security"]["route_rules"] = [{
            "destination": service, "destination_type": "SERVICE_CIDR_BLOCK",
            "network_entity_id": "{service_gateway_id}",
        }]
        for rule in plan["network_security"]["nsg_rules"]:
            rule["source"] = vcn_cidr
        for rule in plan["network_security"]["security_list_egress_rules"]:
            if rule["destination_type"] == "CIDR_BLOCK" and rule["destination"] != "169.254.169.254/32":
                rule["destination"] = vcn_cidr
            elif rule["destination_type"] == "SERVICE_CIDR_BLOCK":
                rule["destination"] = service
        path = self.directory / f"{cell.lower()}-plan.json"
        self.write_json(path, plan)
        return preview.load_plan(path), path

    def make_inventory(self, plan, plan_path):
        existing = plan["existing_forgejo"]
        shared = plan["shared_compartment_id"]
        timestamp = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=2)).isoformat()
        inventory = {
            "schema_version": 2,
            "captured_at": timestamp,
            "plan_sha256": preview.sha256(plan_path),
            "tenancy_id": plan["tenancy_id"],
            "regions": sorted(region for region, _, _ in self.regions.values()),
            "preview_compartment_ids": {
                role: plan["resource_ids"][f"{role}_compartment"]
                for role in ("control", "network", "workload")
            },
            "images": [],
            "buckets": [
                {"name": "ts-forgejo", "bytes": 30 * 1024**3, "versioning": "Disabled",
                 "storage_tier": "Standard", "public_access_type": "NoPublicAccess"},
                {"name": "ts-forgejo-backup", "bytes": 28 * 1024**3, "versioning": "Disabled",
                 "storage_tier": "Standard", "public_access_type": "NoPublicAccess"},
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
        path = self.directory / f"{plan['cell'].lower()}-inventory.json"
        self.write_json(path, inventory)
        return inventory, path

    def make_admission(self, plan, plan_path, inventory, inventory_path):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        estimate = preview.estimate(plan, inventory, plan_path)
        admission = {
            "schema_version": 2,
            "admitted_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + dt.timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
            "plan_sha256": preview.sha256(plan_path),
            "inventory_sha256": preview.sha256(inventory_path),
            "preview_compartment_ids": inventory["preview_compartment_ids"],
            "estimate": estimate,
        }
        path = self.directory / f"{plan['cell'].lower()}-admission.json"
        self.write_json(path, admission)
        return admission, path

    def make_peer_network_ids(self, cell, region):
        suffix = cell.lower()
        return {
            "drg": f"ocid1.drg.oc1.{region}.{suffix}drg",
            "vcn_attachment": f"ocid1.drgattachment.oc1.{region}.{suffix}vcnattachment",
            "rpc": f"ocid1.remotepeeringconnection.oc1.{region}.{suffix}rpc",
            "rpc_attachment": f"ocid1.drgattachment.oc1.{region}.{suffix}rpcattachment",
            "vcn_route": f"ocid1.drgroutetable.oc1.{region}.{suffix}vcnroute",
            "rpc_route": f"ocid1.drgroutetable.oc1.{region}.{suffix}rpcroute",
            "vcn_import": f"ocid1.drgroutedistribution.oc1.{region}.{suffix}vcnimport",
            "rpc_import": f"ocid1.drgroutedistribution.oc1.{region}.{suffix}rpcimport",
        }

    def make_intent(self):
        cells = {}
        for cell, ids in self.network_ids.items():
            cells[cell] = {
                "plan_sha256": preview.sha256(self.plan_paths[cell]),
                "drg_id": ids["drg"],
                "vcn_attachment_id": ids["vcn_attachment"],
                "rpc_id": ids["rpc"],
                "rpc_attachment_id": ids["rpc_attachment"],
                "vcn_drg_route_table_id": ids["vcn_route"],
                "rpc_drg_route_table_id": ids["rpc_route"],
                "vcn_import_distribution_id": ids["vcn_import"],
                "rpc_import_distribution_id": ids["rpc_import"],
                "monthly_cross_region_egress_gb": 20,
            }
        return {
            "schema_version": 1,
            "tenancy_id": self.plans["GRU"]["tenancy_id"],
            "realm": "oc1",
            "allowed_tcp_ports": [4222, 7422],
            "cells": cells,
        }

    @staticmethod
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
                    live[f"{protocol}-options"] = {
                        "destination-port-range": {
                            "min": row[f"{protocol}_min"], "max": row[f"{protocol}_max"],
                        },
                    }
            result.append(live)
        return result

    def fake_oci(self, *args, region=None):
        self.calls.append((args, region))
        plan = next(row for row in self.plans.values() if row["region"] == region)
        cell = plan["cell"]
        ids = plan["resource_ids"]
        peer_cell = "SFO" if cell == "GRU" else "GRU"
        peer_plan = self.plans[peer_cell]
        own_peer = self.network_ids[cell]
        remote_peer = self.network_ids[peer_cell]
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
            return {"id": ids["network_security_group"], "compartment-id": ids["network_compartment"],
                    "vcn-id": ids["vcn"]}
        if command == ("network", "nsg", "rules"):
            expected, _ = preview.private_peer_security_rules(
                plan, peer_plan["subnet_cidr"], self.intent["allowed_tcp_ports"])
            rows = self.live_rules(expected)
            if self.drift == "wide_nsg":
                rows.append({"direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0",
                             "source-type": "CIDR_BLOCK", "is-stateless": False,
                             "tcp-options": {"destination-port-range": {"min": 1, "max": 65535}}})
            if self.drift == "wrong_peer_port":
                rows[-1]["tcp-options"]["destination-port-range"]["max"] += 1
            return rows
        if command == ("network", "security-list", "get"):
            _, egress = preview.private_peer_security_rules(
                plan, peer_plan["subnet_cidr"], self.intent["allowed_tcp_ports"])
            return {"id": ids["security_list"], "compartment-id": ids["network_compartment"],
                    "vcn-id": ids["vcn"],
                    "ingress-security-rules": self.live_rules(
                        plan["network_security"]["security_list_ingress_rules"]),
                    "egress-security-rules": self.live_rules(egress)}
        if command == ("network", "route-table", "get"):
            routes = [{"destination": row["destination"], "destination-type": row["destination_type"],
                       "network-entity-id": ids["service_gateway"]}
                      for row in plan["network_security"]["route_rules"]]
            routes.append({"destination": peer_plan["subnet_cidr"], "destination-type": "CIDR_BLOCK",
                           "network-entity-id": own_peer["drg"]})
            if self.drift == "extra_subnet_route":
                routes.append({"destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK",
                               "network-entity-id": own_peer["drg"]})
            return {"id": ids["route_table"], "compartment-id": ids["network_compartment"],
                    "vcn-id": ids["vcn"], "route-rules": routes}
        if command == ("network", "service-gateway", "get"):
            return {"id": ids["service_gateway"], "compartment-id": ids["network_compartment"],
                    "vcn-id": ids["vcn"], "lifecycle-state": "AVAILABLE",
                    "services": [{"service-id": plan["network_security"]["service_gateway_service_id"]}]}
        if command == ("network", "drg", "get"):
            compartment = "ocid1.compartment.oc1..foreignowner" if self.drift == "wrong_owner" else ids[
                "network_compartment"]
            return {"id": own_peer["drg"], "lifecycle-state": "AVAILABLE", "compartment-id": compartment}
        if command == ("network", "drg-attachment", "list"):
            rows = [{"id": own_peer["vcn_attachment"], "lifecycle-state": "ATTACHED"},
                    {"id": own_peer["rpc_attachment"], "lifecycle-state": "ATTACHED"}]
            if self.drift == "extra_attachment":
                rows.append({"id": f"ocid1.drgattachment.oc1.{region}.unexpected",
                             "lifecycle-state": "ATTACHED"})
            return rows
        if command == ("network", "drg-attachment", "get"):
            attachment_id = args[args.index("--drg-attachment-id") + 1]
            if attachment_id == own_peer["vcn_attachment"]:
                attachment = {"id": attachment_id, "compartment-id": ids["network_compartment"],
                        "drg-id": own_peer["drg"], "lifecycle-state": "ATTACHED",
                        "vcn-id": None,
                        "network-details": {"type": "VCN", "id": ids["vcn"]},
                        "is-cross-tenancy": False, "drg-route-table-id": own_peer["vcn_route"]}
                if self.drift == "vcn_attachment_vcn_id_absent":
                    attachment.pop("vcn-id")
                elif self.drift == "vcn_attachment_vcn_id_matches":
                    attachment["vcn-id"] = ids["vcn"]
                elif self.drift == "vcn_attachment_mismatch":
                    attachment["vcn-id"] = "ocid1.vcn.oc1.unexpected.foreignvcn"
                return attachment
            return {"id": attachment_id, "compartment-id": ids["network_compartment"],
                    "drg-id": own_peer["drg"], "lifecycle-state": "ATTACHED",
                    "network-details": {"type": "REMOTE_PEERING_CONNECTION", "id": own_peer["rpc"]},
                    "is-cross-tenancy": False, "drg-route-table-id": own_peer["rpc_route"]}
        if command == ("network", "remote-peering-connection", "get"):
            state = "PENDING" if self.drift == "disconnected" else "PEERED"
            peer_id = f"ocid1.remotepeeringconnection.oc1.{region}.unexpected" \
                if self.drift == "asymmetric" and cell == "GRU" \
                else remote_peer["rpc"]
            peer_region = "eu-frankfurt-1" if self.drift == "wrong_peer_region" else peer_plan["region"]
            return {"id": own_peer["rpc"], "compartment-id": ids["network_compartment"],
                    "drg-id": own_peer["drg"], "lifecycle-state": "AVAILABLE", "peering-status": state,
                    "peer-id": peer_id, "peer-region-name": peer_region,
                    "peer-tenancy-id": plan["tenancy_id"], "is-cross-tenancy-peering": False}
        if command == ("network", "drg-route-table", "get"):
            table_id = args[args.index("--drg-route-table-id") + 1]
            role = "vcn" if table_id == own_peer["vcn_route"] else "rpc"
            distribution = own_peer[f"{role}_import"]
            return {"id": table_id, "lifecycle-state": "AVAILABLE",
                    "compartment-id": ids["network_compartment"], "drg-id": own_peer["drg"],
                    "import-drg-route-distribution-id": distribution, "is-ecmp-enabled": False}
        if command == ("network", "drg-route-distribution", "get"):
            distribution_id = args[args.index("--route-distribution-id") + 1]
            return {"id": distribution_id, "lifecycle-state": "AVAILABLE", "distribution-type": "IMPORT",
                    "compartment-id": ids["network_compartment"], "drg-id": own_peer["drg"]}
        if command == ("network", "drg-route-distribution-statement", "list"):
            distribution_id = args[args.index("--route-distribution-id") + 1]
            accepted = own_peer["rpc_attachment"] if distribution_id == own_peer["vcn_import"] \
                else own_peer["vcn_attachment"]
            criteria = [{"match-type": "DRG_ATTACHMENT_ID", "drg-attachment-id": accepted}]
            if self.drift == "broad_import":
                criteria = [{"match-type": "MATCH_ALL"}]
            statements = [{"id": f"{cell.lower()}-statement", "action": "ACCEPT", "priority": 100,
                           "match-criteria": criteria}]
            if self.drift == "extra_import_statement":
                statements.append({"id": f"{cell.lower()}-extra", "action": "ACCEPT", "priority": 200,
                                   "match-criteria": [{"match-type": "MATCH_ALL"}]})
            return statements
        if command == ("network", "drg-route-rule", "list"):
            table_id = args[args.index("--drg-route-table-id") + 1]
            if table_id == own_peer["vcn_route"]:
                destination = peer_plan["network_cidr"]
                next_hop = own_peer["rpc_attachment"]
            else:
                destination = plan["network_cidr"]
                next_hop = own_peer["vcn_attachment"]
            rules = [{"destination": destination, "destination-type": "CIDR_BLOCK",
                      "next-hop-drg-attachment-id": next_hop, "route-type": "DYNAMIC",
                      "is-conflict": False, "is-blackhole": False}]
            if self.drift == "extra_drg_route":
                rules.append({"destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK",
                              "next-hop-drg-attachment-id": own_peer["rpc_attachment"],
                              "route-type": "STATIC", "is-conflict": False, "is-blackhole": False})
            return rules
        self.fail(f"unexpected OCI command in fixture: {args}")

    def inspect_paths(self):
        gru, sfo = self.plan_paths["GRU"], self.plan_paths["SFO"]
        return preview.inspect_private_peer(
            self.intent_path, gru, self.inventory_paths["GRU"], self.admission_paths["GRU"],
            sfo, self.inventory_paths["SFO"], self.admission_paths["SFO"])

    def test_cli_emits_hash_bound_configuration_only_readback(self):
        argv = [
            "preview.py", "inspect-private-peer", "--pair-intent", str(self.intent_path),
            "--left-plan", str(self.plan_paths["GRU"]), "--left-inventory",
            str(self.inventory_paths["GRU"]), "--left-admission", str(self.admission_paths["GRU"]),
            "--right-plan", str(self.plan_paths["SFO"]), "--right-inventory",
            str(self.inventory_paths["SFO"]), "--right-admission", str(self.admission_paths["SFO"]),
            "--out", str(self.receipt_path),
        ]
        with (mock.patch.object(preview, "oci", side_effect=self.fake_oci),
              mock.patch.object(preview.sys, "argv", argv),
              mock.patch("builtins.print") as printed):
            preview.main()
        receipt = json.loads(self.receipt_path.read_text())
        self.assertEqual(receipt["status"], "configuration_readback_pass")
        self.assertEqual(receipt["pair_intent_sha256"], preview.sha256(self.intent_path))
        self.assertEqual(set(receipt["cells"]), {"GRU", "SFO"})
        self.assertEqual(receipt["source_evidence"]["GRU"]["plan_sha256"],
                         preview.sha256(self.plan_paths["GRU"]))
        self.assertEqual(receipt["source_evidence"]["SFO"]["inventory_sha256"],
                         preview.sha256(self.inventory_paths["SFO"]))
        self.assertEqual(receipt["budget_admission"]["status"], "blocked")
        self.assertIn("cannot prove the combined USD 200 monthly ceiling",
                      receipt["budget_admission"]["reason"])
        self.assertNotIn("combined_estimate", receipt)
        self.assertNotIn("headroom", receipt)
        self.assertTrue(all("estimate" in row for row in receipt["source_evidence"].values()))
        cli_output = " ".join(str(call.args[0]) for call in printed.call_args_list)
        self.assertIn("budget_admission=BLOCKED", cli_output)
        self.assertNotIn("estimate_usd", cli_output)
        self.assertEqual(receipt["dataplane_reachability"], "not_tested")
        self.assertTrue(receipt["application_mtls_required"])
        self.assertFalse(receipt["application_mtls_verified"])
        self.assertFalse(receipt["native_replication_ready"])
        self.assertEqual({region for _, region in self.calls}, {row[0] for row in self.regions.values()})

    def test_pair_readback_rejects_disconnected_or_asymmetric_rpc(self):
        for drift in ("disconnected", "asymmetric", "wrong_peer_region"):
            with self.subTest(drift=drift):
                self.drift = drift
                with mock.patch.object(preview, "oci", side_effect=self.fake_oci):
                    with self.assertRaisesRegex(ValueError, "live RPC is disconnected, asymmetric"):
                        self.inspect_paths()

    def test_pair_readback_accepts_absent_null_or_matching_deprecated_vcn_id(self):
        for drift in (None, "vcn_attachment_vcn_id_absent", "vcn_attachment_vcn_id_matches"):
            with self.subTest(drift=drift):
                self.drift = drift
                with mock.patch.object(preview, "oci", side_effect=self.fake_oci):
                    self.assertEqual(self.inspect_paths()["status"], "configuration_readback_pass")

    def test_pair_readback_rejects_mismatched_deprecated_vcn_id_when_present(self):
        self.drift = "vcn_attachment_mismatch"
        with mock.patch.object(preview, "oci", side_effect=self.fake_oci):
            with self.assertRaisesRegex(ValueError, "VCN DRG attachment identity"):
                self.inspect_paths()

    def test_pair_readback_rejects_unexpected_routes_imports_attachments_and_ownership(self):
        cases = (
            ("extra_drg_route", "DRG route table rules"),
            ("extra_subnet_route", "reciprocal subnet route table"),
            ("broad_import", "DRG import distribution is not scoped"),
            ("extra_import_statement", "contains extra statements"),
            ("extra_attachment", "unexpected, missing, or disconnected attachment"),
            ("wrong_owner", "DRG is unavailable or owned by another compartment"),
            ("wide_nsg", "peer NSG rules"),
            ("wrong_peer_port", "peer NSG rules"),
        )
        for drift, error in cases:
            with self.subTest(drift=drift):
                self.drift = drift
                with mock.patch.object(preview, "oci", side_effect=self.fake_oci):
                    with self.assertRaisesRegex(ValueError, error):
                        self.inspect_paths()

    def test_pair_intent_fails_closed_on_stale_plan_and_overlap(self):
        changed = json.loads(self.plan_paths["SFO"].read_text())
        changed["network_cidr"] = "10.251.0.0/24"
        changed["subnet_cidr"] = "10.251.0.0/25"
        for host in changed["hosts"]:
            host["private_ip"] = "10.251.0.10"
        for rule in changed["network_security"]["nsg_rules"]:
            rule["source"] = changed["network_cidr"]
        for rule in changed["network_security"]["security_list_egress_rules"]:
            if rule["destination_type"] == "CIDR_BLOCK" and rule["destination"] != "169.254.169.254/32":
                rule["destination"] = changed["network_cidr"]
        self.write_json(self.plan_paths["SFO"], changed)
        with self.assertRaisesRegex(ValueError, "stale for the SFO plan"):
            self.inspect_paths()

        changed_intent = deepcopy(self.intent)
        changed_intent["cells"]["SFO"]["plan_sha256"] = preview.sha256(self.plan_paths["SFO"])
        self.write_json(self.intent_path, changed_intent)
        with self.assertRaisesRegex(ValueError, "CIDRs must not overlap"):
            self.inspect_paths()

    def test_pair_intent_rejects_wrong_tenancy_and_missing_cell_mapping(self):
        changed = json.loads(self.plan_paths["SFO"].read_text())
        changed["tenancy_id"] = "ocid1.tenancy.oc1..differenttenancy"
        self.write_json(self.plan_paths["SFO"], changed)
        changed_intent = deepcopy(self.intent)
        changed_intent["cells"]["SFO"]["plan_sha256"] = preview.sha256(self.plan_paths["SFO"])
        self.write_json(self.intent_path, changed_intent)
        with self.assertRaisesRegex(ValueError, "do not share the exact tenancy and realm"):
            self.inspect_paths()

        original_plan = deepcopy(self.plans["SFO"])
        original_plan.pop("_source_path")
        self.write_json(self.plan_paths["SFO"], original_plan)
        changed_intent = deepcopy(self.intent)
        changed_intent["cells"]["SFO"]["plan_sha256"] = preview.sha256(self.plan_paths["SFO"])
        changed_intent["cells"].pop("SFO")
        self.write_json(self.intent_path, changed_intent)
        with self.assertRaisesRegex(ValueError, "cell map differs"):
            self.inspect_paths()

    def test_pair_intent_rejects_cross_region_resource_mapping(self):
        changed_intent = deepcopy(self.intent)
        changed_intent["cells"]["GRU"]["rpc_id"] = (
            "ocid1.remotepeeringconnection.oc1.us-sanjose-1.wrongregion")
        self.write_json(self.intent_path, changed_intent)
        with self.assertRaisesRegex(ValueError, "invalid remotepeeringconnection OCID"):
            self.inspect_paths()

        changed_intent = deepcopy(self.intent)
        changed_intent["cells"]["GRU"]["vcn_drg_route_table_id"] = (
            "ocid1.drgroute.oc1.sa-saopaulo-1.wrongkind")
        self.write_json(self.intent_path, changed_intent)
        with self.assertRaisesRegex(ValueError, "invalid drgroutetable OCID"):
            self.inspect_paths()

    def test_pair_intent_rejects_non_rfc1918_documentation_ranges(self):
        changed = json.loads(self.plan_paths["SFO"].read_text())
        changed["network_cidr"] = "203.0.113.0/24"
        changed["subnet_cidr"] = "203.0.113.0/25"
        changed["hosts"][0]["private_ip"] = "203.0.113.10"
        for rule in changed["network_security"]["nsg_rules"]:
            rule["source"] = changed["network_cidr"]
        for rule in changed["network_security"]["security_list_egress_rules"]:
            if rule["destination_type"] == "CIDR_BLOCK" and rule["destination"] != "169.254.169.254/32":
                rule["destination"] = changed["network_cidr"]
        self.write_json(self.plan_paths["SFO"], changed)
        changed_intent = deepcopy(self.intent)
        changed_intent["cells"]["SFO"]["plan_sha256"] = preview.sha256(self.plan_paths["SFO"])
        self.write_json(self.intent_path, changed_intent)
        with self.assertRaisesRegex(ValueError, "must be inside an RFC1918 IPv4 range"):
            self.inspect_paths()

    def test_pair_inspection_rejects_stale_inventory_binding(self):
        inventory = json.loads(self.inventory_paths["GRU"].read_text())
        inventory["captured_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.write_json(self.inventory_paths["GRU"], inventory)
        with self.assertRaisesRegex(ValueError, "budget admission is stale"):
            self.inspect_paths()

    def test_private_peer_input_cannot_supply_public_address_as_connectivity_proof(self):
        changed = deepcopy(self.intent)
        changed["public_peer_address"] = "203.0.113.9:7422"
        self.write_json(self.intent_path, changed)
        with mock.patch.object(preview, "oci", side_effect=self.fake_oci):
            with self.assertRaisesRegex(ValueError, "unexpected or missing fields"):
                self.inspect_paths()
        self.assertEqual(self.calls, [])

    def test_egress_reserve_and_port_mappings_are_bounded(self):
        changed = deepcopy(self.intent)
        changed["cells"]["GRU"]["monthly_cross_region_egress_gb"] = 101
        self.write_json(self.intent_path, changed)
        with self.assertRaisesRegex(ValueError, "exceeds the regional plan's priced egress reserve"):
            self.inspect_paths()
        changed = deepcopy(self.intent)
        changed["allowed_tcp_ports"] = [7422, 7422]
        self.write_json(self.intent_path, changed)
        with self.assertRaisesRegex(ValueError, "sorted, unique, exact TCP ports"):
            self.inspect_paths()


if __name__ == "__main__":
    unittest.main()
