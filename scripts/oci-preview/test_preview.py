import datetime as dt
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oci_preview", ROOT / "preview.py")
preview = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preview)


class PreviewAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.plan = preview.load_plan()
        existing = self.plan["existing_forgejo"]
        shared = self.plan["shared_compartment_id"]
        self.inventory = {
            "schema_version": 2,
            "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "plan_sha256": preview.sha256(preview.PLAN),
            "tenancy_id": self.plan["tenancy_id"],
            "preview_compartment_ids": {"control": None, "network": None, "workload": None},
            "buckets": [
                {"name": "ts-forgejo", "bytes": 30 * 1024**3,
                 "versioning": "Disabled", "storage_tier": "Standard"},
                {"name": "ts-forgejo-backup", "bytes": 28 * 1024**3,
                 "versioning": "Disabled", "storage_tier": "Standard"},
            ],
            "resources": [
                {"kind": "instance", "id": existing["instance_id"], "compartment-id": shared,
                 "lifecycle-state": "RUNNING", "shape": "VM.Standard.A1.Flex",
                 "shape-config": {"ocpus": 2, "memory-in-gbs": 4}},
                {"kind": "boot-volume", "id": existing["boot_volume_id"], "compartment-id": shared,
                 "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
                {"kind": "volume", "id": existing["data_volume_id"], "compartment-id": shared,
                 "lifecycle-state": "AVAILABLE", "size-in-gbs": 50, "vpus-per-gb": 10},
                {"kind": "public-ip", "id": existing["public_ip_id"], "compartment-id": shared,
                 "lifecycle-state": "ASSIGNED"},
            ],
        }

    def test_five_host_budget_includes_existing_resources_and_reserves(self):
        cost = preview.estimate(self.plan, self.inventory)
        self.assertEqual(cost["items"]["compute"], "58.6200")
        self.assertEqual(cost["items"]["block_storage"], "10.6250")
        self.assertEqual(cost["items"]["snapshot_reserve"], "8.9250")
        self.assertLess(float(cost["total"]), 100)

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
        for index in range(6):
            row = {"kind": "instance", "id": f"ocid1.instance.preview-{index}",
                   "compartment-id": control if index < 3 else workload, "lifecycle-state": "RUNNING",
                   "shape": "VM.Standard.A1.Flex", "shape-config": {"ocpus": 1, "memory-in-gbs": 6},
                   "time-created": (now - dt.timedelta(hours=73 if index < 5 else 1)).isoformat()}
            if index == 0:
                row["display-name"] = "terrascale-orchestrator-gru"
                row["freeform-tags"] = {"ManagedBy": "ts-infra", "Role": "initial-controller"}
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

    def test_seed_preflight_binds_ts_infra_foundation_and_signed_image(self):
        ids = self.plan["resource_ids"]
        ids.update({"control_compartment": "ocid1.compartment.control", "network_compartment": "ocid1.compartment.network",
                    "workload_compartment": "ocid1.compartment.workload", "vcn": "ocid1.vcn.gru",
                    "subnet": "ocid1.subnet.gru", "network_security_group": "ocid1.networksecuritygroup.gru"})
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
            result = preview.verify_seed_preflight(self.plan, inventory_path, admission_path, summary,
                                                   receipt_path, verified)
            self.assertEqual(result["compartment_id"], ids["control_compartment"])
            self.assertFalse(result["assign_public_ip"])
            summary["profile"]["compartmentOcid"] = ids["workload_compartment"]
            with self.assertRaisesRegex(ValueError, "recorded controller-a profile"):
                preview.verify_seed_preflight(self.plan, inventory_path, admission_path, summary,
                                              receipt_path, verified)
            summary["profile"]["compartmentOcid"] = ids["control_compartment"]
            admission["expires_at"] = (now - dt.timedelta(seconds=1)).isoformat()
            admission_path.write_text(json.dumps(admission))
            with self.assertRaisesRegex(ValueError, "stale"):
                preview.verify_seed_preflight(self.plan, inventory_path, admission_path, summary,
                                              receipt_path, verified)


if __name__ == "__main__":
    unittest.main()
