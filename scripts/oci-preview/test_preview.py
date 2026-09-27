import datetime as dt
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from decimal import Decimal
from email.utils import format_datetime
from unittest import mock


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
                                          "versioning": "Enabled", "storage_tier": "Standard", "versions": [old]})
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

    def test_import_three_gates_count_versions_and_actual_image_gib(self):
        directory, projection, entries = self.import_case()
        first = preview.import_estimate(self.plan, self.inventory, projection, "pre-stage")
        self.assertEqual(first["object_projected_bytes"], sum(row["bytes"] for row in entries))
        self.assertEqual(first["import_image_billed_gib"], "7")
        exact_object_gb = Decimal(sum(row["bytes"] for row in self.inventory["buckets"]) +
                                  first["object_projected_bytes"]) / Decimal(1_000_000_000)
        object_gb = max(exact_object_gb, Decimal("57.93")) + Decimal(10)
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
            prior_path, "pre-stage", preview.sha256(projection)), prior)
        with self.assertRaisesRegex(ValueError, "does not bind"):
            preview.verify_previous_import_admission(prior_path, "pre-stage", "0" * 64)
        prior["expires_at"] = (admitted + dt.timedelta(minutes=30)).isoformat()
        prior_path.write_text(json.dumps(prior))
        with self.assertRaisesRegex(ValueError, "invalid timestamps"):
            preview.verify_previous_import_admission(prior_path, "pre-stage", preview.sha256(projection))

    def test_current_head_uses_unqualified_object_and_requires_version_header(self):
        now = format_datetime(dt.datetime.now(dt.timezone.utc), usegmt=True)
        response = {"opc-version-id": "v1", "content-length": "123", "last-modified": now}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(response), stderr="")
        with mock.patch.object(preview.subprocess, "run", return_value=completed) as run:
            current = preview.current_object_head("namespace", "bucket", "key", self.plan["region"])
            self.assertEqual(current["version_id"], "v1")
            self.assertEqual(current["size"], 123)
            self.assertNotIn("--version-id", run.call_args.args[0])
        completed.stdout = json.dumps({"content-length": "123", "last-modified": now})
        with mock.patch.object(preview.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "version identity"):
                preview.current_object_head("namespace", "bucket", "key", self.plan["region"])


if __name__ == "__main__":
    unittest.main()
