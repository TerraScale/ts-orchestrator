import contextlib
import datetime as dt
import importlib.util
import json
import pathlib
import subprocess
import unittest
from copy import deepcopy
from email.utils import format_datetime
from io import StringIO
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent
fixture_spec = importlib.util.spec_from_file_location("oci_preview_existing_fixtures", ROOT / "test_preview.py")
fixture_module = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixture_module)
preview = fixture_module.preview


class PreviewBaseInventoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.PreviewAdmissionTests(
            "test_import_three_gates_count_versions_and_actual_image_gib")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.directory, self.full_projection, self.entries = self.fixture.import_case()

        self.base_projection = self.directory / "base-projection.json"
        self.base_projection.write_text(json.dumps({"schema_version": 1, "imports": [self.entries[0]]}))
        self.base_staged = self.directory / "base-staged.json"
        self.base_staged.write_text(json.dumps({
            "schema_version": 1,
            "projection_sha256": preview.sha256(self.base_projection),
            "versions": {"base": "base-version-1"},
        }))

    def base_inventory(self, include_base_image=True):
        inventory = deepcopy(self.fixture.inventory)
        base = self.entries[0]
        head = next(bucket for bucket in inventory["buckets"]
                    if bucket["name"] == base["object"]["bucket"])
        head["versions"].append({
            "name": base["object"]["key"],
            "version_id": "base-version-1",
            "is_delete_marker": False,
            "size": base["bytes"],
            "storage_tier": "Standard",
            "archival_state": None,
        })
        head["object_count"] = len(head["versions"])
        head["bytes"] = sum(row["size"] for row in head["versions"] if not row["is_delete_marker"])
        inventory["images"] = ([{
            "region": self.fixture.plan["region"],
            "id": "ocid1.image.base",
            "compartment_id": base["image"]["compartment_id"],
            "display_name": base["image"]["display_name"],
            "lifecycle_state": "AVAILABLE",
            "billable_size_in_gbs": 2,
        }] if include_base_image else [])
        inventory["current_objects"] = []
        return inventory

    def command_argv(self, output):
        return ["preview.py", "import-inventory", "--plan", str(preview.PLAN),
                "--projection", str(self.full_projection), "--staged-versions", str(self.base_staged),
                "--previous-projection", str(self.base_projection), "--out", str(output)]

    def import_inventory_argv(self, output, projection, staged, previous_projection=None):
        argv = ["preview.py", "import-inventory", "--plan", str(preview.PLAN),
                "--projection", str(projection), "--staged-versions", str(staged)]
        if previous_projection is not None:
            argv.extend(("--previous-projection", str(previous_projection)))
        argv.extend(("--out", str(output)))
        return argv

    def run_inventory_command(self, output, projection, staged, include_base_image,
                              previous_projection=None):
        inventory = self.base_inventory(include_base_image=include_base_image)
        with (mock.patch.object(preview, "collect_inventory", return_value=inventory),
              mock.patch.object(preview, "oci", side_effect=self.readonly_oci(inventory)),
              mock.patch.object(preview.subprocess, "run", return_value=self.head_response()),
              mock.patch.object(preview.sys, "argv", self.import_inventory_argv(
                  output, projection, staged, previous_projection)),
              contextlib.redirect_stdout(StringIO())):
            preview.main()
        return json.loads(output.read_text())

    def run_admission_command(self, command, inventory, projection, output, phase=None,
                              staged=None, imported=None, previous_admission=None,
                              previous_projection=None, previous_inventory=None,
                              previous_staged=None, previous_imported=None):
        argv = ["preview.py", command, "--plan", str(preview.PLAN),
                "--inventory", str(inventory), "--projection", str(projection), "--out", str(output)]
        if phase is not None:
            argv.extend(("--phase", phase))
        for flag, path in (("--staged-versions", staged), ("--imported-images", imported),
                           ("--previous-admission", previous_admission),
                           ("--previous-projection", previous_projection),
                           ("--previous-inventory", previous_inventory),
                           ("--previous-staged-versions", previous_staged),
                           ("--previous-imported-images", previous_imported)):
            if path is not None:
                argv.extend((flag, str(path)))
        with (mock.patch.object(preview.sys, "argv", argv),
              contextlib.redirect_stdout(StringIO())):
            preview.main()
        return json.loads(output.read_text())

    def readonly_oci(self, inventory):
        def call(*args, region=None):
            if args[:3] == ("os", "ns", "get"):
                return "test-namespace"
            if args[:3] in (("os", "object", "list"), ("os", "object", "list-object-versions")):
                bucket_name = args[args.index("--bucket-name") + 1]
                bucket = next(bucket for bucket in inventory["buckets"] if bucket["name"] == bucket_name)
                versioned = args[:3] == ("os", "object", "list-object-versions")
                rows = []
                for item in bucket["versions"]:
                    row = {"name": item["name"], "size": item["size"],
                           "storage-tier": item["storage_tier"],
                           "archival-state": item["archival_state"]}
                    if versioned:
                        row.update({"version-id": item["version_id"],
                                    "is-delete-marker": item["is_delete_marker"]})
                    rows.append(row)
                return rows
            self.fail(f"unexpected read-only OCI command: {args}")

        return call

    def head_response(self):
        base = self.entries[0]
        response = {
            "version-id": "base-version-1",
            "content-length": str(base["bytes"]),
            "last-modified": format_datetime(dt.datetime.now(dt.timezone.utc), usegmt=True),
        }
        return subprocess.CompletedProcess([], 0, stdout=json.dumps(response), stderr="")

    def run_import_inventory(self, output, head_call):
        inventory = self.base_inventory()
        with (mock.patch.object(preview, "collect_inventory", return_value=inventory) as collect,
              mock.patch.object(preview, "oci", side_effect=self.readonly_oci(inventory)),
              mock.patch.object(preview.subprocess, "run", return_value=self.head_response()) as api_run,
              mock.patch.object(preview.sys, "argv", self.command_argv(output)),
              contextlib.redirect_stdout(StringIO())):
            preview.main()
        head_call(collect, api_run)

    def test_full_projection_import_inventory_carries_prior_base_receipt(self):
        output = self.directory / "full-inventory.json"

        def verify_calls(collect, api_run):
            collect.assert_called_once()
            api_run.assert_called_once()
            command = api_run.call_args.args[0]
            self.assertEqual(command[:4], ["oci", "os", "object", "head"])
            self.assertEqual(command[command.index("--bucket-name") + 1], self.entries[0]["object"]["bucket"])
            self.assertEqual(command[command.index("--name") + 1], self.entries[0]["object"]["key"])

        self.run_import_inventory(output, verify_calls)

        inventory = json.loads(output.read_text())
        self.assertEqual(len(inventory["current_objects"]), 1)
        current = inventory["current_objects"][0]
        self.assertEqual((current["bucket"], current["name"], current["version_id"], current["size"]),
                         (self.entries[0]["object"]["bucket"], self.entries[0]["object"]["key"],
                          "base-version-1", self.entries[0]["bytes"]))
        self.assertEqual(inventory["images"], [{
            "region": self.fixture.plan["region"],
            "id": "ocid1.image.base",
            "compartment_id": self.entries[0]["image"]["compartment_id"],
            "display_name": self.entries[0]["image"]["display_name"],
            "lifecycle_state": "AVAILABLE",
            "billable_size_in_gbs": 2,
        }])

    def test_full_projection_import_inventory_rejects_tampered_carried_image_identity(self):
        projection = json.loads(self.full_projection.read_text())
        projection["imports"][0]["image"]["display_name"] = "preview-substituted-base"
        self.full_projection.write_text(json.dumps(projection))
        output = self.directory / "tampered-inventory.json"
        inventory = self.base_inventory()

        with (mock.patch.object(preview, "collect_inventory", return_value=inventory) as collect,
              mock.patch.object(preview, "oci", side_effect=self.readonly_oci(inventory)),
              mock.patch.object(preview.subprocess, "run", return_value=self.head_response()) as api_run,
              mock.patch.object(preview.sys, "argv", self.command_argv(output)),
              contextlib.redirect_stdout(StringIO())):
            with self.assertRaisesRegex(ValueError, "base row differs from the staged base-only projection"):
                preview.main()

        collect.assert_called_once()
        api_run.assert_not_called()
        self.assertFalse(output.exists())

    def test_full_projection_import_inventory_requires_exact_base_receipt_hash(self):
        receipt = json.loads(self.base_staged.read_text())
        receipt["projection_sha256"] = preview.sha256(self.full_projection)
        self.base_staged.write_text(json.dumps(receipt))
        output = self.directory / "wrong-receipt-inventory.json"
        inventory = self.base_inventory()

        with (mock.patch.object(preview, "collect_inventory", return_value=inventory) as collect,
              mock.patch.object(preview, "oci", side_effect=self.readonly_oci(inventory)),
              mock.patch.object(preview.subprocess, "run", return_value=self.head_response()) as api_run,
              mock.patch.object(preview.sys, "argv", self.command_argv(output)),
              contextlib.redirect_stdout(StringIO())):
            with self.assertRaisesRegex(ValueError, "bound to another projection"):
                preview.main()

        collect.assert_called_once()
        api_run.assert_not_called()
        self.assertFalse(output.exists())

    def test_base_only_cli_import_chain_and_full_projection_transition(self):
        base_inventory = self.directory / "base-before-upload-inventory.json"
        base_inventory.write_text(json.dumps(self.fixture.inventory))
        prestage_admission = self.directory / "base-prestage-admission.json"
        self.run_admission_command("import-admit", base_inventory, self.base_projection,
                                   prestage_admission, phase="pre-stage")

        staged_inventory = self.directory / "base-staged-inventory.json"
        staged_snapshot = self.run_inventory_command(
            staged_inventory, self.base_projection, self.base_staged, include_base_image=False)
        self.assertEqual(staged_snapshot["current_objects"][0]["version_id"], "base-version-1")
        upload_readback = self.directory / "base-upload-readback-admission.json"
        upload_admission = self.run_admission_command(
            "import-admit", staged_inventory, self.base_projection, upload_readback,
            phase="pre-stage", staged=self.base_staged, previous_admission=prestage_admission)
        self.assertEqual(upload_admission["staged_versions_sha256"], preview.sha256(self.base_staged))

        preimport_admission = self.directory / "base-preimport-admission.json"
        preimport = self.run_admission_command(
            "import-admit", staged_inventory, self.base_projection, preimport_admission,
            phase="pre-import", staged=self.base_staged, previous_staged=self.base_staged,
            previous_admission=upload_readback)
        self.assertEqual(preimport["phase"], "pre-import")
        self.assertEqual(preimport["staged_versions_sha256"], preview.sha256(self.base_staged))

        imported_images = self.directory / "base-imported-images.json"
        imported_images.write_text(json.dumps({
            "schema_version": 1,
            "projection_sha256": preview.sha256(self.base_projection),
            "images": {"base": "ocid1.image.base"},
        }))
        image_inventory = self.directory / "base-image-readback-inventory.json"
        image_snapshot = self.run_inventory_command(
            image_inventory, self.base_projection, self.base_staged, include_base_image=True)
        self.assertEqual(image_snapshot["images"][0]["id"], "ocid1.image.base")
        image_readback_admission = self.directory / "base-image-readback-admission.json"
        self.run_admission_command("import-admit", image_inventory, self.base_projection,
                                   image_readback_admission, phase="pre-import",
                                   staged=self.base_staged, imported=imported_images,
                                   previous_staged=self.base_staged,
                                   previous_admission=preimport_admission)

        postimport_admission = self.directory / "base-postimport-admission.json"
        self.run_admission_command("import-reconcile", image_inventory, self.base_projection,
                                   postimport_admission, staged=self.base_staged,
                                   imported=imported_images, previous_staged=self.base_staged,
                                   previous_imported=imported_images,
                                   previous_admission=image_readback_admission)

        full_prestage_admission = self.directory / "full-prestage-admission.json"
        full_result = self.run_admission_command(
            "import-admit", image_inventory, self.full_projection, full_prestage_admission,
            phase="pre-stage", previous_admission=image_readback_admission,
            previous_projection=self.base_projection, previous_inventory=image_inventory,
            previous_staged=self.base_staged, previous_imported=imported_images)
        self.assertEqual(full_result["base_lineage"]["base_version_id"], "base-version-1")
        self.assertEqual(full_result["base_lineage"]["base_image_id"], "ocid1.image.base")
        self.assertEqual(full_result["estimate"]["object_projected_bytes"], self.entries[1]["bytes"])
