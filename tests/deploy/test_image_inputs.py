"""Exercise deploy/image/image-inputs.py: the pinned image input manifest."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "deploy/image/image-inputs.py"
MANIFEST = ROOT / "deploy/image/image-inputs.json"
SOURCE = "470d1f898897d4a0cefc7d638ce8eb72f0ca73b8"


class ImageInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ts-image-inputs-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.manifest = self.root / "image-inputs.json"
        shutil.copyfile(MANIFEST, self.manifest)
        self.qualification = self.root / "qualification.json"
        self.qualification.write_text(json.dumps({
            "schema": "terrascale.terrabase.qualification.v2", "repository": "TerraScale/TerraBase",
            "source_revision": SOURCE, "source_tree": "b" * 40,
            "verification": {"workflow": "fast.yml", "job": "fast", "run_id": 11711, "run_number": 1018,
                             "conclusion": "success"},
            "artifacts": [
                {"name": "tb-server-linux-amd64", "target": "x86_64-unknown-linux-musl", "sha256": "1" * 64},
                {"name": "tb-server-linux-arm64", "target": "aarch64-unknown-linux-musl", "sha256": "2" * 64},
            ],
        }))
        self.run_detail = self.root / "run-detail.json"
        self.write_run_detail("success", "success")

    def write_run_detail(self, run_status: str, fast_status: str) -> None:
        self.run_detail.write_text(json.dumps({
            "run_id": 11711, "run_number": 1018, "head_sha": SOURCE, "workflow": "fast.yml", "status": run_status,
            "jobs": [{"id": 1, "run_id": 11711, "name": "fast", "status": fast_status, "attempt": 1},
                     {"id": 2, "run_id": 11711, "name": "publish", "status": "running", "attempt": 1}],
        }))

    def tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(TOOL), "--file", str(self.manifest), *arguments],
                              capture_output=True, text=True, check=False)

    def pin(self) -> subprocess.CompletedProcess[str]:
        return self.tool("pin-terrabase", "--qualification", str(self.qualification),
                         "--run-detail", str(self.run_detail))

    def test_checked_in_manifest_is_valid(self) -> None:
        result = self.tool("check")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_non_canonical_formatting_is_rejected(self) -> None:
        self.manifest.write_text(json.dumps(json.loads(self.manifest.read_text())))
        result = self.tool("check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not canonically formatted", result.stderr)

    def test_checked_in_input_must_match_its_pin(self) -> None:
        manifest = json.loads(self.manifest.read_text())
        manifest["timesyncd_config"]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
        result = self.tool("check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("checked-in input differs from its pin", result.stderr)

    def test_netbird_config_and_client_sources_are_pinned(self) -> None:
        manifest = json.loads(self.manifest.read_text())
        manifest["netbird"]["enrollment_config"]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
        result = self.tool("check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("checked-in input differs from its pin", result.stderr)
        manifest["netbird"]["archives"]["arm64"]["url"] = "https://other.example/netbird.tar.gz"
        self.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
        result = self.tool("check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid NetBird arm64 archive source", result.stderr)

    def test_pin_rewrites_only_the_terrabase_block(self) -> None:
        before = json.loads(self.manifest.read_text())
        result = self.pin()
        self.assertEqual(result.returncode, 0, result.stderr)
        after = json.loads(self.manifest.read_text())
        self.assertEqual(after["terrabase"], {
            "source_revision": SOURCE, "source_tree": "b" * 40, "run_id": 11711, "run_number": 1018,
            "qualification_sha256": hashlib.sha256(self.qualification.read_bytes()).hexdigest(),
            "binary_sha256": "2" * 64,
        })
        self.assertEqual({key: value for key, value in after.items() if key != "terrabase"},
                         {key: value for key, value in before.items() if key != "terrabase"})
        self.assertEqual(self.manifest.read_text(), json.dumps(after, indent=2) + "\n")

    def test_pin_accepts_the_publishing_run_while_it_finishes(self) -> None:
        self.write_run_detail("running", "success")
        self.assertEqual(self.pin().returncode, 0)

    def test_pin_rejects_failed_fast_or_mismatched_run(self) -> None:
        original = self.manifest.read_text()
        for run_status, fast_status in (("failure", "success"), ("running", "failure")):
            with self.subTest(run=run_status, fast=fast_status):
                self.write_run_detail(run_status, fast_status)
                result = self.pin()
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.manifest.read_text(), original)
        self.write_run_detail("success", "success")
        detail = json.loads(self.run_detail.read_text())
        detail["head_sha"] = "c" * 40
        self.run_detail.write_text(json.dumps(detail))
        self.assertEqual(self.pin().returncode, 1)
        self.assertEqual(self.manifest.read_text(), original)

    def test_pin_requires_one_arm64_server_artifact(self) -> None:
        qualification = json.loads(self.qualification.read_text())
        qualification["artifacts"] = qualification["artifacts"][:1]
        self.qualification.write_text(json.dumps(qualification))
        result = self.pin()
        self.assertEqual(result.returncode, 1)
        self.assertIn("must list one tb-server-linux-arm64", result.stderr)


if __name__ == "__main__":
    unittest.main()
