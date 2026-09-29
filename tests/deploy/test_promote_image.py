"""Exercise deploy/image/promote-image.py against fake Forgejo, OCI and ts-release tools."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROMOTE = ROOT / "deploy/image/promote-image.py"
SOURCE = "5ff44290b67a91c3b27373c6661d778fe6ef8ffc"
IMAGE_RUN_ID, IMAGE_RUN_NUMBER, IMAGE_JOB_ID = 11738, 713, 25300
GO_RUN_ID, GO_RUN_NUMBER = 11737, 712
IMAGE_TAG = f"image-{SOURCE}-run-{IMAGE_RUN_ID}-attempt-1"
GO_TAG = f"ci-{SOURCE}-run-{GO_RUN_ID}"
BASE_TAG = "image-base-noble-arm64-20260926"
IMPORTED_OCID = "ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaimported"

FAKE_FJ = r"""#!/usr/bin/env python3
import json, os, shutil, sys
from pathlib import Path
fixture = Path(os.environ["PROMOTE_FIXTURE"])
args = sys.argv[1:]
with (fixture / "fj-calls.log").open("a") as log:
    log.write(" ".join(args) + "\n")
if args[-1] == "--help":
    raise SystemExit(0)
if args[:3] == ["release", "asset", "download"]:
    repository, tag, asset, destination = args[4], args[5], args[6], args[8]
    source = fixture / "releases" / repository.replace("/", "_") / tag / asset
    if not source.is_file():
        print(f"asset not found: {tag}/{asset}", file=sys.stderr)
        raise SystemExit(1)
    shutil.copyfile(source, destination)
elif args[:2] == ["actions", "run-detail"]:
    print((fixture / "run-detail" / f"{args[2]}.json").read_text())
elif args[:2] == ["actions", "logs"]:
    print((fixture / "logs" / f"{args[2]}.txt").read_text())
else:
    raise SystemExit(f"unexpected fake fj call: {args}")
"""

FAKE_RELEASE = r"""#!/usr/bin/env python3
import os, sys
from pathlib import Path
fixture = Path(os.environ["PROMOTE_FIXTURE"])
args = sys.argv[1:]
with (fixture / "release-calls.log").open("a") as log:
    log.write("\0".join(args) + "\n")
if os.environ.get("PROMOTE_FAIL_RELEASE") == args[0]:
    print(f"fake {args[0]} rejected its inputs", file=sys.stderr)
    raise SystemExit(1)
if "--out" in args:
    Path(args[args.index("--out") + 1]).write_text('{"fake":"' + args[0] + '"}\n')
if args[0] == "verify-image":
    print("verified OCI image=fake region=GRU")
"""

FAKE_OCI = r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
fixture = Path(os.environ["PROMOTE_FIXTURE"])
args = [arg for arg in sys.argv[1:]]
with (fixture / "oci-calls.log").open("a") as log:
    log.write(" ".join(args) + "\n")
command = " ".join(args[2:5])
shapes = fixture / "oci-shapes.json"
def reply(data):
    print(json.dumps({"data": data}))
if command.startswith("compute image list"):
    reply([])
elif command.startswith("os object head"):
    raise SystemExit(1)
elif command.startswith("os object put"):
    print("{}")
elif command.startswith("compute image import"):
    reply({"id": os.environ["PROMOTE_IMPORTED_OCID"], "lifecycle-state": "IMPORTING"})
elif command.startswith("compute image get"):
    reply({"id": os.environ["PROMOTE_IMPORTED_OCID"], "lifecycle-state": "AVAILABLE", "billable-size-in-gbs": 3})
elif command.startswith("compute image-capability-schema list"):
    reply([])
elif command.startswith("compute global-image-capability-schema list"):
    reply([{"current-version-name": "v1"}])
elif command.startswith("compute image-capability-schema create"):
    reply({"id": "ocid1.schema", "schema-data": json.loads(args[args.index("--schema-data") + 1])})
elif command.startswith("compute image-shape-compatibility-entry list"):
    reply(json.loads(shapes.read_text()) if shapes.exists() else [])
elif command.startswith("compute image-shape-compatibility-entry add"):
    shapes.write_text(json.dumps([{"shape": "VM.Standard.A1.Flex", "ocpu-constraints": {"min": 1, "max": 4},
                                   "memory-constraints": {"min-in-gbs": 6, "max-in-gbs": 24}}]))
    print("{}")
else:
    raise SystemExit(f"unexpected fake oci call: {args}")
"""


def executable(path: Path, contents: str) -> Path:
    path.write_text(contents, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PromoteImageTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ts-promote-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture = self.root / "fixture"
        self.bin = self.root / "bin"
        for directory in (self.fixture / "run-detail", self.fixture / "logs", self.bin):
            directory.mkdir(parents=True)
        self.fj = executable(self.root / "fj", FAKE_FJ)
        self.release_tool = executable(self.root / "ts-release", FAKE_RELEASE)
        executable(self.bin / "oci", FAKE_OCI)
        executable(self.bin / "virt-cat", "#!/bin/sh\necho 'virt-cat 1.52.3'\n")
        self.trust = self.root / "trust"
        self.trust.mkdir()
        for name in ("delegation.json", "root.pub", "leaf.pem"):
            (self.trust / name).write_text(f"fake {name}\n")

        self.base = b"base qcow2 bytes"
        self.binary = b"orchestrator arm64 binary"
        self.go_qualification = json.dumps({"schema": "terrascale.release.qualification.v1"}).encode()
        manifest_inputs = {
            "region": "GRU",
            "base": {"release_tag": BASE_TAG, "oci_image_ocid": "ocid1.image.oc1.sa-saopaulo-1.base",
                     "assets": {"base-image.qcow2": {"bytes": len(self.base), "sha256": digest(self.base)}}},
        }
        self.image = b"final qcow2 bytes"
        self.kernel = b"arm64 kernel"
        self.manifest = {
            "schema": "terrascale.image.qualification.v2", "source_revision": SOURCE, "source_tree": "0" * 40,
            "builder": {"kind": "ci", "workflow": "image.yml", "job": "build/qualified-gru-arm64-image",
                        "run_id": IMAGE_RUN_ID, "run_number": IMAGE_RUN_NUMBER, "job_id": IMAGE_JOB_ID,
                        "run_attempt": 1, "required_final_status": "success"},
            "inputs": {"path": "deploy/image/image-inputs.json", "sha256": "1" * 64, "manifest": manifest_inputs},
            "go_candidate": {"release_tag": GO_TAG, "run_id": GO_RUN_ID, "run_number": GO_RUN_NUMBER,
                             "qualification_sha256": digest(self.go_qualification),
                             "binary_sha256": digest(self.binary), "binary_bytes": len(self.binary)},
            "kernel": {"name": "guest-kernel", "release": "6.8.0-142-generic", "sha256": digest(self.kernel)},
            "image": {"name": "terrascale-gru-arm64.qcow2", "sha256": digest(self.image), "bytes": len(self.image)},
        }
        self.write_image_release()
        self.write_release("TerraScale/ts-orchestrator", GO_TAG, {
            "qualification.json": self.go_qualification,
            "terrascale-orchestrator-linux-arm64": self.binary,
            "canary-linux-arm64.receipt.json": b'{"signed":"binary"}',
        })
        self.write_release("TerraScale/ts-orchestrator", BASE_TAG, {"base-image.qcow2": self.base})
        self.write_image_run("success", "success")

    def write_release(self, repository: str, tag: str, assets: dict[str, bytes]) -> Path:
        directory = self.fixture / "releases" / repository.replace("/", "_") / tag
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in assets.items():
            (directory / name).write_bytes(data)
        return directory

    def write_image_release(self) -> None:
        manifest = (json.dumps(self.manifest, indent=2) + "\n").encode()
        sums = "".join(f"{digest(data)}  {name}\n" for name, data in (
            ("terrascale-gru-arm64.qcow2", self.image), ("guest-kernel", self.kernel),
            ("image-qualification.json", manifest)))
        self.image_dir = self.write_release("TerraScale/ts-orchestrator", IMAGE_TAG, {
            "terrascale-gru-arm64.qcow2": self.image, "guest-kernel": self.kernel,
            "image-qualification.json": manifest, "SHA256SUMS": sums.encode(),
        })
        marker = (f"TS_IMAGE_QUALIFICATION_V1 source_sha={SOURCE} run_id={IMAGE_RUN_ID} "
                  f"run_number={IMAGE_RUN_NUMBER} job_id={IMAGE_JOB_ID} attempt=1 image_sha256={digest(self.image)} "
                  f"kernel_sha256={digest(self.kernel)} provenance_sha256={digest(manifest)} tag={IMAGE_TAG}")
        (self.fixture / "logs" / f"{IMAGE_RUN_NUMBER}.txt").write_text(
            f"job_id={IMAGE_JOB_ID}\n2026-09-29T16:00:00.1234567Z {marker}\n")

    def write_image_run(self, run_status: str, job_status: str) -> None:
        (self.fixture / "run-detail" / f"{IMAGE_RUN_NUMBER}.json").write_text(json.dumps({
            "run_id": IMAGE_RUN_ID, "run_number": IMAGE_RUN_NUMBER, "head_sha": SOURCE, "workflow": "image.yml",
            "status": run_status, "jobs": [{"id": IMAGE_JOB_ID, "run_id": IMAGE_RUN_ID, "attempt": 1,
                                            "name": "build/qualified-gru-arm64-image", "status": job_status}],
        }))

    def promote(self, *extra: str, image: tuple[str, str] = ("--image-release", IMAGE_TAG),
                **environment: str) -> subprocess.CompletedProcess[str]:
        self.out = self.root / "promotion"
        return subprocess.run(
            [sys.executable, str(PROMOTE), *image, "--out", str(self.out),
             "--delegation", str(self.trust / "delegation.json"), "--root-key", str(self.trust / "root.pub"),
             "--fj", str(self.fj), "--release-tool", str(self.release_tool), *extra],
            env={**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                 "PROMOTE_FIXTURE": str(self.fixture), "PROMOTE_IMPORTED_OCID": IMPORTED_OCID, **environment},
            capture_output=True, text=True, check=False,
        )

    def real_arguments(self) -> tuple[str, ...]:
        return ("--signing-key", str(self.trust / "leaf.pem"), "--compartment-id", "ocid1.compartment.oc1..c",
                "--namespace", "ns", "--bucket", "images")

    def release_calls(self) -> list[list[str]]:
        log = self.fixture / "release-calls.log"
        return [line.split("\0") for line in log.read_text().splitlines()] if log.exists() else []

    def oci_calls(self) -> list[str]:
        log = self.fixture / "oci-calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def receipt(self) -> dict:
        return json.loads((self.out / "promotion-receipt.json").read_text())

    def test_ci_image_release_is_imported_signed_verified_and_receipted(self) -> None:
        result = self.promote(*self.real_arguments())
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual([call[0] for call in self.release_calls()],
                         ["verify-binary", "image-candidate", "sign-image", "verify-image"])
        candidate = self.release_calls()[1]
        self.assertEqual(candidate[candidate.index("--image-ocid") + 1], IMPORTED_OCID)
        self.assertEqual(candidate[candidate.index("--base-image-ocid") + 1], "ocid1.image.oc1.sa-saopaulo-1.base")
        self.assertEqual(candidate[candidate.index("--kernel-release") + 1], "6.8.0-142-generic")
        sign = self.release_calls()[2]
        self.assertEqual(sign[sign.index("--signing-key") + 1], str(self.trust / "leaf.pem"))
        self.assertTrue(any(" image import from-object " in call for call in self.oci_calls()))
        receipt = self.receipt()
        self.assertFalse(receipt["dry_run"])
        self.assertEqual(receipt["oci_import"]["image_id"], IMPORTED_OCID)
        self.assertEqual(receipt["oci_import"]["shapes"], ["VM.Standard.A1.Flex"])
        self.assertEqual(receipt["image"]["sha256"], digest(self.image))
        self.assertEqual(receipt["image"]["provenance"]["release_tag"], IMAGE_TAG)
        self.assertEqual(receipt["image_receipt"]["image_ocid"], IMPORTED_OCID)
        self.assertEqual(receipt["tools"]["fj"]["sha256"], digest(self.fj.read_bytes()))
        self.assertEqual(receipt["outcome"], "promotion complete")

    def test_dry_run_passes_read_only_gates_without_import_or_signing(self) -> None:
        result = self.promote("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.oci_calls(), [])
        self.assertEqual([call[0] for call in self.release_calls()], ["verify-binary", "image-candidate"])
        candidate = self.release_calls()[1]
        self.assertTrue(candidate[candidate.index("--image-ocid") + 1].startswith(
            "ocid1.image.oc1.sa-saopaulo-1.dryrun"))
        receipt = self.receipt()
        self.assertTrue(receipt["dry_run"])
        self.assertEqual(receipt["oci_import"]["skipped"], "dry run")

    def assert_rejected_before_effects(self, result: subprocess.CompletedProcess[str], message: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.oci_calls(), [])
        self.assertNotIn("sign-image", [call[0] for call in self.release_calls()])
        self.assertFalse((self.out / "promotion-receipt.json").exists())

    def test_failed_image_run_is_rejected(self) -> None:
        self.write_image_run("failure", "success")
        self.assert_rejected_before_effects(self.promote(*self.real_arguments()), "image.yml run did not succeed")

    def test_other_job_attempt_is_rejected(self) -> None:
        self.write_image_run("success", "failure")
        self.assert_rejected_before_effects(self.promote(*self.real_arguments()),
                                            "image job did not succeed on this attempt")

    def test_missing_log_marker_is_rejected(self) -> None:
        (self.fixture / "logs" / f"{IMAGE_RUN_NUMBER}.txt").write_text("no marker\n")
        self.assert_rejected_before_effects(self.promote(*self.real_arguments()),
                                            "lacks one exact TS_IMAGE_QUALIFICATION_V1 marker")

    def test_tampered_image_bytes_are_rejected(self) -> None:
        (self.image_dir / "terrascale-gru-arm64.qcow2").write_bytes(b"tampered")
        self.assert_rejected_before_effects(self.promote(*self.real_arguments()),
                                            "image asset differs from SHA256SUMS: terrascale-gru-arm64.qcow2")

    def test_candidate_binary_must_match_the_image_manifest(self) -> None:
        self.write_release("TerraScale/ts-orchestrator", GO_TAG, {"terrascale-orchestrator-linux-arm64": b"other"})
        self.assert_rejected_before_effects(self.promote(*self.real_arguments()),
                                            f"candidate release {GO_TAG} differs from the image manifest")

    def test_rejected_binary_receipt_stops_before_import(self) -> None:
        self.assert_rejected_before_effects(self.promote(*self.real_arguments(), PROMOTE_FAIL_RELEASE="verify-binary"),
                                            "ts-release verify-binary failed")

    def test_unsigned_candidate_needs_sign_binary(self) -> None:
        receipt = self.fixture / "releases/TerraScale_ts-orchestrator" / GO_TAG / "canary-linux-arm64.receipt.json"
        receipt.unlink()
        self.assert_rejected_before_effects(self.promote(*self.real_arguments()), "pass --sign-binary")

        shutil.rmtree(self.out)
        (self.fixture / "release-calls.log").unlink()
        result = self.promote("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[0] for call in self.release_calls()], ["binary-candidate"])
        self.assertEqual(self.receipt()["candidate"]["binary_receipt"], "missing: sign with --sign-binary")

        shutil.rmtree(self.out)
        (self.fixture / "release-calls.log").unlink()
        result = self.promote(*self.real_arguments(), "--sign-binary")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[0] for call in self.release_calls()],
                         ["binary-candidate", "sign-binary", "verify-binary", "image-candidate", "sign-image",
                          "verify-image"])

    def test_local_build_directory_is_promoted_without_ci_evidence(self) -> None:
        self.manifest["builder"] = {"kind": "local", "user": "operator", "host": "dev"}
        self.write_image_release()
        local = self.root / "local-image"
        shutil.copytree(self.image_dir, local)
        result = self.promote("--dry-run", image=("--image-dir", str(local)))
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.fixture / "fj-calls.log").read_text()
        self.assertNotIn(f"actions run-detail {IMAGE_RUN_NUMBER}", calls)
        self.assertEqual(self.receipt()["image"]["provenance"]["builder"]["kind"], "local")

    def test_real_promotion_requires_signing_and_oci_targets(self) -> None:
        result = self.promote()
        self.assertEqual(result.returncode, 2)
        self.assertIn("--signing-key, --compartment-id, --namespace, --bucket", result.stderr)

    def test_unpinned_fj_is_rejected(self) -> None:
        executable(self.fj, "#!/bin/sh\nexit 1\n")
        result = self.promote("--dry-run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("lacks the pinned `fj actions run-detail` extension", result.stderr)


if __name__ == "__main__":
    unittest.main()
