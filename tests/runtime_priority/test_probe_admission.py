from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import alpha_adapter
import pressure
import probe_admission


SOURCE = "a" * 40
TREE = "b" * 40
PROBE = b"# exact CI-published probe fixture\n"
PROBE_SHA256 = hashlib.sha256(PROBE).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


class ProbeAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.probe_path = root / probe_admission.PROBE_ASSET
        self.descriptor_path = root / "terrascale-d15-probe.json"
        self.qualification_path = root / "qualification.json"
        self.run_detail_path = root / "run-detail.json"
        self.job_log_path = root / "job.log"
        self.probe_path.write_bytes(PROBE)
        self.descriptor = {
            "schema": probe_admission.PUBLICATION_SCHEMA,
            "repository": "TerraScale/ts-orchestrator",
            "source_revision": SOURCE,
            "source_tree": TREE,
            "verification": {
                "workflow": "ci.yml", "job": probe_admission.JOB_NAME,
                "run_id": 123, "run_number": 7,
            },
            "probe": {
                "name": probe_admission.PROBE_ASSET,
                "bytes": len(PROBE), "sha256": PROBE_SHA256,
            },
        }
        self.qualification = {
            "schema": "terrascale.release.qualification.v1",
            "repository": "TerraScale/ts-orchestrator",
            "source_revision": SOURCE,
            "source_tree": TREE,
            "go_version": "go1.27.1",
            "go_mod_sha256": "c" * 64,
            "go_sum_sha256": "d" * 64,
            "verification": {**self.descriptor["verification"], "conclusion": "success"},
            "artifacts": [
                {"architecture": architecture,
                 "name": f"terrascale-orchestrator-linux-{architecture}",
                 "bytes": 100, "sha256": "e" * 64}
                for architecture in ("amd64", "arm64")
            ],
        }
        self.run_detail = {
            "run_id": 123, "run_number": 7,
            "head_sha": SOURCE, "workflow": "ci.yml", "status": "success",
            "jobs": [{
                "id": 456, "run_id": 123, "name": probe_admission.JOB_NAME,
                "status": "success", "attempt": 2,
            }],
        }
        descriptor_wire = (json.dumps(self.descriptor, sort_keys=True) + "\n").encode()
        qualification_wire = (json.dumps(self.qualification, sort_keys=True) + "\n").encode()
        self.job_log_path.write_text(
            f"2026-09-28T12:00:00Z TS_D15_PROBE_PUBLICATION_V1 source_sha={SOURCE} "
            f"run_id=123 run_number=7 probe_sha256={PROBE_SHA256} "
            f"descriptor_sha256={hashlib.sha256(descriptor_wire).hexdigest()}\n"
            f"2026-09-28T12:00:01Z TS_RELEASE_QUALIFICATION_V1 source_sha={SOURCE} "
            f"run_id=123 run_number=7 "
            f"manifest_sha256={hashlib.sha256(qualification_wire).hexdigest()}\n",
            encoding="utf-8",
        )

    def admit(self) -> dict[str, object]:
        write_json(self.descriptor_path, self.descriptor)
        write_json(self.qualification_path, self.qualification)
        write_json(self.run_detail_path, self.run_detail)
        return probe_admission.admit(
            self.probe_path, self.descriptor_path, self.qualification_path,
            self.run_detail_path, self.job_log_path, f"ci-{SOURCE}-run-123",
        )

    def test_exact_publication_and_successful_job_readback_produce_pinned_receipt(self) -> None:
        receipt = self.admit()
        self.assertEqual(receipt["probe_sha256"], PROBE_SHA256)
        self.assertEqual(receipt["source_revision"], SOURCE)
        self.assertEqual((receipt["run_id"], receipt["job_id"], receipt["attempt"]),
                         (123, 456, 2))
        self.assertEqual(receipt["publication_sha256"], hashlib.sha256(
            self.descriptor_path.read_bytes()).hexdigest())
        self.assertEqual(receipt["qualification_sha256"], hashlib.sha256(
            self.qualification_path.read_bytes()).hexdigest())
        self.assertEqual(receipt["run_detail_sha256"], hashlib.sha256(
            self.run_detail_path.read_bytes()).hexdigest())
        self.assertEqual(receipt["job_log_sha256"], hashlib.sha256(
            self.job_log_path.read_bytes()).hexdigest())

    def test_changed_probe_bytes_or_publication_digest_fail_closed(self) -> None:
        self.descriptor["probe"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(pressure.HarnessError, "differs from the CI publication"):
            self.admit()
        self.descriptor["probe"]["sha256"] = PROBE_SHA256
        self.probe_path.write_bytes(PROBE + b"changed")
        with self.assertRaisesRegex(pressure.HarnessError, "differs from the CI publication"):
            self.admit()

    def test_changed_source_or_failed_job_readback_fail_closed(self) -> None:
        self.qualification["source_revision"] = "c" * 40
        with self.assertRaisesRegex(pressure.HarnessError, "qualification source differs"):
            self.admit()
        self.qualification["source_revision"] = SOURCE
        self.run_detail["jobs"][0]["status"] = "failure"
        with self.assertRaisesRegex(pressure.HarnessError, "job is not successful"):
            self.admit()

    def test_missing_job_attempt_cannot_create_receipt(self) -> None:
        self.run_detail["jobs"][0]["attempt"] = 0
        with self.assertRaisesRegex(pressure.HarnessError, "D15-producing job attempt"):
            self.admit()

    def test_replaced_consistent_probe_pair_has_no_ci_log_marker(self) -> None:
        changed = b"replaced probe on mutable release\n"
        self.probe_path.write_bytes(changed)
        self.descriptor["probe"]["bytes"] = len(changed)
        self.descriptor["probe"]["sha256"] = hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(pressure.HarnessError, "one exact CI publication marker"):
            self.admit()

    def test_replaced_qualification_and_duplicate_marker_fail_closed(self) -> None:
        self.qualification["artifacts"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(pressure.HarnessError, "one exact CI publication marker"):
            self.admit()
        self.qualification["artifacts"][0]["sha256"] = "e" * 64
        self.job_log_path.write_bytes(self.job_log_path.read_bytes() * 2)
        with self.assertRaisesRegex(pressure.HarnessError, "one exact CI publication marker"):
            self.admit()

    def test_missing_or_unordered_binary_records_are_rejected(self) -> None:
        del self.qualification["artifacts"]
        with self.assertRaisesRegex(pressure.HarnessError, "strict v1 two-binary"):
            self.admit()
        self.qualification["artifacts"] = [
            {"architecture": architecture,
             "name": f"terrascale-orchestrator-linux-{architecture}",
             "bytes": 100, "sha256": "e" * 64}
            for architecture in ("arm64", "amd64")
        ]
        with self.assertRaisesRegex(pressure.HarnessError, "invalid or unordered binary"):
            self.admit()


class RemotePinnedProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name) / "terrascale-d15"
        self.path = self.base / "probes" / SOURCE / PROBE_SHA256 / "qualify.py"
        self.path.parent.mkdir(parents=True, mode=0o700)
        for directory in (self.base, *self.path.parents[:3]):
            directory.chmod(0o700)
        self.path.write_bytes(PROBE)
        self.path.chmod(0o444)
        self.runtime = {"qualify_path": str(self.path), "qualify_sha256": PROBE_SHA256}
        module = ast.parse(alpha_adapter.REMOTE_ACTIONS)
        function = next(node for node in module.body
                        if isinstance(node, ast.FunctionDef) and node.name == "open_pinned_probe")
        namespace = {
            "req": {"probe_source_revision": SOURCE}, "runtime": self.runtime,
            "re": re, "Path": Path, "stat": stat, "os": os, "hashlib": hashlib,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<embedded probe opener>", "exec"),
             namespace)
        self.open_pinned_probe = namespace["open_pinned_probe"]

    def root_owned_lstat(self, path: Path) -> object:
        metadata = self.original_lstat(path)
        return types.SimpleNamespace(
            st_mode=metadata.st_mode, st_uid=0, st_gid=0,
            st_dev=metadata.st_dev, st_ino=metadata.st_ino,
            st_size=metadata.st_size, st_nlink=metadata.st_nlink,
        )

    def open_as_root_owned(self) -> int:
        self.original_lstat = Path.lstat
        with mock.patch.object(Path, "lstat", autospec=True, side_effect=self.root_owned_lstat):
            return self.open_pinned_probe(base=self.base)

    def test_exact_staged_probe_opens_by_descriptor(self) -> None:
        descriptor = self.open_as_root_owned()
        try:
            self.assertEqual(os.read(descriptor, len(PROBE)), PROBE)
        finally:
            os.close(descriptor)

    def test_unsafe_file_mode_and_changed_bytes_are_rejected(self) -> None:
        self.path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "root-owned regular mode-0444"):
            self.open_as_root_owned()
        self.path.write_bytes(b"changed probe with same size!!!!!!!\n")
        self.path.chmod(0o444)
        with self.assertRaisesRegex(RuntimeError, "bytes differ from the exact CI digest"):
            self.open_as_root_owned()

    def test_symlink_cannot_replace_staged_probe(self) -> None:
        self.path.unlink()
        replacement = self.base / "replacement"
        replacement.write_bytes(PROBE)
        self.path.symlink_to(replacement)
        with self.assertRaisesRegex(RuntimeError, "root-owned regular mode-0444"):
            self.open_as_root_owned()


if __name__ == "__main__":
    unittest.main()
