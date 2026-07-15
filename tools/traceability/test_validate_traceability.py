from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("validate_traceability.py")
SPEC = importlib.util.spec_from_file_location("validate_traceability", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class StructuredTraceabilityTests(unittest.TestCase):
    def test_valid_link_is_deterministic_but_never_acceptance_evidence(self) -> None:
        with self.fixture() as root:
            first = MODULE.validate(root, 1)
            second = MODULE.validate(root, 1)
            self.assertEqual(first, second)
            self.assertEqual(first["counts"], {"registered": 1, "gap": 0, "linked": 1, "acceptanceSatisfied": 0})
            self.assertFalse(first["claimsAcceptanceEvidence"])
            self.assertFalse(first["entries"][0]["acceptanceSatisfied"])

    def test_canonical_digest_and_report_ignore_link_order_and_yaml_formatting(self) -> None:
        with self.fixture() as root:
            self.write(root / "src/Extra.cs", "public sealed class SecondaryProduction {}\n")
            self.write(root / "tests/ExtraTests.cs", "[Test]\npublic void SecondaryTest() {}\n")
            self.write(root / "docs/evidence/secondary.txt", "SECONDARY-EVIDENCE\n")
            manifest = self.read_manifest(root)
            entry = manifest["entries"][0]
            entry["productionLinks"].append({"path": "src/Extra.cs", "symbol": "SecondaryProduction"})
            entry["testLinks"].append({"path": "tests/ExtraTests.cs", "test": "SecondaryTest"})
            entry["evidenceLinks"].append({"path": "docs/evidence/secondary.txt", "kind": "unit-test-report", "layer": "L0", "identifier": "SECONDARY-EVIDENCE"})
            self.write_manifest(root, manifest)
            first = MODULE.validate(root, 1)
            entry["productionLinks"].reverse()
            entry["testLinks"].reverse()
            entry["evidenceLinks"].reverse()
            self.write(root / "requirements/trace-links.yaml", json.dumps(manifest, separators=(",", ":")))
            second = MODULE.validate(root, 1)
            self.assertEqual(first, second)

    def test_duplicate_unknown_and_missing_ids_reject(self) -> None:
        with self.fixture() as root:
            manifest = self.read_manifest(root)
            manifest["entries"].append(copy.deepcopy(manifest["entries"][0]))
            self.assert_invalid(root, manifest)
            manifest["entries"][1]["id"] = "INV-UNKNOWN"
            self.assert_invalid(root, manifest)
            manifest["entries"] = []
            self.assert_invalid(root, manifest)

    def test_owner_and_acceptance_layer_drift_reject(self) -> None:
        with self.fixture() as root:
            manifest = self.read_manifest(root)
            manifest["entries"][0]["owner"] = "Other"
            self.assert_invalid(root, manifest)
            manifest = self.read_manifest(root)
            manifest["entries"][0]["acceptanceLayers"] = ["L4"]
            self.assert_invalid(root, manifest)

    def test_path_escape_absolute_and_symlink_reject(self) -> None:
        with self.fixture() as root:
            manifest = self.read_manifest(root)
            for path in ("../Core.cs", "/tmp/Core.cs", "src/../src/Core.cs", "src\\Core.cs"):
                candidate = copy.deepcopy(manifest)
                candidate["entries"][0]["productionLinks"][0]["path"] = path
                self.assert_invalid(root, candidate)
            outside = root.parent / "outside.cs"
            outside.write_text("public sealed class ProductionAnchor {}", encoding="utf-8")
            link = root / "src" / "Linked.cs"
            try:
                link.symlink_to(outside)
                manifest["entries"][0]["productionLinks"][0]["path"] = "src/Linked.cs"
                self.assert_invalid(root, manifest)
            finally:
                outside.unlink(missing_ok=True)

    def test_missing_ambiguous_comment_and_string_only_symbols_reject(self) -> None:
        with self.fixture() as root:
            manifest = self.read_manifest(root)
            manifest["entries"][0]["productionLinks"][0]["symbol"] = "MissingAnchor"
            self.assert_invalid(root, manifest)
            manifest = self.read_manifest(root)
            manifest["entries"][0]["productionLinks"][0]["symbol"] = "Forged.Namespace.ProductionAnchor"
            self.assert_invalid(root, manifest)
            self.write(root / "src/Core.cs", "public sealed class ProductionAnchor {}\npublic sealed class ProductionAnchor {}\n")
            self.assert_invalid(root, self.read_manifest(root))
            self.write(root / "src/Core.cs", '// ProductionAnchor\nconst string value = "ProductionAnchor";\n')
            self.assert_invalid(root, self.read_manifest(root))
            self.write(root / "src/Core.cs", 'const string value = """public sealed class ProductionAnchor {}""";\n')
            self.assert_invalid(root, self.read_manifest(root))

    def test_test_only_and_production_only_cannot_promote(self) -> None:
        with self.fixture() as root:
            manifest = self.read_manifest(root)
            manifest["entries"][0]["productionLinks"] = []
            self.assert_invalid(root, manifest)
            manifest = self.read_manifest(root)
            manifest["entries"][0]["testLinks"] = []
            self.assert_invalid(root, manifest)
            manifest = self.read_manifest(root)
            manifest["entries"][0]["evidenceLinks"] = []
            self.assert_invalid(root, manifest)

    def test_gap_is_first_class_and_cannot_smuggle_orphan_links(self) -> None:
        with self.fixture() as root:
            manifest = self.read_manifest(root)
            entry = manifest["entries"][0]
            entry["status"] = "gap"
            entry["gapReason"] = "complete typed links are not established"
            entry["productionLinks"] = []
            entry["testLinks"] = []
            entry["evidenceLinks"] = []
            report = self.validate_manifest(root, manifest)
            self.assertEqual(report["counts"]["gap"], 1)
            entry["productionLinks"] = [{"path": "src/Core.cs", "symbol": "ProductionAnchor"}]
            self.assert_invalid(root, manifest)

    def test_unbounded_manifest_and_link_collections_reject(self) -> None:
        with self.fixture() as root:
            (root / "requirements/trace-links.yaml").write_text(" " * (MODULE.MAX_MANIFEST_BYTES + 1), encoding="utf-8")
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.validate(root, 1)
        with self.fixture() as root:
            manifest = self.read_manifest(root)
            manifest["entries"][0]["productionLinks"] = [copy.deepcopy(manifest["entries"][0]["productionLinks"][0]) for _ in range(MODULE.MAX_LINKS_PER_KIND + 1)]
            self.assert_invalid(root, manifest)
        with self.fixture() as root:
            (root / "docs/evidence/report.txt").write_bytes(b"x" * (MODULE.MAX_LINKED_FILE_BYTES + 1))
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.validate(root, 1)

    def test_malformed_yaml_and_duplicate_mapping_keys_reject(self) -> None:
        with self.fixture() as root:
            self.write(root / "requirements/trace-links.yaml", "entries:\n  - id: INV-001\n")
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.validate(root, 1)
            self.write(root / "requirements/trace-links.yaml", '{"schemaVersion":1,"schemaVersion":1,"claimsAcceptanceEvidence":false,"entries":[]}')
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.validate(root, 1)

    def test_evidence_claim_forgery_and_kind_layer_substitution_reject(self) -> None:
        with self.fixture() as root:
            manifest = self.read_manifest(root)
            manifest["claimsAcceptanceEvidence"] = True
            self.assert_invalid(root, manifest)
            for field, value in (("kind", "qualification-report"), ("layer", "L4"), ("identifier", "FORGED")):
                manifest = self.read_manifest(root)
                manifest["entries"][0]["evidenceLinks"][0][field] = value
                self.assert_invalid(root, manifest)

    def test_link_identity_reuse_rejects_and_unknown_fields_cannot_smuggle_claims(self) -> None:
        with self.fixture(ids=("INV-001", "INV-002")) as root:
            manifest = self.read_manifest(root)
            second = copy.deepcopy(manifest["entries"][0])
            second["id"] = "INV-002"
            manifest["entries"].append(second)
            self.assert_invalid(root, manifest, 2)
            manifest = self.read_manifest(root)
            manifest["entries"][0]["accepted"] = True
            self.assert_invalid(root, manifest)

    def test_stale_check_rejects_changed_or_symlinked_report(self) -> None:
        with self.fixture() as root:
            output = root / "docs/audits/traceability/report.json"
            MODULE.write_or_check(root, output, False, 1)
            MODULE.write_or_check(root, output, True, 1)
            output.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.write_or_check(root, output, True, 1)
            output.unlink()
            target = root / "report-target.json"
            target.write_text(MODULE.render(MODULE.validate(root, 1)), encoding="utf-8")
            output.symlink_to(target)
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.write_or_check(root, output, True, 1)

    def test_report_output_escape_traversal_and_symlinked_parent_reject(self) -> None:
        with self.fixture() as root:
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.write_or_check(root, root.parent / "escaped.json", False, 1)
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.write_or_check(root, root / "docs/audits/traceability/../escaped.json", False, 1)
            outside = root.parent / "outside-audit"
            outside.mkdir()
            audits = root / "docs/audits"
            audits.symlink_to(outside, target_is_directory=True)
            try:
                with self.assertRaises(MODULE.TraceValidationError):
                    MODULE.write_or_check(root, root / "docs/audits/traceability/report.json", False, 1)
            finally:
                audits.unlink()
                outside.rmdir()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_nonregular_registry_rejects_without_reading(self) -> None:
        with self.fixture() as root:
            registry = root / "requirements/registry.yaml"
            registry.unlink()
            os.mkfifo(registry)
            with self.assertRaises(MODULE.TraceValidationError):
                MODULE.validate(root, 1)

    def fixture(self, ids: tuple[str, ...] = ("INV-001",)):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        entries = []
        for item_id in ids:
            entries.extend([f"  - id: {item_id}", "    owner: Core", "    acceptanceLayers:", "      - L0", "    evidenceState: missing"])
        self.write(root / "requirements/registry.yaml", "entries:\n" + "\n".join(entries) + "\n")
        self.write(root / "src/Core.cs", "public sealed class ProductionAnchor {}\n")
        self.write(root / "tests/CoreTests.cs", "[Test]\npublic void TestAnchor() {}\n")
        self.write(root / "docs/evidence/report.txt", "EVIDENCE-ANCHOR\n")
        manifest = {"schemaVersion": 1, "claimsAcceptanceEvidence": False, "entries": [self.entry(ids[0])]}
        self.write_manifest(root, manifest)

        class Fixture:
            def __enter__(self_nonlocal): return root
            def __exit__(self_nonlocal, *_args): temporary.cleanup()
        return Fixture()

    @staticmethod
    def entry(item_id: str) -> dict[str, object]:
        return {
            "id": item_id, "owner": "Core", "acceptanceLayers": ["L0"], "status": "linked", "gapReason": None,
            "productionLinks": [{"path": "src/Core.cs", "symbol": "ProductionAnchor"}],
            "testLinks": [{"path": "tests/CoreTests.cs", "test": "TestAnchor"}],
            "evidenceLinks": [{"path": "docs/evidence/report.txt", "kind": "unit-test-report", "layer": "L0", "identifier": "EVIDENCE-ANCHOR"}],
        }

    def validate_manifest(self, root: Path, manifest: dict[str, object], count: int = 1):
        self.write_manifest(root, manifest)
        return MODULE.validate(root, count)

    def assert_invalid(self, root: Path, manifest: dict[str, object], count: int = 1) -> None:
        self.write_manifest(root, manifest)
        with self.assertRaises(MODULE.TraceValidationError):
            MODULE.validate(root, count)

    @staticmethod
    def read_manifest(root: Path) -> dict[str, object]:
        return json.loads((root / "requirements/trace-links.yaml").read_text(encoding="utf-8"))

    @staticmethod
    def write_manifest(root: Path, manifest: dict[str, object]) -> None:
        StructuredTraceabilityTests.write(root / "requirements/trace-links.yaml", json.dumps(manifest, indent=2) + "\n")

    @staticmethod
    def write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
