from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("generate_traceability.py")
SPEC = importlib.util.spec_from_file_location("generate_traceability", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class TraceabilityTests(unittest.TestCase):
    def test_classifies_references_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_registry(root, ["INV-001", "SEC-SAFE"])
            self._write(root / "src" / "Core.cs", 'const string Rule = "INV-001";\n')
            self._write(root / "tests" / "CoreTests.cs", '// INV-001\n// SEC-SAFE\n')
            first = MODULE.generate(root)
            second = MODULE.generate(root)
            self.assertEqual(first, second)
            self.assertEqual(first["counts"]["linked"], 1)
            self.assertEqual(first["counts"]["test-only"], 1)
            self.assertFalse(first["claimsAcceptanceEvidence"])

    def test_reports_unregistered_references(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_registry(root, ["INV-001"])
            self._write(root / "src" / "Core.cs", '// ERR-NOT-REGISTERED\n')
            report = MODULE.generate(root)
            self.assertEqual(report["unknownReferences"][0]["id"], "ERR-NOT-REGISTERED")

    def test_ignores_build_outputs_and_deduplicates_same_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_registry(root, ["INV-001"])
            self._write(root / "src" / "Core.cs", '// INV-001 INV-001\n')
            self._write(root / "src" / "obj" / "Generated.cs", '// ERR-UNKNOWN\n')
            report = MODULE.generate(root)
            entry = report["entries"][0]
            self.assertEqual(len(entry["productionReferences"]), 1)
            self.assertEqual(report["unknownReferences"], [])

    @staticmethod
    def _write_registry(root: Path, ids: list[str]) -> None:
        entries = []
        for item_id in ids:
            entries.extend([
                f"  - id: {item_id}",
                "    owner: Core",
                "    acceptanceLayers:",
                "      - L0",
                "    evidenceState: missing",
            ])
        TraceabilityTests._write(root / "requirements" / "registry.yaml", "entries:\n" + "\n".join(entries) + "\n")

    @staticmethod
    def _write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
