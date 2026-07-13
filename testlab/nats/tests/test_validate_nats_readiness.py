from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
NATS = HERE.parent
spec = importlib.util.spec_from_file_location("nats_readiness", NATS / "validate_nats_readiness.py")
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


class NatsReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pin = json.loads(validator.PIN.read_text())
        cls.report = json.loads(validator.REPORT.read_text())

    def test_checked_in_evidence_is_valid_and_fail_closed(self) -> None:
        self.assertEqual([], validator.validate(self.pin, self.report))

    def test_adversarial_fixtures_fail_for_expected_reason(self) -> None:
        fixtures = sorted((HERE / "fixtures").glob("*.json"))
        self.assertEqual(7, len(fixtures))
        for path in fixtures:
            fixture = json.loads(path.read_text())
            with self.subTest(fixture=fixture["name"]):
                pin, report = copy.deepcopy(self.pin), copy.deepcopy(self.report)
                if fixture["target"] == "specification":
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        source = (validator.ROOT / "ORCHESTRATOR.md").read_text()
                        self.assertEqual(1, source.count(fixture["old"]))
                        (root / "ORCHESTRATOR.md").write_text(
                            source.replace(fixture["old"], fixture["new"])
                        )
                        errors = validator.validate(pin, report, root=root)
                    self.assertTrue(any(fixture["expected"] in error for error in errors), errors)
                    continue
                target = pin if fixture["target"] == "pin" else report
                parent = target
                for segment in fixture["path"][:-1]:
                    parent = parent[segment]
                leaf = fixture["path"][-1]
                if fixture["operation"] == "set":
                    parent[leaf] = fixture["value"]
                elif fixture["operation"] == "delete":
                    del parent[leaf]
                else:
                    self.fail(f"unknown operation {fixture['operation']}")
                errors = validator.validate(pin, report)
                self.assertTrue(any(fixture["expected"] in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
