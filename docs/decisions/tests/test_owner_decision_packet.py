from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
DECISIONS = HERE.parent
spec = importlib.util.spec_from_file_location(
    "owner_decision_validator", DECISIONS / "validate_owner_decision_packet.py"
)
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


class OwnerDecisionPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packet = json.loads((DECISIONS / "owner-decision-packet.json").read_text())

    def test_checked_in_packet_is_valid_and_entirely_unset(self) -> None:
        self.assertEqual([], validator.validate_document(self.packet))

    def test_adversarial_fixtures_are_rejected_for_expected_reason(self) -> None:
        fixtures = sorted((HERE / "fixtures").glob("*.json"))
        self.assertEqual(4, len(fixtures))
        for path in fixtures:
            fixture = json.loads(path.read_text())
            with self.subTest(fixture=fixture["name"]):
                document = copy.deepcopy(self.packet)
                parent = document
                for segment in fixture["path"][:-1]:
                    parent = parent[segment]
                leaf = fixture["path"][-1]
                if fixture["operation"] == "set":
                    parent[leaf] = fixture["value"]
                elif fixture["operation"] == "delete":
                    del parent[leaf]
                else:
                    self.fail(f"unknown fixture operation {fixture['operation']}")
                errors = validator.validate_document(document)
                self.assertTrue(
                    any(fixture["expected"] in error for error in errors),
                    f"expected {fixture['expected']!r} in {errors!r}",
                )


if __name__ == "__main__":
    unittest.main()
