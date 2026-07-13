from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
spec = importlib.util.spec_from_file_location("delivery_inventory_validator", TOOL / "validate_inventory.py")
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


class DeliveryInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(validator.INVENTORY.read_text())

    def test_checked_inventory_matches_all_pinned_trees(self) -> None:
        self.assertEqual([], validator.validate(self.document))

    def test_generator_is_byte_deterministic(self) -> None:
        generated = json.dumps(validator.generator.build_document(), indent=2, sort_keys=True) + "\n"
        self.assertEqual(validator.INVENTORY.read_text(), generated)

    def test_adversarial_fixtures_fail_closed(self) -> None:
        fixtures = sorted((HERE / "fixtures").glob("*.json"))
        self.assertEqual(10, len(fixtures))
        for path in fixtures:
            fixture = json.loads(path.read_text())
            with self.subTest(fixture=fixture["name"]):
                document = copy.deepcopy(self.document)
                parent = document
                for segment in fixture["path"][:-1]:
                    parent = parent[segment]
                leaf = fixture["path"][-1]
                if fixture["operation"] == "set":
                    parent[leaf] = fixture["value"]
                elif fixture["operation"] == "delete":
                    del parent[leaf]
                else:
                    self.fail(f"unknown operation {fixture['operation']}")
                errors = validator.validate(document)
                self.assertTrue(any(fixture["expected"] in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
