from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("l0c_validator", HERE / "validate_l0c_foundation.py")
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


class L0cFoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = validator.load_bounded(validator.INVENTORY, validator.MAX_INVENTORY_BYTES)
        cls.report = validator.load_bounded(validator.REPORT, validator.MAX_REPORT_BYTES)
        cls.pin = validator.load_bounded(validator.PIN_PATH, validator.MAX_PIN_BYTES)
        cls.pin_digest = validator.file_sha256(validator.PIN_PATH)

    def errors(self, inventory=None, report=None, pin=None):
        return validator.validate(
            self.inventory if inventory is None else inventory,
            self.report if report is None else report,
            self.pin if pin is None else pin,
            self.pin_digest,
        )

    def test_checked_in_foundation_is_valid_but_stale_and_blocked(self) -> None:
        self.assertEqual([], self.errors())
        self.assertFalse(self.inventory["claimsAcceptanceEvidence"])
        self.assertEqual("stale-blocked-no-execution", self.report["classification"])
        self.assertEqual(0, self.report["executedCaseCount"])

    def test_machine_inventory_covers_every_closed_category_and_assertion(self) -> None:
        self.assertEqual(28, len(self.inventory["cases"]))
        self.assertEqual(validator.CATEGORIES, {case["category"] for case in self.inventory["cases"]})
        self.assertEqual(
            validator.REQUIRED_ASSERTIONS,
            {item for case in self.inventory["cases"] for item in case["assertions"]},
        )

    def test_adversarial_fixtures_fail_for_the_named_reason(self) -> None:
        fixtures = json.loads((HERE / "negative-cases.json").read_text(encoding="utf-8"))
        self.assertEqual(15, len(fixtures))
        for fixture in fixtures:
            inventory = copy.deepcopy(self.inventory)
            report = copy.deepcopy(self.report)
            pin = copy.deepcopy(self.pin)
            target = {"inventory": inventory, "report": report, "pin": pin}[fixture["target"]]
            parent = target
            for segment in fixture["path"][:-1]:
                parent = parent[segment]
            leaf = fixture["path"][-1]
            if fixture["operation"] in {"set", "add"}:
                parent[leaf] = fixture["value"]
            elif fixture["operation"] == "delete":
                del parent[leaf]
            else:
                self.fail(f"unsupported fixture operation {fixture['operation']}")
            errors = validator.validate(inventory, report, pin, self.pin_digest)
            with self.subTest(fixture=fixture["name"]):
                self.assertTrue(any(fixture["expected"] in error for error in errors), errors)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(validator.DuplicateKey):
            json.loads('{"schemaVersion":1,"schemaVersion":1}', object_pairs_hook=validator._pairs)

    def test_symlink_and_oversized_inputs_are_rejected_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory(dir=validator.ROOT) as directory:
            base = Path(directory)
            regular = base / "regular.json"
            regular.write_text("{}", encoding="utf-8")
            link = base / "link.json"
            link.symlink_to(regular)
            with self.assertRaisesRegex(ValueError, "symlink component"):
                validator.load_bounded(link, 100)
            oversized = base / "large.json"
            oversized.write_text(" " * 101, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "byte count"):
                validator.load_bounded(oversized, 100)

    def test_symlinked_parent_is_rejected_even_when_target_stays_inside_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=validator.ROOT) as directory:
            base = Path(directory)
            real_parent = base / "real-parent"
            real_parent.mkdir()
            (real_parent / "input.json").write_text("{}", encoding="utf-8")
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink component"):
                validator.load_bounded(linked_parent / "input.json", 100)

    def test_path_outside_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escapes repository root"):
                validator.load_bounded(outside, 100)

    def test_case_and_string_bounds_fail_closed(self) -> None:
        inventory = copy.deepcopy(self.inventory)
        inventory["cases"] = inventory["cases"] * 6
        self.assertTrue(any("exactly 28" in error for error in self.errors(inventory=inventory)))
        inventory = copy.deepcopy(self.inventory)
        inventory["cases"][0]["fault"] = "x" * (validator.MAX_STRING_BYTES + 1)
        self.assertTrue(any("oversized string" in error for error in self.errors(inventory=inventory)))


if __name__ == "__main__":
    unittest.main()
