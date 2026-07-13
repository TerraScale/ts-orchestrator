#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).parent
MODULE_PATH = HERE / "validate_runtime_readiness.py"
SPEC = importlib.util.spec_from_file_location("validate_runtime_readiness", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
VALID = json.loads(MODULE.DEFAULT_RECORD.read_text(encoding="utf-8"))


class RuntimeReadinessValidatorTests(unittest.TestCase):
    def test_valid_proposal(self):
        self.assertEqual([], MODULE.validate(copy.deepcopy(VALID)))

    def test_adversarial_fixtures_fail_with_expected_errors(self):
        expected = {
            "accepted-selection.json": "status must remain proposal-unqualified",
            "arm64-local-masquerade.json": "local observation must remain observed-not-qualified",
            "missing-filesystem.json": "filesystem candidates must contain ext4 and XFS exactly once",
            "missing-host-filesystem-combination.json": "must require all four host/filesystem combinations exactly once",
            "unknown-source.json": "unknown source IDs",
        }
        for name, marker in expected.items():
            with self.subTest(name=name):
                overlay = json.loads((HERE / "fixtures" / name).read_text(encoding="utf-8"))
                document = copy.deepcopy(VALID)
                self._merge(document, overlay)
                errors = MODULE.validate(document)
                self.assertTrue(any(marker in error for error in errors), errors)

    def test_allowlisted_host_cannot_replace_reviewed_primary_citation(self):
        document = copy.deepcopy(VALID)
        document["primarySources"][0]["url"] = "https://github.com/example/secondary-summary"
        errors = MODULE.validate(document)
        self.assertTrue(
            any("URL differs from the reviewed primary citation" in error for error in errors),
            errors,
        )

    @staticmethod
    def _merge(target, overlay):
        for key, value in overlay.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                RuntimeReadinessValidatorTests._merge(target[key], value)
            else:
                target[key] = value


if __name__ == "__main__":
    unittest.main()
