#!/usr/bin/env python3
"""Adversarial fixtures for the ADR readiness validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ADR_DIR = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_readiness", ADR_DIR / "validate_readiness.py")
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ReadinessValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.valid = json.loads((ADR_DIR / "readiness-index.yaml").read_text(encoding="utf-8"))

    def errors_after(self, mutation):
        document = copy.deepcopy(self.valid)
        mutation(document)
        return VALIDATOR.validate_document(document)

    def test_happy_path(self) -> None:
        self.assertEqual([], VALIDATOR.validate_document(copy.deepcopy(self.valid)))

    def test_missing_adr_is_rejected(self) -> None:
        errors = self.errors_after(lambda document: document["entries"].pop())
        self.assertTrue(any("exactly 1..24 once" in error for error in errors), errors)

    def test_stale_line_anchor_is_rejected(self) -> None:
        def mutate(document):
            document["entries"][0]["availableEvidence"][0] = "ORCHESTRATOR.md:99999-100000"

        errors = self.errors_after(mutate)
        self.assertTrue(any("out of bounds" in error for error in errors), errors)

    def test_accepted_open_owner_conflict_is_rejected(self) -> None:
        def mutate(document):
            document["entries"][0]["status"] = "accepted"

        errors = self.errors_after(mutate)
        self.assertTrue(any("accepted is forbidden" in error for error in errors), errors)

    def test_unknown_lane_is_rejected(self) -> None:
        def mutate(document):
            document["entries"][0]["ownerLane"] = "core"

        errors = self.errors_after(mutate)
        self.assertTrue(any("non-canonical owner lane" in error for error in errors), errors)

    def test_unknown_dependency_is_rejected(self) -> None:
        def mutate(document):
            document["entries"][0]["dependencies"] = [999]

        errors = self.errors_after(mutate)
        self.assertTrue(any("unknown dependencies" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
