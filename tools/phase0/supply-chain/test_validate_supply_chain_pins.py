from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from validate_supply_chain_pins import DEFAULT_MANIFEST, validate


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures/negative-cases.json"


def resolve(root: object, path: list[object]) -> object:
    current = root
    for part in path:
        current = current[part]  # type: ignore[index]
    return current


def mutate(document: object, fixture: dict[str, object]) -> None:
    operation = fixture["operation"]
    path = fixture["path"]
    assert isinstance(path, list)
    if operation == "set":
        parent = resolve(document, path[:-1])
        parent[path[-1]] = fixture["value"]  # type: ignore[index]
    elif operation == "copy":
        source = fixture["from"]
        assert isinstance(source, list)
        parent = resolve(document, path[:-1])
        parent[path[-1]] = resolve(document, source)  # type: ignore[index]
    elif operation == "add-key":
        target = resolve(document, path)
        target[fixture["key"]] = fixture["value"]  # type: ignore[index]
    elif operation == "delete-list-value":
        target = resolve(document, path)
        target.remove(fixture["value"])  # type: ignore[attr-defined]
    elif operation == "delete-list-index":
        target = resolve(document, path)
        del target[fixture["value"]]  # type: ignore[index]
    else:
        raise AssertionError(f"unknown fixture operation: {operation}")


class SupplyChainPinValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        cls.fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))

    def test_baseline(self) -> None:
        self.assertEqual([], validate(self.baseline))

    def test_negative_fixtures(self) -> None:
        names: list[str] = []
        for fixture in self.fixtures:
            with self.subTest(fixture=fixture["name"]):
                names.append(fixture["name"])
                document = copy.deepcopy(self.baseline)
                mutate(document, fixture)
                errors = validate(document)
                self.assertTrue(
                    any(fixture["error"] in error for error in errors),
                    f"expected {fixture['error']!r} in {errors!r}",
                )
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()
