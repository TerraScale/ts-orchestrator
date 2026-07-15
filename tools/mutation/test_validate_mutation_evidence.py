from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from datetime import date
from pathlib import Path

from validate_mutation_evidence import (
    DEFAULT_POLICY,
    DEFAULT_REPORT,
    ROOT,
    SUPPLY_CHAIN,
    load_json,
    validate,
)


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures/negative-cases.json"


def resolve(document: object, path: list[object]) -> object:
    current = document
    for part in path:
        current = current[part]  # type: ignore[index]
    return current


def mutate(document: object, fixture: dict[str, object]) -> None:
    path = fixture["path"]
    assert isinstance(path, list)
    operation = fixture["operation"]
    if operation == "set":
        parent = resolve(document, path[:-1])
        parent[path[-1]] = fixture["value"]  # type: ignore[index]
    elif operation == "append":
        resolve(document, path).append(fixture["value"])  # type: ignore[attr-defined]
    elif operation == "delete-list-value":
        resolve(document, path).remove(fixture["value"])  # type: ignore[attr-defined]
    else:
        raise AssertionError(f"unknown operation: {operation}")


class MutationEvidenceValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_json(DEFAULT_POLICY)
        cls.report = load_json(DEFAULT_REPORT)
        cls.fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
        cls.supply = load_json(SUPPLY_CHAIN)

    def make_repository(self, directory: str) -> tuple[Path, dict[str, object], dict[str, object], Path]:
        root = Path(directory)
        shutil.copytree(
            ROOT / "src",
            root / "src",
            ignore=shutil.ignore_patterns("bin", "obj"),
        )
        proof = root / "docs/audits/mutation/composition-root-exclusion-proof.md"
        proof.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "docs/audits/mutation/composition-root-exclusion-proof.md", proof)
        policy = copy.deepcopy(self.policy)
        report = copy.deepcopy(self.report)
        policy_path = root / "tools/mutation/mutation-policy.json"
        policy_path.parent.mkdir(parents=True)
        policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
        report["policySha256"] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        return root, policy, report, policy_path

    def test_current_zero_claim_report_is_valid_on_audit_date(self) -> None:
        self.assertEqual(
            [],
            validate(self.policy, self.report, validation_date=date(2026, 7, 13)),
        )

    def test_negative_fixtures_fail_closed(self) -> None:
        names: list[str] = []
        for fixture in self.fixtures:
            with self.subTest(fixture=fixture["name"]):
                names.append(fixture["name"])
                policy = copy.deepcopy(self.policy)
                report = copy.deepcopy(self.report)
                target = policy if fixture["document"] == "policy" else report
                mutate(target, fixture)
                errors = validate(policy, report, validation_date=date(2026, 7, 13))
                self.assertTrue(
                    any(fixture["error"] in error for error in errors),
                    f"expected {fixture['error']!r} in {errors!r}",
                )
        self.assertEqual(len(names), len(set(names)))

    def test_report_expires_fail_closed(self) -> None:
        errors = validate(self.policy, self.report, validation_date=date(2026, 8, 13))
        self.assertTrue(any("evidence is stale" in error for error in errors))

    def test_project_inventory_drift_fails(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["projects"] = policy["projects"][:-1]
        errors = validate(policy, self.report, validation_date=date(2026, 7, 13))
        self.assertTrue(any("inventory drift" in error for error in errors))

    def test_recursive_nested_project_inventory_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, policy, report, policy_path = self.make_repository(directory)
            nested = root / "src/Nested/Deeper/Unexpected.csproj"
            nested.parent.mkdir(parents=True)
            nested.write_text("<Project Sdk=\"Microsoft.NET.Sdk\" />\n", encoding="utf-8")
            errors = validate(
                policy, report, repo_root=root, policy_path=policy_path,
                validation_date=date(2026, 7, 13), supply=self.supply,
            )
            self.assertTrue(any("inventory drift" in error for error in errors))

    def test_recursive_nested_composition_source_invalidates_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, policy, report, policy_path = self.make_repository(directory)
            nested = root / "src/TerraScale.Orchestrator/Nested/Mutation.cs"
            nested.parent.mkdir(parents=True)
            nested.write_text("internal static class Mutation {}\n", encoding="utf-8")
            errors = validate(
                policy, report, repo_root=root, policy_path=policy_path,
                validation_date=date(2026, 7, 13), supply=self.supply,
            )
            self.assertTrue(any("proof is stale or broader" in error for error in errors))

    def test_symlinked_proof_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, policy, report, policy_path = self.make_repository(directory)
            link = root / "linked-proof"
            link.symlink_to(root / "docs/audits/mutation", target_is_directory=True)
            linked_path = "linked-proof/composition-root-exclusion-proof.md"
            policy["projects"][-1]["exclusionProof"] = linked_path
            policy["exclusions"][0]["proof"] = linked_path
            policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
            report["policySha256"] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
            errors = validate(
                policy, report, repo_root=root, policy_path=policy_path,
                validation_date=date(2026, 7, 13), supply=self.supply,
            )
            self.assertTrue(any("symlink path components are forbidden" in error for error in errors))

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_json(path)

    def test_unknown_fields_are_rejected(self) -> None:
        report = copy.deepcopy(self.report)
        report["score"] = 85
        errors = validate(self.policy, report, validation_date=date(2026, 7, 13))
        self.assertTrue(any("unknown keys" in error for error in errors))

    def test_unsafe_exclusion_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["exclusions"][0]["paths"] = ["../Program.cs"]
        errors = validate(policy, self.report, validation_date=date(2026, 7, 13))
        self.assertTrue(any("unsafe repository-relative path" in error for error in errors))

    def test_trailing_slash_and_overlong_paths_are_rejected(self) -> None:
        for invalid in (
            "src/TerraScale.Orchestrator/Program.cs/",
            "src/" + ("x" * 509),
        ):
            with self.subTest(path=invalid[:40]):
                policy = copy.deepcopy(self.policy)
                policy["exclusions"][0]["paths"] = [invalid]
                errors = validate(policy, self.report, validation_date=date(2026, 7, 13))
                self.assertTrue(any("repository-relative path" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
