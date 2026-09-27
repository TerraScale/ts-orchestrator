#!/usr/bin/env python3
"""Static safety checks for the manually dispatched signed release workflow."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".forgejo/workflows/release.yml"


class ReleaseWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_only_main_and_explicit_environment_select_a_protected_environment(self) -> None:
        self.assertIn(
            "if: ${{ github.ref == 'refs/heads/main' && (inputs.sign_release == true || "
            "inputs.publish == true) }}",
            self.workflow,
        )
        self.assertIn("default: canary", self.workflow)
        self.assertIn("- canary\n          - production", self.workflow)
        self.assertIn(
            "name: ${{ github.ref == 'refs/heads/main' && inputs.release_environment == 'canary' "
            "&& 'canary-release' || github.ref == 'refs/heads/main' && "
            "inputs.release_environment == 'production' && 'production-release' || "
            "'invalid-release-environment' }}",
            self.workflow,
        )
        self.assertIn('test "${SOURCE_REF:?event ref is required}" = "refs/heads/main"', self.workflow)
        self.assertIn(
            '[[ "${RELEASE_ENVIRONMENT}" == canary || "${RELEASE_ENVIRONMENT}" == production ]]',
            self.workflow,
        )

    def test_signing_material_and_publish_targets_are_environment_scoped(self) -> None:
        self.assertIn("ROOT_PUBLIC_KEY: ${{ secrets.TS_RELEASE_ROOT_PUBLIC_KEY }}", self.workflow)
        self.assertIn("RELEASE_DELEGATION: ${{ secrets.TS_RELEASE_DELEGATION }}", self.workflow)
        self.assertIn("DELEGATED_SIGNING_KEY: ${{ secrets.TS_RELEASE_SIGNING_KEY }}", self.workflow)
        self.assertIn("OCI_RELEASE_NAMESPACE: ${{ vars.OCI_RELEASE_NAMESPACE }}", self.workflow)
        self.assertIn("OCI_RELEASE_BUCKET: ${{ vars.OCI_RELEASE_BUCKET }}", self.workflow)
        self.assertNotIn("TS_RELEASE_SIGNING_KEY_CANARY", self.workflow)

    def test_exact_source_qualification_and_environment_signature_checks_remain(self) -> None:
        for required in (
            "ref: ${{ forgejo.sha }}",
            'test "${source_commit}" = "${SOURCE_SHA:?event SHA is required}"',
            ".source_revision == $sha",
            ".head_sha == $sha and .workflow == \"ci.yml\" and .status == \"success\"",
            "test \"$(jq -r .source_tree dist/qualification.json)\" = \"$(git rev-parse 'HEAD^{tree}')\"",
            '--environment "${RELEASE_ENVIRONMENT}" --out "${receipt}"',
            '--environment "${RELEASE_ENVIRONMENT}"',
            "python3 tests/ci/test_release_workflow.py",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.workflow)


if __name__ == "__main__":
    unittest.main()
