"""Keep the CI workflows, the image pipeline and the release admission in step."""

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".forgejo/workflows"


def paths_ignore(workflow: Path) -> list[str]:
    lines = workflow.read_text(encoding="utf-8").splitlines()
    start = lines.index("    paths-ignore:") + 1
    patterns = []
    for line in lines[start:]:
        match = re.fullmatch(r"      - '([^']+)'", line)
        if not match:
            break
        patterns.append(match.group(1))
    return patterns


def job_names(workflow: Path) -> list[str]:
    return re.findall(r"^    name: (.+)$", workflow.read_text(encoding="utf-8"), re.MULTILINE)


class WorkflowContractTests(unittest.TestCase):
    def test_docs_only_changes_skip_ci_and_ci_alone_starts_images(self) -> None:
        self.assertEqual(paths_ignore(WORKFLOWS / "ci.yml"), ["docs/**", "**/*.md"])
        image = (WORKFLOWS / "image.yml").read_text(encoding="utf-8")
        self.assertNotIn("  push:", image)
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        steps = re.findall(r"^      - name: (.+)$", ci, re.MULTILINE)
        self.assertEqual(steps[-1], "Start the image build for this revision")
        self.assertIn("run: bash scripts/ci/dispatch-image.sh", ci.rsplit("- name:", 1)[1])
        self.assertIn("continue-on-error: true", ci.rsplit("- name:", 1)[1])
        dispatch = (ROOT / "scripts/ci/dispatch-image.sh").read_text(encoding="utf-8")
        self.assertIn('trigger:"ci"', dispatch)
        self.assertIn("inputs.trigger == 'ci'", image)
        # Automatic builds queue; a running image build is never cancelled.
        self.assertIn("  cancel-in-progress: false\n", image)
        self.assertIn("bash scripts/ci/image-superseded.sh", image)

    def test_ci_stays_one_job_named_as_release_admission_expects(self) -> None:
        # ts-release admission requires exactly one job in the qualifying ci.yml run.
        names = job_names(WORKFLOWS / "ci.yml")
        self.assertEqual(names, ["verify/go + artifact/linux-amd64-arm64"])
        for script in ("scripts/ci/publish-qualification.sh", "deploy/image/build-image.sh"):
            self.assertIn(names[0], (ROOT / script).read_text(encoding="utf-8"), script)

    def test_image_job_name_matches_its_provenance(self) -> None:
        names = job_names(WORKFLOWS / "image.yml")
        self.assertEqual(names, ["build/qualified-gru-arm64-image"])
        self.assertIn(f"image_job='{names[0]}'", (ROOT / "deploy/image/build-image.sh").read_text(encoding="utf-8"))

    def test_image_waits_for_ci_instead_of_taking_copied_inputs(self) -> None:
        workflow = (WORKFLOWS / "image.yml").read_text(encoding="utf-8")
        self.assertIn("--wait-for-ci", workflow)
        inputs = re.findall(r"^      ([a-z_]+):$", workflow.split("workflow_dispatch:", 1)[1].split("concurrency:")[0],
                            re.MULTILINE)
        self.assertEqual(inputs, ["source_revision", "trigger"])

    def test_checked_in_image_inputs_are_valid(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / "deploy/image/image-inputs.py"), "check"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((ROOT / "deploy/image/image-inputs.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["trust_roots"][0]["sha256"],
                         "bbdab8425dac0382d641cdf9de7c5a6685f0355a63f6b1131c64241873d418bc")


if __name__ == "__main__":
    unittest.main()
