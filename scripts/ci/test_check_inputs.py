import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location("check_inputs", Path(__file__).with_name("check-inputs.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ChangedInputs(unittest.TestCase):
    def test_docs_only(self):
        self.assertFalse(module.checks_required(["README.md", "docs/design.json"]))

    def test_mixed_and_executable_changes(self):
        for path in ["internal/app/run.go", "go.sum", ".github/workflows/ci.yml", "test/e2e/m1/run.sh"]:
            with self.subTest(path=path):
                self.assertTrue(module.checks_required(["docs/guide.md", path]))

    def test_missing_history_never_skips(self):
        self.assertTrue(module.changed_checks("", "HEAD"))
        self.assertTrue(module.changed_checks("0" * 40, "HEAD"))
        with patch.object(module.subprocess, "check_output", side_effect=subprocess.CalledProcessError(128, "git")):
            self.assertTrue(module.changed_checks("missing", "HEAD"))
