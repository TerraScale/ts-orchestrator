import copy
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from check_nuget_vulnerabilities import main, validate_report


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.project = "service.csproj"
        self.clean = {
            "version": 1,
            "parameters": "--vulnerable --include-transitive",
            "sources": ["https://api.nuget.org/v3/index.json"],
            "projects": [{"path": str(Path(self.project).resolve())}],
        }

    def test_real_clean_shape_without_frameworks(self):
        self.assertEqual(validate_report(self.clean, self.project), [])

    def test_incomplete_reports_rejected(self):
        for changes in (
            {"version": True},
            {"version": 2},
            {"sources": []},
            {"projects": []},
            {"parameters": "--vulnerable"},
            {"logs": [{"level": "Warning", "message": "source unavailable"}]},
            {"projects": [{"path": "other.csproj"}]},
            {"projects": [{"path": self.project, "frameworks": None}]},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_report({**self.clean, **changes}, self.project)
        with self.assertRaises(ValueError):
            validate_report({}, self.project)

    def test_direct_and_transitive_advisories(self):
        for kind in ("topLevelPackages", "transitivePackages"):
            report = copy.deepcopy(self.clean)
            package = {
                "id": "Example",
                "resolvedVersion": "1.0",
                "vulnerabilities": [
                    {"severity": "High", "advisoryurl": "https://example.test/advisory"}
                ],
            }
            report["projects"][0]["frameworks"] = [{"framework": "net11.0", kind: [package]}]
            self.assertEqual(validate_report(report, self.project), [package])
            with (
                patch("sys.argv", ["audit", self.project]),
                patch(
                    "check_nuget_vulnerabilities.subprocess.run",
                    return_value=CompletedProcess([], 0, json.dumps(report), ""),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(), 1)
            package["vulnerabilities"] = None
            with self.assertRaises(ValueError):
                validate_report(report, self.project)

    def test_cli_exit_status(self):
        for output, code, expected in (
            (json.dumps(self.clean), 0, 0),
            ("{}", 0, 1),
            ("not json", 0, 1),
            (json.dumps(self.clean), 1, 1),
        ):
            with (
                self.subTest(output=output, code=code),
                patch("sys.argv", ["audit", self.project]),
                patch(
                    "check_nuget_vulnerabilities.subprocess.run",
                    return_value=CompletedProcess([], code, output, ""),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(), expected)


if __name__ == "__main__":
    unittest.main()
