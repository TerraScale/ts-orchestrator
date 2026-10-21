"""Exercise the zero-config CLI against real, isolated Git diffs."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


GUARD = Path(__file__).with_name("zero-config-check.py").resolve()


class ZeroConfigCheckTests(unittest.TestCase):
    def check_diff(self, before, after):
        with tempfile.TemporaryDirectory(prefix="ts-zero-config-check-") as directory:
            root = Path(directory)
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

            def git(*args):
                return subprocess.run(
                    ["git", "-c", "user.name=ZeroConfigFixture", "-c",
                     "user.email=fixture@example.invalid", "-c",
                     "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],
                    cwd=root, env=env, capture_output=True, text=True,
                    check=True, timeout=10,
                ).stdout.strip()

            def write(files):
                for name, content in files.items():
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(content)

            git("init", "-q", "--template=")
            write(before)
            git("add", ".")
            git("commit", "-qm", "base", "--allow-empty")
            base = git("rev-parse", "HEAD")
            write(after)
            git("add", ".")
            git("commit", "-qm", "head", "--allow-empty")
            head = git("rev-parse", "HEAD")
            return subprocess.run(
                [sys.executable, "-I", "-B", str(GUARD), base, head],
                cwd=root, env=env, capture_output=True, text=True, timeout=10,
            )

    def test_split_config_fields_use_unchanged_head_context(self):
        before = {}
        after = {}
        for filename, name in (
            ("workload_autoscale.go", "AutoscaleConfig"),
            ("oci_reconcile.go", "OciReconcileConfig"),
            ("terrabase_seats.go", "TerraBaseSeatsConfig"),
        ):
            path = f"internal/app/{filename}"
            before[path] = f"package app\n\ntype {name} struct {{\n}}\n"
            after[path] = before[path].replace("\n}", "\n\tEnabled bool `json:\"enabled\"`\n}")
        result = self.check_diff(before, after)
        self.assertEqual(result.returncode, 1, result.stderr)
        for path in after:
            self.assertIn(f"file={path},line=4::", result.stdout)
        self.assertIn("3 violation(s)", result.stdout)

    def test_host_telemetry_is_an_operator_switch(self):
        for path, content in (
            ("internal/app/workload_autoscale.go",
             'package app\ntype AutoscaleConfig struct {\n\tHostTelemetry bool `json:"host_telemetry,omitzero"`\n}\n'),
            ("internal/app/config.go",
             'package app\ntype Config struct {\n\tHostTelemetry bool `json:"host_telemetry"`\n}\n'),
            (".github/workflows/settings.yml", "host_telemetry: true\n"),
        ):
            with self.subTest(path=path):
                result = self.check_diff({}, {path: content})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"file={path},", result.stdout)

    def test_customer_and_authority_state_in_split_file_stay_out_of_scope(self):
        path = "internal/app/workload_autoscale.go"
        result = self.check_diff({}, {path: (
            "package app\n"
            "type AutoscaleConfig struct {\n\tIntervalSeconds int\n}\n"
            "type CustomerConnection struct {\n\tEnabled bool\n\tHostTelemetry bool\n}\n"
            "type Registration struct {\n\tDisabled bool\n\tReady bool\n}\n"
        )})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_go_tests_stay_out_of_scope(self):
        result = self.check_diff({}, {
            "internal/app/workload_autoscale_test.go": (
                "package app\ntype AutoscaleConfig struct {\n\tEnabled bool\n"
                '\tHostTelemetry bool\n}\nvar setting = os.Getenv("ENABLE_TEST")\n'
            ),
            "internal/config/config_test.go": "package config\nvar Disabled bool\n",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_inline_config_does_not_capture_following_state(self):
        result = self.check_diff({}, {"internal/app/workload_autoscale.go": (
            "package app\ntype AutoscaleConfig struct{} // empty settings\n"
            "type CustomerConnection struct {\n\tEnabled bool\n}\n"
        )})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_declaration_comment_brace_does_not_end_config(self):
        path = "internal/app/workload_autoscale.go"
        original = "package app\ntype AutoscaleConfig struct { // } documents a brace\n}\n"
        result = self.check_diff({path: original}, {
            path: original.replace("\n}", "\n\tHostTelemetry bool\n}")
        })
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"file={path},line=3::", result.stdout)

    def test_unchanged_switch_is_not_reported(self):
        path = "internal/app/workload_autoscale.go"
        original = "package app\ntype AutoscaleConfig struct {\n\tEnabled bool\n}\n"
        result = self.check_diff({path: original}, {
            path: original.replace("\n}", "\n\tIntervalSeconds int\n}")
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("clean (1 added configuration line(s) scanned)", result.stdout)

    def test_removing_switch_is_allowed(self):
        path = "internal/app/workload_autoscale.go"
        result = self.check_diff({path: (
            "package app\ntype AutoscaleConfig struct {\n\tEnabled bool\n}\n"
        )}, {path: "package app\ntype AutoscaleConfig struct {\n}\n"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_exception_needs_a_reason_and_only_exempts_its_line(self):
        path = "internal/app/vendor_adapter.go"
        result = self.check_diff({}, {path: (
            "package app\ntype VendorConfig struct {\n"
            "\tEnabled bool // # zero-config: unavoidable vendor field name\n"
            "\tDisabled bool // # zero-config:   \n"
            "\tHostTelemetry bool\n}\n"
        )})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(f"file={path},line=3::", result.stdout)
        self.assertIn(f"file={path},line=4::", result.stdout)
        self.assertIn(f"file={path},line=5::", result.stdout)
        self.assertIn("2 violation(s)", result.stdout)

    def test_existing_config_and_env_surfaces_remain_checked(self):
        for path, content in (
            (".env", "ENABLE_API=true\n"),
            (".github/workflows/ci.yml", "enabled: true\n"),
            ("internal/config/settings.go", "package config\nvar Disabled bool\n"),
            ("internal/other/config.go", "package other\nvar Enabled bool\n"),
            ("internal/other/runtime.go", 'package other\nvar setting = os.Getenv("ENABLE_API")\n'),
        ):
            with self.subTest(path=path):
                result = self.check_diff({}, {path: content})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"file={path},", result.stdout)


if __name__ == "__main__":
    unittest.main()
