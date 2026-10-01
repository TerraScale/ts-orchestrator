"""Attempt tooling follows the pinned source's command convention."""

import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("attempt", pathlib.Path(__file__).with_name("attempt.py"))
attempt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(attempt)


class AttemptToolTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        config = self.root / "attempt.json"
        config.write_text(json.dumps({
            "workdir": str(self.root / "work"), "deployment_id": "deployment-a", "prefix": "bootstrap/a",
            "validity_days": 1,
            "trust": {name: str(self.root / name) for name in (
                "root_public", "root_private", "release_leaf_public", "release_leaf_private")},
            "tools": {"fj_dir": "/fj", "guestfs_tools_dir": "/guestfs",
                      "libguestfs_dir": "/libguestfs", "libguestfs_appliance": "/appliance"},
            "orchestrator": {"repository": "/repository", "source_revision": "a" * 40, "ci_run_number": 1},
            "image": {"base_qcow2": "/base.qcow2"},
        }))
        self.runner = attempt.Attempt(config)

    def checkout(self, legacy):
        marker = self.runner.path("source", "cmd", "ts-bootstrap" if legacy else "terrascale-orchestrator", "main.go")
        marker.parent.mkdir(parents=True)
        marker.write_text("pinned entry point\n")

    def build(self, legacy):
        def checkout(*args):
            self.checkout(legacy)

        def compile(command, **kwargs):
            binary = pathlib.Path(command[command.index("-o") + 1])
            # Reject the wrong namespace when a real caller executes this tool.
            binary.write_text("#!/usr/bin/env python3\n"
                              "import json, sys\nfrom pathlib import Path\n"
                              "args = sys.argv[1:]\n"
                              f"legacy = {legacy!r}\n"
                              "if legacy:\n"
                              "    assert args[0] not in ('bootstrap', 'release'), args\n"
                              "else:\n"
                              "    assert args[0] in ('bootstrap', 'release'), args\n"
                              f"with Path({str(self.root / 'tool-calls.jsonl')!r}).open('a') as log:\n"
                              "    log.write(json.dumps(args) + '\\n')\n"
                              "if '--out' in args:\n"
                              "    Path(args[args.index('--out') + 1]).write_text('{}')\n")
            binary.chmod(0o700)

        with mock.patch.object(self.runner, "run", side_effect=checkout) as run, \
             mock.patch.object(attempt.subprocess, "run", side_effect=compile) as build:
            self.runner.build_tools()
        run.assert_called_once_with("git", "-C", "/repository", "worktree", "add", "--detach",
                                    self.runner.path("source"), "a" * 40)
        return build.call_args_list

    def test_one_binary_is_built_and_reused_for_bootstrap_and_release(self):
        builds = self.build(False)
        self.assertEqual(len(builds), 1)
        self.assertEqual(builds[0].args[0][-1], "./cmd/terrascale-orchestrator")
        self.assertEqual(self.runner.bootstrap_tool, self.runner.release_tool)
        with mock.patch.object(self.runner, "run") as run, mock.patch.object(attempt.subprocess, "run") as build:
            self.runner.build_tools()
        run.assert_not_called()
        build.assert_not_called()

    def test_legacy_source_builds_and_reuses_both_standalone_tools(self):
        builds = self.build(True)
        self.assertEqual([call.args[0][-1] for call in builds], ["./cmd/ts-bootstrap", "./cmd/ts-release"])
        self.assertEqual(self.runner.bootstrap_tool.name, "ts-bootstrap")
        self.assertEqual(self.runner.release_tool.name, "ts-release")
        with mock.patch.object(self.runner, "run") as run, mock.patch.object(attempt.subprocess, "run") as build:
            self.runner.build_tools()
        run.assert_not_called()
        build.assert_not_called()

    def test_release_phase_and_bootstrap_calls_use_the_source_convention(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                # Each source layout is an independent attempt.
                if self.runner.path("source").exists():
                    shutil.rmtree(self.runner.work)
                    self.runner.work.mkdir()
                self.build(legacy)
                log = self.root / "tool-calls.jsonl"
                log.unlink(missing_ok=True)
                self.runner.run_bootstrap("verify-anchor")
                release = self.runner.path("release")
                release.mkdir()
                for asset in ("qualification.json", "terrascale-orchestrator-linux-arm64", attempt.OPERATOR_CLI):
                    (release / asset).write_text("qualified fixture")
                original_run = self.runner.run

                def run(*args, **kwargs):
                    if args[0] == "fj":
                        return json.dumps({"head_sha": "a" * 40, "status": "success", "run_id": 2})
                    return original_run(*args, **kwargs)

                with mock.patch.object(self.runner, "run", side_effect=run):
                    self.runner.phase_release()
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                commands = ("verify-anchor", "sign-delegation", "binary-candidate", "sign-binary", "verify-binary")
                self.assertEqual([call[0 if legacy else 1] for call in calls], list(commands))
                if not legacy:
                    self.assertEqual([call[0] for call in calls], ["bootstrap", "release", "release", "release", "release"])

    def test_launch_passes_explicit_legacy_flags_to_modern_preview(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                if not self.runner.path("source").exists():
                    self.checkout(legacy)
                marker = self.runner.path("source", "cmd", "ts-bootstrap", "main.go")
                if legacy:
                    marker.parent.mkdir(parents=True, exist_ok=True)
                    marker.write_text("legacy")
                image = self.runner.path("image")
                image.mkdir(exist_ok=True)
                (image / "import.json").write_text(json.dumps({"image_id": "ocid1.image.fixture"}))
                with mock.patch.object(self.runner, "fresh_admission", return_value=("inventory", "admission")), \
                     mock.patch.object(self.runner, "run", side_effect=RuntimeError("preflight captured")) as run:
                    with self.assertRaisesRegex(RuntimeError, "preflight captured"):
                        self.runner.phase_launch()
                command = run.call_args.args
                self.assertEqual("--legacy-bootstrap-tool" in command, legacy)
                self.assertEqual("--legacy-release-tool" in command, legacy)
                self.assertEqual(command[command.index("--bootstrap-tool") + 1], self.runner.bootstrap_tool)
                self.assertEqual(command[command.index("--release-tool") + 1], self.runner.release_tool)

    def test_legacy_image_builder_receives_its_standalone_release_tool(self):
        self.checkout(True)
        self.runner.config["image"].update({
            "kernel_release": "kernel", "native_verifier": "/native", "native_verifier_sha256": "b" * 64,
            "timesyncd_config": "/timesyncd", "priority": {"profile_id": "profile", **{
                key: 1 for key in ("system_reserve_bytes", "host_memory_min_bytes", "host_memory_low_bytes",
                                  "controller_memory_min_bytes", "controller_memory_low_bytes",
                                  "system_slice_memory_min_bytes", "system_slice_memory_low_bytes")}},
        })
        with mock.patch.object(attempt.subprocess, "run", side_effect=RuntimeError("builder captured")) as run:
            with self.assertRaisesRegex(RuntimeError, "builder captured"):
                self.runner.phase_image()
        command = run.call_args.args[0]
        self.assertEqual(command[1], str(self.runner.path("source", "deploy/image/build-offline.sh")))
        self.assertEqual(command[command.index("--release-tool") + 1], str(self.runner.path("tools", "ts-release")))


if __name__ == "__main__":
    unittest.main()
