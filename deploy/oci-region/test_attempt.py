"""The attempt runner builds and reuses one tool for both command groups."""

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("attempt", pathlib.Path(__file__).with_name("attempt.py"))
attempt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(attempt)


class AttemptToolTests(unittest.TestCase):
    def test_one_binary_is_built_and_reused_for_bootstrap_and_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / "attempt.json"
            config.write_text(json.dumps({
                "workdir": str(root / "work"), "deployment_id": "deployment-a", "prefix": "bootstrap/a",
                "trust": {}, "tools": {"fj_dir": "/fj", "guestfs_tools_dir": "/guestfs",
                                        "libguestfs_dir": "/libguestfs", "libguestfs_appliance": "/appliance"},
                "orchestrator": {"repository": "/repository", "source_revision": "a" * 40},
            }))
            runner = attempt.Attempt(config)
            with mock.patch.object(runner, "run") as run, mock.patch.object(attempt.subprocess, "run") as build:
                runner.build_tools()
                run.assert_called_once_with("git", "-C", "/repository", "worktree", "add", "--detach",
                                            runner.path("source"), "a" * 40)
                build.assert_called_once()
                args = build.call_args.args[0]
                self.assertEqual(args[args.index("-o") + 1], str(runner.bootstrap_tool))
                self.assertEqual(args[-1], "./cmd/terrascale-orchestrator")
                self.assertEqual(runner.bootstrap_tool, runner.release_tool)
                runner.bootstrap_tool.write_bytes(b"already-built unified executable")
                run.reset_mock()
                build.reset_mock()
                runner.build_tools()
                run.assert_not_called()
                build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
