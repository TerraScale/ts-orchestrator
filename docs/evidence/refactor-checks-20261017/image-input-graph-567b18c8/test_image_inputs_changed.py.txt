#!/usr/bin/env python3
"""Exercise the detector against real Git trees without cloud or Go downloads."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("image-inputs-changed.sh")


class ImageInputsChanged(unittest.TestCase):
    def check_change(self, change, expected, *, graph_failure=False, partial=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()

            def write(name, contents):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)

            def git(*args):
                return subprocess.check_output(
                    ["git", *args], cwd=root, stderr=subprocess.STDOUT, text=True
                ).strip()

            files = {
                "go.mod": "module example.invalid/image-fixture\n",
                "go.sum": "",
                "internal/image/image.go": "package image\n",
                "internal/netbird/client/client.go": "package client\n",
                "internal/runtimepriority/render.go": "package runtimepriority\n",
                "internal/runtimepriority/platform_arm64.go": "package runtimepriority\n",
                "internal/runtimepriority/render_test.go": "package runtimepriority\n",
                "internal/armruntime/policy.go": "package armruntime\n",
                "internal/runtimepriority/assets/policy.json": "{}\n",
                "internal/trust/root.pem": "fixture root\n",
                "internal/app/app.go": "package app\n",
                "docs/guide.md": "fixture guide\n",
                "deploy/image/image-inputs.json": json.dumps(
                    {"trust_roots": [{"path": "internal/trust/root.pem"}]}
                ),
                "scripts/ci/image-inputs-changed.sh": SCRIPT.read_text(),
            }
            for name, contents in files.items():
                write(name, contents)
            git("init", "-q")
            git("config", "user.name", "Image input fixture")
            git("config", "user.email", "image-inputs@example.invalid")
            git("add", ".")
            git("commit", "-qm", "retained image")
            base = git("rev-parse", "HEAD")
            git("remote", "add", "origin", str(root))
            change(root, write)
            git("add", "-A")
            git("commit", "-qm", "candidate")
            head = git("rev-parse", "HEAD")

            state = Path(temporary) / "state"
            state.mkdir()
            graph = [
                {"Dir": str(root / package),
                 "Module": {"GoMod": str(root / "go.mod")},
                 "EmbedPatterns": ["assets/*.json"] if package.endswith("runtimepriority") else []}
                for package in (
                    "internal/image", "internal/netbird/client", "internal/runtimepriority"
                )
            ]
            (state / "graph").write_text("\n".join(json.dumps(p) for p in graph))
            (state / "armgraph").write_text(json.dumps({"Dir": str(root / "internal/armruntime")}))
            releases = [{"tag_name": f"image-{base}-run-1-attempt-1", "draft": False,
                         "assets": [{"name": "image-qualification.json"}]}]
            if partial:
                releases.insert(0, {"tag_name": f"image-{head}-run-2-attempt-1",
                                    "draft": False, "assets": []})
            (state / "releases").write_text(json.dumps(releases))
            tools = Path(temporary) / "tools"
            tools.mkdir()
            for tool in ("go", "gh"):
                path = tools / tool
                path.write_text(f"#!{sys.executable}\n" + """
import os, pathlib, sys
state = pathlib.Path(os.environ['FIXTURE_STATE'])
if pathlib.Path(sys.argv[0]).name == 'go':
    assert sys.argv[1:] == ['list', '-mod=readonly', '-deps', '-json', './internal/image', './internal/netbird/client']
    for key, value in {'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOTOOLCHAIN': 'local', 'GOOS': 'linux'}.items():
        assert os.environ[key] == value, key
    assert os.environ['GOARCH'] in ('amd64', 'arm64')
    if os.environ.get('FIXTURE_GRAPH_FAILURE') == '1':
        sys.exit(1)
    print((state / 'graph').read_text())
    if os.environ['GOARCH'] == 'arm64':
        print((state / 'armgraph').read_text())
else:
    assert sys.argv[1:] == ['api', 'repos/TerraScale/ts-orchestrator/releases?per_page=50&page=1']
    print((state / 'releases').read_text())
""")
                path.chmod(0o755)
            env = os.environ | {
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "GH_TOKEN": "fixture-token", "GITHUB_SHA": head,
                "FIXTURE_STATE": str(state),
                "FIXTURE_GRAPH_FAILURE": "1" if graph_failure else "0",
            }
            result = subprocess.run(
                ["bash", str(root / "scripts/ci/image-inputs-changed.sh")],
                cwd=root, env=env, text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_unchanged_image_inputs(self):
        for name in ("docs/guide.md", "internal/app/app.go", "internal/runtimepriority/render_test.go"):
            with self.subTest(path=name):
                self.check_change(lambda root, write: write(name, "changed\n"), 3)

    def test_changed_image_inputs(self):
        for name in ("internal/runtimepriority/render.go", "internal/runtimepriority/platform_arm64.go",
                     "internal/armruntime/policy.go", "internal/trust/root.pem", "go.mod", "go.sum",
                     "scripts/ci/image-inputs-changed.sh"):
            with self.subTest(path=name):
                self.check_change(lambda root, write: write(name, SCRIPT.read_text() + "\n# changed\n")
                                  if name.endswith(".sh") else write(name, "changed\n"), 0)

    def test_deleted_and_renamed_inputs(self):
        for name in ("internal/runtimepriority/render.go", "internal/runtimepriority/assets/policy.json"):
            with self.subTest(path=name):
                self.check_change(lambda root, write: (root / name).unlink(), 0)
        self.check_change(lambda root, write: (root / "internal/runtimepriority/render.go").rename(
            root / "internal/app/moved.go"), 0)

    def test_unknown_graph_or_pins_build(self):
        self.check_change(lambda root, write: write("docs/guide.md", "changed\n"),
                          0, graph_failure=True)
        self.check_change(lambda root, write: write("deploy/image/image-inputs.json", "{}\n"), 0)

    def test_incomplete_release_does_not_hide_changed_input(self):
        self.check_change(lambda root, write: write("internal/runtimepriority/render.go", "changed\n"),
                          0, partial=True)


if __name__ == "__main__":
    unittest.main()
