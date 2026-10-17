#!/usr/bin/env python3
"""Real Git histories and local-only tools exercise publication and tool admission."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).parent
REPOSITORY = "TerraScale/ts-orchestrator"
JOB = "verify/go + artifact/linux-amd64-arm64"


class ArtifactGraph(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.root = self.work / "repo"
        self.root.mkdir()
        for name in ("qualified_release.py", "release-inputs-changed.py",
                     "image-inputs-changed.sh", "image-superseded.sh", "deploy-fleet.sh"):
            self.write("scripts/ci/" + name, (SCRIPTS / name).read_text())
        for name, content in {
            "go.mod": "module example.invalid/fixture\n",
            "go.sum": "",
            "cmd/terrascale-orchestrator/main.go": "package main\n",
            "internal/runtime/runtime.go": "package runtime\n",
            "internal/runtime/runtime_test.go": "package runtime\n",
            "internal/runtime/platform_arm64.go": "package runtime\n",
            "internal/runtime/assets/policy.json": "{}\n",
            "internal/armruntime/policy.go": "package armruntime\n",
            "docs/guide.md": "guide\n",
            "internal/trust/root.pem": "fixture root\n",
            "deploy/image/image-inputs.json": json.dumps({
                "trust_roots": [{"path": "internal/trust/root.pem"}]}),
            "scripts/ci/fetch-production-evidence.sh": "#!/usr/bin/env bash\nexit 0\n",
        }.items():
            self.write(name, content)
        self.git("init", "-q")
        self.git("config", "user.name", "CI graph fixture")
        self.git("config", "user.email", "ci-graph@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "qualified baseline")
        self.base = self.git("rev-parse", "HEAD")
        self.git("remote", "add", "origin", str(self.root))
        self.state = {"root": str(self.root), "candidates": {}, "runs": {},
                      "releases": [], "graph_failure": False}
        self.retain(self.base, 1)
        self.state["releases"].append({
            "tag_name": f"image-{self.base}-run-1-attempt-1", "draft": False,
            "prerelease": True, "assets": [{"name": "image-qualification.json", "size": 1}]})
        tools = self.work / "tools"
        tools.mkdir()
        program = "#!" + sys.executable + "\n" + TOOL
        for name in ("go", "gh"):
            path = tools / name
            path.write_text(program)
            path.chmod(0o700)
        self.env = os.environ | {
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "FIXTURE_STATE": str(self.work / "state.json"), "GH_TOKEN": "fixture-token",
            "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": self.base,
            "SOURCE_SHA": self.base, "SOURCE_CI_RUN_ID": "1",
            "RUNNER_TEMP": str(self.work), "GITHUB_OUTPUT": str(self.work / "output"),
            "FIXTURE_EXECUTION": str(self.work / "executed"),
        }

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True,
                                       stderr=subprocess.STDOUT).strip()

    def advance(self, name, content="changed\n"):
        self.write(name, content)
        self.git("add", "-A")
        self.git("commit", "-qm", "candidate change")
        head = self.git("rev-parse", "HEAD")
        self.env.update(GITHUB_SHA=head, SOURCE_SHA=head)
        return head

    def retain(self, source, run_id):
        tag = f"ci-{source}-run-{run_id}"
        files = {}
        records = []
        for architecture in ("amd64", "arm64"):
            name = f"terrascale-orchestrator-linux-{architecture}"
            files[name] = (f"#!/usr/bin/env bash\n# source={source} architecture={architecture}\n"
                           'printf "%s\\n" "$*" >> "$FIXTURE_EXECUTION"\n'
                           'printf \'{"schema":"terrascale.release.production-admission.v1",'
                           '"source_revision":"%s","cell":"GRU","state":"qualified"}\\n\' "$SOURCE_SHA"\n')
            data = files[name].encode()
            records.append({"name": name, "architecture": architecture, "bytes": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        q = {"schema": "terrascale.release.qualification.v1", "repository": REPOSITORY,
             "source_revision": source, "source_tree": self.git("rev-parse", source + "^{tree}"),
             "go_version": "go1.27.1", "artifacts": records,
             "verification": {"workflow": "ci.yml", "job": JOB, "run_id": run_id,
                              "run_number": run_id, "conclusion": "success"}}
        for name in ("go.mod", "go.sum"):
            data = subprocess.check_output(["git", "show", f"{source}:{name}"], cwd=self.root)
            q[name.replace(".", "_") + "_sha256"] = hashlib.sha256(data).hexdigest()
        files["qualification.json"] = json.dumps(q)
        view = {"tag_name": tag, "draft": False, "prerelease": True,
                "assets": [{"name": name, "size": len(data.encode())} for name, data in files.items()]}
        run = {"id": run_id, "run_number": run_id, "head_sha": source, "head_branch": "main",
               "path": ".github/workflows/ci.yml", "event": "push", "status": "completed",
               "conclusion": "success", "repository": {"full_name": REPOSITORY},
               "head_repository": {"full_name": REPOSITORY}}
        self.state["candidates"][tag] = {"files": files, "view": view}
        self.state["runs"][str(run_id)] = run
        self.state["releases"].insert(0, view)
        return self.state["candidates"][tag]

    def run_script(self, name, *args):
        (self.work / "state.json").write_text(json.dumps(self.state))
        interpreter = sys.executable if name.endswith(".py") else "bash"
        flags = ["-B"] if name.endswith(".py") else []
        return subprocess.run([interpreter, *flags, str(self.root / "scripts/ci" / name), *args],
                              cwd=self.root, env=self.env, capture_output=True, text=True, timeout=60)

    def classification(self, expected):
        result = self.run_script("release-inputs-changed.py")
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_docs_and_tests_only_skip_publication(self):
        self.advance("docs/guide.md")
        self.classification(3)
        self.advance("internal/runtime/runtime_test.go")
        self.classification(3)

    def test_runtime_platform_embed_and_module_changes_build(self):
        for name in ("internal/runtime/runtime.go", "internal/runtime/platform_arm64.go",
                     "internal/armruntime/policy.go", "internal/runtime/assets/policy.json", "go.mod"):
            with self.subTest(path=name):
                self.git("reset", "--hard", self.base)
                self.advance(name)
                self.classification(0)

    def test_deleted_and_renamed_embedded_inputs_build(self):
        path = self.root / "internal/runtime/assets/policy.json"
        path.rename(path.with_name("renamed.json"))
        self.advance("docs/guide.md")
        self.classification(0)
        self.git("reset", "--hard", self.base)
        (self.root / "internal/runtime/runtime.go").unlink()
        self.advance("docs/guide.md")
        self.classification(0)

    def test_cancelled_runtime_push_is_not_hidden_by_docs_parent(self):
        runtime = self.advance("internal/runtime/runtime.go")
        partial = self.retain(runtime, 2)
        partial["view"]["assets"] = [a for a in partial["view"]["assets"] if a["name"] != "qualification.json"]
        self.state["runs"]["2"]["conclusion"] = "cancelled"
        self.advance("docs/guide.md")
        self.classification(0)

    def test_newest_complete_ancestor_not_release_listing_order(self):
        runtime = self.advance("internal/runtime/runtime.go")
        self.retain(runtime, 2)
        self.state["releases"].reverse()
        self.advance("docs/guide.md")
        self.classification(3)

    def test_schedule_and_image_pin_change_require_current_candidate(self):
        self.advance("docs/guide.md")
        self.env["GITHUB_EVENT_NAME"] = "schedule"
        self.classification(0)
        self.env["GITHUB_EVENT_NAME"] = "push"
        self.advance("internal/trust/root.pem")
        self.classification(0)

    def test_unknown_graph_or_qualification_cannot_skip(self):
        self.advance("docs/guide.md")
        self.state["graph_failure"] = True
        self.classification(0)
        self.state["graph_failure"] = False
        self.state["runs"]["1"]["conclusion"] = "cancelled"
        self.classification(0)

    def test_tool_bytes_are_admitted_before_execution_without_build(self):
        result = self.run_script("deploy-fleet.sh", "qualify")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        executed = (self.work / "executed").read_text()
        self.assertIn("release verify-production", executed)
        self.assertTrue((self.work / f"production-{self.base}-run-1/qualification.sha256").exists())

    def test_wrong_digest_manifest_or_job_refuses_tool_before_execution(self):
        tag = f"ci-{self.base}-run-1"
        original = json.dumps(self.state)
        for mutation in ("bytes", "marker", "tree", "tag", "run", "vcs"):
            with self.subTest(mutation=mutation):
                self.state = json.loads(original)
                self.state["fault"] = mutation
                directory = self.work / mutation
                result = self.run_script("qualified_release.py", self.base, "1", str(directory))
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse((self.work / "executed").exists())
                tool = directory / "terrascale-orchestrator-linux-amd64"
                if tool.exists():
                    self.assertEqual(tool.stat().st_mode & 0o111, 0)

    def test_docs_run_does_not_supersede_retained_candidate(self):
        docs = self.advance("docs/guide.md")
        newer = self.retain(docs, 2)
        newer["view"]["assets"] = []  # successful checks without a runtime publication
        result = self.run_script("image-superseded.sh", self.base, "1", "1", "30")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.work / "output").read_text().strip(), "skip=false")
        newer["view"]["assets"] = self.state["candidates"][f"ci-{self.base}-run-1"]["view"]["assets"]
        (self.work / "output").unlink()
        result = self.run_script("image-superseded.sh", self.base, "1", "1", "30")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.work / "output").read_text().strip(), "skip=true")


TOOL = r'''
import hashlib, json, os, pathlib, re, sys
state = json.loads(pathlib.Path(os.environ["FIXTURE_STATE"]).read_text())
args = sys.argv[1:]
fault = state.get("fault")
if pathlib.Path(sys.argv[0]).name == "go":
    if args[:3] == ["list", "-mod=readonly", "-deps"]:
        assert args[3] == "-json"
        for key, value in {"GOPROXY":"off", "GOSUMDB":"off", "GOTOOLCHAIN":"local", "GOOS":"linux"}.items():
            assert os.environ[key] == value
        if state["graph_failure"]:
            sys.exit(1)
        image = args[4:] == ["./internal/image", "./internal/netbird/client"]
        assert image or args[4:] == ["./cmd/terrascale-orchestrator"]
        directories = ["internal/image", "internal/netbird/client"] if image else ["cmd/terrascale-orchestrator", "internal/runtime"]
        if not image and os.environ["GOARCH"] == "arm64":
            directories.append("internal/armruntime")
        for directory in directories:
            print(json.dumps({"Dir":str(pathlib.Path(state["root"]) / directory),
                "Module":{"GoMod":str(pathlib.Path(state["root"]) / "go.mod")},
                "EmbedPatterns":["assets/*.json"] if directory == "internal/runtime" else []}))
    else:
        assert args[:2] == ["version", "-m"], "no actual Go build is allowed: " + repr(args)
        data = pathlib.Path(args[2]).read_text()
        source, architecture = re.search(r"source=([0-9a-f]{40}) architecture=(amd64|arm64)", data).groups()
        if fault == "vcs":
            source = "0" * 40
        print("fixture: go1.27.1")
        for setting in ["GOOS=linux", "CGO_ENABLED=0", "GOARCH=" + architecture,
                        "vcs.revision=" + source, "vcs.modified=false"]:
            print("\tbuild\t" + setting)
    sys.exit(0)
if args[:2] == ["release", "download"]:
    tag = args[2]
    name = args[args.index("--pattern") + 1]
    output = pathlib.Path(args[args.index("--output") + 1])
    data = state["candidates"][tag]["files"][name]
    if name == "qualification.json" and fault == "tree":
        q = json.loads(data); q["source_tree"] = "0" * 40; data = json.dumps(q)
    if name.endswith("amd64") and fault == "bytes":
        data = data[:-1] + "x"
    output.write_text(data)
    output.chmod(0o600)
    sys.exit(0)
assert args[0] == "api", "read-only GitHub fixture: " + repr(args)
endpoint = args[-1].removeprefix("repos/TerraScale/ts-orchestrator/")
if endpoint == "releases?per_page=50&page=1":
    output = state["releases"]
elif endpoint.startswith("releases/tags/"):
    tag = endpoint.removeprefix("releases/tags/")
    output = state["candidates"][tag]["view"]
elif endpoint.startswith("commits/"):
    output = {"sha": "0" * 40 if fault == "tag" else re.fullmatch(r"ci-([0-9a-f]{40})-run-[0-9]+", endpoint[8:])[1]}
elif endpoint.startswith("actions/workflows/ci.yml/runs?"):
    output = [{"workflow_runs":list(state["runs"].values())}]
elif re.fullmatch(r"actions/runs/[0-9]+", endpoint):
    output = dict(state["runs"][endpoint.split("/")[2]])
    if fault == "run": output["head_sha"] = "0" * 40
elif "/jobs?per_page=100" in endpoint:
    run_id = int(endpoint.split("/")[2])
    output = [{"jobs":[{"id": run_id * 10, "run_id":run_id, "name":"verify/go + artifact/linux-amd64-arm64",
                        "status":"completed", "conclusion":"success"}]}]
elif endpoint.startswith("actions/jobs/"):
    run_id = int(endpoint.split("/")[2]) // 10
    run = state["runs"][str(run_id)]
    tag = f"ci-{run['head_sha']}-run-{run_id}"
    digest = hashlib.sha256(state["candidates"][tag]["files"]["qualification.json"].encode()).hexdigest()
    if fault == "marker": digest = "0" * 64
    print(f"2026-10-17T00:00:00Z TS_RELEASE_QUALIFICATION_V1 source_sha={run['head_sha']} run_id={run_id} run_number={run_id} manifest_sha256={digest}")
    sys.exit(0)
else:
    raise AssertionError(endpoint)
print(json.dumps(output))
'''


if __name__ == "__main__":
    unittest.main()
