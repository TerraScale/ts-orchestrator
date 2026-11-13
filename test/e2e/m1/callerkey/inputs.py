import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path


def command(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True)


def graph(root):
    with tempfile.TemporaryDirectory() as temporary:
        overlay = Path(temporary) / "overlay.json"
        arguments = ["go", "list", "-deps", "-json"]
        adapter = root / "test/e2e/m1/callerkey/store.go.txt"
        if adapter.exists() and (root / "internal/callerkey/vault.go").exists():
            overlay.write_text(json.dumps({"Replace": {
                str(root / "internal/callerkey/vault.go"): str(adapter)
            }}))
            arguments.extend(["-overlay", str(overlay)])
        arguments.append("./cmd/terrascale-orchestrator")
        if (root / "test/e2e/m1/callerkey/main.go").exists():
            arguments.append("./test/e2e/m1/callerkey")
        output = command(*arguments, cwd=root)
    decoder = json.JSONDecoder()
    directories, files = set(), set()
    while output.strip():
        package, offset = decoder.raw_decode(output.lstrip())
        output = output.lstrip()[offset:]
        directory = Path(package["Dir"])
        if not directory.is_relative_to(root):
            continue
        relative = directory.relative_to(root).as_posix()
        directories.add(relative + "/")
        for name in package.get("EmbedFiles", []):
            files.add((directory / name).relative_to(root).as_posix())
        module = package.get("Module", {})
        module = module.get("Replace", module)
        if "GoMod" in module and Path(module["GoMod"]).is_relative_to(root):
            path = Path(module["GoMod"]).relative_to(root)
            files.update([path.as_posix(), path.with_name("go.sum").as_posix()])
    return directories, files


os.environ.update(GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
if os.environ["GITHUB_EVENT_NAME"] == "schedule":
    changed = True
else:
    root = Path.cwd()
    source = os.environ["SOURCE_SHA"]
    base = os.environ.get("CHANGE_BASE", "")
    if not base or set(base) == {"0"}:
        base = command("git", "rev-parse", source + "^").strip()
    directories, files = graph(root)
    with tempfile.TemporaryDirectory() as temporary:
        base_root = Path(temporary) / "base"
        base_root.mkdir()
        archive = Path(temporary) / "base.tar"
        subprocess.run(["git", "archive", "--output", str(archive), base], check=True)
        with tarfile.open(archive) as contents:
            contents.extractall(base_root, filter="data")
        base_directories, base_files = graph(base_root)
    directories.update(base_directories)
    directories.update(["test/e2e/m1/callerkey/", ".github/actions/go/"])
    files.update(base_files)
    files.update(["go.mod", "go.sum", ".github/workflows/ci.yml",
                  "docs/caller-keys.md", "docs/e2e-ci.md"])
    paths = command("git", "diff", "--name-only", "--no-renames", "-z", base, source).split("\0")
    matches = sorted(path for path in paths if path and
                     (path in files or any(path.startswith(directory) for directory in directories)))
    changed = bool(matches)
    for directory in sorted(directories):
        print("input directory:", directory)
    for path in sorted(files):
        print("input file:", path)
    for path in matches:
        print("changed input:", path)
with open(os.environ["GITHUB_OUTPUT"], "a") as output:
    output.write(f"changed={str(changed).lower()}\n")
