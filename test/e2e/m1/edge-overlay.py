import json
import pathlib
import subprocess
import sys

repo = pathlib.Path(sys.argv[1]).resolve()
work = pathlib.Path(sys.argv[2])
areas = ["internal/edge", "internal/observability"]
current = subprocess.check_output(["git", "-C", str(repo), "ls-files", *areas], text=True)
base = subprocess.check_output(
    ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "origin/main", *areas],
    text=True,
)
base_paths = set(base.splitlines())
replacements = {}
for name in sorted(set(current.splitlines()) | base_paths):
    if not name.endswith(".go"):
        continue
    original = repo / name
    content = (
        subprocess.check_output(
            ["git", "-C", str(repo), "show", f"origin/main:{name}"]
        )
        if name in base_paths
        else f"package {original.parent.name}\n".encode()
    )
    target = work / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    replacements[str(original)] = str(target)
(work / "overlay.json").write_text(json.dumps({"Replace": replacements}))
