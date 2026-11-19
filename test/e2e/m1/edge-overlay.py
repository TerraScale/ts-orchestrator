import io
import json
import pathlib
import subprocess
import sys
import tarfile

repo = pathlib.Path(sys.argv[1]).resolve()
work = pathlib.Path(sys.argv[2])
areas = ["internal", "third_party", "deploy"]
current = subprocess.check_output(["git", "-C", str(repo), "ls-files", *areas], text=True)
archive = subprocess.check_output(
    ["git", "-C", str(repo), "archive", "origin/main", "--", *areas]
)
with tarfile.open(fileobj=io.BytesIO(archive)) as sources:
    base = {
        member.name: sources.extractfile(member).read()
        for member in sources
        if member.isfile()
    }
replacements = {}
for name in sorted(set(current.splitlines()) | base.keys()):
    original = repo / name
    if name not in base:
        replacements[str(original)] = ""
        continue
    target = work / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(base[name])
    replacements[str(original)] = str(target)
(work / "overlay.json").write_text(json.dumps({"Replace": replacements}))
