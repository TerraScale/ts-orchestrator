import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

repo = pathlib.Path(sys.argv[1]).resolve()
work = pathlib.Path(sys.argv[2])
areas = ["internal", "third_party"]
current = subprocess.check_output(["git", "-C", str(repo), "ls-files", *areas], text=True)
archive = subprocess.check_output(
    ["git", "-C", str(repo), "archive", "origin/main", "--", *areas]
)
with tarfile.open(fileobj=io.BytesIO(archive)) as sources:
    base = {
        member.name: sources.extractfile(member).read()
        for member in sources
        if member.isfile() and member.name.endswith(".go")
    }
replacements = {}
for name in sorted(set(current.splitlines()) | base.keys()):
    if not name.endswith(".go"):
        continue
    original = repo / name
    if name in base:
        content = base[name]
    else:
        package = re.search(rb"(?m)^package\s+(\w+)", original.read_bytes()).group(1)
        content = b"package " + package + b"\n"
    target = work / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    replacements[str(original)] = str(target)
(work / "overlay.json").write_text(json.dumps({"Replace": replacements}))
