import json
import os
import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
source = root / "deploy/m1/nodes.json"
target = root / "deploy/m1/embed.go"
wire = source.read_text()
json.loads(wire)
declaration = "const NodeList = " + json.dumps(wire, ensure_ascii=False) + "\n"
current = target.read_text()
match = re.search(r"^const NodeList = .*\n?", current, re.MULTILINE)
updated = current[:match.start()] + declaration + current[match.end():] if match else current.rstrip() + "\n\n" + declaration
if sys.argv[1:] == ["check"]:
    base = os.environ.get("CHANGE_BASE") or subprocess.check_output(
        ["git", "merge-base", "origin/main", "HEAD"], cwd=root, text=True
    ).strip()

    def previous(path):
        result = subprocess.run(["git", "show", f"{base}:{path}"], cwd=root, text=True, capture_output=True, check=False)
        return result.stdout if result.returncode == 0 else ""

    before = previous("deploy/m1/nodes.json")
    if before:
        old, new = json.loads(before), json.loads(wire)
        if old != new and new["sequence"] <= old["sequence"]:
            sys.exit("changed node list requires a higher sequence than the base")

    def indices(text):
        result = {}
        constants = dict(re.findall(r'^\s*(\w+)\s*=\s*"([^"]+)"', text, re.MULTILINE))
        for entry in re.findall(r"\{[^{}]*Cell:[^{}]*\}", text):
            cell = re.search(r'Cell: ("[^"]+"|\w+)', entry).group(1).strip('"')
            cell = constants.get(cell, cell)
            index = re.search(r"MeshIndex: (\d+)", entry)
            if not index:
                continue
            result[cell] = int(index.group(1))
        return result

    catalog_path = "internal/ociregion/catalog/catalog.go"
    catalog = (root / catalog_path).read_text()
    indexes = indices(catalog)
    if len(indexes) != len(re.findall(r"\{[^{}]*Cell:", catalog)):
        sys.exit("each catalog entry requires a fixed mesh index")
    if len(set(indexes.values())) != len(indexes) or any(i < 1 or i > 254 for i in indexes.values()):
        sys.exit("catalog mesh indexes must be unique integers in 1..254")
    for cell, index in indices(previous(catalog_path)).items():
        if indexes.get(cell) != index:
            sys.exit(f"catalog mesh index for {cell} must remain {index}")
    if updated != current:
        sys.exit("embedded node list differs; run make generate")
elif not sys.argv[1:]:
    target.write_text(updated)
else:
    sys.exit("usage: node-list.py [check]")
