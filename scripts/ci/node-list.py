import json
import re
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
    if updated != current:
        sys.exit("embedded node list differs; run make generate")
elif not sys.argv[1:]:
    target.write_text(updated)
else:
    sys.exit("usage: node-list.py [check]")
