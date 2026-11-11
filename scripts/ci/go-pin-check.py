import re
import sys
import tomllib
from pathlib import Path

from qualified_release import GO_LINE

root = Path(__file__).resolve().parents[2]
go_mod = (root / "go.mod").read_text()
go = GO_LINE.search(go_mod)
if go is None:
    sys.exit("go.mod has no `go <version>` line")
toolchain = re.search(r"(?m)^toolchain ([^\s/]+)[ \t]*(?://.*)?$", go_mod)
if toolchain and toolchain[1] != f"go{go[1]}":
    sys.exit(f"go.mod has `toolchain {toolchain[1]}`, which differs from its `go {go[1]}` line: delete the toolchain line")
mise = tomllib.loads((root / ".mise.toml").read_text())["tools"].get("go")
if not isinstance(mise, str):
    sys.exit(f'.mise.toml tools.go must be a plain version string such as "{go[1]}", not {mise!r}')
receipt = re.search(r'(?m)^\s*DefaultGoVersion\s*= "go([^"]+)"[ \t]*(?://.*)?$',
                    (root / "internal/release/receipt.go").read_text())
if receipt is None:
    sys.exit('internal/release/receipt.go has no `DefaultGoVersion = "go<version>"` line')
pins = {
    "go.mod": go[1],
    ".mise.toml": mise,
    "internal/release/receipt.go DefaultGoVersion": receipt[1],
}
if len(set(pins.values())) > 1:
    sys.exit("Go version pins differ: " + ", ".join(f"{name} {version}" for name, version in pins.items()))
print(f"Go version pins agree: {go[1]}")
