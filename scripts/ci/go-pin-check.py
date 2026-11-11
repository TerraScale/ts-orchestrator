import re
import sys
import tomllib
from pathlib import Path

root = Path(__file__).resolve().parents[2]
go_mod = re.search(r"(?m)^go (\S+)$", (root / "go.mod").read_text())
receipt = re.search(r'(?m)^\s*DefaultGoVersion\s*= "go([^"]+)"$',
                    (root / "internal/release/receipt.go").read_text())
pins = {
    "go.mod": go_mod and go_mod[1],
    ".mise.toml": tomllib.loads((root / ".mise.toml").read_text())["tools"].get("go"),
    "internal/release/receipt.go DefaultGoVersion": receipt and receipt[1],
}
if None in pins.values() or len(set(pins.values())) > 1:
    sys.exit("Go version pins differ: " + ", ".join(f"{name} {version}" for name, version in pins.items()))
print(f"Go version pins agree: {pins['go.mod']}")
