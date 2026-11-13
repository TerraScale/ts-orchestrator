import re
from pathlib import Path

root = Path(__file__).resolve().parents[3]
production = root / "deploy/observability/production"
expected = set((production / "hosts.txt").read_text().splitlines())
if not expected or len(expected) != len((production / "hosts.txt").read_text().splitlines()):
    raise SystemExit("monitoring host sets: invalid installer inventory")
for name in (
    "deploy/observability/production/prometheus.yml",
    "deploy/observability/production/operational-rules.yml",
    "test/e2e/m1/monitoring/rules.yml",
):
    actual = set(re.findall(r"\bts-[a-z]{3}-[0-9]+\b", (root / name).read_text()))
    if actual != expected:
        raise SystemExit(f"monitoring host sets: mismatch in {name}")
print("monitoring host sets: equal")
