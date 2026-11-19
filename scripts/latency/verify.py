import json
import math
import os
import sys
from pathlib import Path

budgets = {row["name"]: row for row in json.loads(Path(sys.argv[1]).read_text())}
proof = Path(sys.argv[2])
revision = os.environ["GITHUB_SHA"]
manifest = json.loads((proof / "manifest.json").read_text())
assert manifest["revision"] == revision, "staging revision mismatch"
targets = {target["name"]: target for target in manifest["targets"]}
assert set(targets) == set(budgets), "staging inventory differs from budget table"
expected = {(name, path) for name, row in budgets.items()
            for path in (["connect"] if row["kind"] == "postgres" else ["fresh", "kept"])}
for vantage in ["beta", "delta", "mariogk-dev"]:
    report = json.loads((proof / f"{vantage}.json").read_text())
    assert report["revision"] == revision and report["vantage"] == vantage, "pool identity mismatch"
    assert report["passed"] is True, f"{vantage}: lane failed"
    seen = set()
    for result in report["results"]:
        key = (result["name"], result["path"])
        assert key in expected and key not in seen, f"{vantage}: unexpected result {key}"
        seen.add(key)
        assert result["region"] == targets[key[0]]["region"], "region mismatch"
        assert result["samples"] == 1000 and result["passed"] is True, "incomplete sample"
        quantiles = result["seconds_p50_p95_p99"]
        assert set(quantiles) == {"dns", "connect", "tls", "first_byte", "total"}, "missing phase"
        limit = budgets[key[0]]["kept" if key[1] == "kept" else "fresh"]
        assert result["budget_seconds_p50_p95_p99"] == limit, "stale budget"
        for phase, values in quantiles.items():
            assert len(values) == 3 and all(math.isfinite(v) and v >= 0 for v in values), "invalid quantile"
            assert values == sorted(values), "unordered quantiles"
            if phase in {"first_byte", "total"}:
                assert all(value <= bound for value, bound in zip(values, limit)), f"{vantage}: {key} {phase} exceeds budget"
        print(f"{vantage} {key[0]} {key[1]}: p50/p95/p99 {quantiles['total']} PASS")
    assert seen == expected, f"{vantage}: missing public name or path"
print(f"latency gate: {revision} passed on all three pool servers")
