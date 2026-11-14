import os
import subprocess
from pathlib import Path

root = Path(subprocess.check_output(["go", "env", "GOCACHE"], text=True).strip())
entries = [(path.stat(), path) for path in root.rglob("*") if path.is_file()]
total = sum(stat.st_size for stat, _ in entries)
limit = 1024 * 1024 * 1024
before = total
for stat, path in sorted(entries, key=lambda entry: (entry[0].st_mtime_ns, str(entry[1]))):
    if total <= limit:
        break
    path.unlink()
    total -= stat.st_size
message = f"Go build cache: {before} -> {total} bytes (limit {limit})"
print(message)
if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(summary, "a") as output:
        output.write(message + "\n")
