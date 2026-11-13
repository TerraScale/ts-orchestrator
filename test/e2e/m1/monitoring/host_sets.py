import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[4]
files = (
    "deploy/observability/production/hosts.txt",
    "deploy/observability/production/check-hosts.py",
    "deploy/observability/production/prometheus.yml",
    "deploy/observability/production/operational-rules.yml",
    "test/e2e/m1/monitoring/rules.yml",
)
subprocess.run(["python3", str(root / files[1])], check=True)
with tempfile.TemporaryDirectory() as directory:
    staged = Path(directory)
    for name in files:
        target = staged / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, target)
    fixture = staged / files[-1]
    fixture.write_text(fixture.read_text().replace("ts-gru-2", "ts-gru-9"))
    result = subprocess.run(["python3", str(staged / files[1])], capture_output=True, text=True, check=False)
    if result.returncode == 0 or "mismatch" not in result.stderr:
        raise SystemExit("monitoring: mismatched host sets were accepted")
print("monitoring: host-set equality and mismatch rejection passed")
