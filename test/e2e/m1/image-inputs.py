import json
import os
import re
import subprocess
from pathlib import Path

repository = os.environ["GITHUB_REPOSITORY"]
repo = Path(__file__).resolve().parents[3]


def pages(endpoint):
    return json.loads(
        subprocess.check_output(
            ["gh", "api", "--paginate", "--slurp", f"repos/{repository}/{endpoint}"],
            text=True,
        )
    )


runs = {}
for page in pages(
    "actions/workflows/host-image.yml/runs?branch=main&status=success&event=push&per_page=100"
):
    for run in page["workflow_runs"]:
        if run["head_sha"] not in runs:
            runs[run["head_sha"]] = run

candidates = []
for page in pages("releases?per_page=100"):
    for release in page:
        source = release["target_commitish"]
        assets = {asset["name"]: asset for asset in release["assets"]}
        if (
            release["draft"]
            or not release["tag_name"].startswith("host-image-")
            or not re.fullmatch(r"[0-9a-f]{40}", source)
            or source not in runs
            or not {
                "ts-host-debian13-amd64.qcow2",
                "ts-host-debian13-amd64.qcow2.sha256",
            }
            <= assets.keys()
        ):
            continue
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "merge-base",
                "--is-ancestor",
                source,
                "origin/main",
            ],
            check=False,
        )
        if result.returncode == 1:
            continue
        result.check_returncode()
        candidates.append((runs[source]["id"], release["id"], release, assets))
if not candidates:
    raise SystemExit("no published qualified main host image has both amd64 assets")
_, _, release, assets = max(candidates, key=lambda candidate: candidate[:2])
identity = "-".join(
    str(assets[name]["id"])
    for name in ("ts-host-debian13-amd64.qcow2", "ts-host-debian13-amd64.qcow2.sha256")
)
values = {
    "tag": release["tag_name"],
    "source": release["target_commitish"],
    "url": runs[release["target_commitish"]]["html_url"],
    "identity": identity,
    "directory": str(Path.home() / ".cache/ts-m1-host-image" / identity),
}
with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
    output.write("\n".join(f"{name}={value}" for name, value in values.items()) + "\n")
print(f"qualified main image: {values['tag']} ({values['source']}, assets {identity})")
