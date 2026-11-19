import json
import os
import re
import subprocess
from pathlib import Path

repository = os.environ["GITHUB_REPOSITORY"]
repo = Path(__file__).resolve().parents[3]
tag = "host-image-20261119-11d7827"


def pages(endpoint):
    return json.loads(
        subprocess.check_output(
            ["gh", "api", "--paginate", "--slurp", f"repos/{repository}/{endpoint}"],
            text=True,
        )
    )


release = json.loads(
    subprocess.check_output(
        ["gh", "api", f"repos/{repository}/releases/tags/{tag}"], text=True
    )
)
source = release["target_commitish"]
assets = {asset["name"]: asset for asset in release["assets"]}
if (
    release["draft"]
    or release["tag_name"] != tag
    or not re.fullmatch(r"[0-9a-f]{40}", source)
    or not {
        "ts-host-debian13-amd64.qcow2",
        "ts-host-debian13-amd64.qcow2.sha256",
    }
    <= assets.keys()
):
    raise SystemExit(f"pinned host image {tag} is not published with both amd64 assets")
subprocess.run(
    ["git", "-C", str(repo), "merge-base", "--is-ancestor", source, "origin/main"],
    check=True,
)
runs = [
    run
    for page in pages(
        "actions/workflows/host-image.yml/runs?branch=main&status=success&event=push"
        f"&head_sha={source}&per_page=100"
    )
    for run in page["workflow_runs"]
    if run["head_sha"] == source
]
if not runs:
    raise SystemExit(f"pinned host image {tag} has no successful main qualification")
run = max(runs, key=lambda run: run["id"])
identity = "-".join(
    str(assets[name]["id"])
    for name in ("ts-host-debian13-amd64.qcow2", "ts-host-debian13-amd64.qcow2.sha256")
)
values = {
    "tag": release["tag_name"],
    "source": release["target_commitish"],
    "url": run["html_url"],
    "identity": identity,
    "directory": str(Path.home() / ".cache/ts-m1-host-image" / identity),
}
with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
    output.write("\n".join(f"{name}={value}" for name, value in values.items()) + "\n")
print(f"qualified main image: {values['tag']} ({values['source']}, assets {identity})")
