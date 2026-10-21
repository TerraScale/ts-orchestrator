#!/usr/bin/env python3
"""Admit retained CI bytes before using an orchestrator as a build/deploy tool."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


REPOSITORY = "TerraScale/ts-orchestrator"
JOB = "verify/go + artifact/linux-amd64-arm64"
TAG = re.compile(r"ci-([0-9a-f]{40})-run-([1-9][0-9]{0,17})")


def command(*args, **kwargs):
    return subprocess.check_output(args, timeout=30, **kwargs)


def api(path):
    return json.loads(command("gh", "api", f"repos/{REPOSITORY}/{path}"))


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def admit(tag, directory):
    """Download and verify one exact, successful main-run release; execute nothing."""
    match = TAG.fullmatch(tag)
    require(match is not None, "invalid retained release tag")
    source, run_id = match[1], int(match[2])
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    view = api(f"releases/tags/{tag}")
    require(view["tag_name"] == tag and view["draft"] is False and view["prerelease"] is True,
            "retained release state differs")
    require(api(f"commits/{tag}")["sha"] == source, "retained tag points to another source")
    assets = view["assets"]

    def download(name, limit):
        advertised = [asset for asset in assets if asset["name"] == name]
        require(len(advertised) == 1 and 0 < advertised[0]["size"] <= limit,
                f"missing or invalid retained asset: {name}")
        path = directory / name
        require(not path.exists() and not path.is_symlink(), "candidate path already exists")
        command("gh", "release", "download", tag, "--repo", REPOSITORY,
                "--pattern", name, "--output", str(path))
        require(path.is_file() and not path.is_symlink() and
                path.stat().st_size == advertised[0]["size"], f"retained size differs: {name}")
        return path

    manifest = download("qualification.json", 1048576)
    q = json.loads(manifest.read_bytes())
    tree = command("git", "rev-parse", f"{source}^{{tree}}", text=True).strip()
    require(q["schema"] == "terrascale.release.qualification.v1" and
            q["repository"] == REPOSITORY and q["source_revision"] == source and
            q["source_tree"] == tree and q["go_version"] == "go1.27.1",
            "retained source, tree or toolchain differs")
    for name in ("go.mod", "go.sum"):
        contents = command("git", "show", f"{source}:{name}")
        require(q[name.replace(".", "_") + "_sha256"] == hashlib.sha256(contents).hexdigest(),
                f"retained module digest differs: {name}")
    verification = q["verification"]
    run_number = verification["run_number"]
    require(type(run_number) is int and run_number > 0 and
            verification["run_id"] == run_id and verification["workflow"] == "ci.yml" and
            verification["job"] == JOB and verification["conclusion"] == "success",
            "retained verification identity differs")
    run = api(f"actions/runs/{run_id}")
    require(run["id"] == run_id and run["run_number"] == run_number and
            run["head_sha"] == source and run["head_branch"] == "main" and
            run["path"] == ".github/workflows/ci.yml" and run["event"] != "pull_request" and
            run["status"] == "completed" and run["conclusion"] == "success" and
            run["repository"]["full_name"] == REPOSITORY and
            run["head_repository"]["full_name"] == REPOSITORY,
            "retained run did not qualify this main revision")
    pages = json.loads(command("gh", "api", "--paginate", "--slurp",
                              f"repos/{REPOSITORY}/actions/runs/{run_id}/jobs?per_page=100"))
    jobs = [job for page in pages for job in page["jobs"] if job["name"] == JOB]
    require(len(jobs) == 1 and jobs[0]["run_id"] == run_id and
            jobs[0]["status"] == "completed" and jobs[0]["conclusion"] == "success",
            "retained qualifying job did not succeed")
    logs = command("gh", "api", f"repos/{REPOSITORY}/actions/jobs/{jobs[0]['id']}/logs").decode()
    marker = (f"TS_RELEASE_QUALIFICATION_V1 source_sha={source} run_id={run_id} "
              f"run_number={run_number} manifest_sha256={digest(manifest)}")
    require(len(re.findall(r"^[0-9TZ:.-]+ " + re.escape(marker) + r"$",
                           logs.replace("\r", ""), re.MULTILINE)) == 1,
            "retained manifest lacks its exact successful job marker")
    require(len(q["artifacts"]) == 2, "retained candidate requires both architectures")
    for architecture in ("amd64", "arm64"):
        name = f"terrascale-orchestrator-linux-{architecture}"
        records = [record for record in q["artifacts"] if record["name"] == name and
                   record["architecture"] == architecture]
        require(len(records) == 1 and type(records[0]["bytes"]) is int and
                0 < records[0]["bytes"] <= 536870912 and
                re.fullmatch(r"[0-9a-f]{64}", records[0]["sha256"]), "invalid artifact record")
        record = records[0]
        path = download(name, 536870912)
        require(path.stat().st_size == record["bytes"] and digest(path) == record["sha256"],
                f"retained artifact digest differs: {name}")
        build = command("go", "version", "-m", str(path), text=True)
        for setting in (f"GOARCH={architecture}", "GOOS=linux", "CGO_ENABLED=0",
                        f"vcs.revision={source}", "vcs.modified=false"):
            require(re.search(r"(?m)^\s*build\s+" + re.escape(setting) + r"$", build),
                    f"retained build metadata differs: {setting}")
    return q


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 4, "usage: qualified_release.py SOURCE_SHA RUN_ID DIRECTORY")
        source, run_id, directory = sys.argv[1:]
        require(command("git", "rev-parse", "HEAD", text=True).strip() == source,
                "tool source differs from checkout")
        os.environ["GH_HOST"] = "github.com"
        admit(f"ci-{source}-run-{run_id}", directory)
        tool = Path(directory) / "terrascale-orchestrator-linux-amd64"
        tool.chmod(0o700)
        print(f"retained tool admitted source={source} run_id={run_id} sha256={digest(tool)}")
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f"retained tool admission failed: {error}")
