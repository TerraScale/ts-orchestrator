#!/usr/bin/env python3
"""Exit 3 only after proving executable inputs match a retained main ancestor."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from qualified_release import TAG, admit, api, command


def inputs():
    root = Path(command("git", "rev-parse", "--show-toplevel", text=True).strip())
    paths = {"go.mod", "go.sum", "Makefile", ".github/workflows/ci.yml",
             "scripts/ci/check-release-binaries.sh", "scripts/ci/publish-qualification.sh",
             "scripts/ci/qualified_release.py", "scripts/ci/release-inputs-changed.py"}
    decoder = json.JSONDecoder()
    packages = 0
    for architecture in ("amd64", "arm64"):
        env = os.environ | {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local",
                            "GOOS": "linux", "GOARCH": architecture, "CGO_ENABLED": "0"}
        graph = command("go", "list", "-mod=readonly", "-deps", "-json",
                        "./cmd/terrascale-orchestrator", env=env, text=True)
        while graph.strip():
            package, end = decoder.raw_decode(graph.lstrip())
            graph = graph.lstrip()[end:]
            directory = Path(package["Dir"])
            if not directory.is_relative_to(root):
                continue
            packages += 1
            relative = directory.relative_to(root).as_posix()
            for suffix in ("go", "s", "S", "h", "c", "cc", "cpp", "m", "mm", "syso"):
                paths.add(f":(glob){relative}/*.{suffix}")
            for pattern in package.get("EmbedPatterns", []):
                prefix = re.split(r"[*?\[]", pattern.removeprefix("all:"), maxsplit=1)[0]
                if prefix != pattern.removeprefix("all:"):
                    prefix = prefix.rpartition("/")[0]
                paths.add(f":(literal){relative}/{prefix}".rstrip("/"))
            module = package.get("Module") or {}
            if module.get("GoMod") and Path(module["GoMod"]).is_relative_to(root):
                paths.add(":(literal)" + Path(module["GoMod"]).relative_to(root).as_posix())
    if not packages or any("\n" in path or "\r" in path for path in paths):
        raise ValueError("unreadable executable input graph")
    return sorted(paths) + [":(exclude,glob)**/*_test.go"]


def changed():
    source = os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", source) or command(
            "git", "rev-parse", "HEAD", text=True).strip() != source:
        raise ValueError("candidate source differs from checkout")
    if os.environ.get("GITHUB_EVENT_NAME") == "schedule":
        print("scheduled refresh requires current-source binaries")
        return 0
    paths = inputs()
    retained = []
    for page in range(1, 11):
        releases = api(f"releases?per_page=50&page={page}")
        retained.extend(releases)
        if len(releases) < 50:
            break
    candidates = []
    for release in retained:
        tag = release["tag_name"]
        match = TAG.fullmatch(tag)
        names = [asset["name"] for asset in release["assets"]]
        if (match and not release["draft"] and release["prerelease"] and
                all(names.count(name) == 1 for name in ("qualification.json",
                    "terrascale-orchestrator-linux-amd64", "terrascale-orchestrator-linux-arm64"))):
            candidates.append((int(match[2]), match[1], tag))
    with tempfile.TemporaryDirectory() as temporary:
        for _, base, tag in sorted(candidates, reverse=True):
            ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", base, source])
            if ancestry.returncode == 1:
                continue
            if ancestry.returncode != 0:
                raise ValueError("retained source ancestry is unreadable")
            diff = subprocess.run(["git", "diff", "--quiet", base, source, "--", *paths])
            if diff.returncode == 1:
                # Building current source needs no retained bytes. Only a skip
                # requires downloading and admitting the complete baseline.
                print(f"executable inputs changed since retained qualification {tag}")
                return 0
            if diff.returncode != 0:
                raise ValueError("executable input comparison failed")
            try:
                admit(tag, Path(temporary) / tag)
            except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
                print(f"retained baseline {tag} refused: {error}", file=sys.stderr)
                continue
            print(f"executable inputs unchanged since retained qualification {tag}")
            return 3
    print("no complete retained qualified main ancestor; building current source")
    return 0


if __name__ == "__main__":
    os.environ["GH_HOST"] = "github.com"
    try:
        status = changed()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"executable inputs are unreadable; building current source: {error}", file=sys.stderr)
        status = 0
    sys.exit(status)
