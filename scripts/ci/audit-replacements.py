#!/usr/bin/env python3
"""Bind patched sources to reviewed upstream baselines and query their advisories."""
import hashlib
import http.client
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Resolve once: a vendored module's tool-manager files must not select a different Go.
GO = str(Path(subprocess.check_output(["go", "env", "GOROOT"], cwd=ROOT, text=True).strip()) / "bin/go")

# Version/commit provenance is retained in each existing record. The digest
# binds every tracked replacement file (including manifests) to this review.
BASELINES = (
    (
        "github.com/moby/swarmkit/v2", "v2.1.2", "third_party/swarmkit",
        "12ce3490ef26cbca6ef9b243cb013fffbfe6a6cb",
        "docs/evidence/core-runtime-contract.md",
        "4e2475adee705924c9c800d205ab2b5c8869359318c8db3eee600ea157c0737c",
    ),
    (
        "github.com/nats-io/nats-server/v2", "v2.15.0", "third_party/nats-server",
        "eb763679aa3c24a40dcd3012aa046ad1996d851c",
        "third_party/nats-server/README.terrascale.md",
        "015e2890bdc6cc24c83fc326df161c64225d18301679b1cb3752b7667ad72ee8",
    ),
    (
        "github.com/oracle/oci-go-sdk/v65", "v65.126.0", "third_party/oci-go-sdk",
        "d48ee53a6d31d110dbe1316cf8762a191b916747",
        "docs/patches/oci-sdk-v65.126.0-context/provenance.json",
        "917bb93c8c43242d0502bef3dbd541428861ade0bd5dde0929ff4da380c9a67d",
    ),
)


PACKAGE_BASELINES = (
    (
        "golang.org/x/crypto", "v0.58.0", "third_party/acme",
        "8fdf07b3114278fb3b78c1cf1814e08bd851eb4c",
        "third_party/acme/README.terrascale.md",
        "025180f8f152a703435a2092891588809e513a40be1d8a2f1d7ffc86fcfdfeeb",
    ),
)


def run(root, *args):
    if args[0] == "go":
        args = (GO, *args[1:])
    return subprocess.check_output(args, cwd=root)


def source_digest(root, directory):
    names = run(root, "git", "ls-files", "-z", "--", directory).split(b"\0")[:-1]
    if not names or not any(name.endswith(b".go") for name in names):
        raise ValueError(f"no tracked Go source: {directory}")
    if run(root, "git", "ls-files", "--others", "--", directory):
        raise ValueError(f"untracked replacement files: {directory}")
    digest = hashlib.sha256()
    for name in names:
        path = root / name.decode()
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"replacement path escapes reviewed sources: {path}")
        digest.update(name + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def qualify(root, baseline):
    module, version, directory, commit, record, digest = baseline
    manifest = json.loads(run(root, "go", "mod", "edit", "-json"))
    requires = [r for r in manifest["Require"] if r["Path"] == module]
    replacements = [r for r in manifest["Replace"] if r["Old"]["Path"] == module]
    if len(requires) != 1 or requires[0]["Version"] != version:
        raise ValueError(f"root requirement differs from reviewed baseline: {module}")
    if len(replacements) != 1 or replacements[0] != {
        "Old": {"Path": module}, "New": {"Path": "./" + directory}
    }:
        raise ValueError(f"root replacement differs from reviewed path: {module}")
    local = json.loads(run(root / directory, "go", "mod", "edit", "-json"))
    if local["Module"]["Path"] != module:
        raise ValueError(f"replacement module identity differs: {directory}")
    selected = json.loads(run(root, "go", "list", "-m", "-json", module))
    if selected["Version"] != version or selected["Replace"]["Path"] != "./" + directory:
        raise ValueError(f"selected module differs from reviewed baseline: {module}")
    provenance = (root / record).read_text()
    if not all(value in provenance for value in (module, version, commit)):
        raise ValueError(f"upstream version/commit missing from provenance: {record}")
    if source_digest(root, directory) != digest:
        raise ValueError(f"replacement sources changed; review and update provenance digest: {directory}")
    print(json.dumps({"module": module, "version": version, "upstream_commit": commit,
                      "replacement": directory, "source_sha256": digest}), flush=True)


def qualify_package(root, baseline):
    module, version, directory, commit, record, digest = baseline
    selected = json.loads(run(root, "go", "list", "-m", "-json", module))
    if selected["Version"] != version or "Replace" in selected:
        raise ValueError(f"upstream package baseline differs: {module}")
    provenance = (root / record).read_text()
    if not all(value in provenance for value in (module, version, commit)):
        raise ValueError(f"upstream version/commit missing from provenance: {record}")
    if source_digest(root, directory) != digest:
        raise ValueError(f"vendored package sources changed; review and update provenance digest: {directory}")
    print(json.dumps({"module": module, "version": version, "upstream_commit": commit,
                      "package_copy": directory, "source_sha256": digest}), flush=True)


def affects_package(finding, package):
    affected = finding.get("affected")
    if not isinstance(affected, list) or not affected:
        return True
    for entry in affected:
        imports = entry.get("ecosystem_specific", {}).get("imports")
        if not isinstance(imports, list) or not imports:
            return True
        for imported in imports:
            path = imported.get("path")
            if not isinstance(path, str) or path == package:
                return True
    return False


def audit(module, version, package=None):
    query = {"package": {"ecosystem": "Go", "name": module}, "version": version}
    print(json.dumps({"osv_query": query}), flush=True)
    request = urllib.request.Request(
        "https://api.osv.dev/v1/query", data=json.dumps(query).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode()
    # Keep the complete public response visible, even for malformed responses.
    print(raw, flush=True)
    result = json.loads(raw)
    if not isinstance(result, dict) or set(result) - {"vulns"}:
        raise ValueError("malformed OSV response")
    findings = result.get("vulns", [])
    if not isinstance(findings, list):
        raise TypeError("malformed OSV findings")
    if package:
        for finding in findings:
            if not affects_package(finding, package):
                print(json.dumps({"advisory": finding["id"], "copied_package": package,
                                  "scope": "affected imports are outside the copied package"}), flush=True)
        findings = [finding for finding in findings if affects_package(finding, package)]
    if findings:
        raise ValueError(f"upstream advisory findings: {module}@{version}; see complete response above")


def main():
    root = ROOT
    manifest = json.loads(run(root, "go", "mod", "edit", "-json"))
    local = {r["Old"]["Path"] for r in manifest["Replace"] if not r["New"].get("Version")}
    if local != {baseline[0] for baseline in BASELINES}:
        raise ValueError("local replacement inventory differs from reviewed baselines")
    # Validate every binding before making any clean upstream-advisory claim.
    for baseline in BASELINES:
        qualify(root, baseline)
    for baseline in PACKAGE_BASELINES:
        qualify_package(root, baseline)
    failures = []
    inventories = [(baseline, None) for baseline in BASELINES]
    inventories += [(baseline, baseline[0] + "/acme") for baseline in PACKAGE_BASELINES]
    for (module, version, *_), package in inventories:
        try:
            audit(module, version, package)
        except (OSError, ValueError, TypeError, http.client.HTTPException) as error:
            failures.append(f"{module}: {error}")
    if failures:
        raise ValueError("\n".join(failures))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(f"replacement advisory qualification failed: {error}")
