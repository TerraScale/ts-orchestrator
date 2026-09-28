#!/usr/bin/env python3
"""Reproduce a candidate SHA-256 over the qualified TerraBase source tree.

The source commit is read from Git objects, never from the dirty worktree.
The Turso repository argument must contain the prepared tree named by the
qualification receipt; reproduce it in a disposable clone from the pinned
gitlink and ordered patches/turso files before running this script.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


DOMAIN = b"terrascale.terrabase.source-tree-sha256.v1\0"
REPOSITORY = b"https://git.terrascale.tech/TerraScale/TerraBase"
QUALIFICATION_SHA256 = "8ae3133ab66b6b300e5ad2e34ca42a11b61cef580657715480e68362f4bc7b09"
SERVER_SHA256 = "bd940fe8055c61ea076e584b7d221c0f6b2c7dc1fee02232a82c476cb34ba81c"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def fields(repo, tree):
    entries = []
    for row in git(repo, "ls-tree", "-r", "-z", tree).split(b"\0"):
        if not row:
            continue
        head, path = row.split(b"\t", 1)
        mode, kind, oid = head.split(b" ")
        entries.append((mode, kind, oid, path))
    return entries


def content_hashes(repo, entries):
    command = ["git", "-C", str(repo), "cat-file", "--batch"]
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        require(proc.stdin is not None and proc.stdout is not None, "Git batch pipes unavailable")
        for mode, kind, oid, path in entries:
            if kind != b"blob":
                raise ValueError(f"unexpected non-blob at {path!r}: {kind!r}")
            proc.stdin.write(oid + b"\n")
            proc.stdin.flush()
            header = proc.stdout.readline().rstrip(b"\n").split(b" ")
            if len(header) != 3 or header[0] != oid or header[1] != b"blob":
                raise ValueError(f"invalid Git blob response for {path!r}")
            remaining = int(header[2])
            leaf = hashlib.sha256()
            while remaining:
                chunk = proc.stdout.read(min(remaining, 1 << 20))
                if not chunk:
                    raise ValueError(f"truncated Git blob for {path!r}")
                leaf.update(chunk)
                remaining -= len(chunk)
            if proc.stdout.read(1) != b"\n":
                raise ValueError(f"invalid Git blob terminator for {path!r}")
            yield mode, path, leaf.digest()
        proc.stdin.close()
        if proc.wait() != 0:
            raise ValueError("Git batch blob reader failed")


def framed(hasher, value):
    hasher.update(len(value).to_bytes(4, "big"))
    hasher.update(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--terrabase-repo", type=Path, required=True)
    parser.add_argument("--prepared-turso-repo", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    qualification_bytes = args.qualification.read_bytes()
    require(hashlib.sha256(qualification_bytes).hexdigest() == QUALIFICATION_SHA256,
            "qualification bytes differ from CI #1004 release receipt")
    qualification = json.loads(qualification_bytes)
    require(qualification["schema"] == "terrascale.terrabase.qualification.v2", "qualification schema mismatch")
    require(qualification["repository"] == "TerraScale/TerraBase", "qualification repository mismatch")
    require(qualification["source_revision"] == "1909dcd36c1f0e09189756d976891127312a2d19",
            "qualification source revision mismatch")
    require(qualification["source_tree"] == "9c3855d1bcc53e45882a70da1e5beb94d0025eff",
            "qualification source tree mismatch")
    require(qualification["turso_revision"] == "64b8ef5742fc18937f9c89806c81e3f6475dc7a3",
            "qualification Turso gitlink mismatch")
    require(qualification["turso_source_tree"] == "1f89fbacaf2214005ecebf0d98a40c15d01ae5eb",
            "qualification prepared Turso tree mismatch")
    require(qualification["verification"] == {
        "workflow": "fast.yml", "job": "fast", "run_id": 11644,
        "run_number": 1004, "conclusion": "success",
    }, "qualification Fast run mismatch")
    source = qualification["source_revision"]
    tree = git(args.terrabase_repo, "rev-parse", source + "^{tree}").strip().decode()
    require(tree == qualification["source_tree"], "local source tree differs from qualification")
    root_entries = fields(args.terrabase_repo, source)
    gitlinks = [(path, oid.decode()) for _, kind, oid, path in root_entries if kind == b"commit"]
    require(gitlinks == [(b"crates/turso", qualification["turso_revision"])],
            "source gitlinks differ from qualified Turso input")
    require(bool(git(args.terrabase_repo, "show", source + ":Cargo.lock")), "Cargo.lock missing")
    lock_sha = hashlib.sha256(git(args.terrabase_repo, "show", source + ":Cargo.lock")).hexdigest()
    require(lock_sha == qualification["cargo_lock_sha256"], "Cargo.lock differs from qualification")

    prepared = qualification["turso_source_tree"]
    require(git(args.prepared_turso_repo, "cat-file", "-t", prepared).strip() == b"tree",
            "prepared Turso tree object is missing")
    turso_entries = fields(args.prepared_turso_repo, prepared)
    require(all(kind == b"blob" for _, kind, _, _ in turso_entries), "prepared Turso has nested gitlink")

    server_records = [a for a in qualification["artifacts"] if a["name"] == "tb-server-linux-arm64"]
    require(len(server_records) == 1, "ARM64 server artifact is not unique")
    server_record = server_records[0]
    require(server_record["target"] == "aarch64-unknown-linux-musl" and
            server_record["bytes"] == 45845688 and server_record["sha256"] == SERVER_SHA256,
            "qualified ARM64 artifact target, size or digest mismatch")
    server_bytes = args.server.read_bytes()
    require(len(server_bytes) == server_record["bytes"], "local ARM64 artifact size mismatch")
    require(hashlib.sha256(server_bytes).hexdigest() == server_record["sha256"],
            "local ARM64 artifact digest mismatch")

    records = list(content_hashes(args.terrabase_repo,
                                   [e for e in root_entries if e[1] == b"blob"]))
    records += [(mode, b"crates/turso/" + path, digest)
                for mode, path, digest in content_hashes(args.prepared_turso_repo, turso_entries)]
    records.sort(key=lambda record: record[1])
    require(len(records) == len(set(path for _, path, _ in records)), "source paths are not unique")

    digest = hashlib.sha256()
    digest.update(DOMAIN)
    for value in (REPOSITORY, source.encode(), tree.encode(),
                  qualification["turso_revision"].encode(), prepared.encode()):
        framed(digest, value)
    for mode, path, leaf in records:
        digest.update(b"F\0")
        framed(digest, mode)
        framed(digest, path)
        digest.update(leaf)
    digest.update(b"END\0")
    digest.update(len(records).to_bytes(8, "big"))

    receipt = {
        "schema": "terrascale.terrabase.source-digest-candidate.v1",
        "status": "candidate_pending_independent_policy_review",
        "algorithm": "SHA-256 of DOMAIN; length-prefixed HTTPS repository, commit, Git tree, Turso gitlink and prepared tree; then Git-path-sorted mode/path and SHA-256 of every tracked blob; END and 8-byte big-endian file count",
        "domain_hex": DOMAIN.hex(),
        "repository": REPOSITORY.decode(),
        "source_revision": source,
        "source_tree_git_sha1": tree,
        "turso_gitlink_revision": qualification["turso_revision"],
        "turso_prepared_tree_git_sha1": prepared,
        "cargo_lock_sha256": lock_sha,
        "qualification_sha256": hashlib.sha256(qualification_bytes).hexdigest(),
        "server_linux_arm64_sha256": server_record["sha256"],
        "superproject_blob_count": len(root_entries) - len(gitlinks),
        "prepared_turso_blob_count": len(turso_entries),
        "total_blob_count": len(records),
        "source_digest_sha256": digest.hexdigest(),
    }
    wire = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(prefix=".source-digest-", dir=args.out.parent, delete=False) as output:
        staged = Path(output.name)
        output.write(wire)
        output.flush()
        os.fsync(output.fileno())
    try:
        os.link(staged, args.out)
    finally:
        staged.unlink()
    print(receipt["source_digest_sha256"])


if __name__ == "__main__":
    main()
