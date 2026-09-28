# TerraBase source identity for CI #1004

**Disposition: accepted for the current signed artifact claim.** The
independent admission preflight accepted the source-tree derivation on
2026-09-28 after reproducing it and passing the malformed-run and existing-
output adversarial checks. This accepts the meaning of the existing
`ArtifactRecord.Source.TreeDigest` value; it does not change that record's
schema or its signing behavior.

## Pinned inputs and result

| Input | Value |
| --- | --- |
| Repository | `https://git.terrascale.tech/TerraScale/TerraBase` |
| TerraBase commit | `1909dcd36c1f0e09189756d976891127312a2d19` |
| TerraBase Git tree | `9c3855d1bcc53e45882a70da1e5beb94d0025eff` |
| Turso gitlink commit | `64b8ef5742fc18937f9c89806c81e3f6475dc7a3` |
| Prepared Turso Git tree | `1f89fbacaf2214005ecebf0d98a40c15d01ae5eb` |
| CI qualification JSON SHA-256 | `8ae3133ab66b6b300e5ad2e34ca42a11b61cef580657715480e68362f4bc7b09` |
| CI Fast run | run ID `11644`, run number `1004`, success |
| ARM64 release artifact SHA-256 | `bd940fe8055c61ea076e584b7d221c0f6b2c7dc1fee02232a82c476cb34ba81c` |
| Accepted `TreeDigest` | `ab867f7f89131ef61ca2f9050840ca6da184b4239c876e022d2cdd5d9e264bc7` |

The two ordered patches at the pinned TerraBase commit,
`patches/turso/0001-complete-log-validation.patch` and
`patches/turso/0002-rust-1.98-warnings.patch`, applied to the Turso gitlink
produce the pinned prepared Turso tree. The qualification's `Cargo.lock`
SHA-256 is `d86e80530dba0864fbf22e3557407adb7e2a8253d98658a1b29bb452b49deec0`.
The qualification records the ARM64 artifact as 45,845,688 bytes; the local
artifact bytes matched both that size and the listed SHA-256.

## Digest definition

The accepted v1 script is
[`terrabase-source-digest-v1.py`](../../scripts/ci/terrabase-source-digest-v1.py),
SHA-256 `bc2c36aa39e4d3e1f969569bc5d60a1628e018ac1203e3d73580e29420a4a3dd`.
The immutable result is
[`terrabase-source-digest-ci1004-v1.json`](terrabase-source-digest-ci1004-v1.json),
SHA-256 `52badd76acb8fe4b896a3153b4bfb4cf289f82ec43e1eebf4a18f3978f138a93`.
The receipt was generated before the independent policy verdict, so its
`status` field retains the historical value
`candidate_pending_independent_policy_review`; the verdict above records the
subsequent disposition. Its digest inputs and output were not rewritten.

The script hashes this byte stream:

1. ASCII `terrascale.terrabase.source-tree-sha256.v1` and NUL.
2. The HTTPS repository URL, TerraBase commit, TerraBase superproject tree,
   Turso gitlink commit, and prepared Turso tree, in that order. Each UTF-8
   value is prefixed with a four-byte unsigned big-endian length.
3. All tracked TerraBase blobs except the Turso gitlink, plus every tracked
   blob below `crates/turso/` in the prepared Turso tree, sorted by raw Git
   path bytes. Each record contains `F` and NUL, length-prefixed Git mode,
   length-prefixed path, and the raw 32-byte SHA-256 of the blob content.
   Symlinks are represented by their Git blob target bytes.
4. ASCII `END` and NUL, then the record count as an eight-byte unsigned
   big-endian integer.

The resulting stream binds 259 superproject blobs and 4,116 prepared Turso
blobs. The Git SHA-1 tree identifiers are also bound as metadata; the digest
itself covers the exact tracked file modes and bytes. It does not include
untracked files, host toolchains, dependency registries, or prove that the
qualified binary is reproducible from those files.

## Reproduction

Run this with a clean trusted TerraBase clone that contains the pinned Git
objects, the exact qualification JSON, and the downloaded ARM64 artifact.
Use a fresh scratch directory and a new output path; the script refuses to
overwrite its output.

```bash
set -euo pipefail
TERRABASE_REPO=/path/to/TerraBase
QUALIFICATION=/path/to/qualification.json
SERVER=/path/to/tb-server-linux-arm64
TB_COMMIT=1909dcd36c1f0e09189756d976891127312a2d19
TURSO_COMMIT=64b8ef5742fc18937f9c89806c81e3f6475dc7a3
PREPARED_TREE=1f89fbacaf2214005ecebf0d98a40c15d01ae5eb
SCRATCH=$(mktemp -d /tmp/terrabase-source-identity.XXXXXXXX)

git clone --shared --no-checkout "$TERRABASE_REPO/crates/turso" "$SCRATCH/turso"
git -C "$SCRATCH/turso" checkout --detach "$TURSO_COMMIT"
git -C "$TERRABASE_REPO" show "$TB_COMMIT:patches/turso/0001-complete-log-validation.patch" > "$SCRATCH/0001.patch"
git -C "$TERRABASE_REPO" show "$TB_COMMIT:patches/turso/0002-rust-1.98-warnings.patch" > "$SCRATCH/0002.patch"
git -C "$SCRATCH/turso" apply "$SCRATCH/0001.patch"
git -C "$SCRATCH/turso" apply "$SCRATCH/0002.patch"
git -C "$SCRATCH/turso" add -A
test "$(git -C "$SCRATCH/turso" write-tree)" = "$PREPARED_TREE"
python3 scripts/ci/terrabase-source-digest-v1.py \
  --terrabase-repo "$TERRABASE_REPO" \
  --prepared-turso-repo "$SCRATCH/turso" \
  --qualification "$QUALIFICATION" \
  --server "$SERVER" \
  --out "$SCRATCH/source-digest.json"
```

The expected printed `TreeDigest` is the value in the table above. Independent
preflight reproduced the same receipt bytes with a corrected second
reproducer. It also verified, under `python3 -O`, that changing the
qualification run ID to `999999` is rejected and that an existing output file
is not replaced. The source and qualification inputs must still be obtained
from the trusted CI release record; the local script validates their pinned
content but does not authenticate how they were downloaded.

## Signing checklist

Before an operator signs and admits an artifact using this `TreeDigest`:

1. Confirm the trusted CI #1004 qualification record names the pinned
   repository commit/tree, Turso gitlink/prepared tree, Cargo lock digest,
   successful Fast run, target, artifact size, and artifact SHA-256 above.
2. Reproduce the ordered Turso patch preparation from the pinned commit and
   run the retained script against the exact qualification JSON and artifact
   bytes. Confirm the prepared tree and output `TreeDigest` match this record.
3. Confirm the artifact being uploaded has the qualified ARM64 artifact SHA
   and size. The Go artifact uploader computes the content digest from the
   bytes it reads; this source identity does not substitute for that check.
4. Use the existing artifact claim fields: the TerraBase HTTPS repository,
   pinned commit, accepted source `TreeDigest`, role/environment, and exact
   binary bytes. The configured signer then signs the existing
   `ArtifactRecord`; no CI qualification or build-profile fields are implied
   by this derivation.
5. Treat a missing, mismatched, or untrusted qualification, source input,
   prepared tree, or artifact readback as a hold. Do not infer source identity
   from the Git commit alone.

This procedure gives the current source claim a reproducible byte-level
meaning while leaving the limits of the signed artifact contract explicit.
It does not establish a native ARM64 verifier run, managed guest launch,
prepared managed material, or runtime serving proof.
