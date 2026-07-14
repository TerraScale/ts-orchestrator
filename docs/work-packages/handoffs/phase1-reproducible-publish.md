# Phase 1 reproducible dual-architecture publish handoff

## Result

The reviewed .NET publish verifier completed a real double publish for `linux-x64` and `linux-arm64` from two byte-identical isolated input copies. Both per-RID repeat artifacts were byte-identical, and the architecture artifact digests were distinct.

This is cross-publish evidence only. The ARM64 artifact was not executed. This handoff does not provide ARM64 runtime or L4 qualification, signing, release approval, or pre-deployment attestation.

## Pre-commit worktree observation

- Captured diagnostic counts: stdout `2496` characters; stderr `0` characters
- `linux-x64`: length `72410776`; SHA-256 `251dae53e0464d8f46bafa296a3d0e22403dd8d01aef37d7b8650aa2a37e7c88`; repeat SHA-256 `251dae53e0464d8f46bafa296a3d0e22403dd8d01aef37d7b8650aa2a37e7c88`
- `linux-arm64`: length `81024186`; SHA-256 `ca924e17aa9d1af613eff01580c53c1305a3e88f7ddc1a526564109c1bd80892`; repeat SHA-256 `ca924e17aa9d1af613eff01580c53c1305a3e88f7ddc1a526564109c1bd80892`

These values came from a successful real double publish in the uncommitted implementation worktree. The verifier checked each single-file payload as a 64-bit little-endian ELF executable/shared-object with the expected machine value (`EM_X86_64` or `EM_AARCH64`) and at least one Unix execute bit. No produced binary was normalized or rewritten.

This observation is not evidence for the final commit: recording results in this handoff changes the input tree, so embedding a purported final-tree digest would be self-referential and stale. CI or the release operator must run the command below cold on the exact committed tree and retain the externally reported canonical input digest and artifacts as the final evidence.

## Reproduction command

Run after a successful locked restore of the source tree. Output roots must not exist or must be empty, and must be outside the source tree.

```bash
set -euo pipefail
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build tools/reproducible-publish/TerraScale.ReproduciblePublish.csproj --no-restore --nologo

tree_digest=$(dotnet tools/reproducible-publish/bin/Debug/net10.0/terrascale-reproducible-publish.dll --compute-input-digest "$PWD")
base=$(mktemp -d /tmp/terrascale-repro-publish.XXXXXX)

dotnet tools/reproducible-publish/bin/Debug/net10.0/terrascale-reproducible-publish.dll \
  --source-root "$PWD" \
  --first-output-root "$base/first" \
  --repeat-output-root "$base/repeat" \
  --tree-digest "$tree_digest" \
  --configuration Release \
  --rid linux-x64 \
  --rid linux-arm64 \
  --timeout-seconds 900 \
  --diagnostic-character-limit 200000 \
  --output-item-limit 100 \
  --source-date-epoch 1700000000
```

The digest mode reads the source tree with the same canonical path/content/mode algorithm used for each isolated copy. A publish succeeds only when both copied-tree digests equal each other and the supplied digest, preventing substitution of an unrelated claimed identity.

The tool itself performs no restore, network, Git, signing, credential, deployment, or source-tree mutation. It invokes the fixed `dotnet publish` argument list with `--no-restore`, clears the child environment and supplies only reviewed entries, captures only bounded diagnostic counts, and emits a canonical result to stdout. The shell shown above is caller-side setup and evidence capture; it is not executed by the tool.

## Remaining external evidence

- Execute and qualify the ARM64 artifact on the owner-approved ARM64 host image/kernel/glibc combination.
- Complete L4/runtime qualification.
- Apply the owner-controlled signing profile and release approval.
- Produce the required pre-deployment attestation.
