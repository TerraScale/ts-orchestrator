# Phase 0 ARM64 runtime readiness handoff

- Branch: `docs/phase0-arm64-runtime-readiness`
- Work package: `docs/work-packages/phase0-arm64-runtime-readiness.md`
- Scope changed: `docs/audits/runtime/**`, `testlab/pins/arm64-runtime-*.json`, `tools/phase0/runtime-readiness/**`, and this handoff
- External/destructive actions: none

## Result

The readiness record compares Oracle Linux 9 and Ubuntu 24.04 LTS standard OCI
aarch64 platform-image families without selecting either. Ubuntu 26.04 LTS is a
watch item because Canonical documents ARM64 LTS support but the current cited
OCI platform-image catalog does not list it.

ext4 and XFS remain equally unqualified candidates. systemd remains coupled to
the eventual host image; upstream and distribution containerd/runc tracks and
upstream BuildKit 0.30 remain candidates with exact builds unset. No LTS claim is
made for BuildKit.

The current machine was inspected read-only as NixOS x86_64. Its kernel, glibc,
PID 1, systemd tools, root filesystem, and tool presence are recorded only as
local observations with no qualification layer. No ARM64 execution occurred.

The audit defines fail-closed L1R and L4 command contracts, required immutable
inputs, scenario matrices, evidence bindings, failure criteria, and cleanup
proof. Both layers require OL9/ext4, OL9/XFS, Ubuntu/ext4, and Ubuntu/XFS until a
later explicit coupled selection deliberately narrows the matrix. The
qualification harness is intentionally recorded as missing rather than
represented as runnable.

## Validation

```text
python3 tools/phase0/runtime-readiness/validate_runtime_readiness.py
python3 -m unittest discover -s tools/phase0/runtime-readiness -p 'test_*.py' -v
python3 -m json.tool testlab/pins/arm64-runtime-candidates.json
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
dotnet test TerraScale.Orchestrator.slnx --no-build --no-restore -- --disable-logo --no-progress
python3 docs/adr/validate_readiness.py
python3 -m unittest discover -s docs/adr/tests -v
git diff --check
```

The adversarial overlays prove rejection of an accepted/selected proposal, an
ARM64-qualified local-observation masquerade, a missing filesystem comparison,
an incomplete host-by-filesystem interaction matrix, and an unknown evidence
source.

## Remaining gates

1. Owner-approved host image and filesystem ADR after comparable evidence; this package cannot select them.
2. Immutable per-region image IDs, exact package manifests, mirror/signature policy, and runtime pairing/pins.
3. Approved storage SLO, memory/runtime budget, cost/TTL, and destructive scratch/cloud authorization.
4. Implemented qualification harness and valid exact-tree L0/L0C pre-deployment attestation.
5. Real aarch64 systemd-as-PID-1 L1R for all four host-by-filesystem combinations.
6. Explicitly authorized disposable OCI A1 L4 for all four combinations, runtime boundaries, performance, replacement, and cleanup.

No image was downloaded, package installed, service/VM started, filesystem
changed, cloud API called, or sibling/shared file edited.
