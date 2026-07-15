# Phase 1 mutation readiness audit

- Audit date: 2026-07-13
- Status: blocked; mutation tool selection unresolved
- Execution: no mutation tool installed, restored, downloaded, or run
- Result: no mutation score, mutant count, threshold, safety closure, L0, or
  deployment-evidence claim

## Finding

The checked-in Phase 0 supply-chain audit contains `dotnet-stryker` 4.16.0 as
`PIN-DOTNET-STRYKER`, but its state is `candidate-unselected`. The audit also
states that TUnit/.NET 10 compatibility, stable mutation accounting,
safety-mutant policy, locked NuGet content hash, and internal mirroring are
unproven. `Directory.Packages.props` does not select a mutation tool. Therefore
this work does not add or invoke a package and does not manufacture a score.

The owner/toolchain steward must select the mutation engine and exact version.
That decision must also approve a locked content hash/internal mirror and the
stable denominator/report-normalization contract. Candidate metadata is not a
selection.

## Fail-closed foundation

The machine-readable policy inventories all five current production projects.
Contracts, ControlPlane, Protocol, and Scheduler are always mutation-required.
The baseline executable has one content-addressed exclusion for its exact
trivial `Program.cs`, backed by a checked-in proof. Adding or changing source in
that composition root invalidates the proof.

Exclusions can never name state transitions, validators, authority, fencing,
deletion, retry, compensation, or adapter result classification. The allowed
set is limited to generated code, immutable DTO property accessors, and proven
trivial composition-root wiring. The validator rejects project inventory
drift, unknown/duplicate schema fields, unsafe/symlink paths, stale policy or
source hashes, a weakened 85% threshold, any safety survivor, and all premature
execution or acceptance claims.

The current report is explicitly `blocked-unselected-tool`: execution fields
are null and claims are false. It expires after 30 days so unresolved readiness
must be reviewed rather than silently treated as current.

## Verification and non-claims

On 2026-07-13 the validator passed, and eleven unit tests plus eighteen named
negative fixtures passed. These checks validate policy/report structure only.
They do not validate dotnet-stryker, run mutants, establish a mutation score,
satisfy the full correctness-critical solution, mint L0/L0C or CI evidence, or
grant deployment authority.
