# Phase 1 mutation-evidence foundation handoff

## Delivered

- Strict machine-readable inventory for all five current production projects.
  The four correctness-critical library projects are mandatory. The only
  exclusion is the exact Phase 0 composition-root source, bound by path and
  SHA-256 to a checked-in proof.
- Closed allowed and forbidden exclusion catalogs. State transitions,
  validators, authority, fencing, deletion, retry, compensation, and adapter
  result classification can never be excluded.
- A zero-claim report cross-checked against the existing supply-chain audit,
  which identifies dotnet-stryker 4.16.0 only as an unselected candidate.
  Every result is null and every acceptance claim is false.
- A standard-library validator that rejects schema drift, duplicate keys,
  unsafe/symlink paths, production-project drift, stale policy/exclusion
  digests, expiration, weakened thresholds, safety survivors, and premature
  selection/execution/acceptance claims.
- Eighteen data-driven negative fixtures plus direct tests for stale reports,
  recursive project/source drift, duplicate JSON keys, unknown fields,
  noncanonical/overlong paths, and symlinked path components.

## Required decision

The owner/toolchain steward must select the mutation tool and exact version.
Before execution is wired, the selection also requires a locked content hash,
internal mirror, .NET 10/TUnit compatibility proof, stable mutant denominator,
deterministic normalized report, and reviewed safety-mutant classification.
The existing candidate record is not that decision.

## Verification

- `dotnet run --project tools/TerraScale.Orchestrator.Tooling -- mutation-evidence --as-of 2026-07-13` —
  passed with the explicit unresolved/zero-claim result.
- `dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test` — passed
  (11/11 tests; 18 named negative fixtures).
- All three JSON documents passed the C# `json-format` command.

## Non-claims

No mutation package was selected, installed, restored, downloaded, or run. No
mutants were generated. This package claims no mutation score, denominator,
safety-invariant closure, L0/L0C completion, full correctness-critical run,
CI credential gate, or deployment evidence. It changes no production code,
central package pin, solution file, or sibling repository.
