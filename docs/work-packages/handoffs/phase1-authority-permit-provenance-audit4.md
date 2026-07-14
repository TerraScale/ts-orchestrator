# Phase 1 authority mutation-permit provenance audit 4 handoff

## Change summary

- Started from exact central commit `6fb86b534de7c06990f9017fb7645225a552f358` in an isolated worktree.
- Preserved two pre-fix executable counterexamples: different evaluation request identities, and the same request/evidence across different accepted command types.
- Retained the exact accepted `AuthorityCommand` on `MutationAuthorityPermit` and derived all permit projections from it.
- Restricted permit construction to the three successful permit-minting command shapes and made the engine helper command-only.
- Bound the canonical permit/decision digest to command type and every nested command field.
- Extended construction/clone closure, 1,000-case culture replay, and the strict content-addressed authority corpus.

## Review focus

Review the single-source boundary in `MutationAuthorityPermit`, all three `CreatePermit(command)` call sites, and the distinct canonical tags in `AuthorityDigest`. The intended invariant is: a non-null permit retains the exact command object that the pure engine accepted; rejected or held commands never return one.

The public record clone remains an immutable-copy route and deliberately preserves the same authorizing-command reference. No public constructor, setter, deconstructor, or independent factory was introduced.

## Verification and nonclaims

After rebasing onto central `1f73564`, the Release warning-as-error solution build passed with zero warnings/errors. All five test executables passed 870/870: ControlPlane 643, Contract 29, Model 44, Protocol 70, and Scheduler 84. This work performs no external effects and makes no claim about authenticated transport, NATS/KV linearization, adapter correlation, provider execution, or deploy readiness.
