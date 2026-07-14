# Phase 1 compute survival-generation anti-rollback handoff

- Base: `2418569`
- Scope: pure compute survival request/decision, tests, and this handoff
- External I/O or mutation: none

## Defect and correction

Survival validation compared the required bundle with its observed evidence but
had no authoritative current accepted generation. After generation 3 had been
accepted, a fully internally consistent generation-2 bundle, authority proof,
and disconnected replacement target could still emit
`AuthorizeSurvivalIntent` while the older bundle's freshness window remained
open.

`SurvivalRequest` now requires a positive `CurrentAcceptedGeneration`. This
decision consumes an already accepted bundle; it does not advance acceptance.
The required bundle generation must therefore equal that high-water exactly:

- a lower required generation holds with `EvidenceStale`;
- a higher required generation holds with `EvidenceMismatch`, because it is
  being presented as accepted before the authoritative accepted high-water;
- exact equality preserves readiness and disconnected replacement behavior.

Required/observed bundle equivalence is checked before high-water
classification. Once the exact subject is established, generation comparison
precedes completeness, expiry, authority, and replacement-target gates. Thus a
rebound observation remains `EvidenceMismatch`, while internally exact stale
material cannot select a later mutation path by also changing a usability
flag.

The change adds no error, action, trace, intent, factory, provider operation,
or acceptance path. `SurvivalRequest` grows from seven to eight public
properties. Both survival intents already retain the exact bundle, whose
generation must equal the new high-water, so their public shapes are unchanged.

## Regression evidence

- The original executable regression was red: 533 focused tests passed and the
  generation-2 replay test failed because it emitted authorization instead of
  `EvidenceStale`.
- Focused post-fix validation passes 536/536.
- Targeted tests pin zero/negative high-waters as `InvalidInput`, equality for
  readiness and disconnected authorization, lower/higher rejection, and exact
  precedence against rebound, incomplete, expired, and non-authoritative
  evidence.
- A 1,000-case independent lower/equal/higher oracle checks exact outcomes,
  prohibits either survival acceptance intent on rejection, and replays each
  decision across `tr-TR` and `ar-SA` cultures.
- Reflection pins eight `SurvivalRequest` properties and all 16 existing
  compute intent shapes.

## Validation boundary

Release build passed with zero warnings and errors before the focused suite.
The integration handoff records the final post-rebase locked restore, all-suite
result, and diff check.

This is pure decision-core evidence only. It makes no disconnected lab,
provider, OCI, Pulumi, VM, destructive replacement, ARM64, L0C, or deployment
acceptance claim.
