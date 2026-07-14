# Phase 1 NATS policy accepted-observation audit 3 handoff

## Proven defect and resolution

The pure replacement policy accepted distinct operations while collapsing their initial or repeated observation
commands to the same executable value whenever operation ID, cluster, and observation bounds matched. In
particular, changing only the accepted authority epoch produced an equal `ObserveClusterIntent`, erasing the
provenance needed to distinguish the authorized operation.

`ObserveClusterIntent` now retains the exact accepted `ReplacementOperation` under `Replacement`. Its existing
operation-ID, cluster, and sequence-bound properties are derived from that retained value, so the prior read surface
continues to expose the same values. Both policy construction sites pass the accepted operation directly. No
validation, numeric comparison, error/trace catalog, decision precedence, or replacement progression changed.

## Deterministic evidence

- The focused regression pins exact reference retention and all sixteen replacement-operation fields.
- Sixteen independently accepted substitutions prove output and canonical-fingerprint inequality, including the
  original authority-epoch substitution.
- Identical replay remains equal and its complete fingerprint is invariant under Turkish and Arabic cultures.
- The surviving active-attachment re-observation branch retains the same exact operation under reversed peer and
  replica evidence order.
- The 1,000-case replacement property oracle now requires exact replacement retention, and the embedded Messaging
  corpus fingerprint serializes every retained operation field.
- Existing reflection coverage continues to prove that intents and decisions expose no public constructors,
  setters, deconstructors, or alternate public factories.

## Scope boundary and nonclaims

This binds accepted replacement-operation provenance only. The intent does not retain the cluster observation,
surviving-store proof, rejected evidence, response authenticity, or the complete selection/authorization context.
It performs no NATS, network, process, credential, filesystem-administration, VM, cloud, or deployment action.

The real-NATS L0C foundation remains an intentionally stale, zero-result plan. This audit neither executed it nor
proves NATS/JetStream persistence, membership administration, response authenticity, R3 durability, gateway
isolation, snapshot recovery, compatibility, ARM64 readiness, or production qualification.

## Validation

- Offline Release build with existing locked restore artifacts: 0 warnings, 0 errors.
- Focused observation provenance, re-observation permutation, 1,000-case replacement property, embedded replay
  corpus, and construction-closure tests: passed.
- `git diff --check`: passed.
