# Phase 1 Messaging/NATS surviving-store evidence audit handoff

## Scope and baseline

- Audited the pure Messaging/NATS replacement policy on final integration baseline `ec0dc50` after rebasing
  the initially proven `369a3a1` counterexample onto the steward's current tree.
- Changed only Messaging replacement contracts and decisions, their dedicated tests, and this handoff.
- No NATS process, socket, filesystem, VM, cloud API, or other external system was used.

## Proven defect

`ReplacementOperation` bound the failed server and peer but not the store identity or its accepted generation.
An otherwise exact surviving-store observation could therefore substitute an unrelated store owned by the same
server at generation 1 and receive a `ReattachSurvivingStoreIntent` for that substituted store. The retained
pre-fix regression failed because the decision contained no error and authorized the reattachment.

## Resolution

- Every replacement operation now carries the exact failed store and positive current accepted store generation.
- The proposed and persisted operation equality therefore binds both fields before any mutation output.
- A surviving proof for another store is conflicting evidence.
- A proof below the accepted store generation is stale; a proof above it is future evidence. This evaluator does
  not advance store generations, so only exact equality can reattach.
- Validation precedence is structural and scope consistency, store identity, trust-plane isolation, any lower
  membership/ownership/store dimension, any higher dimension, then exact acceptance.
- Existing error and trace enums were not changed.

## Deterministic evidence

- Unit regressions pin arbitrary-store substitution, lower and higher store generations, mixed lower/future
  precedence, malformed operation store fields, persisted-operation mismatch by each added field, and exact
  configure and reattach output fields.
- A 1,000-case property matrix covers exact, different-store, lower-generation, higher-generation, and mixed
  lower/future proofs under distinct cultures and reversed evidence order.
- The Messaging replay fingerprint now includes every public field of `ReattachSurvivingStoreIntent`, including
  store generation and observed membership sequence, so distinct accepted outputs cannot collide silently.

## Validation boundary

This package proves pure L0 decision behavior only. It does not qualify NATS or JetStream persistence, peer
administration, store attachment, disk synchronization, or crash recovery. Real NATS L0C and later L2S/L3S/L4
membership and recovery gates remain required.

## Validation

- Locked restore succeeded.
- Serialized Release warnings-as-errors solution build succeeded with 0 warnings and 0 errors. An earlier
  parallel build lost an MSBuild child process while other agent builds were active; the serialized rerun was
  clean and no source/test failure was involved.
- Focused Messaging policy shard: 27 passed, 0 failed.
- Full Control Plane suite: 554 passed, 0 failed.
- On the exact `ec0dc50`-based audit tree, all five executable suites passed: Contract 24, Protocol 65,
  Scheduler 77, Control Plane 554, and Model 38; 758 total passed, 0 failed.
- `git diff --check` passed.
