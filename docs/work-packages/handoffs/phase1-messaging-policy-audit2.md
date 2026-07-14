# Phase 1 Messaging/NATS policy audit handoff

## Scope and baseline

- Audited the pure Messaging/NATS policy at integration baseline `621c37d`.
- Changed only the Messaging replacement decision, its dedicated property tests, and this handoff.
- No NATS process, socket, filesystem, VM, cloud API, or other external system was used.

## Proven defect

`DecideTopology` rejected a critical stream or bucket that did not meet the declared membership floor,
replicated acknowledgement, and acknowledged-write-strict disk-sync contract. The public
`DecideReplacement` entry point did not repeat that safety validation. A caller could therefore supply a
floor-three plane with a critical RF1 stream, present a matching healthy RF1 observation after replacement
catch-up, and receive `RemovePeerIntent`.

The test-only pre-fix regression failed on exact integration head `1ad1769` and again after rebasing because
the returned decision contained no error and reached the remove-peer branch. The regression was retained and
expanded only after adversarial steward review.

## Resolution

- Replacement validation now examines every stream and bucket before an absent or supplied observation can
  produce persistence, add, reattach, or removal output.
- Undefined or out-of-range durability, acknowledgement, or disk-sync values and replica counts above the
  admitted server count return `InvalidInput`.
- A defined critical resource below the caller-declared membership floor, without replicated acknowledgement,
  or without acknowledged-write-strict sync returns `DurabilityViolation`.
- The pre-existing `Replicas <= 0` replacement classification remains `ReplacementConflict`.
- Explicit bounded resources remain permitted below the membership floor. No implicit R3, retention, subject,
  account, timing, storage, or owner-decision default was added.
- Topology and replacement validation share the same narrow critical-durability predicate so the two entry
  points cannot drift on this invariant.

## Completeness inventory

- Input enum families inspected: plane, durability, retention, discard, acknowledgement, disk-sync, peer
  health, store classification, compatibility feature/pair, authority scope, and connectivity.
- Output enum families inspected: messaging action, error code, and trace code.
- Replacement branches inventoried: initial observation, persist, add, catch-up wait, replica-verification wait,
  remove, completion, surviving-store reattach, surviving-store re-observation, and every hold class.
- Other decision outputs inventoried: ordered control/product configuration, regional/global continuation,
  compatibility acceptance, and hold.
- Existing construction-closure reflection covers every exported `MessagingIntent` subtype and
  `MessagingDecision`; no public constructor, setter, deconstructor, or factory outside the four decision
  methods exists.
- Existing dual-plane properties cover shared cluster/server/peer/account/stream/bucket/subject authority,
  product gateways, and control-to-product gateway conflicts. This audit did not weaken those boundaries.

## New deterministic evidence

- 1,000 adversarial cases alternate stream and bucket mutations across below-floor replicas,
  non-replicated acknowledgement, non-strict sync, undefined/out-of-range safety enum values, and replicas
  above the admitted server count. Exact error, hold intent subject, trace tuple, and absence of remove output
  are asserted.
- 1,000 positive cases preserve caller-configurable policy by alternating bounded RF1 stream, bounded RF1
  bucket, and exact-floor critical resources. Exact remove-peer subject and trace tuple are asserted.
- Both matrices replay under distinct cultures and reversed input collection order.
- Invalid replacement resource policy takes precedence before observation handling; existing observation
  duplicate/conflict/stale/future precedence is unchanged.

## Validation

- Focused completeness shard: 2 passed, 0 failed.
- Full Control Plane suite: 487 passed, 0 failed.
- Final locked restore, warnings-as-errors solution build, all executable test suites, and diff check are recorded
  by the integration handoff after the final exact-head validation.

## Deliberate boundaries

- This is pure L0 policy evidence only. It does not qualify NATS configuration, JetStream behavior,
  acknowledgement persistence, disk sync, peer administration, or replacement against a real NATS server.
- L0C and the later L2S/L3S/L4 membership, conformance, failure, and recovery gates remain required.
