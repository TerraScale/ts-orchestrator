# Phase 1 messaging policy property shard handoff

## Delivered

- Three deterministic 1,000-case property families cover replacement ordering, regional/global partition authority, and every dual-plane isolation surface, including exact emitted subjects and cross-culture/permutation replay.
- Public authorizing `MessagingIntent` implementations and `MessagingDecision` are construction-closed; reflection coverage enumerates every exported assignable intent type and rejects public constructors/factories.
- Caller-controlled messaging collections are defensively captured with a documented 4,096-item technical bound. Over-bound input is rejected before the extra element's `Current`; ordinary iterator/count failures are generic and secret-safe, while `OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException` propagate.
- Compatibility decisions fail closed as `InvalidCatalog` for hostile counts/enumerators. The pre-existing `MaximumResources` business input remains independent and unchanged.
- The 12-entry embedded replay corpus is strict-schema, duplicate-aware, UTF-8 byte-bounded to 32,768 bytes, whole-file SHA-256-pinned, closed to known family/mode/outcome triples, and verifies input-sensitive replay fingerprints.

## Compatibility

- Intent and decision public types and property getters remain available, and policy-engine decision signatures are unchanged.
- This intentionally breaks source/binary compatibility for callers that directly invoked public positional constructors or positional `Deconstruct` members on intent/decision records. Such callers could forge authorizing outputs; construction is now internal to the control-plane assembly.
- Collections of at most 4,096 non-null items retain their prior values and enumeration order. Larger collections now throw `ArgumentException` during DTO construction instead of being captured without bound. Ordinary hostile iterator details are no longer exposed through exception text or inner exceptions.
- `DecideCompatibility` retains its fail-closed decision style: oversized or ordinarily faulty feature lists yield held `InvalidCatalog`; fatal runtime exceptions still propagate.

## Boundary

Pure policy only. No NATS/process/network/filesystem/cloud execution was added or tested, and no L0C claim is made.
