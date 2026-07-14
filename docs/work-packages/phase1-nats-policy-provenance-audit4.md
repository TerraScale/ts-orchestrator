# Phase 1 NATS replacement decision provenance audit 4

## Scope and initial base

- Initial audited base: central `chore/phase0-bootstrap` at `3f283065a68957f0530f312c9308cd97512fad40`.
- Allowed paths: pure Messaging/NATS contracts and policy engine, Messaging policy tests, and this work package.
- Pure deterministic L0 policy only. No NATS server, JetStream, network, process, credential, filesystem, VM, cloud, provider, or deployment action was performed.

## Executable defect

Audit 3 bound an initial or repeated `ObserveClusterIntent` to its exact replacement operation. It did not cover accepted decision branches whose intents flatten the operation or whose successful terminal result contains no intent.

Two fully valid completed replacements differed in operation ID, authority epoch, failed-store identity, replacement server/peer/placement, observation identity, and corresponding peer evidence. Both returned this complete public decision:

```text
Intents       = []
Errors        = []
Trace         = [1:ReplacementComplete:Observe]
Compatibility = null
```

The executable red test fingerprint for each was exactly `||1:ReplacementComplete:Observe|`. A persisted completion could therefore not prove which validated request reached the terminal state. The decision-level gap also affected provenance around flattened add, wait, remove, and reattach intents even when those intents retained the minimum fields needed for their immediate action.

## Correction

`MessagingDecision.AcceptedReplacementRequest` retains the exact immutable `ReplacementRequest` reference on every successful `DecideReplacement` result. One private `ReplacementDecision` helper is the only production path that attaches it. All successful branches use that helper, including:

- initial observation and persisted-operation requests;
- add-peer, catch-up wait, replica-verification wait, and failed-peer removal;
- terminal completion after the failed peer is absent;
- surviving-store reattach, active-attachment re-observation, and active-attachment completion.

Every held/error result and every topology, partition, or compatibility decision retains null. No admitted boolean, flattened duplicate request state, public constructor, or public factory was added. Existing intents, errors, compatibility acceptance, trace codes, numeric values, ordering, precedence, validation, and replacement progression are unchanged.

The request already owns defensive immutable snapshots for policy and observation collections. Retaining it therefore binds plane policy, proposed and nullable persisted operations, maximum identity length, cluster observation, peer/store proof, and replica evidence without rebuilding an incomplete parallel DTO.

## Deterministic evidence

The focused tests prove exact request-reference retention over every existing eight-mode replacement property path plus surviving-store reattach, active-attachment re-observation, and active-attachment completion. The no-intent collision is now distinct. Invalid replacement input is null, and successful/held partition, compatibility, and topology examples also prove that no non-replacement decision can acquire replacement provenance.

A generic test-only canonical walker uses runtime-type and property-name tags plus invariant length framing. Enumerable items are independently framed and ordinal-sorted, so policy, peer, proof, and replica permutations are semantically stable. Exact public-property inventories pin every field of `ReplacementRequest`, `PlanePolicy`, `ServerPolicy`, `RouteLink`, `AccountPolicy`, `StreamPolicy`, `BucketPolicy`, `ReplacementOperation`, `ClusterObservation`, `PeerObservation`, `SurvivingStoreProof`, and `ReplicaObservation`.

An independent sensitivity matrix changes exactly one semantic leaf or collection family per mutant. It covers policy plane/cell/cluster/generation/floor; count and item mutations for servers, routes, gateways, accounts/subject roots, streams, and buckets; every server, route, stream, and bucket field; all sixteen proposed-operation fields; persisted null and a differing persisted field; request maximum identity length; all observation scalars and collection counts; every peer scalar and nullable proof; every surviving-store proof field; and all stream/bucket replica fields. Every mutant has a distinct hash from the baseline and from every other mutant. Canonical material remains replay-stable under English, Turkish, and Arabic cultures and differs across every accepted branch, including nullable persisted/observation state.

The 1,000-case replacement and surviving-store properties require exact accepted-request references for normal and reversed evidence. Held resource-safety cases require null. Topology and partition properties require null. Replacement corpus replay fingerprints now include the complete accepted-request hash.

The historical corpus remains byte-identical with SHA-256 `2dbee32886e47ab9ee7a59f515a5183f9db764f10d788f34e2be592399f536af`. Its existing v1 entries/outcomes are unchanged; Audit 4 strengthens the test-side replacement output fingerprint without claiming that the old fixture schema independently enumerated all request fields.

## Construction closure

The exported hierarchy contains one abstract and ten concrete `MessagingIntent` records plus `MessagingDecision`. Every concrete output is sealed. Every output exposes getter-only public properties and has no public constructor or deconstructor. Exhaustive inspection covers every exported type's declared public static and instance method/accessor returning a decision, an intent, an enumerable/collection projection of intents, or a replacement request. The exact allowlist is the four real static `MessagingPolicyEngine` decision originators; the non-originating zero-argument same-type compiler clones for the decision, intent hierarchy, and replacement request; `MessagingDecision.get_Intents`; and `MessagingDecision.get_AcceptedReplacementRequest`. Clone invocation proves that it preserves the exact immutable intent/error/trace snapshots and accepted request reference rather than transforming or minting them.

## Evidence boundary and nonclaims

This proves only which caller-supplied immutable request passed the pure replacement policy. It does not authenticate observations or surviving-store proofs, persist a journal checkpoint, make an adapter call, or prove that NATS performed an operation. It does not qualify NATS/JetStream response authenticity, membership administration, R3 durability, disk synchronization, gateway isolation, snapshot/restore, compatibility, ARM64, L0C, L3S/L4, or production deployment.

It adds no NATS SDK, socket, endpoint, credential, secret, filesystem path, process, clock, provider permission, VM, cloud, or deployment surface.

## Verification before actual-diff review

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore --nologo -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --disable-logo --no-progress
git diff --check
```

The focused audit passed 3/3, the focused review correction passed 2/2, and the pre-correction ControlPlane executable passed 626/626 with zero failures or skips before final integration rebase. Final exact-tree whole-solution counts are recorded in the integration handoff.
