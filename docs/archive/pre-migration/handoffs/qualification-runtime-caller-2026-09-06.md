# Qualification initial-to-run caller task

## Verified missing call path

`vmqualsuite.runtimeControlProof.initialize` calls the factory's
`QualificationControlRuntime(ctx)` before the bootstrap scenario. That method
returns unavailable unless `services.controlRuntime` was configured.
`firecrackerFactory.ConfigureQualificationControlRuntime` has no caller in the
repository. `QualificationHostControl` has tests but no non-test caller.
Initialization requires bindings for GRU/SFO/FRA/IAD, each with at least two exact
member identities; reserved IAD addresses alone are not admission.

Implement the actual composition in `vmqualruntime`, connecting the admitted
owner/bootstrap/controller sources below. Keep the full six-guest declaration;
do not replace missing authority with fixed epochs, fixture liveness, or root NATS.

## Consumer interfaces and source requirements

`QualificationHostControl(ctx, region, candidateID, resolve, commandAuthority)`
requires lowercase region, an enrolled command signer candidate named
`<region>-controller-<guestID>`, and two callbacks:

- `resolve(context.Context, string) (hostcontrol.Host, error)` reads admitted
  membership and returns exact NodeID, uppercase Region, and host Architecture.
  The factory additionally requires the matching owned active guest.
- `commandAuthority(context.Context, hostcontrol.Host)
  (delivery.RegionalCommandAuthority, error)` re-reads the live lease and admitted
  desired generation. Required fields are AuthorityID, Epoch, CandidateID,
  LeaseID, IssuedAt, ExpiresAt, DesiredGeneration. The factory binds authority to
  `<region>-regional`, the selected signer, positive epoch/generation, and current
  validity; hostcontrol rechecks before publishing.

`nodeauthority.ReadRegionalCommandLease(ctx, conn, "ORCH_LEADERS")` reads
`authority.regional` from the actual TLS-connected KV leader and validates the
seven-field lease document. It returns the KV revision separately. Do not equate
topology epochs, desired generations, KV revisions, or lease election terms.

`ConfigureQualificationControlRuntime(bootstrap.NATSControlRuntimeConfig,
[]bootstrap.ControlRegionBinding)` requires:

- `Hosts`: clients returned by the owned factory method above.
- `Stores`: names to `{URL, Options []nats.Option}`, resolved from protected owner
  credentials. URLs must be TLS and address actual planned guests. Root fixture
  JetStream is forbidden. Connections open after handoff, allowing an admitted
  candidate to be configured before its listener starts.
- `Members`: exact OCI MemberID, ts-node HostID, NATS ServerName, lowercase Region,
  Instance, pinned membership IdentityPublicKey, and Store. Pins must match the
  factory's preissued guest membership identity; network IDs are not OCI IDs.
- `Actions`: exact Kind/Region/ExpectedEpoch/TargetEpoch action plans. Each may
  carry signed host handoffs (MemberID, ExpectedManifestSHA256, complete Manifest),
  mirror and stream/consumer replica updates, checks, and revoked credentials.
- Region bindings: exact member IDs, unique and exhaustive against configured
  members and clients, including reserved expansion hosts only after admission.

Each `ControlStoreCheck` binds Store, Region, AuthorityID, LeaseKey, actual
AuthorityTerm, mutation CandidateID/LeaseID, member inventory, stream assignments,
and mirrors. `NATSControlRuntime.checkStoreMode` independently reads the current
lease and rechecks it after observations. `readControlMember` reads
`ORCH_RUNTIME/controller.<Instance>`, verifies the signature against the pin,
region/instance, freshness (30 seconds), and unexpired membership lease.
Stream checks require real file-backed JetStream state, exact replica count,
leader and replica server inventory. These readers already exist; the missing
piece is the admitted producer/composition, not a replacement observer.

## Initial-to-run manifest and credential sequencing

`qualificationRuntimeServices.Bootstrap` currently supports GRU only. It applies
`engineSeed.Apply` to the base manifest, then `controlSeed.LaunchManifest`
overwrites the orchestrator command/config with strict
`initial-gru-r1 --config @config` and `initialgrant.Config`. The full engine
placement/database host material requires production `run --config @config` and
therefore correctly fails final manifest validation.

Connect explicit stage ownership: initial GRU grant, admitted candidate launch,
and signed production-run handoff must each carry only their matching config and
protected credentials. Preserve the complete intended run material for its
actual handoff; merely dropping it from all stages is incomplete. Non-GRU
bootstrap must consume admitted allocation/controller config rather than remove
the current refusal. Sign the final immutable manifest after composition, keeping
exact artifact digests and expected prior-manifest binding.

The initial runtime exposes `RegionalAuthority`, `GlobalAuthority`, and
`Membership` snapshots in-process; guest runtime state must be read through the
authenticated production paths, not recreated as host-side assumed snapshots.
The host credential consumer is implemented (see capacity handoff), but the GRU
dynamic issuer/run producer and broker enrollment remain missing producers.

## Acceptance

Exercise the actual caller with live guest leases, signed membership, and observed
JetStream assignments; stale/foreign/replaced leases and manifests must fail.
Then run full declaration through real GRU bootstrap, SFO/FRA admission, R3 and
remaining suite scenarios. Preserve per-scenario results and exact binaries.
The stage-specific exploratory attempt is diagnostic evidence only.
