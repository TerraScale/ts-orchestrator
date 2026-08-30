# NATS capability-adoption matrix and messaging contract

> Frozen v1 implementation contract for the checked-in NATS adapter. The
> repository [`GOAL.md`](../../GOAL.md) and
> [ADR 0033](../adr/0033-gru-global-authority-and-regional-autonomy.md) replace
> its optional-NATS target with the mandatory `ts.orch.v2` control network; the
> subject tokens below name that v2 control root, and the checked-in adapter
> still serves the superseded v1 root until the migration lands. It cannot
> define v2 authority or permit database data, replication, reactive sync,
> usage truth, or product correctness to depend on NATS.

| | |
| --- | --- |
| Contract version | 1 (frozen) |
| Ratified by | `TerraScale.Orchestrator` issue #18 (parent #16, dependency #17) |
| Machine-readable definitions | `src/TerraScale.Orchestrator/Protocol/Messaging/` — `NatsCapabilityMatrix.cs`, `NatsSubjectTaxonomy.cs`, `MessagingEnvelope.cs`, `MessagingSemanticClasses.cs`, `MessagingDeliverySemantics.cs`, `MessagingRegionalAutonomy.cs`, `MessagingCompatibility.cs` |
| Signed command envelope | `src/TerraScale.Orchestrator/Protocol/CommandEnvelope.cs` + `CommandValidation.cs` (INV-005 fail-closed admission) |
| Drift binding | `tests/TerraScale.Orchestrator.Protocol.Tests/NatsCapabilityMatrixTests.cs` reads the table below; `NatsSubjectTaxonomyTests`/`MessagingSemanticClassesTests` bind subjects to the landed topologies; `tests/TerraScale.Orchestrator.Tests/MessagingContractSourceScanTests.cs` forbids private subject copies outside the canonical taxonomy |
| Canonicality | Canonical for the checked-in v1 implementation only. The repository `GOAL.md` and ADR 0033 control the v2 target. |

Dispositions: **ACCEPT** — adopted, all attributes frozen, adapters must conform. **DEFER** — not adopted yet, no adapter may assume it, a revisit trigger is recorded. **REJECT** — excluded.

## 1. Capability-adoption matrix

| Capability | Disposition | Owner | Data class | Durability | Ordering | Security boundary | Failure mode | Observability | Landed evidence |
| --- | --- | --- | --- | --- | --- |---|---|---|---|
| `CorePubSub` | ACCEPT | RegionalControlRuntime | OperationalTelemetry | Ephemeral | Unordered | Control account subject permissions; publish only taxonomy subjects; no product-plane subjects. | Lost publications are safe: hints, heartbeats, and fanout are advisory and consumers reconcile from durable state. | Drop/latency counters per subject namespace; no alert may depend on a lossy hint. | `NatsRuntime` service endpoints; `RegionalRuntimeMembership` heartbeats via bounded `ORCH_RUNTIME` KV. |
| `RequestReply` | ACCEPT | RegionalControlRuntime | OperatorQuery | Ephemeral | Unordered | Typed endpoints only; scoped subscribe + `_INBOX`; no-responder surfaces as an error, never silence. | Timeout/no-responder is caller-visible; retries reuse the idempotency key. | Request latency and no-responder rate per endpoint. | `NatsRuntime` health/status/members; directory service `ts.orch.v2.global.query.cells`. |
| `ServicesAndDiscovery` | ACCEPT | RegionalControlRuntime | OperatorQuery | Ephemeral | Unordered | `$SRV` subjects stay account-scoped; only declared endpoints registered; complements workload DNS/LB. | Missing service/endpoint metadata fails the caller closed (startup verifies discovery). | Endpoint presence, queue-group membership, per-endpoint latency/errors. | `terrascale_orchestrator_<cell>` service with `$SRV.INFO` readback verification. |
| `QueueGroups` | ACCEPT | RegionalControlRuntime | ControlCommand | Ephemeral | Unordered | Distribute only equivalent-worker work; the single authoritative writer is always chosen by a KV CAS lease, never by a queue group. | Any member may answer; answers must be equivalent; authoritative writes are epoch-fenced. | Group size, member churn, duplicate-answer rejections. | `NatsTopology.ServiceQueueGroup`, `OperationJournalWriterQueueGroup`. |
| `Headers` | ACCEPT | MessagingContracts | ControlCommand | Ephemeral | Unordered | Only contract-defined `TS-*` metadata; never secrets, credentials, or body. | Missing/malformed required headers fail closed at the wire codec. | Header validation rejections by name. | `TS-*` headers in `NativeGitOpsCellWireCodec`, `DirectDeliveryCommandWire`, startup verification. |
| `MessageIds` | ACCEPT | MessagingContracts | ControlCommand | DurableBounded | Unordered | Transport suppression only, bounded by stream duplicate windows; never an exactly-once claim. | A duplicate outside the window is admitted; idempotency keys stay authoritative. | Duplicate-suppression counters beside idempotency-replay counters. | `MsgId` on every JetStream publish; 2 m / 24 h windows in both topologies. |
| `JetStreamStreams` | ACCEPT | InfrastructureBootstrap | AuthoritativeState | ReplicatedDurableFile | PerSubjectFifo | Infrastructure-provisioned; controllers validate exact configuration and never create/update streams. | Start fails closed on mismatch; limits retention bounds age/bytes. | Depth, age, bytes, discards, replica health per critical stream. | `CELL_SPEC`, `CELL_OPERATIONS`, `CELL_EVENTS`, `GLOBAL_SPEC`, `GLOBAL_CI`. |
| `DurableConsumers` | ACCEPT | InfrastructureBootstrap | ControlCommand | ReplicatedDurableFile | PerSubjectFifo | Closed profiles; controllers may only create/open/ack their named consumer. | Missing/mismatched consumer fails check/run closed. | Lag, pending, redeliveries, profile-validation failures. | `runtime_startup`, `gitops_cell_spec_*`, `global_ci_trigger`, `global_ci_runtime_proof`, `ci_runner_*`. |
| `Acknowledgement` | ACCEPT | DeliveryContracts | ControlCommand | ReplicatedDurableFile | PerSubjectFifo | Ack only after the durable effect is journaled or an idempotent replay is proven; progress heartbeats for long work. | Crash before ack means redelivery; authority loss after acceptance withholds the ack. | Ack latency after effect, progress age, authority-lost-after-acceptance counts. | Double-ack after journal acceptance; `AckProgressAsync`; terminal acks for deterministic conflicts. |
| `RedeliveryAndBackoff` | ACCEPT | DeliveryContracts | ControlCommand | ReplicatedDurableFile | PerSubjectFifo | Max 5 deliveries; 1 s/5 s/15 s/30 s ladder; ack wait equals the first interval. | Exhaustion stops redelivery only with terminal evidence; nothing disappears silently. | Redelivery histograms, exhaustion, final-delivery warnings by subject. | Consumer profiles; final-delivery warning and nak-with-delay in `ForgejoCiEventConsumer`. |
| `FlowControl` | ACCEPT | InfrastructureBootstrap | OperationalTelemetry | Ephemeral | Unordered | `$JS.FC` grants only to owners of the consuming stream/bucket; the global authority gets no durable/pull/ack shapes for watch-only buckets. | A stalled consumer is marked slow and surfaced, never silently dropped. | Slow-consumer advisories; outstanding flow-control latency. | Explicit `$JS.FC` grants in `GlobalNatsPermissions`; the `GlobalNatsAccessContract` account model grants them only to the owning stream or bucket identity. |
| `KeyValueCasAndWatch` | ACCEPT | RegionalControlRuntime | CoordinationRecord | ReplicatedDurableFile | PerAggregateEpoch | KV is for leases, epochs, and small coordination only; the operation stream is the durable history; journal KV stores are denied to controllers. | CAS conflict is normal: the loser re-observes and retries; ambiguity holds. | CAS conflict rate, lease age, watch lag, journal-store denial attempts. | `RegionalAuthorityCoordinator` CAS leases; `cell.>` watch; inbox-delivered ephemeral watch consumers. |
| `ObjectStore` | ACCEPT | StorageAndSnapshots | EvidenceArtifact | ReplicatedDurableFile | PerSubjectFifo | Small signed bundles, protocol packages, evidence only; never the build registry or backup system; no secrets. | Missing/byte-unequal protocol package fails startup; bundles are content-addressed. | Object counts/bytes per bucket; integrity failures. | `CELL_BUNDLES`, `GLOBAL_BUNDLES`, `CI_RUNNER_BUNDLES`, `ORCH_PROTOCOL_PACKAGE`. |
| `Accounts` | ACCEPT | SecurityAndIdentity | CoordinationRecord | ReplicatedDurableFile | Unordered | Hard namespaces (system, global authority, global directory, regional control, CI, audit, operator, product, test); the capability selects the account, never caller credentials. | Wrong-account identities simply lack permissions; cross-plane authorization is structurally impossible. | Account-scoped auth failures and denials feed security alerts. | `GlobalNatsAccountNames`/`GlobalNatsAccessContract`; distinct control/product planes. |
| `Jwts` | DEFER | SecurityAndIdentity | — | — | — | — | — | — | Revisit trigger: operator/account/user JWT issuance and the JWT/NKey administration toolchain are unselected (phase1-nats-l0c-foundation outcome); adopt only after the L0C lane pins the toolchain and rotating account-signing-key procedure. |
| `NKeys` | ACCEPT | SecurityAndIdentity | CoordinationRecord | Ephemeral | Unordered | Controllers, writer, infrastructure, directory, and operator identities; every command rejects every NATS credential family it does not own before file resolution. | Anonymous connections denied (verified at startup); missing NKey fails closed. | Auth failures by identity family; anonymous-denial verification. | `OrchestratorOptions.NatsNKeyFile`, `VerifyAnonymousDeniedAsync`, `CiRunnerNatsCredentialIssuer`, `GlobalNatsAccessContract` identity separation. |
| `Mtls` | ACCEPT | SecurityAndIdentity | CoordinationRecord | Ephemeral | Unordered | Proves machine/workload transport identity for clients, routes, gateways; never replaces NKey/JWT authorization; global endpoints require absolute `tls://` URLs. | TLS failure is a startup/connection failure; no plaintext fallback. | Certificate expiry freshness, handshake failures, per-endpoint TLS mode. | `NatsTlsOpts` Require mode; `NatsTlsFiles`; infrastructure mTLS required by `NatsOperationJournalProvisioner`. |
| `ImportsAndExports` | ACCEPT | SecurityAndIdentity | OperatorQuery | Ephemeral | Unordered | Least-privilege service import/export across accounts within one cluster only (the directory query service). Cross-cluster/region stream or service import/export is **rejected** — the gateway mesh is the only cross-cluster path and no stream may span regions. | A missing import/export makes the cross-account call fail closed with no-responder. | Import/export presence per account pair; undeclared cross-account subjects are security alerts. | `GlobalNatsServiceImport`/`Export` for `ts.orch.v2.global.query.cells`; no cross-region stream exists. |
| `Gateways` | ACCEPT | InfrastructureBootstrap | CoordinationRecord | Ephemeral | Unordered | Full mTLS gateway mesh (not hub-and-spoke) inside one offline control-plane operator domain; local streams and actions stay regional; explicit known clusters. | Gateway loss isolates regions; regional control stays autonomous and pre-authorized work continues. | Gateway link state/latency; isolated-region duration; envelope expansion is a new owner decision. | Gateway membership validated by `MessagingPolicyEngine` plane policies; no production gateway adapter deployed yet. |
| `Advisories` | ACCEPT | Observability | OperationalTelemetry | Ephemeral | Unordered | Authenticated `$SYS` subjects only for remote status; advisories are read, never authority. | A missed advisory degrades monitoring only; control decisions never change. | Slow-consumer, quorum/leader-change, auth-failure advisories are alert inputs. | docs/architecture/orchestrator.md monitoring contract; observability adapters tracked under unresolved measurements. |
| `SystemMonitoring` | ACCEPT | Observability | OperationalTelemetry | Ephemeral | Unordered | HTTP monitoring binds loopback/isolated management addresses only, scraped locally; remote status via authenticated `$SYS`; never internet- or workload-exposed. | Monitoring loss blinds operators without affecting control correctness. | Server/account/connection/consumer health and quorum state feed Grafana/alerts. | docs/architecture/orchestrator.md NATS monitoring rules; adapter status tracked under unresolved measurements. |
| `Snapshots` | ACCEPT | StorageAndSnapshots | EvidenceArtifact | ReplicatedDurableFile | PerSubjectFifo | Signed stream position + schema version; restore replays from that position and refuses an older snapshot over a newer accepted epoch; journal KV stores deny snapshot/restore to controllers. | Restore never regresses accepted epochs; product and control backups stay separate. | Snapshot freshness, restore attempts, refusals by reason. | `SignedSnapshot`/`SnapshotRestore` core; journal stores provisioned by `NatsOperationJournalProvisioner` with snapshot/restore denied to controllers; exercise is an L0C gate. |
| `RollingCompatibility` | ACCEPT | MessagingContracts | ControlCommand | ReplicatedDurableFile | PerAggregateEpoch | N and N-1 interoperate for commands, snapshots, schema reads, leadership transfer; upgrades proceed one plane/failure domain at a time and cannot break quorum floors. | An upgrade cannot proceed without current and rollback artifacts; N-1 nodes fail closed on N-major documents. | Per-version interop matrix results; rollback outcomes per failure domain. | `MessagingPolicyEngine.DecideCompatibility`; forward-only journal migration discipline. |

## 2. Closed subject taxonomy

Canonical definitions: `Protocol/Messaging/NatsSubjectTaxonomy.cs`. Production adapters compose subjects ONLY through the taxonomy; `MessagingContractSourceScanTests` fails any `ts.orch`/`ts.product` literal outside the canonical directory.

| Namespace | Root / pattern | Status | Notes |
| --- | --- | --- | --- |
| Global authority | `ts.orch.v2.global.>` (minus `ci.>`, `query.cells`, `audit.>`) | landed | GRU-owned global journals: `desired.gitops.<cell>` (GLOBAL_SPEC), release/CI ledger keys. |
| Global directory | `ts.orch.v2.global.query.cells` | landed | Served by the GRU directory-service identity over the standalone snapshot. |
| Regional control | `ts.orch.v2.<cell>.{query,command,event,desired,internal.reply}.>` | landed | Controller services, delivery admission, startup events, accepted CellSpecs, inboxes. |
| Operations | `ts.orch.v2.<cell>.{operation,internal.operation-journal,internal.runtime-lifecycle-journal}.>` | landed | Authoritative journaled mutation channels. |
| Continuous integration | `ts.orch.v2.global.ci.>` | landed | `forgejo` triggers, `runtime-proof` observations, `job.<zone>.<hash>` runner inboxes. |
| Agent | `ts.orch.v2.<cell>.agent.>` | reserved | Host-agent channels; work-queue semantics when landed. |
| Audit | `ts.orch.v2.<cell>.audit.>` and `ts.orch.v2.global.audit.>` | reserved | Audit history is authoritative and export-only. |
| Product plane | `ts.product.…` | rejected from control | Separate trust plane and clusters; no control subject is ever defined under it. |

Platform-reserved NATS roots (`$JS`, `$KV`, `$O`, `$SRV`, `$SYS`, `_INBOX`, `_R_`, `#`) are not control subjects; classification returns `PlatformReserved`, and unknown subjects fail closed.

## 3. Versioned envelope contract

`Protocol/Messaging/MessagingEnvelope.cs` extends — never duplicates — the signed `CommandEnvelope`:

- From `CommandEnvelope` (signed): protocol version, cell, aggregate, desired generation, writer epoch (fencing), operation id, operation idempotency key, issued/expiry, delivery attempt, payload + digest, signature. Signed material and validation are owned by `CommandEnvelopeValidator` (INV-005).
- Added by the messaging envelope: schema major/minor, message id, correlation id, causation id, source (instance, session, cell, cluster), target scope (namespace, subject, cell), payload type, trace context, observation time.

Fail-closed validation (`MessagingEnvelopeValidator`, typed rejections, all covered by tests): unknown major version, malformed subject, subject outside the closed taxonomy, subject/cell/source disagreement, unpermitted payload type, malformed trace context, and every signed-command rejection — expired, not-yet-valid (delayed), wrong cell, stale generation/epoch, invalid signature shape, digest disagreement (via `CommandValidationError`).

## 4. Semantic classes

`Protocol/Messaging/MessagingSemanticClasses.cs`: `Lossy`, `Replayable`, `WorkQueue`, `Snapshot`, `AuthoritativeJournal`.

| Subject pattern | Class | Loss meaning |
| --- | --- | --- |
| `ts.orch.v2.global.query.cells` | Lossy | request/reply over the durable directory snapshot |
| `ts.orch.v2.global.desired.gitops.>` | AuthoritativeJournal | GLOBAL_SPEC authority |
| `ts.orch.v2.global.ci.forgejo` | WorkQueue | leader-only trigger decisions |
| `ts.orch.v2.global.ci.job.>` | WorkQueue | fenced per-runner inbox (MaxAckPending 1) |
| `ts.orch.v2.global.ci.runtime-proof` | Replayable | bounded durable observations |
| `ts.orch.v2.*.query.>`, `ts.orch.v2.*.command.>`, `ts.orch.v2.*.internal.reply.>` | Lossy | caller-visible retry; effects journaled separately |
| `ts.orch.v2.*.event.>` | Replayable | CELL_EVENTS bounded history |
| `ts.orch.v2.*.desired.>` | AuthoritativeJournal | accepted CellSpec history (CELL_SPEC) |
| `ts.orch.v2.*.operation.>`, `ts.orch.v2.*.internal.operation-journal.>`, `ts.orch.v2.*.internal.runtime-lifecycle-journal.>` | AuthoritativeJournal | authoritative regional journals |
| `ts.orch.v2.*.agent.>` (reserved) | WorkQueue | host-agent command/ack |
| `ts.orch.v2.*.audit.>` (reserved) | AuthoritativeJournal | audit history, export-only |

Store classes (`StoreRules`): authoritative journals — `ORCH_OPERATIONS`, `GLOBAL_RELEASES`; snapshots — `GLOBAL_CELLS`, `CELL_BUNDLES`, `GLOBAL_BUNDLES`, `CI_RUNNER_BUNDLES`, `ORCH_PROTOCOL_PACKAGE`; coordination (lossy in the contract sense — CAS plus epochs carry correctness) — `ORCH_LEADERS`, `ORCH_RUNTIME`, `ORCH_DELIVERY`, `ORCH_OPERATION_PROOFS`, `CI_RUNNER_JOBS`. A drift test pins every landed bucket to a declared class.

## 5. Delivery semantics

- **Acknowledgement** — only after the durable effect (journal acceptance / convergence record) or a proven idempotent replay; double-ack; progress heartbeats for long work (`DurableEffectAcknowledgementPolicy`).
- **Redelivery/backoff** — at most 5 deliveries, 1 s/5 s/15 s/30 s ladder, ack wait derived from the first interval, bounded ack-pending (`BoundedRedeliveryPolicy`).
- **Poison terminal evidence** — deterministic identity conflicts terminate immediately with durable terminal records; transient failures retry on the ladder; operational capacity failures hold loudly and never terminate a healthy message; budget exhaustion ALWAYS leaves terminal evidence (final-delivery warning naming subject + counts) (`PoisonMessagePolicy`).
- **Cancellation** — cancel-before-effect does not acknowledge (redelivery); cancel-during-effect completes or compensates through the journal; no partial acknowledgement (`CancellationPolicy`).

## 6. Message-ID duplicate windows

Transport suppression BENEATH operation-level idempotency: 2 minutes for regional cell streams, 24 hours for the global CI stream. Same id + same digest inside the window → suppress; same id + different digest → conflict (surfaced, never silently dropped); outside the window → admitted and idempotency decides. **No exactly-once claim** (`DuplicateWindowPolicy.NoExactlyOnceClaim`, pure `MessageIdDuplicateWindow` tracker).

## 7. Queue-group ownership and fencing

Queue groups distribute only equivalent-worker work; authoritative work requires the live fenced lease (`AuthorityLeaseClaim`: epoch from KV CAS, KV revision, expiry, candidate). `QueueGroupOwnership.Decide` returns Admit / StaleEpoch / LeaseLost / NotLeader. Split-writer prevention: `MayCommitAuthoritativeWrite` requires the SAME live claim (same epoch, revision, candidate) immediately before the durable write and immediately before the acknowledgement; a loss at either checkpoint abandons or withholds. Lease loss stops new work; in-flight mutation effects claimed under the lost lease are not acknowledged and are re-derived by the next epoch holder. Executable lease mechanics: `RegionalAuthorityCoordinator` (15 s lease, 3 s tick, CAS acquire/renew/observe).

## 8. Regional autonomy

`Protocol/Messaging/MessagingRegionalAutonomy.cs` (rules) + `MessagingPolicyEngine.DecidePartition` (executable epoch/generation core):

- Connected — everything permitted (subject to epoch/generation checks).
- Globally isolated — pre-authorized regional work and observation continue; new global generations, policy, releases, and global authority claims are frozen.
- Regional quorum lost — all mutations held (running workloads continue on last committed allocations); observation continues.

## 9. N/N-1 compatibility rules

`Protocol/Messaging/MessagingCompatibility.cs` — closed negotiation (`MessagingSchemaNegotiation`): accept exact, migrate registered older minors forward, reject unknown majors, reject newer versions (an N-1 node never guesses), reject unmigratable older versions. Matches the landed journal discipline (forward-only stepwise migration; unknown JSON members fail closed). Rule areas: clients, servers, streams, consumers, KV values, Object Store metadata, rolling upgrades (forward+rollback artifacts required; quorum floors never broken; rollback never upgrades data).

## 10. Unresolved production measurements (deferred)

- `$SYS`/advisory consumption and HTTP-monitoring scrape wiring (adapters belong to the observability lane).
- Production gateway deployment and gateway-mesh latency/isolation measurement (pure plane policies landed; no production-shape gateway measurement exists yet).
- JWT operator/account/user toolchain selection and rotation procedure (matrix disposition DEFER).
- Stream/KV snapshot-and-restore execution per plane (pure core landed; L0C gate pending).
- Duplicate-window effectiveness (suppress vs conflict vs beyond-window rates) under production redelivery pressure — measured, not assumed.
- `sync_interval` (disk RPO) selection for control and product planes (Phase 0 benchmark).
