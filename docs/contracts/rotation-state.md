# Global rotation state

`keyrotation.NewProduction` requires `NATSStateStoreConfig`. Each coordinator
receives its own optimistic state session. The constructor no longer accepts
a file or arbitrary `security.StateStore` as production authority.

The root must supply the actual GRU global lease candidate, epoch and lease ID and an
authenticated global-account connection. The connection requires verified
TLS 1.3, mTLS, a user NKey, disabled reconnect and disabled reconnect buffering.
The existing generic global connection allows reconnect; it cannot be reused
without changing its lifecycle. The caller owns this connection and must
recreate the coordinator and store after takeover or connection loss. The
production worker supervisor now constructs these sessions after election;
the complete CLI adapter resolver remains unfinished.

Lease, state and read barriers share `KV_ORCH_LEADERS`. The stream must use R3
FileStorage with no TTL, at least 300 KiB per-message support and at least
600 KiB total capacity. These are adapter admission minima, not production
capacity targets. The account needs stream INFO and leader STREAM.MSG.GET
requests plus publication to:

- `$KV.ORCH_LEADERS.security.rotation.state`
- `$KV.ORCH_LEADERS.security.rotation.barrier`

JetStream KV revisions are stream sequences. State and barrier writes can
advance the sequence between lease writes. The authority engine and journal
replay therefore require a successful lease CAS or deletion to advance the
observed revision, while preserving the exact proposed lease and epoch.
The store still enforces CAS against the previous revision of the lease key.
A real NATS regression covers renewal with intervening sibling-key writes,
stale CAS rejection and refusal to overwrite a successor lease.

Load, including an absent-state result, commits a quorum barrier. Save checks
the session's loaded state revision and uses a stream-wide expected-sequence
commit that also fences global lease changes. Identical retries require a
fresh barrier. Broker commit timestamps determine whether a write landed
within its admitted lease; a late write retains the prior state for recovery,
including recovery from the first attempted write back to absent state.

Persisted state reuses the coordinator's domain validation. Issued credential
references, operation scope and committed publication receipts cannot change
within the same admitted rotation. The coordinator also rejects conflicting
provider issuance results before replacing a persisted reference.

Three-server tests cover restart, competing sessions under one lease, master
takeover, minority outage, lost acknowledgements, expired commits and recovery.
An integration regression runs the production coordinator through two
generations, reload without reissuance, publication and retirement against
that store, with external provider effects supplied by test fixtures.
They qualify durable state behavior only. Issuer, Vault, member, Secrets Store,
reloader and publisher adapters must still recheck authority before external
effects. The CLI root does not yet construct the complete production runtime.

`RefreshAuthority` and `CheckEffectAuthority` commit a fresh quorum barrier
without changing the coordinator's loaded state cursor. The root uses a
separate proof session and permanently cancels the worker context after a
failed check. Lease renewal may update timestamps and revisions; candidate,
epoch and lease ID remain fixed for the session.

The [recorded gates](../evidence/rotation-state-gates-2026-09-05.txt) passed on
the integrated source. Test setup waits for the elected stream leader and
both current replicas after startup and restart. This fixture timing does
not change the production store's two-second operation bound.
