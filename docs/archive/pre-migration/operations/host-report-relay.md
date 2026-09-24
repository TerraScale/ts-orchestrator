# Controller-owned signed host report relay

Host publishers send admission and runtime observations through
`ts.orch.v2.<cell>.agent.<host-hash>.observation.report`. Regional controllers
require the current signed process session before storing an atomic
`StoredHostReport` in private `ORCH_RUNTIME`. Hosts have no private KV access.
Admission and service health remain separate observations.

The schema-2 envelope contains a mandatory `RegionalHostReportProof` and
exactly one observation. Its 32-character request nonce determines the exact
reply subject, `ts.orch.v2.<cell>.agent.<host-hash>.command.report-<nonce>`.
The publisher subscribes before sending, bounds PING/PONG and acknowledgement
waiting to five seconds, and never requests generic `_INBOX` access. An accepted
schema-2 reply must bind the nonce and SHA-256 of the exact canonical envelope.
It contains no storage revision: readiness checks and retries can advance
internal CAS revisions without changing the report. Convergence records its
successful installation marker only after its report is acknowledged.

`RegionalHostReportSigner` holds an immutable, exact accepted session response
and reloads the protected enrolled NKey when signing. A renewal replaces the
signer snapshot; signing does not renew a lease. The signer requires the node,
cell, workload role and current lease to match the signed enrollment.

The controller validates subject/reply/body identity, cell, artifact, digest,
schema, timestamps and current signed session. It rejects null identities,
unknown/duplicate JSON fields and reserved key prefixes. The whole envelope
is bounded to 32 KiB, with proof and payload limits of 16 KiB each. Proofs
expire after ten seconds and observations after thirty seconds; future
observations are rejected. Hosts and controllers need synchronized clocks.
See [host session authentication](host-session-authentication.md).

Every persistence attempt reauthorizes the current session and uses a report
CAS, including unchanged retries. An exact-envelope retry can recover a lost
acknowledgement; a newly signed envelope at the same observation timestamp is
a conflict. Retrying callers must retain the original envelope. Older reports
cannot replace a newer withdrawal. Explicit deletion or corrupt ordering state
fails closed; initial revision-zero CAS cannot resurrect a tombstone. Eight
CAS conflicts exhaust the bounded attempt budget. Startup and each report
also have five-second deadlines.

Startup requires acknowledged, file-backed R3 storage, limits retention,
discard-new capacity handling, no global message-count limit, no per-message
TTL or delete-marker expiry, and retention longer than the accepted-report
window. The production runtime retains observations for five minutes. These
checks do not protect against a compromised controller or privileged stream
administration.

Readiness consumers verify both current report/session CAS barriers. OCI
serving readiness and operator ready counts also require a ready admission
for the same node, artifact digest, enrollment generation, session and epoch.
A newer admission withdrawal invalidates an older converged report. Both
authorizations must remain unexpired. This is a current observation, not a
physical writer fence or a guarantee against revocation after the read.

The authenticated operator status exposes `host-report-relay` as `listening`
or `retrying`, with `host-report-relay:retry-report` on persistence/transport
failure. Another host's success cannot clear that failure. Tracking is local,
bounded to 512 report keys; overflow stays degraded until restart. Telemetry
exports `terrascale.orchestrator.host.reports` with `cell` and
`result=accepted|rejected|failed`, without per-host metric labels.

## Qualification boundary

The local R3 tests use separate JWT/mTLS identities for a TerraBase host and
an authentication host. They exercise production session admission, signing,
report publication, controller persistence, authorized reads, explicit NATS
permission denials, malformed traffic, lost replies, stale replica reads,
withdrawal/restart, revocation/replacement/expiry, storage failure and retention
validation. Loopback and injected-store tests cover withheld responses and
bounded cancellation. The actual restricted `NatsRuntime` startup test also
publishes through the real host transport and queries authenticated operator
status. Core host execution tests inject a report sink and do not qualify the
production transport or cryptographic boundary.

**OCI deployment remains blocked.** Controller run/check rejects host roles.
A dedicated restricted host entry point still needs admitted desired/artifact
protocols, independent lease renewal, in-flight cancellation, physical workload
stop and durable drain handling. Host convergence still has controller-owned
private store dependencies. Do not broaden host credentials to make that
unfinished path run. Regional first-boot/ownership transfer, storage fencing
and ARM64 workload execution remain separate deployment gates.
