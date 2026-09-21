# Controller-owned host report relay

Host convergence sends admission and runtime observations through
`ts.orch.v2.<cell>.agent.<host-hash>.observation.report`. The regional controller
stores each accepted observation in private `ORCH_RUNTIME`; hosts no longer
write these report keys directly. Admission and service health remain separate.

The schema-1 envelope contains a 32-character hexadecimal request nonce and
exactly one admission or runtime observation. Its reply subject must be exactly
`ts.orch.v2.<cell>.agent.<host-hash>.command.report-<nonce>`. The producer listens
before sending and waits at most ten seconds for an accepted acknowledgement
with the same nonce and a nonzero stored revision. It never requests generic
`_INBOX` access. Convergence does not record a successful installation marker
until its report has been acknowledged.

The controller derives the storage key, validates subject/body identity and
cell, catalog artifact, canonical digest, schema, bounds and timestamp, and
rejects duplicate or unknown JSON fields. Reserved identity prefixes cannot
alias admission, backoff or replacement keys. Observations are accepted only
within the preceding 30 seconds; future timestamps are rejected. Hosts and
controllers therefore need synchronized clocks.

Compare-and-set preserves timestamp order across retries and multiple relay
instances. An exact retry returns the existing revision; an older or conflicting
same-time report cannot replace a newer withdrawal or health observation.
Startup requires retention longer than the accepted-report window, discard-new
capacity handling, no global message-count limit and no message-specific TTL.
The production runtime retains observations for five minutes. This protects
against expiry/eviction reopening the accepted replay window, not privileged
store deletion or a compromised controller.

Regional-controller grants allow command publication and observation/ack
subscriptions for every agent in their own fixed region. Host-agent grants
remain pinned to one hash; hosts cannot publish controller commands, other
hosts' reports or private KV mutations. Reports themselves are not signed
enrollment authorization and do not replace the enrollment gate.

The authenticated operator status includes a `host-report-relay` action
(`listening` or `retrying`) and `host-report-relay:retry-report` when a valid
report's persistence or acknowledgement failed. A different host's success
does not clear this need. Failure tracking is process-local, bounded to 512
report keys; overflow remains degraded until restart. Telemetry exports
`terrascale.orchestrator.host.reports` with `cell` and
`result=accepted|rejected|failed`; it adds no per-host label cardinality.

## Qualification boundary

Real NATS tests exercise the production report producer, multiple restricted
host identities, regional controller agent grants, explicit permission denials,
malformed traffic, stale withdrawals, idempotent retries, storage failure and
recovery, unsafe retention rejection, status and metric projection. Controller
store handles and native execution are injected in the host convergence tests.
An additional three-server test uses JWT/mTLS host credentials and each
restricted controller's own private-store connection, then restarts the relay
and verifies that a stale ready report cannot replace a withdrawal. That test
starts the relay directly, not the complete regional runtime.

The full OCI host path is still incomplete. It currently enters controller
startup and depends on private desired/artifact stores, enrollment replay
fences, retry backoff and replacement leases. A dedicated host runtime and
bounded protocols for those dependencies, plus durable drain handling, must
pass qualification before deployment. Do not broaden host credentials to make
the current controller startup succeed.
