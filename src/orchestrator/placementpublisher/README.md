# Durable placement proposals

This package carries pending control intent from the GRU authority to the
same-host TerraBase TBEP server. A pending receipt is never a membership,
writer, RF=2, catch-up, readiness, or edge-routing grant.

`NATSJournal.Accept` persists the exact operation ID, engine SPIFFE identity,
local orchestrator principal, expected engine revision, and canonical producer
protobuf request before dispatch. The journal shares `KV_ORCH_LEADERS` with the
global lease and uses stream-sequence CAS, exact candidate/epoch/lease identity,
leader-routed reads, and server commit timestamps. Every state mutation retains
the prior plain state so a delayed post-expiry commit cannot erase accepted
intent when the bucket history is one. The journal requires authenticated mTLS
R3 file storage without expiry; it neither creates a bucket nor changes R3.

An unresolved host operation cannot be replaced. The next proposal requires a
persisted pending receipt, its revision as `expected_revision`, and strictly
larger generation and epoch. After a lost response or restart, `Reconcile`
replays the same request and operation ID. TerraBase returns its original
persisted receipt even when its current proposal head has advanced. A receipt
must match the exact canonical request and expected revision plus one. A newer
`Get` head does not resolve an older unknown operation.

VM engine declarations may supply explicit `engineControl` credential references.
The renderer binds their separate host NKeys to existing global accounts in
`broker-hosts.json`. `TS_ORCH_PLACEMENT_BROKER_GRANTS_FILE` applies those exact
public grants to selected embedded broker options before listeners open; it
rejects account omission, system-account grants, duplicate identities, and
reuse of broader authority keys.

The global publisher uses `orch.placement.host.<SHA256-of-engine-SPIFFE>.stage`.
Each host has a dedicated NKey with the exact `HostPermissions` allowlist and
replies only on request inboxes. Only global authority may publish stage
requests. The host bridge pins its engine endpoint and principal from local
configuration, rejects foreign identities and database metadata, and calls
TBEP with TLS 1.3 and the exact admitted server SPIFFE URI. NATS carries only
bounded placement proposals and receipts, never customer documents or data
replication traffic. The bridge is sequential with bounded pending messages.

The journal retains at most 128 host records and 480 KiB of aggregate encoded
state. Acceptance reserves space for each pending receipt before committing;
it refuses oversized intent without sending it. The complete envelope is
bounded to 1 MiB. These limits are control-plane bounds, not advertised database
capacity. Raising them requires qualifying the actual global stream limits.

Production composition in `cmd/orchestrator/runtime_placement.go` binds the
journal and dispatcher to the live GRU worker session. Domain placement and
residency validation is required before `AcceptPlacement`. The local `run`
service uses `TS_ORCH_PLACEMENT_HOST_FILE`; this JSON references separate NATS
and TBEP credentials and names the exact cell and instance. Example structure:

```json
{
  "version": 1,
  "cell": "gru",
  "instance": "member-a",
  "natsUrl": "tls://control.example:4222",
  "nkeyFile": "/etc/terrascale/placement/host.nkey",
  "natsIdentity": {
    "certificateFile": "/etc/terrascale/placement/nats.crt",
    "privateKeyFile": "/etc/terrascale/placement/nats.key",
    "trustBundleFile": "/etc/terrascale/placement/nats-ca.crt"
  },
  "engineEndpoint": "127.0.0.1:8421",
  "engineIdentity": "spiffe://terrascale.tech/production/terrabase-member/CLUSTER_ULID/MEMBER_ULID",
  "engineTls": {
    "certificateFile": "/etc/terrascale/placement/orchestrator.crt",
    "privateKeyFile": "/etc/terrascale/placement/orchestrator.key",
    "trustBundleFile": "/etc/terrascale/placement/engine-ca.crt"
  }
}
```

The example identities and paths are placeholders and must match admitted
producer configuration. The engine must allowlist the exact orchestrator
certificate SPIFFE principal for host control. The pinned producer contract is
still a worktree snapshot, not a published immutable contract artifact.

Portable tests exercise real authenticated R3 NATS, complete broker restart,
minority outage, lease takeover, delayed post-expiry commits, immutable retries
after an engine response loss, exact-host dispatch, and TBEP mTLS/metadata.
They do not qualify six production members, actual engine replication,
Firecracker, or provider deployment.

## Accepted transitions and signed readiness

Pending Stage remains separate from admission. The host control bridge also
carries `Accept`, `Drain`, and `Readiness` on distinct exact-host subjects.
`Accept` transports the exact durably issued GRU proof and its original
operation ID. Its receipt must match the staged proposal revision, epoch,
generation, and SHA256 of the authenticated proof payload. The only acceptance
status is `ADMITTED_CATCHING_UP`; it is not a readiness statement.

Before a successor can be issued, `Drain` requires a durably committed signed
`prepared_epoch` grant binding the prior accepted proof and exact next request.
The engine verifies GRU authority, drains and durably fences its own old-epoch
acknowledgments, and signs its actual final frontier receipt. Unknown replies
reuse the exact prepare bytes and operation ID. The GRU issuer independently
verifies member signatures and requires the old RF2 fence quorum before issuing
the accepted successor. The bridge never signs or synthesizes these receipts.

`Readiness` is a challenged read of an actual member proof. It carries the
explicit database tuple, durable placement operation ID, and a fresh 32-byte
nonce encoded as lowercase hex. The raw signed receipt is bounded and returned
unchanged. `databaseadmission` verifies the pinned member signatures, freshness,
nonce, exact proposal digest, same physical snapshot/WAL boundary within each
RF2 pair, and the same causal cut/frontier/root across all required members.
The runtime discards partial collections. No pending or accepted RPC receipt
can substitute for that independent data evidence.

Production database configuration requires `readinessKeys`, a map from exact
engine SPIFFE identity to `{ "key_id": "...", "public_key_file": "/..." }`.
Every admitted member must have one explicit raw32 Ed25519 public key. The
concrete collector uses the current GRU session and exact admitted host routes.
