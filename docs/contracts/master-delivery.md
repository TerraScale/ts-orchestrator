# Master delivery

`MasterDelivery.Submit` accepts a bounded signed `CommandEnvelope` for cell
`gru`, aggregate `delivery-master`, with an existing delivery Request v1 as its
payload. The master accepts at most 256 KiB of intent payload and 512 KiB of
original envelope, and validates every expanded child envelope and the complete
journal record before any mirror write. Its epoch names the live GRU global authority. Every target must be in
the configured estate and have an explicit regional route. No target is added.

Before provider work, the master journals the original signed envelope, its
payload digest, desired generation, idempotency identity, and deterministic
child operation IDs. The original envelope remains immutable through recovery.
A conflicting operation, payload, generation, or idempotency identity fails.
A newer admitted global desired generation fences earlier work.

The global owner verifies the release signature and durably saves its raw detached
signature before the first mirror PUT. It mirrors the exact bytes to
all estate regions, and reads and hashes those objects before regional fanout.
Preparation is recorded only after that verification succeeds. Recovery of a
prepared operation verifies the objects again without rewriting them or fetching
Forgejo. Partially prepared operations recover from any mirror whose actual bytes
match the signed digest and saved signature; registry fallback is allowed only
while preparation is incomplete. Completed parent replays return the durable
receipt after authority and lineage validation.

Each child has a separately signed envelope whose payload contains `version`,
`parentEnvelope`, `globalLease`, `releaseSignature`, and `request`. The request remains Request v1;
only its operation ID and target region list differ from the parent. The durable
parent record binds each child operation and request digest. The wrapper binds
the current signed parent to the global lease epoch, candidate, and lease ID.
The required 64-byte release signature lets regions read mirrored bytes and verify
them under their current release trust without calling Forgejo. The digest, source
version, architecture, and service remain bound to the original signed request.
The child envelope names its exact regional cell and freshly observed regional
writer epoch. This epoch does not assert that the
master holds the regional lease: the receiving regional controller must still
hold and reread that lease before execution. Regional command trust must
explicitly include the configured master signer key for each route. Regional
admission additionally requires `MasterDeliveryAdmissionConfig` with separate
master and original-intent verifiers and a connection to the authoritative global
lease. Every regional delivery requires the wrapper; bare requests are rejected. Regional execution rereads the global
lease identity at admission and every subsequent effect alongside its regional
lease. A delayed old-master command is rejected even if regional leadership has
not changed.

The master rereads global authority before every preparation mutation, durable
progress update, and regional publication. Routes use authenticated mTLS/NKey
NATS connections without reconnect publication buffering. A bounded exact
`accepted` reply marks one child complete. Timeout or any other reply leaves the
child incomplete. Recovery uses its same operation ID and payload, but a fresh
signed attempt, allowing the regional durable journal to prove a prior result.
Already acknowledged children are skipped. Success requires durable acceptance
from every original target; partial acceptance is retained and returned as an
error until recovery completes it.

The caller owns the connections and provisions the persistent master journal.
The adapter neither provisions global R3 nor changes regional membership.

`GlobalNatsRuntimeConfiguration.DeliveryEnabled` requires a concrete
`MasterDeliveryRuntimeConfig`. The global runtime opens the preprovisioned
`GLOBAL_DELIVERIES` R3 FileStorage bucket with no TTL, binds its own live global
authority and connection, and subscribes to `ts.orch.v1.global.release.delivery`.
Followers stay silent. The writer passes the unchanged signed bytes to `Submit`
and returns bounded JSON containing `code` and the durable `receipt` when present.
Only `accepted` with a complete receipt proves completed fanout. Missing replies
and `dispatch-failed` require resuming the same intent lineage.

The runtime owns the subscription and cancels in-flight work on shutdown. The
caller owns regional connections and signing keys. Command composition requires
explicit regional `Delegation`, shares its original-intent verifier and release
trust with the optional master, and gives both the same root-owned mirror.
`productionRuntime.BindGlobalDelivery` installs the admitted master inputs into
the GRU global configuration. It rejects missing master inputs, non-GRU binding,
and master inputs left unused by a process without a global runtime.

The default `admitProductionRuntime` resolver still returns the missing-composition
error. Production startup requires that resolver to admit credential references
and build real adapters after the embedded broker is ready. Each regional process
needs an authenticated global lease-reader connection and explicit master and CI
intent trust. GRU additionally needs the Forgejo fetcher, master signing key, and
an authenticated command route with a leaders bucket for each admitted region.
Those routes must install the master's signer in regional command trust. The
provider mirror's ownership callback must fence global preparation writes.
Infrastructure must provision the exact `GLOBAL_DELIVERIES` profile and grant
leader-routed KV reads and the bounded delivery subjects. Connection and signer
owners must keep them alive until both control runtimes have stopped.
