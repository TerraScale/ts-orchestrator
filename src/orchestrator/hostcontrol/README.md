# Regional ts-node request/reply client

`Client` calls the existing `hostagent.Node*Subject` commands over NATS. Its
constructor requires an explicit Region, a connected NKey/JWT-authenticated
NATS client with verified TLS 1.3 and a client certificate, an admitted host
resolver, a live mutation authority callback, and a bounded request deadline.
TLS verification cannot be disabled. Use `nats.ReconnectBufSize(-1)` or
`nats.NoReconnect()` so a mutation cannot wait in a reconnect publication
buffer after its authority check.

Each request resolves the host from admission again. The node identity must
match the requested host exactly, its cell prefix must match the admitted
Region, and that Region must equal the client's Region. Bootstrap and delivery
must select the correct regional client. NATS account and subject ACLs must
restrict the node's command subscription and response publishing to its
admitted process. Replies do not contain a separate host signature. Mutations
carry the shared signed protocol envelope, binding the exact host, subject,
command payload, current regional authority candidate, lease, epoch and expiry.

`SetDrain`, `ApplyManifest`, `Deploy`, and `Rollback` require explicit stable
command IDs and return validated typed receipts. Receipts must bind the exact
command and host, and successful manifest/version changes must report the
expected digest or version. Replies reject unknown, duplicate, missing, null,
oversized, inconsistent, and malformed fields. `Status` always sends a fresh
request identity and validates the full current status. It never substitutes
a heartbeat cache, provisioning receipt, or previous observation.

No mutation is retried internally. A timeout means the remote outcome is
indeterminate. Recovery must use the same persisted command ID with the same
payload; ts-node's durable command journal handles its replay.

## Delivery adapter

`NewDeliveryControl` returns the existing `delivery.HostControl` interface.
Its release resolver supplies the complete authenticated desired host
manifest, expected predecessor manifest digest, and release architecture.
The complete manifest preserves other host components. Each artifact entry
includes the exact version and digest plus the signed binary's artifact and
signature URLs. The actual ts-node installer verifies the binary signature
and digest before advertising the desired version as installed.

The adapter accepts the canonical TerraBase systemd runtime plan and requires
its digest and architecture to match the admitted release and host. It obtains
stable IDs through `delivery.HostCommandID` and checks
`delivery.CheckExecutionFence` before every mutation. It establishes drain,
applies the manifest with CAS, polls fresh status until the target is verified
installed, deploys its exact version, and observes that version active. A
fresh matching manifest/current/installed/active report makes a completed
operation replay succeed without stopping and redeploying the target.

Rollback follows the same path with the explicitly admitted rollback
manifest/digest/version. It does not infer the desired artifact from a previous
symlink. `Cordon(false)` releases drain and confirms the result with fresh
status. The adapter does not claim TerraBase replication or backup readiness;
those remain independent gates.

## Receiver authority and verification

The client requires `SigningKey` and obtains the real regional lease through
`CommandAuthority` or the delivery execution context. The receiver independently
reads `authority.regional` using the ordinary JetStream stream-leader MSG.GET
API, checks the candidate-bound public key, exact lease and expiry, and persists
the highest accepted epoch before writing an intent or applying an effect.
Follower direct reads and cached observations cannot authorize a mutation.

The `nodeauthority` epoch file survives restart, and a lifetime flock prevents
two receivers from racing the host's command journal. Same-epoch acceptance
syncs the parent directory again so an interrupted directory sync cannot allow
an acknowledged but nondurable floor. Pending mutations require a fresh signed
reissue after restart; their fixed transition plan and command identity remain
in the journal. Completed receipts replay without repeating their mutation.
Only completed drain state is restored automatically.

The leader-only read uses the pinned NATS server's leader-routing semantics;
it does not add a consensus barrier to that API. Expired authority cancels the
command context, but an external systemd action already accepted by the OS may
finish after cancellation. Receiver epoch fencing does not assert atomicity
between a lease transition and an already-running external side effect.

Initial bootstrap activation cannot use regional authority before a real
regional lease exists. It requires an independently authenticated bootstrap
manifest/grant path with its own retirement rules. Qualification must not mint
regional leases in its root fixture to bypass that boundary. The receiver can
start and answer status with configured trust before a lease exists; new
mutations fail closed.

Portable tests run actual TLS 1.3 mTLS/NKey NATS connections. They cover signed
sender/receiver interoperability, actual JetStream lease reads, stale lease
rejection, signature tampering, deleted authority, durable epoch restart,
exclusive receiver ownership, exact artifact/manifest mapping, rollback,
replay, authority loss and indeterminate timeouts without retries. The node
responders in adapter tests model the host contract. Actual systemd mutation
and outage behavior still require executable guest qualification.

```sh
go test -race ./src/orchestrator/hostcontrol ./src/orchestrator/nodeauthority ./src/orchestrator/hostagent
```
