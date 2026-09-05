# Initial GRU R1 admission

`initial-gru-r1` starts the temporary GRU authority and membership processes
under the existing owner-signed node bootstrap grant. The seed embeds NATS,
provisions the complete initial regional and global inventories, then opens
restricted runtime connections. The participant runs its own regional
coordinator and signed membership against that same broker.

Host proof publication requires Linux. This command is a separate initial role. Ordinary `run`, production admission,
signed delivery requirements and global R3 validators keep their existing
requirements. The initial runtime does not construct global operational
workers, command ingress, delivery workers, operation journal writers or OCI
estate reconciliation.

## Original authority and command interface

The owner-signed `nodebootstrap.BootstrapGrant` binds the complete canonical
host manifest, including the orchestrator component's arguments, configuration,
artifact identity, service user and storage location. No second owner signature
or runtime-selected trust key is introduced. The signed launch is exactly:

```text
initial-gru-r1 --config @config
```

The host resolves `@config` to the immutable configuration beside the admitted
release. The executable accepts exactly `initial-gru-r1 --config FILE`.
`initialgrant.ReadConfiguration` reads bounded configuration through verified
directory descriptors. `AdmitConfiguration` compares its canonical bytes with
the original signed component, verifies the published admission and credential
material, and passes an opaque admission to `initialcontrol.Start`. The command
waits for cancellation or runtime completion and preserves runtime and cleanup
errors.

After pinning the original bootstrap grant and manifest in its private
`EpochStore`, root publishes the original public key and signed grant at:

```text
/var/lib/terrascale/host-admission/initial-gru-r1/proof.json
```

The containing directory is root-owned mode `0755`; the canonical proof is a
root-owned, single-link regular file with mode `0644`. Publication is immutable
and descriptor-relative. Runtime callers cannot choose an owner key path or
replace a public proof with a configuration-only assertion. The owner private
key is never published.

The same fixed directory holds `initial-r1.json` and its stable lock. The
record binds role, host, grant digest, original manifest, exact launch, runtime
candidate, store scope and grant lifetime. Private pending/committed publication
progress remains inside the root host `EpochStore`. Public admission remains
pending until the private commit is durable; an interrupted pending publication
can resume exactly. Committed admission does not recreate a missing public
record or lock.

Host admission checks the signed component before credential handoff. The
runtime separately validates material before effects: CA/certificate hashes,
TLS key pairing, the NKey seed's public identity, distinct membership identities
and the exact signed peer pins. Transport construction checks the captured bytes
it uses. Configuration contains public pins and file references, not private
keys or NKey seed values.

## Seed and participant

| Scope | Seed | Participant |
| --- | --- | --- |
| Embedded broker | Sole broker, exact signed inline configuration | Connects to the signed seed endpoint |
| Provisioning | Separate regional and global provisioner identities | No provisioner credentials |
| Regional runtime | Own restricted NKey, coordinator and membership signer | Own distinct restricted NKey, coordinator and membership signer |
| Global runtime | Separate restricted identity and coordinator | No global connection or credentials |
| Storage | One regional account and one global account | Uses the seed's regional account |

The signed peer list is sorted and unique. Both hosts retain separate grants
and admission records; each grant binds its own launch and credentials. They
share the broker scope and retained-profile digest computed using the seed
instance. A participant neither starts another independent R1 store nor reuses
the seed's runtime or membership identity.

Provisioner connections close before coordinators start. Restricted runtime
permissions allow profile inspection, the relevant authority key, and each
regional process's own membership record and membership-watch consumers. They
do not grant stream or bucket provisioning, profile replacement, sibling
membership writes or global operational effects.

## Retained profiles and storage budget

`initialcontrol.ProfileDigest` binds the complete initial stream, KV, object
store and durable consumer configurations. The initial projection uses R1 while
retaining the production data limits and profile semantics. The regional and
global `ORCH_LEADERS` buckets belong to separate accounts.

| Account | Retained resource | Limit |
| --- | --- | ---: |
| Regional | `CELL_SPEC` | 256 MiB |
| Regional | `CELL_OPERATIONS` | 1,024 MiB |
| Regional | `CELL_EVENTS` | 256 MiB |
| Regional | `KV_ORCH_LEADERS` | 8 MiB |
| Regional | `KV_ORCH_RUNTIME` | 8 MiB |
| Regional | `KV_ORCH_DELIVERY` | 256 MiB |
| Regional | `KV_ORCH_COMMAND_REPLAY` | 16 MiB |
| Regional | `KV_ORCH_OPERATIONS` | 256 MiB |
| Regional | `KV_ORCH_OPERATION_PROOFS` | 8 MiB |
| Regional | `OBJ_CELL_BUNDLES` | 256 MiB |
| Regional | `OBJ_ORCH_PROTOCOL_PACKAGE` | 256 KiB |
| Global | `GLOBAL_SPEC` | 256 MiB |
| Global | `KV_ORCH_LEADERS` | 8 MiB |
| Global | `KV_GLOBAL_CELLS` | 64 MiB |
| Global | `KV_GLOBAL_DELIVERIES` | 1,024 MiB |

The regional consumers are `runtime_startup` on `CELL_EVENTS` and
`gitops_cell_spec_{seedInstance}` on `CELL_SPEC`. The global consumer is
`global_cell_spec_gru` on `GLOBAL_SPEC`. Their complete consumer profiles are
verified, including filters, acknowledgment, retry, delivery and replica
settings. The regional protocol object contains the exact embedded package.
CI stores and runner credentials are absent.

Regional limits total 2,344.25 MiB and global limits total 1,352 MiB.
`RequiredStorageBytes` adds 256 MiB of overhead: 3,952.25 MiB
(4,144,234,496 bytes) for this inventory. The signed broker budget must cover
that result; startup also checks filesystem free space. These figures are
configured retention ceilings and startup checks, not measured allocation,
performance or idle resource usage.

Provisioning rejects unexpected stores and mismatched existing profiles before
creating missing resources within each account. It does not rewrite conflicts
into the expected shape. Restart can finish a partially created matching
inventory. Full profile readback precedes runtime coordinator construction.
The embedded broker accepts only the signed accounts, NKeys, permissions,
endpoint, store directory and pinned TLS configuration; it exposes no cluster,
gateway, leaf-node, monitoring or alternate authentication route.

The runtime captures credentials through the same descriptor-based reader as
admission and checks their signed pins before use. It validates the signed TLS
declaration, removes TLS paths before NATS parses the remaining configuration,
and attaches the captured TLS material before option validation and startup.
The broker parser cannot reopen those paths. Runtime and global worker clients
share cancellation-aware NATS connection setup through DNS, TCP, TLS and PONG.

## Expiry, retirement and interrupted replacement

The initial admission lifetime is the original finite grant lifetime. Broker
startup, provisioning, lease mutations and membership writes hold the shared
admission lock and use bounded contexts capped by that lifetime. Supervision
checks admission and stops coordinators, membership, clients and the seed broker
on expiry, retirement or a terminal component failure. A callback that ignores
cancellation retains its shared lock; retirement times out instead of claiming
that concurrent mutation has stopped.

Runtime connections disable reconnect. A closed connection terminates the
initial process with an error so systemd can restart through fresh admission.
Normal shutdown marks closure before disposing components, preventing their
expected completion from being reported as a new runtime failure.

Regional command epoch advancement permanently retires the host's bootstrap
command authority. Initial R1 runtime admission has a separate monotone
retirement record because regional command authority may become available
before global R1 ends.

The existing authenticated ApplyManifest handler writes retirement before
replacement manifest or unit effects. It uses the actual verified
`CommandAuthorization`, its persisted regional floor, and the strict shared
ApplyManifest parser. Retirement binds command ID, predecessor and replacement
manifest digests, authority identity, epoch, candidate and lease. A later
accepted regional tuple can retry the same logical transition; it cannot
change the original retirement receipt. No separate retirement endpoint or
caller-supplied epoch assertion is added.

The command journal records pending ApplyManifest intent before retirement.
If the host crashes after retirement but before replacing the old manifest,
startup requires a pending strict ApplyManifest with the same predecessor and
no initial component, then hydrates an empty desired set. The host receiver can start and await a freshly authenticated retry
without relaunching the retired initial component. Startup performs no pending
command effects. A stale retired manifest without the matching pending intent
fails startup. The retry must still match the immutable retirement receipt.
Installed-release checks also reject retired initial launches
at actual unit transition boundaries, including rollback.

## Remaining activation-to-R3 work

This slice supplies initial broker provisioning, authority and membership,
and the consumer-side retirement boundary for an authenticated replacement.
It does not supply the end-to-end activation-to-R3 producer/consumer chain:
constructing and delivering the admitted replacement manifests and credentials,
starting and synchronizing the SFO/FRA storage participants, promoting and
verifying actual R3 profiles and quorum, and retiring every host's initial
admission through the verified replacement path. Control action records and
provider receipts alone cannot authorize that transition.

Production `run` still requires its concrete composition and external adapters.
Global operational workers remain R3-only. Passing focused admission, broker
and host-recovery tests does not establish successful guest activation, OCI
resource operations, TerraBase production membership, fourth-Region behavior
or production readiness. Those require their own executable integration and
qualification evidence.
