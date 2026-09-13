# TerraScale.Orchestrator design

Status: current Go implementation map, not product authority. The workspace
[`GOAL.md`](../GOAL.md) control target
architecture and replacement work. Package names and adapter contracts below
describe code that exists today; they do not preserve a retired topology.

## Module

- Module path: `terrascale.tech/orchestrator`, Go 1.27, single module.
- Binary entry points: `cmd/orchestrator` (runtime and control commands),
  `cmd/ts-node` (host agent), `cmd/vm-artifacts`, `cmd/vm-guest-control`, and
  `cmd/vm-qualify` (qualification tooling), plus
  `src/TerraScale.Orchestrator.Tooling` (repository validation) and
  `tests/journalchild` (the fixture executable spawned by control journal
  tests).

## Package map

| Area | Go package | Imports |
| --- | --- | --- |
| Contracts | `src/orchestrator/contracts` | — |
| NATS subjects, accounts and capability policy | `src/orchestrator/natspolicy` | contracts |
| Protocol envelopes and delivery semantics | `src/orchestrator/protocol` | contracts, natspolicy |
| GRU operational NATS client | `src/orchestrator/globalclient` | control/directory, natsconnect |
| Captured-identity NATS connection | `src/orchestrator/natsconnect` | NATS client |
| Signed initial GRU admission | `src/orchestrator/initialgrant` | hostmanifest, nodeauthority, nodebootstrap |
| Temporary GRU authority runtime | `src/orchestrator/initialcontrol` | initialgrant, bootstrap, control, natsconnect |
| Scheduled service lifecycle | `src/orchestrator/lifecycle` | — (leaf) |
| Runtime | `src/orchestrator/runtime` | — (leaf) |
| Security | `src/orchestrator/security` | — (leaf) |
| Scheduling | `src/orchestrator/scheduling` | — (leaf) |
| Estate (declared desired state) | `src/orchestrator/estate` | — (leaf) |
| OCI transport, ownership and resource adapters | `src/orchestrator/provider` | delivery, errs |
| OCI reconciliation and bootstrap | `src/orchestrator/ocireconcile` | provider, estate, errs, tsnodebootstrap |
| Control plane (delivery, messaging, observability, operations) | `src/orchestrator/control` | contracts, protocol, runtime, security |
| Bootstrap (embedded NATS) | `src/orchestrator/bootstrap` | security, control |
| Host manifest and canonical handoff | `src/orchestrator/hostmanifest` | errs |
| Host agent | `src/orchestrator/hostagent` | runtime, hostmanifest |
| Initial host grant wire and signing | `src/orchestrator/nodebootstrap` | protocol, security |
| Initial local host activation | `src/orchestrator/hostbootstrap` | hostagent, nodeauthority, nodebootstrap |
| Initial host credentials | `src/orchestrator/hostsecrets` | OCI Go SDK instance identity and Secrets API |
| Production rotation and global state | `src/orchestrator/keyrotation` | security, control/authority |
| Authenticated host client | `src/orchestrator/hostcontrol` | hostagent, delivery |
| OCI control snapshot storage | `src/orchestrator/restoresnapshot` | restoredrill, provider, delivery |
| CLI / process entry | `cmd/orchestrator` | control, provider, ocireconcile |
| VM qualification core | `src/orchestrator/vmqual` | shared configuration, lifecycle, journals, diagnostic/resource evidence, guest contracts |
| Read-only member diagnostic | `src/orchestrator/memberobserve` | tbep |
| Guest startup diagnostic parsing | `src/orchestrator/guestdiagnostic` | standard library only |
| Firecracker qualification runtime | `src/orchestrator/vmqualruntime` | vmqual, sandboxvm, vmnet, vmdisk, vmimage, guestdiagnostic, production host/provider packages |
| Qualification grant issuer and activation | `src/orchestrator/vmqualbootstrap` | hostagent, security |
| Guest controller configuration | `src/orchestrator/vmcontrolseed` | control, hostagent, security |
| Qualification scenarios | `src/orchestrator/vmqualsuite` | vmqual, production controllers, sandboxproviders |

The table above names the primary package boundaries. The repository also
contains supporting packages such as `authbootstrap`, `brokeradmission`,
`databaseadmission`, `databaselifecycle`, `enrollment`, `hostplatform`,
`lifecycleaggregate`, `placementpublisher`, `placementrelocation`,
`qualificationstate`, `runmaterial`, `sourcepublication`, `storageplan`,
`systemdlimits`, `transferplan`, `transitiongrant`, `transitionreceipts`,
`vmcandidateseed`, `vmqualartifact`, and `writebudget`. The authoritative
package inventory is `go list ./...`; this document intentionally does not
duplicate the full generated list.

Within `src/orchestrator/control`, use concise snake_case filenames named for
the Go responsibility (`authority_engine.go`, `journal_store.go`). Package
and symbol names carry the contract identity.

## Go conventions

- NATS through `github.com/nats-io/nats.go` (JetStream context).
- OCI cloud access through raw `net/http` transports in `src/orchestrator/provider`.
- JSON through `encoding/json` with `SetEscapeHTML(false)`; wire casing
  (camelCase for Web-style payloads, PascalCase elsewhere) and null
  semantics (pointers) are part of each contract.
- Certificates and signatures through `crypto/x509`, `crypto/ecdsa`,
  `crypto/ed25519`, `crypto/rand`.
- Cancellation through `context.Context` as the first parameter; async
  boundaries are `(T, error)` returns.
- Service singletons are `var Name name` (unexported struct) with methods.
- Concurrency through `sync/atomic`, `sync.Mutex`, channels, `sync.Cond`.

## Current compatibility-sensitive contracts

- NATS subjects, stream names, consumer names, message JSON payloads, headers,
  and the `ts.orch.v1` domain naming.
- Journal/persistence file formats and digest rules (sha256, canonicalization).
- Certificate/trust-bundle formats and validation rules; NKey/creds handling.
- CLI commands, options, exit codes, output strings of `cmd/orchestrator` and
  the tooling dispatcher.
- Env var names and defaults (TS_ORCH_*, TS_ORCH_CELL, etc.).
- Control-plane message protocol versioning and admission rules.

This is a greenfield implementation. Replace these contracts wherever the goal
requires it, update every consumer, test, and document together, and delete the
superseded implementation in the same series. Do not retain compatibility
adapters, legacy readers, aliases, or migration shims. The final design must
still prove durable operation recovery and safe release rollback.

## Local qualification boundary

The required end-to-end test path is the Firecracker architecture in
[`GOAL.md`](../GOAL.md#ts-orchestrator). Its Go `SandboxVMProvider`, Firecracker Unix-socket
client, provider-contract endpoints, guest-image builder, and fault controller
live only in test or tooling packages. Production packages may depend on
provider-neutral behavior contracts, but never on Firecracker, TAP management,
`nftables`, `tc`, test credentials, or local provider endpoints.

The qualification stack runs the production `ts-node`, orchestrator, and
TerraBase binaries in Ubuntu LTS guests under systemd. Host lifecycle,
delivery, repair, storage, networking, and degraded mode are not complete when
proved only by in-process fakes.

## Rules

1. Keep cohesive Go responsibilities together and use concise snake_case
   filenames.
2. `go build ./... && go vet ./... && gofmt -l .` clean; behavior changes ship
   with the tests that pin them.
3. Fail-closed semantics everywhere (admission, verification, secrets
   handling). Never log secret material.
4. Keep the package graph acyclic: the `control` package absorbs anything
   that would otherwise cycle.

The qualification command composes `vmqualruntime` factories and networks with
`vmqual` stacks and `vmqualsuite` scenarios. Runtime and suite implementations
both import the core; neither implementation package imports the other.
Shared delivery/fault observations live in the core. Stack readers receive
synchronized copies of topology and VM handles. The single-guest cleanup
probe has its own validated constructor and fault lifecycle; the baseline
constructor continues to require six guests. The command explicitly requires
kernel resource evidence for real qualification runs.

Startup failures capture bounded console and metrics evidence before automatic
cleanup. The stack retains those observations for suite reporting after the
owned guest paths and cleanup journal have been removed.

Every qualification guest must report an active local orchestrator unit. The
`Guest.Control` flag designates a global control replica and does not exempt
other member hosts from local orchestrator health checks.

The full `vm-qualify test` profile declares two IAD network slots alongside the
six launch hosts. It starts only GRU/SFO/FRA before control admission. The
fourth-region scenario first accepts the control proof, then commits both IAD
resource plans to the cleanup journal before starting either guest. Both new
hosts must return live identity and readiness observations; neither becomes a
global control replica. The existing memory, disk, and idle budgets still apply
to all eight hosts. Journal recovery accepts the two IAD identities only when
the validated owned network journal contains that Region, and it preserves both
host cleanup obligations together. The `stack` profile remains six guests.

Qualification networks journal temporary host INPUT rules before applying
them. Each rule accepts one declared endpoint on its exact root veth, from the
Region uplink /32 to the listener /32, with the declared protocol and port.
Full run ownership comments and exact rule specifications identify cleanup
targets. Cleanup preserves unrelated firewall rules and retains the host
allocation lease if deletion fails. Qualification requires a trusted iptables
executable; it never changes host firewall policies or flushes host chains.

Bootstrap control transitions use authenticated host observations, signed
membership pins, actual authority leases, and the complete declared JetStream
assignments. OCI instance tags identify owned resources; they cannot prove that
a controller started, synchronized state, or formed a storage quorum. Regional
membership epochs and global election terms are separate values.

The qualification broker uses disposable mTLS and per-host NKey identities.
Its bounded file store is registered in the stack cleanup journal before
creation. Crash cleanup validates the exact run path and ownership marker;
orderly cleanup retains the journal if the service store remains. This broker
is a fixture transport and cannot establish guest global authority or R3.
