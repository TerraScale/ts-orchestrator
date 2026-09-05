# TerraScale.Orchestrator design

Status: current Go implementation map, not product authority. The workspace
[`GOAL.md`](../GOAL.md) and repository [`GOAL.md`](GOAL.md) control target
architecture and replacement work. Package names and adapter contracts below
describe code that exists today; they do not preserve a retired topology.

## Module

- Module path: `terrascale.tech/orchestrator`, Go 1.27, single module.
- Binary entry points: `cmd/orchestrator` (runtime), `cmd/ts-node` (host
  agent), `tools/orchestrator-tooling` (repository validation), and
  `tests/journalchild` (the fixture executable spawned by control journal
  tests).

## Package map

| Area | Go package | Imports |
| --- | --- | --- |
| Contracts | `src/orchestrator/contracts` | — |
| Protocol | `src/orchestrator/protocol` | contracts |
| Runtime | `src/orchestrator/runtime` | — (leaf) |
| Security | `src/orchestrator/security` | — (leaf) |
| Scheduling | `src/orchestrator/scheduling` | — (leaf) |
| Estate (declared desired state) | `src/orchestrator/estate` | — (leaf) |
| Provider (OCI cloud) | `src/orchestrator/provider` | — (leaf) |
| Control plane (delivery, messaging, observability, operations) | `src/orchestrator/control` | contracts, protocol, runtime, security |
| Bootstrap (embedded NATS) | `src/orchestrator/bootstrap` | security, control |
| Host agent | `src/orchestrator/hostagent` | runtime |
| CLI / process entry | `cmd/orchestrator` | control, provider |
| VM qualification core | `src/orchestrator/vmqual` | shared configuration, lifecycle, journals, diagnostic/resource evidence, guest contracts |
| Firecracker qualification runtime | `src/orchestrator/vmqualruntime` | vmqual, sandboxvm, vmnet, vmdisk, vmimage, production host/provider packages |
| Qualification scenarios | `src/orchestrator/vmqualsuite` | vmqual, production controllers, sandboxproviders |

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
[`GOAL.md`](GOAL.md). Its Go `SandboxVMProvider`, Firecracker Unix-socket
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
