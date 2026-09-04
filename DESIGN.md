# TerraScale.Orchestrator design

Status: active Go implementation. This document is the binding contract for
the package layout and wire-compatible behavior.

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

## Contracts that must stay EXACT

- NATS subjects, stream names, consumer names, message JSON payloads, headers,
  and the `ts.orch.v2` domain naming.
- Journal/persistence file formats and digest rules (sha256, canonicalization).
- Certificate/trust-bundle formats and validation rules; NKey/creds handling.
- CLI commands, options, exit codes, output strings of `cmd/orchestrator` and
  the tooling dispatcher.
- Env var names and defaults (TS_ORCH_*, TS_ORCH_CELL, etc.).
- Control-plane message protocol versioning and admission rules.

## Rules

1. Keep cohesive Go responsibilities together and use concise snake_case
   filenames.
2. `go build ./... && go vet ./... && gofmt -l .` clean; behavior changes ship
   with the tests that pin them.
3. Fail-closed semantics everywhere (admission, verification, secrets
   handling). Never log secret material.
4. Keep the package graph acyclic: the `control` package absorbs anything
   that would otherwise cycle.
