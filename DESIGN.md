# TerraScale.Orchestrator Go migration design

Status: active Go implementation. This document is the binding contract for
the package layout and wire-compatible behavior, following the approach proven
in `ts-internals` (see ../ts-internals/docs/go-migration/DESIGN.md). Historical
source names in the mapping below identify where contracts originated; they are
not active source paths or build inputs.

## Module

- Module path: `terrascale.tech/orchestrator`, Go 1.27, single module.
- Binary entry points: `cmd/orchestrator` (runtime),
  `tools/orchestrator-tooling` (repository validation), and `tests/journalchild`
  (the fixture executable spawned by control journal tests).

## Package map (historical source area → Go package)

The historical dependency analysis (folder-level import graph) shows
ControlPlane, Delivery, Messaging, Observability and Operations form one
strongly connected component, so they share ONE Go package:

| Historical area (files, lines) | Go package | Imports |
| --- | --- | --- |
| Contracts (12, 1.5k) | `src/orchestrator/contracts` | — |
| Protocol (23, 4.7k) | `src/orchestrator/protocol` | contracts |
| Runtime (9, 2.3k) | `src/orchestrator/runtime` | — (leaf) |
| Security (4, 1.2k) | `src/orchestrator/security` | — (leaf) |
| Scheduling (4, 1.4k) | `src/orchestrator/scheduling` | — (leaf) |
| ControlPlane + Delivery + Messaging + Observability + Operations (212, 63k) | `src/orchestrator/control` | contracts, protocol, runtime (+ security via root) |
| Bootstrap (6, 0.9k) | `src/orchestrator/bootstrap` | security, control |
| Root files (Program.cs, OrchestratorRuntimeConfiguration/Composition, ProcessLifecycle, CellTokenRule, BuildVersion, OrchestratorOptions, AssemblyInfo) | `cmd/orchestrator` + `src/orchestrator/control` for the pieces other code calls | control etc. |
| CLI source | `cmd/orchestrator` | control |
| Repository tooling | `tools/orchestrator-tooling` | — (standalone) |
| tests/*.Tests projects | `*_test.go` inside the matching package (control tests in src/orchestrator/control, protocol tests in src/orchestrator/protocol, …) | |

Within `src/orchestrator/control`, use concise snake_case filenames named for
the Go responsibility (`authority_engine.go`, `journal_store.go`). Package and
symbol names carry the contract identity; filenames must not concatenate the
old C# folder and class names.

## Stack mapping

| .NET | Go |
| --- | --- |
| NATS.Net (core + JetStream) | github.com/nats-io/nats.go (JetStream context) — same subjects, stream/config names, headers, NKey/creds/JWT auth semantics |
| OCI.DotNetSDK.Core (Oracle Cloud) | github.com/oracle/oci-go-sdk/v65 — same API calls/regions |
| OpenTelemetry OTLP export | go.opentelemetry.io/otel + otlp exporters |
| ZString | strings.Builder / fmt |
| System.Text.Json | encoding/json, SetEscapeHTML(false); mirror casing (camelCase for Web defaults, PascalCase for default options) and null semantics (pointers) exactly |
| System.Security.Cryptography (certs, signatures) | crypto/x509, crypto/ecdsa, crypto/ed25519, crypto/rand |
| Microsoft.Extensions.* (hosting/logging/config/DI) | explicit constructors + log/slog + env/JSON config loader (follow ts-internals src/core/hosting idioms — copy the helper if needed) |
| Spectre-free CLI dispatch in Tooling/CLI | manual dispatch like ts-internals src/cli |
| CancellationToken | context.Context (first param) |
| async Task | (T, error) returns |
| Records | structs, exported same-name fields |
| Exceptions | error returns; typed error structs where callers distinguish |
| Static classes | `var Name name` (unexported struct) with methods, so call sites read like C# |
| Interlocked/locks | sync/atomic, sync.Mutex |
| Channels/TaskCompletionSource | native Go channels, sync.Cond |

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
   filenames. Do not preserve C# folder prefixes or one-class-per-file naming
   when that makes the Go package harder to navigate.
2. Keep C# type names. Interfaces keep their C# names; ports become
   one-method Go interfaces where the C# had single-method interfaces.
3. `go build ./... && go vet ./... && gofmt -l .` clean; ported packages get
   their C# tests ported into `*_test.go` (skip no-longer-meaningful
   .NET-pinning tests; note skips in the report).
4. Fail-closed semantics preserved everywhere (admission, verification,
   secrets handling). Never log secret material.
5. Do not create import cycles beyond the C# project graph (single C#
   project = the `control` package absorbs all intra-cycle areas).
