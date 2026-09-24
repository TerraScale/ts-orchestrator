# Actual Firecracker execution, 2026-09-06

The exploratory `vm-qualify test` invocation booted one real GRU guest and failed
while activating TerraBase. It did not qualify the six-guest estate or any of the
18 required scenarios. GRU member 2 and both SFO/FRA members were not booted.

## Exact executed artifacts

| Artifact | SHA-256 |
| --- | --- |
| TerraBase static PIE | `0cd416efd26395ee34ed725da381ab30c6b40b5ef188da91928ebf226539382d` |
| ts-node | `261794ff81d38c7db1240407be6ba44d4c9d86a194a13bfa7a55b051dd47d828` |
| orchestrator | `694b69a8147a6afc0f5e0fc10052cc287e931242b7d9a24d27379d025b5f117d` |
| attempt 8 runner | `73aeca8618f7408490ce6469080b3f2f5aee0ff077313f272e5a72b51e51cd50` |

TerraBase is the explicitly authorized **pre-origin-epoch-fix** exploratory
artifact, not corrected restore evidence. Its frozen source archive is
`.agents/swarm-production/server-build/pre-origin/source.tar.gz` in the parent
workspace, SHA-256
`b88cc9028f0101cc1031e4e9f0e4e0f5d4233e46c5194365769e5f36242b39a4`.
The source manifest SHA-256 is
`afbf76ef22ded5d16258ba698bec9ca9ef26bfdbc33f4ec20dadf9d1c403426c`.

Exact signed binaries, signatures, declarations, and private diagnostic artifacts
are retained under `/var/lib/tsq-astra/astra-current/`. The full declaration is
preserved beside each generated initial-stage declaration with suffix `.full-run`.
No private material belongs in this document or public evidence.

## Observed attempt 8

The suite ran from `2026-09-07T00:26:52Z` to `00:30:10Z`. Firecracker successfully
started GRU member 1 at `00:28:19Z`; Ubuntu 24.04.3 completed cloud-init, verified
the ts-node checksum/signature, and started the host agent. Activation diagnostics
observed ts-node and orchestrator units running. TerraBase was in auto-restart with
exit status 1, so the runner failed before scenario execution.

The report's `scenarios` is null. Bootstrap, add-region, control-r3, fourth-region,
reconcile, signed-delivery, rollback, edge-promotion, kv-routing,
estate-publication, self-heal, key-rotation, fault-matrix, restore, degraded,
partition-heal, placement, and cleanup scenario bodies were **not executed**.
Automatic failure cleanup did run: provider paths were absent, six local provider
listeners were unreachable, and no owned network namespaces or VMM process remained.

Attempt 9 repeated the actual guest boot using a recorded local diagnostic Go
overlay (runner SHA-256
`e33c58d345b6952720282ab84faa622fa8918133786d053271b7298e8139c339`).
Before normal cleanup, it retained the existing allowlisted bounded journal query
in root-private files. TerraBase reported `Error: InvalidProductionBoundary` twice.
The frozen parser's `config.rs:1061` rejects an enabled database without backup
configuration. `internal/testengineconfig/private.go` declares a selected database
without `Backup`, and the renderer emits `enabled = true`. A real explicit backup
destination policy and protected credentials must be supplied; removing the
production requirement would not qualify the intended runtime. The recorded
overlay and journal files remain in the private run evidence directory.

## Concrete blockers and corrections

1. The original run directory was user-owned while root read protected
   declarations. Corrected only that owned directory's ownership.
2. A full declaration includes optional production `run --config` placement and
   database host material, but `vmcontrolseed.LaunchManifest` replaces the
   orchestrator command/configuration with strict `initial-gru-r1` inputs.
   Existing validators correctly reject that mismatch. The exploratory input
   explicitly deferred those two optional host objects; it retains member TLS,
   observer identity, and database declarations. This is not full runtime admission.
3. `validateDatabaseManifest` incorrectly decoded the unrelated initial-grant
   schema even when no database host material existed. Added the same absent
   material guard used by its apply method and the control validator. The package
   test passes and still rejects declared invalid material.
4. The long prepared root produced a 132-byte API socket path; Linux permits 107.
   An independent state-root override then violated cleanup resource containment.
   Moving the entire isolated run to `/var/lib/tsq-astra` fixed both setup issues.

## Required actual caller integration

`firecrackerFactory.ConfigureQualificationControlRuntime` currently has no caller.
Its inputs require authenticated host-control clients, actual guest NATS stores,
admitted member identities, live lease IDs/terms, stream assignments, and signed
action manifests. `QualificationControlRuntime` rejects an absent runtime.
`qualificationRuntimeServices.Bootstrap` also refuses non-GRU bootstrap without
admitted allocation and controller configuration.

The missing GRU issuer/run producer and broker enrollment are tracked in
[the capacity handoff](capacity-runtime-2026-09-06.md). Connecting these real
producers is required before the full declaration can transition from initial
GRU to production run and before six-guest qualification can succeed. No runner
may infer admitted membership or authority from guest liveness.
