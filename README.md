# TerraScale.Orchestrator

TerraScale.Orchestrator is the greenfield, TerraScale-specific control plane described in [ORCHESTRATOR.md](ORCHESTRATOR.md). The repository is currently in Phase 0: architecture discovery, evidence capture, toolchain pinning, and repository baseline work.

Phase 1 contract freeze is intentionally blocked until the ten owner questions and measurable cost, database-storage, RPO, and RTO targets are resolved. The repository must not start a system-under-test VM or mutate cloud infrastructure before exact-tree L0/L0C evidence authorizes it.

## Baseline validation

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --no-restore
dotnet test TerraScale.Orchestrator.slnx --no-build
```

The architecture is one operational binary built from one production project. The code is organized by capability inside `src/TerraScale.Orchestrator`; pure decisions stay separate from infrastructure adapters through namespaces and directory boundaries rather than project ceremony.

## Run

The orchestrator requires NATS with JetStream enabled. `check` reconciles the regional control resources, verifies the NATS service endpoint through request/reply, and exits. `run` performs the same checks and keeps the discoverable service online until shutdown.

```bash
TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=nats://127.0.0.1:4222 \
TS_ORCH_REPLICAS=1 \
dotnet run --project src/TerraScale.Orchestrator -- check

dotnet run --project src/TerraScale.Orchestrator -- run
```

Use `TS_ORCH_REPLICAS=3` with a production regional NATS cluster. Startup reconciles the `CELL_SPEC`, `CELL_OPERATIONS`, and `CELL_EVENTS` file-backed JetStream streams, the `ORCH_LEADERS` and `ORCH_RUNTIME` KV buckets, the `CELL_BUNDLES` Object Store, and the cell-scoped NATS health service. It writes and reads the versioned protocol package through Object Store, whose retrieval verifies the stored digest, before accepting the bytes. Runtime registration is revision-fenced: startup creates and watches a unique `starting` entry, compares-and-swaps it to `ready`, observes that revision, and conditionally deletes it during shutdown. The health endpoint is distributed through a cell queue group; readiness verifies its standard NATS service discovery metadata and request statistics. The orchestrator also publishes a deduplicated startup event with protocol/cell/correlation headers, receives it through a bounded durable pull consumer, validates the metadata, and explicitly acknowledges delivery.
