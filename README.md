# TerraScale.Orchestrator

TerraScale.Orchestrator is the greenfield, TerraScale-specific control plane described in [ORCHESTRATOR.md](ORCHESTRATOR.md). The repository is currently in Phase 0: architecture discovery, evidence capture, toolchain pinning, and repository baseline work.

Phase 1 contract freeze is intentionally blocked until the ten owner questions and measurable cost, database-storage, RPO, and RTO targets are resolved. The repository must not start a system-under-test VM or mutate cloud infrastructure before exact-tree L0/L0C evidence authorizes it.

## Baseline validation

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --no-restore
dotnet test TerraScale.Orchestrator.slnx --no-build
```

The architecture is one operational binary assembled from strict projects. Contracts and pure decision projects stay infrastructure-free; infrastructure integrations are adapters around persisted intents and typed observations.

