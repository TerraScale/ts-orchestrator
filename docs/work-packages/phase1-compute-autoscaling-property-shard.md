# Phase 1 compute autoscaling property shard

- Owner: `phase1_compute_properties`
- Allowed production paths: `src/TerraScale.Orchestrator.ControlPlane/Compute/**`
- Allowed test paths: `tests/TerraScale.Orchestrator.ControlPlane.Tests/ComputePolicyCompletenessPropertyTests.cs`, narrowly scoped fixture correction in `ComputeEngineTests.cs`
- Requirements: `REQ-O009`, `REQ-O010`, `REQ-O011`; invariants 4-8 and 14
- Boundary: pure `DecideScaleOut`, `DecideScaleIn`, and `DecideSurvival` policy only. No provider, cloud, NATS, network, process, filesystem, deployment, or lab execution.

## Deliverable

Audit existing example and property coverage, then add generated independent-oracle cases for ordered authorization denial, exact checkpoint prefixes, authority epochs/generations, critical floors, N+1 availability, stateful drain/reclaim semantics, and regional survival authorization. Any production hardening must be tied to a reproduced pure-policy defect and preserve construction-closed outputs.

## Evidence boundary

Focused in-process tests are evidence for pure policy behavior only. They do not qualify OCI, NATS, systemd, rootless container, regional failover, or any deployment acceptance level.
