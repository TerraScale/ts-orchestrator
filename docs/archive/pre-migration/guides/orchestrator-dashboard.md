# Orchestrator observer commands

The current C# runtime does not ship a standalone dashboard binary. Its
read-only operator surface is exposed by the main executable and is intended
for an authenticated operator environment:

```bash
dotnet run --project src/TerraScale.Orchestrator -- operator status
dotnet run --project src/TerraScale.Orchestrator -- operator members
dotnet run --project src/TerraScale.Orchestrator -- operator operator-status
dotnet run --project src/TerraScale.Orchestrator -- operator stats
```

All commands require a `tls://` NATS endpoint, a private operator NKey,
and complete mTLS files. They accept `--cell`, `--nats-url`, `--nkey-file`,
`--tls-ca-file`, `--tls-cert-file`, and `--tls-key-file`; the same values may
be supplied through the `TS_ORCH_*` environment variables. They return bounded
JSON observations and have no mutation routes.

`operator operator-status` calls the authenticated regional
`ts.orch.v2.<cell>.query.operator-status` endpoint. It reports desired,
observed, and ready replicas, bounded actions and needs, and convergence
progress for each admitted workload. Each workload also reports its independent
minimum/maximum replica policy and the pending scale action (`scale-out`,
`scale-in`, `hold`, or `blocked`), so changing `ts-auth` capacity cannot change
the TerraBase target. `operator stats` returns endpoint request,
error, and latency aggregates.

The operator credential is a regional `operator-query` NATS account. It may
publish only `query.health`, `query.status`, `query.members`, `query.stats`, and
`query.operator-status` for its own region and may subscribe only to `_INBOX.>`
for request replies. It has no desired-state, host-agent, JetStream, or OCI
mutation permission. The controller and operator identities remain separate.

For a local, provider-free view of admitted runtime roles, use:

```bash
dotnet run --project src/TerraScale.Orchestrator -- catalog
```

The former Go/Datastar dashboard and its file-backed projection are retained
only in the repository's historical source and evidence. They are not part of
the current .NET runtime or an installable operator command.

When a regional controller is allowed to mutate OCI workload capacity, set
`TS_ORCH_WORKLOAD_FLEET_FILE` (or `OciWorkloadFleetConfigurationFile` in the
runtime config). The file is regional and contains one pinned launch template
and credential-free cloud-init digest for each workload. It always defines an
independent `ts-auth` policy. If the stateful TerraBase placement reconciler is
not configured, it also defines the independent `terrabase-server` policy. If
the placement reconciler is configured, that reconciler owns TerraBase members
and the generic file must omit `terrabase-server`; startup rejects duplicate
ownership. Each policy has separate `minReplicas`, `maxReplicas`, and
hysteresis values. The controller reads desired counts from the accepted
CellSpec, observes only its ownership-tagged instances, writes a durable
operation record containing the OCI work-request id, and applies at most one
replica change per workload tick. Instance principals authenticate the SDK;
private keys and NATS seeds never appear in this file.

OCI fleet startup also requires `TS_ORCH_REGION_INTENT_FILE`, containing the
schema 1 public output from `ts-infra`. The file authorizes supported regions
and binds each controller's fleet to its own OCI region; it does not declare
the regional cluster ready. Minimum/maximum values in status come from that
workload's fleet policy when configured. Without a generic fleet policy, the
role catalog minimum and protocol maximum are reported; these are not
provider quota measurements. Missing or suspended desired state blocks
allocation. A provider failure in one workload leaves it blocked while the
other workload can continue reconciling.

Every replacement host must also receive a signed regional enrollment envelope.
The envelope binds the region, stable node identity, bootstrap generation,
NATS account/user public keys, credential-bundle digest, and cluster name. The
regional verifier rejects wrong-region identities, stale generations, reused
grants, wrong NATS accounts, and denied bootstrap grants before the node may
join the regional cluster or consume work. The replay/generation store must be
durable in an OCI deployment; the in-memory implementation is only a local
qualification seam. Production `run` provisions and uses the non-expiring
`ORCH_NODE_ENROLLMENTS` KV fence and attaches this verifier and
credential-readiness gate to `TS_ORCH_HOST_ROLES`. The gate checks the signed
grant's cryptographic validity, audience, certificate binding, fixed system
Project, idempotent operation allow-list, exact NATS identities, and the
credential-bundle digest before consuming the regional KV replay fence. A
successful result is cached for the process lifetime; a missing or invalid
material leaves the host in `blocked-admission` and it cannot install, start,
or pick up work.

This admission gate does not yet retrieve its material from OCI Vault. A
consumed generation cannot be reused after process restart; credential renewal
and a durable restart protocol are still required. Current workload status and
metrics do not cover regional foundation creation, secret rotation, or seed
handoff progress, whose production lifecycles are not yet composed.
