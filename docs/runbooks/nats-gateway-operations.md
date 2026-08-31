# NATS gateway operations

This runbook applies to the `ts.orch.v2` control supercluster. It is not a
TerraBase replication runbook. Database convergence must be diagnosed through
TerraBase signals.

## Topology

- GRU, SFO, and FRA each run a regional JetStream R3 domain.
- GRU also runs the separate global JetStream R3 domain.
- Gateway links carry only approved control subjects between domains.
- No stream, consumer, KV bucket, or Raft group spans regions.
- A gateway failure isolates distribution while local regional quorum and
  already allowed work continue.
- Server, route, gateway, monitoring, and client identities use separate TLS
  and NATS permissions.

The typed gateway plan and renderer are the configuration source. Operators do
not hand-edit generated NATS files.

## Read a generated configuration

Every rendered file starts with a generation header:

```text
# terrascale-nats-gateway-plan plane=control cell=gru server=gru-control-nats-1 trust=1 config=1
```

The header identifies the region, server, trust generation, and configuration
generation. Compare it with the accepted plan before inspecting individual
settings.

`NatsGatewayConfigurationRenderer.RedactForEvidence` removes private-key
blocks, NKey seeds, JWTs, and passwords from a diagnostic copy. Never paste an
unredacted generated configuration into an issue, log, or chat.

## Rotate certificates or configuration

`NatsGatewayRotation` produces the ordered steps. Rotation touches one server
and one failure domain at a time.

1. Build the next typed plan with the same cluster and server identities. A
   trust change advances the complete supercluster trust generation.
2. Validate the transition. Changed clusters must include every server, each
   changed configuration needs a digest, and membership and store paths remain
   stable.
3. Render and stage the affected files. Record the pre-change and post-change
   generation and digest through `RenderEvidenceIdentity`.
4. Restart one server. Wait for local quorum, routes, gateways, and the global
   directory query before continuing.
5. Repeat until the plan converges.
6. If a check fails, apply the inverse steps from
   `NatsGatewayRotation.Rollback` to the executed suffix, then recheck quorum
   and gateway links.

Never take two servers from one R3 domain out of service together. Never change
a server's store directory during rotation.

## Admission failures

The validator refuses a plan with an invalid region, wildcard or portless
endpoint, shared server identity, reused listener, shared store directory,
duplicate unit or cgroup, missing account scope, incomplete gateway
relationship, multiple trust roots, or undeclared import and export.

Fix the typed plan and render again. Do not bypass admission or edit the output
file.

## Failure triage

### A server will not start

Read the generation header and process error. If startup validation rejects the
file, restore the prior generated file and fix the plan. Do not create a new
store or server identity to get around the error.

### Gateway links do not form

Check both directions. Confirm each side has the expected remote endpoint,
gateway certificate, trust bundle, and peer identity. A running but incomplete
mesh usually means deployed configuration differs from the accepted plan.

### A cross-region query times out

Confirm the caller's account has the declared import and the serving account
has the matching export. Undeclared cross-account access must fail with no
responder. Do not widen a wildcard permission during an incident.

### A regional stream appears elsewhere

Treat this as an isolation fault. Stop rollout and mutation in the affected
domains. Do not copy or recreate the stream in another region. Compare the
running domain, account, stream configuration, and gateway permissions with
the typed plan.

### GRU is unavailable

Regional groups continue local safety work under their accepted policy. Global
release, catalog, and policy changes remain frozen. Do not promote SFO or FRA
to global authority.

## Incident record

Attach the redacted pre-change and post-change configuration digests, rotation
steps, rollback target, startup validation result, affected domains, and test
output. Never claim an R3 quorum result from a single-server local fixture.
