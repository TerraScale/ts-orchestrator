# NATS gateway operations runbook

> Applies only while the current optional Orchestrator NATS adapter is deployed.
> It is not a TerraBase replication runbook and cannot be used to diagnose or
> repair database convergence.

Operator procedures for the regional control-NATS gateway supercluster generated
from the typed gateway plan (`NatsGatewayPlaneTopology` →
`NatsGatewayPlanValidation` → `NatsGatewayConfigurationRenderer`). The typed
plan is the only source: no runtime path hand-writes `gateway {` configuration,
and an inadmissible plan fails closed before rendering or startup. When this
document and the implementation disagree, the implementation's typed decisions
and their error strings win.

## Topology facts (what you are operating)

- Three regional control clusters — `orchestrator-control-fra`, `-gru`, `-sfo` —
  each with its own JetStream domain (`ORCH_FRA`, `ORCH_GRU`, `ORCH_SFO`), three
  servers, and three failure domains.
- One control-plane operator trust root (`ts-orch-control`) across the whole
  supercluster; separately scoped accounts per region
  (`ts-orch-regional-control-<cell>` plus the GRU-owned global authority and
  directory accounts), each with its own signing-key reference and users.
- A full directed gateway mesh: every ordered region pair has exactly one
  gateway relationship. Hub-and-spoke, missing, duplicate, or self edges fail
  admission. The product plane has no gateways at all.
- mTLS everywhere with per-transport certificate profiles: client, route, and
  gateway each use their own certificate, key, and expected-peer identities.
- The product plane (`terrascale-product-<cell>`, operator
  `ts-terrascale-product`) is cell-local: distinct accounts, ports
  (4223/6223 vs 4222/6222/7222), cgroup slice, per-server store directories,
  and PKI root. Nothing crosses the planes.

## Reading a generated configuration

Every rendered file starts with a generation header:

```
# terrascale-nats-gateway-plan plane=control cell=gru server=gru-control-nats-1 trust=1 config=1
```

The header is deterministic output of the typed plan, not a comment someone
wrote: it names the plane, cell, server, trust generation, and configuration
generation the rest of the file was rendered from. Use it first when comparing
what is running against what was intended.

Evidence copies of configuration are redacted with
`NatsGatewayConfigurationRenderer.RedactForEvidence`: private-key blocks, NKey
seeds, JWTs, and password assignments are replaced. Rendered configuration must
always pass `ScanForSecrets` (it contains file references and public account
JWTs only). Never paste an unredacted configuration into a ticket, log, or chat.

## Certificate or configuration rotation (the rolling procedure)

Rotation is a typed decision (`NatsGatewayRotation`), not an ad-hoc script. The
decision produces an ordered, serialized step list — one plane, one server, one
failure domain at a time — where each step records the pre-state and the
post-state (trust generation, configuration generation, and the rendered
configuration digests) plus its rollback target.

Runbook shape:

1. **Prepare.** Build the next typed plan (same clusters, same server
   identities, bumped generations). A trust-generation bump must advance every
   cluster in the supercluster — a partial trust rotation fails validation with
   "A trust rotation must advance every cluster".
2. **Validate.** The rotation transition is rejected unless: every changed
   cluster rolls all of its servers, digests exist for every server, the digest
   actually changes when the configuration generation changes, membership is
   unchanged, and the sequence stays inside one plane. Fix the plan; never
   bypass the gate.
3. **Render and stage.** Render each affected server's configuration. Record
   `RenderEvidenceIdentity` (cluster/server, generations, digest) for the
   pre-state and post-state; this is the redacted rotation evidence.
4. **Roll.** Execute the steps strictly in order: stop/restart one server at a
   time, verifying health and mesh membership (cross-region service path plus
   cluster routes) before the next step. Never hold two servers of one cluster
   in flight; a production cluster is host-spread, so one step touches one
   host.
5. **Verify.** After the last step, confirm every region reaches the directory
   service through the mesh and each cluster serves its own domain only.
6. **Roll back if needed.** `NatsGatewayRotation.Rollback` produces the inverse
   steps in reverse order, each restoring the recorded pre-state generations and
   digest. Roll back the executed suffix of the sequence, then re-verify.

Invariants that hold during any correct rotation: quorum is never reduced below
two peers per regional cluster, the store directory of every server is stable
across the rotation (a replacement config that changes it is rejected), and the
trust root name never changes.

## Fail-closed admission (what never starts)

`NatsGatewayPlanValidation.EnsureValid` refuses to render or start a plan with
any of: an invalid cell token; an unqualified endpoint (bare host, wildcard,
port 0); a shared server identity, listener endpoint, store directory, process
unit, or cgroup; cluster accounts without an account scope; non-canonical
cluster names or JetStream domains; a control server without a gateway listener
or with a missing expected peer identity; more than one certificate authority
per plane; wildcard or unapproved cross-account imports/exports; an incomplete
mesh; loopback endpoints (production admission). Product-plane plans may not
declare gateway listeners, relationships, or imports/exports at all, and the
dual-plane gate rejects any shared operator, account, port, store path, unit,
cgroup, or credential file across the planes.

## Failure triage

- **A region's server will not start after a config change.** The rendered
  header tells you which generation it is. If it exits during readiness, the
  admission gate or the config is wrong — do not edit the file by hand; fix the
  typed plan and re-render. Roll back the region's step.
- **Gateway connections not forming.** The mesh is explicit: check that the
  rendering lists every remote cluster's gateway URLs and that each side's
  gateway certificate profile expects the remote SPIFFE identities. An
  incomplete mesh fails admission before startup, so a running-but-partitioned
  mesh means configuration drift, not a plan error.
- **Cross-region request times out.** Confirm the requesting region's account
  has the import (only the directory service is approved) and the serving
  region hosts the export. GRU's own regional account deliberately has no
  import: cross-account access is import-gated, never implicit.
- **JetStream asset visible in the wrong region.** That is an isolation breach.
  Global-authority assets (names under `GLOBAL_`/`CI_`) exist only on GRU; every
  other domain holds only its regional assets. Do not "repair" by creating the
  asset elsewhere; re-render the correct region from its typed plan.

## Evidence

Attach to any rotation or incident record: the redacted pre/post configuration
digests (`RenderEvidenceIdentity`), the rotation step list with rollback
targets, the admission result, and the test-lane receipt. Local L0C conformance
(three loopback clusters, two servers per region, rootless containers) proves
gateway/TLS/JWT/domain behavior — it is not regional R3 quorum evidence, and it
must never be reported as production qualification.
