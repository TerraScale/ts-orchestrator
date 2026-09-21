# OCI bootstrap and ownership handoff

`ts-infra` owns the supported-region declaration and starts the first GRU
orchestrator. That controller must then establish regional clusters and manage
their OCI resource lifecycle. This is the required production architecture;
the complete first-boot and ownership handoff are not implemented yet.

The former Go `bootstrap`, `add-region`, and `ts-node` instructions do not apply
to the current C# executable. Its runtime commands are `run`, `check`, `catalog`,
`provision-journal`, and `journal-writer`, plus the operator/CI commands listed
in the main README. The new `oci-bootstrap-secrets` command implements pinned
Vault materialization before normal runtime startup; its contract and limits
are in [oci-vault-bootstrap.md](oci-vault-bootstrap.md). Do not use historical
command names as deployment evidence.

## Region intent

In `ts-infra/infra.tfvars`, `terrascale_supported_regions` is the authoritative
allow-list and `terrascale_region_intent_generation` versions it. GRU maps to
`sa-saopaulo-1`, SFO to `us-sanjose-1` (OCI SJC), and FRA to `eu-frankfurt-1`.
`ts-infra` emits schema 1 JSON and includes it in the seed's
`terrascale_region_intent` metadata. The first controller is always in GRU.

The current runtime consumes that JSON through `TS_ORCH_REGION_INTENT_FILE`
(`OciRegionIntentFile` in the runtime configuration). Install it as an
owner-private regular file, at most 16 KiB. When an OCI fleet is configured,
startup requires this file, rejects unsupported cells, and binds the OCI
compute endpoint and member/workload templates to the controller's own cell.

Startup validation does not distribute updates or fence rollback. Durable
intent generation, authenticated distribution to every regional controller,
regional estate reconciliation, and region draining remain required. Removing
a region from intent must stop new allocation while preserving access needed
to drain workloads, retain data, and tear down safely. It must never implicitly
authorize deletion. Supported, provisioning, admitted, draining, and retired
must be separate states in status.

## Seed and handoff contract

1. CI validates region intent and the exact seed plan, then `ts-infra` creates
   only the GRU foundation and one private, pinned ARM64 controller. IAM,
   private network egress, artifact access, and Vault references must work
   before first boot. No secret values belong in cloud-init or metadata.
2. The seed uses OCI Instance Principal to retrieve only its pinned secret
   versions. Bootstrap must verify artifact digests, install restrictive file
   permissions, start authenticated regional NATS, provision the isolated
   journal identity, and start the controller with the reviewed trust bundle.
   The first seed also needs a separately bounded bootstrap authority to create
   its initial peers before regional R3 exists. Normal provider mutation is
   fenced by NATS authority and cannot bootstrap its own absent quorum. Do not
   silently downgrade production streams to R1 or treat the current system
   project bootstrap grants as OCI provisioning authority. This founding-quorum
   path still needs implementation and crash/retry tests.
3. The controller records a signed, durable adoption request containing the
   region-intent generation, source revision, exact resource OCIDs, types,
   compartments, current ownership, and observed provider revisions. It must
   verify these against OCI; tags or an output file alone are not evidence.
   While this request is pending it may inspect seed resources but not mutate
   them. Newly created workload resources have their own controller owner.
4. CI verifies that request and the live controller's health. A reviewed
   declarative `removed` configuration with `lifecycle { destroy = false }`
   relinquishes the recorded seed resources without deleting them. The
   encrypted resulting state must be durably published before CI issues a
   signed release receipt bound to that request and source revision.
5. Only after verifying the release receipt may orchestrator commit the new
   owner in its durable journal and mutate the seed resources. A retry uses
   the same handoff identifier; a crash at any boundary resumes from durable
   receipts. CI must never reintroduce released resources under the same
   addresses. Lost or unverified receipts leave mutation blocked.
6. GRU can then create the foundation and seed controllers for supported
   regions through the same fenced provider workflow. Each region forms its
   own authenticated NATS/orchestrator cluster, proves readiness, and admits
   hosts before they receive work. Controllers and workload hosts need
   distinct IAM and NATS capabilities. Region formation must survive GRU
   restart without duplicate regional seeds.

This procedure is a contract for implementation, not an executable handoff
command. Today the seed is still OpenTofu-owned and has `prevent_destroy`.
Do not disable the estate as a transfer mechanism or edit/remove state locally.
IAM root trust is also an explicit ownership boundary: the controller policy
must not grant unbounded tenancy administration to implement the handoff.

## Workload admission and independent capacity

After Vault retrieval, each node needs a signed enrollment envelope bound to
its OCI node identity, region, NATS account/user, certificate, credential-bundle
digest, and bootstrap generation. The production host gate verifies this before
installing or claiming work. Its current replay fence accepts a node generation
once and caches admission in memory; restart/renewal needs a complete protocol
before deployment. Reusing a consumed grant is not that protocol.

`ts-auth` and TerraBase have independent desired counts and bounds. If the
stateful TerraBase placement reconciler owns member instances, the generic
workload fleet must contain only `ts-auth`; duplicate ownership is rejected.
Missing or suspended desired state blocks generic allocation. An observation
or apply failure in one workload reports a blocked decision while the other
continues. Generic TerraBase scale-in is blocked; retirement must use the stateful
placement fleet with drain and retained-data proofs. The provider preserves
invalid desired counts so the scaler can reject them instead of silently
clamping them into permission to launch.

The authenticated NATS endpoint `ts.orch.v2.<cell>.query.operator-status`
reports workload needs, actions, progress, and configured policy limits.
Orchestrator telemetry exports the same workload aggregates. Full regional
foundation, handoff, Vault, and resource-operation status must be added with
those lifecycle implementations; the current endpoint is not evidence of
complete OCI coverage. See the [readiness record](../evidence/oci-readiness-2026-09-20.md)
for qualification results and outstanding local/live gates.
