# Admit MCP as a first-party product workload

> Superseded on 2026-08-29. The Dashboard now owns Streamable HTTP MCP as
> named Better Auth and TerraScale SDK operations. The separate
> `TerraScale.MCP` workload, HTTP host, stdio host, ports, credentials, and
> delivery role are migration sources scheduled for deletion. This ADR remains
> as a record of the earlier implementation decision.

Status: superseded on 2026-08-29

Tracking: [TerraScale.Orchestrator#9](https://git.terrascale.tech/TerraScale/TerraScale.Orchestrator/issues/9)

The TerraScale MCP server is a first-party product workload in the closed
role catalog (`AdmittedRole.McpServer`, artifact key `terrascale-mcp`). It
is a stateless HTTP service operated by this Orchestrator like Platform,
Authentication, and the Dashboard: admitted from a typed manifest, deployed
through direct delivery, health-gated, and rollback-anchored. It is not a
tenant workload, carries no payment-provider role, and never exposes a raw
HTTP escape hatch — the MCP surface stays the typed, authenticated,
tenant-isolated product contract owned by the `TerraScale.MCP` repository.

## Runtime lane

The qualified artifact format is a digest-bound self-contained HTTP
executable archive produced by the `TerraScale.MCP` repository (one archive
per platform, including `linux-arm64` and `linux-x64`). Because that is a
native executable rather than an OCI image, the admitted driver is native
systemd through the existing closed native first-party lane — the same lane
`Orchestrator`, the NATS servers, `RoutePolicyController`, and
`JournalWriter` already use — with the standard hardening envelope
(`NoNewPrivileges`, `ProtectSystem=strict`, dropped SUID/SGID, cgroup v2
limits, encrypted credential loading). ADR 0031 governs tenant runtimes
(unprivileged OCI is the only tenant runtime); first-party roles keep the
closed catalog as their allow-list, and an OCI image lane for MCP may be
added only when `TerraScale.MCP` qualifies one.

## Placement and ownership

Two instances is the admission floor (`minimumReplicas: 2`), one per host,
in two independent failure domains. The workload is stateless: routing
carries no session affinity, any healthy backend serves any request, and
the reconciler's backend selection is a pure function of the request
sequence. The typed desired state rejects two instances in one failure
domain. Placement is a deployment-time property; this repository implements
and proves the typed placement and reconciliation semantics in process, and
the live two-instance run is deferred to the deployment evidence lane.

## Ports

The workload binds one fixed host-local HTTP listener port. The development
lane is the reserved GRU loopback listener `http://127.0.0.1:18675`
(resource key `mcp`), which DevHost republishes as fixed tailnet HTTPS port
`18452`; port `18451` stays legacy cleanup-only and is never reassigned. A
distinct production port may be assigned only through a catalog change
after deployment qualification records it. The manifest rejects every
other port.

## Resources

The catalog admission ceiling for the stateless gateway is 512 MiB memory,
256 tasks, 200% CPU quota, weights 400/300, nice 0 — an admission bound,
not a measured budget. Measured A1 memory, CPU, and startup budgets remain
deployment-qualification inputs and may not be relaxed by a delivery
request.

## Secret profile

The confidential OAuth client secret is admitted BY REFERENCE only
(`vault:terrascale/mcp/oauth-client-secret`). Secret bytes never appear in
desired state, the typed manifest, NATS, logs, traces, metrics, receipts,
or evidence; the runtime delivers the material through the encrypted
credential mechanism. Approved configuration is a closed key set
(public base URL, authentication issuer, Platform public API base URL,
minimum log level) whose values are bounded, non-secret, and HTTPS where
URL-valued. Keys for the Internals MCP access and token-exchange contract
join the set only when that contract lands.

## Health and route contract

The canonical public route is `https://mcp.terrascale.tech/mcp`; TLS
terminates at the shared product edge and forwarding preserves the host's
HTTPS requirement. The host owns `/.well-known/oauth-protected-resource/mcp`,
`/health/live`, and `/health/ready`. The route mapping is redacted by
construction: it carries host, path, transport, and routability only — no
Project, caller, credential, or internal diagnostic field exists to leak.
Liveness and readiness are not publicly routable.

## Ingress, withdrawal, and rollback

Ingress stays closed until live Authentication, scope-denial, isolation,
health, and rollback evidence passes (typed fail-closed gate). Emergency
withdrawal closes ONLY the MCP HTTP route and leaves the separately
distributed stdio artifacts and every other product route untouched; it is
a route action, not a workload mutation. Rollback restores the exact
previous qualified digest without rebuilding: release preparation verifies
the source revision, artifact digest, architecture, provenance identity,
configuration schema revision, and the exact rollback artifact before the
workload is activated, and a deployment over a live artifact without its
rollback anchor is rejected.

## Artifact qualification (cross-repository dependency)

The Orchestrator-side admission is complete and fail-closed: the qualified
HTTP artifact set starts empty (`McpHttpArtifactQualification.None` admits
nothing), and digests enter it only from accepted qualification evidence
produced by the `TerraScale.MCP` repository. Until that evidence lands,
every artifact is rejected — including arbitrary images, executable paths,
mounts, capabilities, environments, ports, probes, and free-form ingress,
which are additionally not expressible in the typed manifest. Deployment of
the real workload therefore waits on that cross-repository blocker and on
the Internals MCP access and token-exchange contract.

## Consequences

- The closed catalog, the direct-delivery target allow-lists, and the
  typed manifest admission are the only ways to run or deliver this
  workload; there is no MCP-specific mutation path.
- `CONTEXT.md` still summarizes "all workloads run as OCI containers";
  the native first-party lane this ADR uses predates it and is recorded
  here so the glossary can be reconciled by the integration steward.
- The development lab does not yet start an MCP process: the resource key,
  listener port, and DevHost port reservations are typed and tested, and
  the lab wiring follows the qualified artifact.

## Amendment (2026-08-25) — scope relative to ADR 0031

ADR 0031's body text states that OCI containers are "its only workload
runtime", read broadly that sentence covers every workload in the
repository, not only tenant compute. That broader reading conflicts with
this ADR's native-systemd admission for `McpServer`, so the conflict is
recorded here instead of being left implicit or silently resolved by
editing ADR 0031 (which stays untouched).

The operative scoping is `docs/architecture/orchestrator.md`'s authoritative decision
register, which ADR 0031 itself cites: decision 4A (as superseded) runs
"trusted OCI containers for TerraBase and TerraScale APIs, unprivileged
OCI containers for customer compute, and **systemd only for admitted
host-native roles**". The closed role catalog has carried a native
first-party lane since before ADR 0031 (`Orchestrator`, `ControlNatsServer`,
`ProductNatsServer`, `RoutePolicyController`, `JournalWriter`, and
`TerraBaseMember`'s native option), and `AdmittedRoleCatalog` remains the
allow-list for first-party roles. ADR 0031's OCI-only rule is therefore
tenant-scoped in effect, and this ADR admits `McpServer` onto the
pre-existing native first-party lane because the qualified artifact format
is a digest-bound self-contained HTTP executable, not an OCI image.

This amendment is recorded with the parent-steward's authorization
(repair loop on issue #9, 2026-08-25). Moving MCP to an OCI image lane
remains open and requires no superseding decision here: it becomes the
preferred shape once `TerraScale.MCP` qualifies an OCI image, at which
point the catalog entry's allowed drivers change through the normal
qualification record. Until then, no OCI image of MCP is admitted.
