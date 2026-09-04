# Automated OCI bootstrap

Routine TerraScale estate creation is orchestrator-owned. There is no manual
OCI resource runbook. The owner completes only account, payment, home-Region,
plan, and initial credential setup, then runs the authenticated bootstrap
command from a trusted machine.

The workspace [`GOAL.md`](../../../GOAL.md) and repository
[`GOAL.md`](../../GOAL.md) define the exact authority and acceptance criteria.
The complete Firecracker `make vm-test` qualification must pass before the same
bootstrap path is used against OCI.

## Owner prerequisites

- PAYG tenancy with GRU (`sa-saopaulo-1`) as the home Region.
- Initial OCI API identity scoped to the bootstrap operations.
- Cloudflare Pro and Workers Paid account prerequisites and narrowly scoped
  initial credentials.
- Grafana Cloud and required external account identifiers.
- Local release-verification material supplied as file references, never raw
  secret command-line values.

These prerequisites authorize the command; they do not become desired estate
and are not copied onto a host.

## Command contract

```bash
terrascale-orchestrator bootstrap
```

`--dry-run` performs discovery and prints the deterministic dependency-ordered
plan without provider mutation. The real command repeatedly observes and
reconciles until it has:

1. created and verified compartments, IAM policy, and instance-principal
   authority;
2. created GRU networking, routing, NSGs, Vault software keys, Object Storage
   buckets, versioning, and lifecycle policy;
3. created two member hosts in separate failure domains, using Ampere A1 and
   automatically selecting E5 amd64 when A1 capacity is unavailable;
4. installed only `ts-node` through cloud-init;
5. admitted host identities and let `ts-node` fetch and verify the signed
   orchestrator and TerraBase artifacts;
6. formed the launch control replica on the selected GRU member and joined it
   to the declared cross-Region control topology as Regions are added;
7. converged certificates, Cloudflare DNS and routes, KV, telemetry, and
   external probes; and
8. handed mutation authority to the running control plane and removed the
   bootstrap API key from runtime state.

Every mutation uses persisted intent, provider idempotency, re-observation,
and ownership fencing. An uncertain destructive operation is never repeated
until its outcome and authority are proven. Restarting the command resumes the
same operation rather than creating parallel estate.

## Completion

Bootstrap completes only after both GRU member hosts, storage and backup
targets, the control replica, identities, edge routing, telemetry, and external
probes are healthy. Partial completion remains declared state for automatic
repair; it does not turn into a list of console steps.

Adding SFO or FRA uses `terrascale-orchestrator add-region <code>` and the same
reconcile, readiness, ownership, and rollback rules. Region removal is also
declarative and must fence placement and routing, drain safely, and prove all
residency and retention obligations before deletion.

The local Firecracker suite qualifies orchestration behavior and failure
handling. A real bootstrap is still required to qualify OCI and Cloudflare
service behavior, credentials, quotas, and production performance.
