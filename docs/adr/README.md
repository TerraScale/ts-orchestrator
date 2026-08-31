# ADR readiness index

The current repository goal is [`../../GOAL.md`](../../GOAL.md). The accepted
foundational control decision is
[ADR 0033](0033-gru-global-authority-and-regional-autonomy.md). It selects GRU
global authority, autonomous regional JetStream R3 domains, NATS as the
Orchestrator control store, Orchestrator-owned bootstrap without Pulumi or
OpenTofu, regional blue-green cutover, and removal of development-host
composition from the production project.

> The readiness index is a machine-validated historical map of the earlier
> architecture. The workspace and repository `GOAL.md` files control new work.
> ADR 0033 supersedes the deleted ADRs 0004, 0013, and 0026, while
> ADRs 0018 and the deleted ADR 0032 remain superseded. Other historical ADRs require
> reconciliation before they can authorize work on changed database,
> product-role, transport, or NATS boundaries.

This directory retains the current architecture decisions. Git history retains the superseded architecture backlog.

Owner choices **1A–10A were accepted on 2026-07-16** with reliability first. Measurable cost, storage, RPO, and RTO targets remain deployment-qualification inputs rather than silent architecture defaults.

Git history retains the former machine-validated readiness map.

## Decision register

| ADR | Decision | Current status |
| --- | --- | --- |
| [0018](0018-placement-boundary.md) | Project placement versus host scheduling | Superseded; Region selection belongs to each database |
| [0020](0020-provider-actuator-threat-model.md) | Provider mutation fencing and same-operation recovery | Accepted safety boundary; live provider evidence pending |
| [0024](0024-greenfield-bringup.md) | Greenfield bring-up and residual-resource quarantine | Accepted boundary; scoped inventory pending |
| [0025](0025-rollback-on-customer-gate-failure.md) | Roll back on customer or security gate failure | Accepted |
| [0029](0029-offer-stateless-tenant-compute.md) | Stateless tenant compute with managed TerraBase | Accepted |
| [0031](0031-run-tenant-workloads-as-unprivileged-oci-containers.md) | Unprivileged OCI tenant workloads | Accepted |
| [0033](0033-gru-global-authority-and-regional-autonomy.md) | GRU global authority and autonomous regional control | Accepted |

ADR 0033 supersedes ADR 0004's Pulumi ownership, ADR 0013's Git authority
after admission, ADR 0026's global activation barrier, and the previous
optional-NATS target. ADR 0020 and ADR 0024 remain required safety inputs.

Condensed boundaries for these decisions: [`../guides/architecture-boundaries.md`](../guides/architecture-boundaries.md).

## Status rules

- `draft-ready`: the proposed contract and checked-in evidence are sufficient to write a choice-preserving draft. It does not mean accepted.
- `owner-input-required`: a numbered owner choice **or** an owner-approved SLO can still materially change the decision. A draft may compare alternatives but cannot select one.
- `evidence-required`: the decision is not controlled by an open numbered owner choice, but a measurement, inventory, threat-model result, product-contract reconciliation, or primary implementation source is still missing.
- `accepted`: requires an explicit owner/architecture approval record plus every exit-evidence item. No ADR is accepted solely because questions 1–10 closed.

Git history retains the former exclusive-workstream table and its canonical lane names.

## Validation

```bash
go run ./tools/orchestrator-tooling adr-readiness
go run ./tools/orchestrator-tooling test
```

The validator proves IDs 1 through 24 occur exactly once, fields are populated, lanes and statuses are canonical, and every local evidence anchor resolves to an existing file with in-bounds line numbers.
