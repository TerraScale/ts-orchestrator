# Architecture decisions

The workspace [`GOAL.md`](../../../GOAL.md) wins when an ADR conflicts with a
fixed decision. This directory contains only decisions that still constrain
the current architecture.

| ADR | Status |
| --- | --- |
| [0018: Database placement and host scheduling](0018-placement-boundary.md) | Accepted |
| [0020: Provider mutation fencing](0020-provider-actuator-threat-model.md) | Accepted |
| [0024: Greenfield OCI boundary](0024-greenfield-bringup.md) | Accepted |
| [0025: Roll back on customer gate failure](0025-rollback-on-customer-gate-failure.md) | Accepted |
| [0029: Stateless tenant compute](0029-offer-stateless-tenant-compute.md) | Accepted, post-launch |
| [0031: Unprivileged tenant containers](0031-run-tenant-workloads-as-unprivileged-oci-containers.md) | Accepted, post-launch |
| [0033: GRU global authority and regional autonomy](0033-gru-global-authority-and-regional-autonomy.md) | Accepted |

Git history contains superseded records. New documentation must not cite a
deleted ADR as current authority.
