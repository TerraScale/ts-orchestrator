# Architecture decisions

The workspace [`GOAL.md`](../../../GOAL.md) wins whenever an ADR conflicts
with a closed product decision. This directory contains only ADRs that still
constrain the current Go orchestrator and its native systemd runtime.

| ADR | Status |
| --- | --- |
| [0020: Provider mutation fencing](0020-provider-actuator-threat-model.md) | Accepted safety boundary; provider qualification remains a gate |
| [0024: Greenfield bring-up](0024-greenfield-bringup.md) | Accepted boundary; production qualification remains a gate |
| [0025: Rollback on customer gate failure](0025-rollback-on-customer-gate-failure.md) | Accepted |

The delivery and qualification contracts are defined by workspace decisions
D-67, D-68, and D-81. Retired deployment and workload records are not retained
as documentation inputs.
