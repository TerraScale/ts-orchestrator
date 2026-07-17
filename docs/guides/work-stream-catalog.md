# Historical work-stream catalog

> Index of all 113 work packages and handoffs consolidated on 2026-07-17.

Original files: `docs/archive/docs-historical-full.tar.xz` and searchable `docs/archive/historical-docs-bundle.md.xz`.
Paths inside the archive preserve `docs/work-packages/**` and `docs/work-packages/handoffs/**`.

| Domain | Packages | With handoff |
|---|---:|---:|
| Adversarial model and replay | 2 | 1 |
| Regional authority and fencing | 4 | 3 |
| Budget and cost policy | 5 | 4 |
| Compute autoscaling and survival | 6 | 4 |
| Native GitOps, CI, CD, and publish | 10 | 9 |
| Evidence gates and mutation foundation | 8 | 5 |
| Messaging policy and NATS subjects | 7 | 6 |
| Networking and routing policy | 4 | 4 |
| Observability projection | 4 | 3 |
| Control operations | 4 | 4 |
| Phase 0 readiness evidence | 16 | 9 |
| Protocol primitives and negotiation | 6 | 4 |
| Provider ownership and actuators | 3 | 3 |
| Reconciliation and resource contracts | 5 | 3 |
| Runtime health and self-update | 7 | 7 |
| Deterministic scheduler | 6 | 5 |
| Identity, PKI, vault, and security | 4 | 4 |
| Snapshots and restore | 3 | 2 |
| Storage lifecycle | 5 | 4 |
| TerraBase topology and recovery | 4 | 4 |

## Full index

| ID | Domain | Title | Handoff |
|---|---|---|---|
| `phase1-adversarial-model-core` | adversarial | Phase 1 deterministic adversarial model core | yes |
| `phase1-adversarial-model-provenance-audit3` | adversarial | Phase 1 adversarial model accepted-event provenance audit | no |
| `phase1-authority-core` | authority | Phase 1 regional authority core | yes |
| `phase1-authority-permit-provenance-audit4` | authority | Phase 1 authority mutation-permit provenance audit 4 | yes |
| `phase1-authority-policy-completeness` | authority | Phase 1 authority policy completeness shard | yes |
| `phase1-authority-read-provenance-audit3` | authority | Phase 1 Authority read-intent provenance audit | no |
| `phase1-budget-authorization-basis-audit4` | budget | Phase 1 budget authorization basis audit 4 | yes |
| `phase1-budget-authorization-subject-audit` | budget | Phase 1 budget authorization-subject audit handoff | yes |
| `phase1-budget-core` | budget | Phase 1 budget and cost decision core | yes |
| `phase1-budget-policy-completeness` | budget | Phase 1 budget policy completeness | yes |
| `phase1-budget-provider-property-shard` | budget | Phase 1 budget and provider ownership property/replay shard | no |
| `phase1-compute-accepted-completion-provenance-audit` | compute | Phase 1 compute accepted-completion provenance audit | no |
| `phase1-compute-audit2` | compute | Phase 1 compute accepted-output audit handoff | yes |
| `phase1-compute-autoscaling-core` | compute | Phase 1 compute autoscaling and regional survival core | yes |
| `phase1-compute-autoscaling-property-shard` | compute | Phase 1 compute autoscaling property shard | no |
| `phase1-compute-survival-generation` | compute | Phase 1 compute survival-generation anti-rollback handoff | yes |
| `phase1-storage-compute-property-shard` | compute | Phase 1 storage and compute deterministic property/replay shard | yes |
| `phase1-ci-decision-properties` | delivery-ci | Phase 1 CI trust-zone decision property shard | yes |
| `phase1-ci-dispatch-provenance-audit3` | delivery-ci | Phase 1 CI dispatch provenance audit | no |
| `phase1-ci-evidence-report-audit4` | delivery-ci | Phase 1 CI evidence report accepted-output audit 4 | yes |
| `phase1-delivery-core` | delivery-ci | Phase 1 native GitOps, CI, and release decision core | yes |
| `phase1-delivery-policy-completeness` | delivery-ci | Phase 1 Delivery policy completeness shard | yes |
| `phase1-delivery-source-signature-audit` | delivery-ci | Phase 1 Delivery source-signature audit | yes |
| `phase1-delivery-stage-output-audit4` | delivery-ci | Phase 1 delivery stage output audit 4 | yes |
| `phase1-delivery-terrabase-properties` | delivery-ci | Phase 1 delivery and TerraBase property/replay shard | yes |
| `phase1-reproducible-publish` | delivery-ci | Phase 1 reproducible dual-architecture publish | yes |
| `phase1-reproducible-publish-audit3` | delivery-ci | Phase 1 reproducible-publish provenance audit 3 | yes |
| `phase1-accepted-output-construction-closure` | evidence-mutation | Phase 1 accepted-output construction-closure audit | no |
| `phase1-evidence-accepted-scope-audit` | evidence-mutation | Phase 1 evidence accepted-scope audit | yes |
| `phase1-evidence-policy-completeness` | evidence-mutation | Phase 1 evidence policy completeness shard | no |
| `phase1-mutation-foundation` | evidence-mutation | Phase 1 mutation-evidence foundation | yes |
| `phase1-predeployment-evidence-core` | evidence-mutation | Phase 1 pre-deployment evidence core | yes |
| `phase1-reconciliation-evidence-audit` | evidence-mutation | Phase 1 reconciliation dependency-evidence audit | yes |
| `phase1-snapshot-evidence-property-shard` | evidence-mutation | Phase 1 snapshot and pre-deployment evidence property/replay shard | no |
| `phase1-structured-trace-foundation` | evidence-mutation | Phase 1 structured traceability foundation | yes |
| `phase1-messaging-policy-audit2` | messaging-nats | Phase 1 Messaging/NATS policy audit handoff | yes |
| `phase1-messaging-policy-audit3` | messaging-nats | Phase 1 Messaging/NATS surviving-store evidence audit handoff | yes |
| `phase1-messaging-policy-properties` | messaging-nats | Phase 1 messaging policy property/replay shard | yes |
| `phase1-nats-l0c-foundation` | messaging-nats | Phase 1 real-NATS L0C foundation | yes |
| `phase1-nats-policy-audit3` | messaging-nats | Phase 1 NATS policy accepted-observation audit 3 | yes |
| `phase1-nats-policy-core` | messaging-nats | Phase 1 dual-NATS policy and membership core | yes |
| `phase1-nats-policy-provenance-audit4` | messaging-nats | Phase 1 NATS replacement decision provenance audit 4 | no |
| `phase1-identity-network-properties` | networking | Phase 1 identity and network deterministic property shard handoff | yes |
| `phase1-networking-output-provenance-audit4` | networking | Phase 1 networking accepted-output provenance audit 4 | yes |
| `phase1-networking-policy-core` | networking | Phase 1 networking, VPN, DNS, and ingress policy core | yes |
| `phase1-networking-policy-properties` | networking | Phase 1 networking policy completeness shard handoff | yes |
| `phase1-observability-projection-audit3` | observability | Phase 1 observability projection checkpoint audit | yes |
| `phase1-observability-projection-core` | observability | Phase 1 observability and Grafana projection core | yes |
| `phase1-observability-projection-provenance-audit4` | observability | Phase 1 observability managed-projection provenance audit 4 | no |
| `phase1-observability-properties` | observability | Phase 1 observability projection and authorization property shard | yes |
| `phase1-control-operation-properties` | operations | Phase 1 control/operation deterministic property shard | yes |
| `phase1-operation-core` | operations | Phase 1 fenced operation core | yes |
| `phase1-operation-policy-completeness` | operations | Phase 1 operation policy completeness handoff | yes |
| `phase1-operations-audit3` | operations | Phase 1 operations work-request continuity audit | yes |
| `phase0-adr-readiness` | phase0-evidence | Phase 0 work package: ADR and toolchain readiness map | yes |
| `phase0-arm64-runtime-readiness` | phase0-evidence | Phase 0 work package: ARM64 host and runtime readiness | yes |
| `phase0-ci-descriptor-inventory` | phase0-evidence | Phase 0 work package: runtime/build descriptor and CI policy inventory | yes |
| `phase0-cloud-adrs` | phase0-evidence | Phase 0 cloud ADR draft handoff | yes |
| `phase0-draft-cloud-adrs` | phase0-evidence | Phase 0 work package: draft cloud ownership ADRs 4 and 20 | no |
| `phase0-draft-delivery-placement-adrs` | phase0-evidence | Phase 0 work package: draft GitOps and placement ADRs 13 and 18 | no |
| `phase0-nats-readiness` | phase0-evidence | Phase 0 work package: NATS pins, compatibility, and L0C readiness | yes |
| `phase0-oci-readonly-inventory` | phase0-evidence | Phase 0 work package: read-only OCI residual inventory | no |
| `phase0-owner-decision-packet` | phase0-evidence | Phase 0 work package: owner decision and SLO freeze packet | yes |
| `phase0-provider-qualification-schema` | phase0-evidence | Phase 0 work package: provider/TCO and OCI region qualification schema | yes |
| `phase0-registry-coverage-audit` | phase0-evidence | Phase 0 work package: requirement and state-machine coverage audit | no |
| `phase0-registry-v2-review` | phase0-evidence | Phase 0 work package: independent semantic registry v2 review | no |
| `phase0-source-contract-audit` | phase0-evidence | Phase 0 work package: product contract source audit | no |
| `phase0-supply-chain-pins` | phase0-evidence | Phase 0 work package: supply-chain and verification tool pins | yes |
| `phase0-workaround-ledger` | phase0-evidence | Phase 0 work package: historical workaround ledger | no |
| `phase01-provider-handoff-determinism-audit` | phase0-evidence | Phase 0/1 provider handoff determinism audit | yes |
| `phase1-protocol-command-receipt-audit3` | protocol | Phase 1 Protocol accepted-command receipt audit | no |
| `phase1-protocol-contract-completeness` | protocol | Phase 1 protocol contract-completeness property shard | no |
| `phase1-protocol-fuzz-shard` | protocol | Phase 1 deterministic protocol fuzz shard | yes |
| `phase1-protocol-negotiation-completeness` | protocol | Phase 1 protocol-negotiation completeness audit | yes |
| `phase1-protocol-primitives` | protocol | Phase 1 protocol primitives | yes |
| `phase1-subject-grammar` | protocol | Phase 1 NATS subject grammar | yes |
| `phase1-provider-create-observation-audit4` | provider | Phase 1 provider create-observation audit 4 | yes |
| `phase1-provider-ownership-completeness` | provider | Phase 1 provider ownership completeness shard | yes |
| `phase1-provider-ownership-core` | provider | Phase 1 provider ownership and handoff decision core | yes |
| `phase1-reconciliation-core` | reconciliation | Phase 1 desired/observed reconciliation core | yes |
| `phase1-reconciliation-policy-provenance-audit` | reconciliation | Phase 1 reconciliation policy-provenance audit | no |
| `phase1-reconciliation-property-shard` | reconciliation | Phase 1 reconciliation property/replay shard | no |
| `phase1-resource-contracts` | reconciliation | Phase 1 resource contracts | yes |
| `phase1-resource-projection-audit3` | reconciliation | Phase 1 resource projection audit 3 | yes |
| `phase1-runtime-cleanup-audit` | runtime | Phase 1 runtime cleanup audit handoff | yes |
| `phase1-runtime-health-intent-audit` | runtime | Phase 1 runtime health-intent audit handoff | yes |
| `phase1-runtime-observe-output-audit4` | runtime | Phase 1 runtime executor-observation output audit 4 | yes |
| `phase1-runtime-selfupdate-completeness` | runtime | Phase 1 runtime self-update completeness shard handoff | yes |
| `phase1-runtime-selfupdate-core` | runtime | Phase 1 runtime lifecycle and self-update core | yes |
| `phase1-runtime-soak-audit` | runtime | Phase 1 runtime self-update soak audit handoff | yes |
| `phase1-runtime-upgrade-properties` | runtime | Phase 1 runtime self-upgrade deterministic property shard handoff | yes |
| `phase1-scheduler-audit2` | scheduler | Phase 1 scheduler capacity/completeness audit | yes |
| `phase1-scheduler-audit3` | scheduler | Phase 1 scheduler observation-generation audit | yes |
| `phase1-scheduler-availability` | scheduler | Phase 1 scheduler availability policy | yes |
| `phase1-scheduler-availability-provenance-audit4` | scheduler | Phase 1 scheduler availability authorization provenance audit | no |
| `phase1-scheduler-core` | scheduler | Phase 1 deterministic scheduler core | yes |
| `phase1-scheduler-property-shard` | scheduler | Phase 1 scheduler deterministic property/replay shard | yes |
| `phase1-identity-vault-core` | security-identity | Phase 1 identity, PKI, and vault decision core | yes |
| `phase1-security-authorization-output-audit3` | security-identity | Phase 1 security authorization output audit 3 | yes |
| `phase1-security-enrollment-generation-audit4` | security-identity | Phase 1 security enrollment generation audit 4 | yes |
| `phase1-security-policy-properties` | security-identity | Phase 1 security policy property shard | yes |
| `phase1-snapshot-core` | snapshot | Phase 1 snapshot and restore core | yes |
| `phase1-snapshot-policy-completeness` | snapshot | Phase 1 snapshot policy completeness | yes |
| `phase1-snapshot-restore-provenance-audit3` | snapshot | Phase 1 snapshot restore provenance audit | no |
| `phase1-storage-create-output-audit4` | storage | Phase 1 storage create output audit 4 | yes |
| `phase1-storage-lifecycle-core` | storage | Phase 1 storage lifecycle and expansion core | yes |
| `phase1-storage-planner-property-shard` | storage | Phase 1 storage planner property and replay shard | no |
| `phase1-storage-policy-audit2` | storage | Phase 1 storage expansion policy audit 2 handoff | yes |
| `phase1-storage-policy-audit3` | storage | Phase 1 storage destructive-output audit 3 handoff | yes |
| `phase1-terrabase-audit2` | terrabase | Phase 1 TerraBase accepted-output audit 2 | yes |
| `phase1-terrabase-audit3` | terrabase | Phase 1 TerraBase accepted upgrade output audit 3 | yes |
| `phase1-terrabase-core` | terrabase | Phase 1 TerraBase topology and recovery core | yes |
| `phase1-terrabase-topology-provenance-audit4` | terrabase | Phase 1 TerraBase topology provenance audit 4 | yes |
