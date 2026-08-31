# Phase 1 pure-contract map

> Historical contract inventory. It describes checked-in pure contracts from
> the earlier architecture. New work follows the repository `GOAL.md` and the
> workspace `GOAL.md`, including RF=2 TerraBase placement, database-owned
> Regions, QUIC TBEP, and the mandatory `ts.orch.v2` NATS control network.

> Consolidated 2026-07-17 from 113 work packages / 88 handoffs and the live `src/TerraScale.Orchestrator/ControlPlane` tree.

Git history retains the historical per-package scopes and handoffs.
Normative architecture remains the repository [`GOAL.md`](../../GOAL.md). Owner choices 1A–10A are accepted; measurable cost/storage/RPO/RTO targets remain deployment gates.

## How to read this map

- **Core** packages froze pure decision engines (no NATS, clock, filesystem, provider, or network I/O).
- **Audit / completeness / property** packages closed accepted-output provenance, policy completeness, and replay evidence on those cores.
- **Live source** points at the current implementation under the main Orchestrator project (`src/TerraScale.Orchestrator/ControlPlane/**`).
- Pure contracts may freeze with explicit policy inputs; they do **not** authorize deployment.

## Live pure-engine inventory

| Domain folder | Source files |
|---|---|
| `ControlPlane/Authority` | `AuthorityContracts.cs`, `AuthorityDigest.cs`, `AuthorityEngine.cs` |
| `ControlPlane/Budgets` | `BudgetAnomalies.cs`, `BudgetDecision.cs`, `BudgetEvidence.cs`, `BudgetPolicy.cs`, `BudgetPrimitives.cs` |
| `ControlPlane/Compute` | `ComputeContracts.cs`, `ComputeEngine.cs` |
| `ControlPlane/Delivery` | `DeliveryContracts.cs`, `DeliveryEngine.cs` |
| `ControlPlane/Evidence` | `EvidenceGate.cs`, `EvidenceManifest.cs`, `EvidencePolicy.cs`, `EvidencePrimitives.cs` |
| `ControlPlane/Messaging` | `MessagingContracts.cs`, `MessagingPolicyEngine.cs` |
| `ControlPlane/Networking` | `NetworkDiscovery.cs`, `NetworkInputSnapshot.cs`, `NetworkRouting.cs`, `NetworkingPrimitives.cs` |
| `ControlPlane/Observability` | `ObservabilityDecisionEngine.cs`, `ObservabilityModels.cs` |
| `ControlPlane/Operations` | `OperationContracts.cs`, `OperationDigest.cs`, `OperationEngine.cs` |
| `ControlPlane/Providers` | `OciCiRunnerCapacity.cs`, `ProviderModels.cs`, `ProviderOwnershipEngine.cs` |
| `ControlPlane/Reconciliation` | `ReconciliationContracts.cs`, `ReconciliationEngine.cs` |
| `ControlPlane/Runtime` | `RuntimeDecisionEngine.cs`, `RuntimeInputSnapshot.cs`, `RuntimeModels.cs` |
| `ControlPlane/Security` | `SecurityDecisionEngine.cs`, `SecurityInputSnapshot.cs`, `SecurityModels.cs` |
| `ControlPlane/Snapshots` | `SignedSnapshot.cs`, `SnapshotOpaqueBytes.cs`, `SnapshotPrimitives.cs`, `SnapshotRestore.cs` |
| `ControlPlane/Storage` | `StorageDeletion.cs`, `StorageExpansion.cs`, `StorageLifecycle.cs`, `StoragePrimitives.cs`, `StorageVolumeRecord.cs` |
| `ControlPlane/TerraBase` | `TerraBaseLifecycle.cs`, `TerraBasePrimitives.cs`, `TerraBaseRecovery.cs` |
| `src/TerraScale.Orchestrator.Protocol` | subject grammar and protocol packages |
| `src/TerraScale.Orchestrator.Scheduler` | deterministic constrained least-waste scheduler |

## Adversarial model and replay

**Live source:** `(ModelTests)`

### Contract cores and primary packages

#### `phase1-adversarial-model-core` — Phase 1 deterministic adversarial model core

**Scope:** Implement the deterministic L0 model simulator, reusable failure schedules, and replay corpus required by `docs/architecture/orchestrator.md:1114-1180` and the Phase 1 exit gate. The lane exercises existing pure cores and never executes an adapter or performs deployment.

**Outcome:** The model-test project now has a deterministic, bounded three-node simulator with an explicit virtual clock and identity source, immutable event evidence plus separate delivery scheduling metadata, stable failure-kind ordering, visited-state deduplication, deterministic replay, and replay-validated delta shrinking. The closed schedule catalog covers loss, duplicate, reorder, delay, crash, restart, leader change, partition, and heal. Exploration includes baseline progression and applicable node f

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-adversarial-model-provenance-audit3` | Phase 1 adversarial model accepted-event provenance audit | no | Two accepted authorization events with the same event ID and authorization subject but different replay coordinates produced equal accepted … |

## Regional authority and fencing

**Live source:** `Authority`

### Contract cores and primary packages

#### `phase1-authority-core` — Phase 1 regional authority core

**Scope:** Implement the pure regional-authority lease/epoch decision state machine described at `docs/architecture/orchestrator.md:454` and `545-550`. It models KV CAS intents/observations but performs no NATS or clock I/O.

**Outcome:** Implemented a pure authority reducer for `INV-004`, with `INV-005` referenced only for append/replay/idempotency behavior proven here. It emits typed compare-and-set, compare-and-delete, and read intents; it never reads a clock, NATS, environment, filesystem, network, or policy default. Each reducer journal is explicitly scoped to one `(AuthorityId, CandidateId)` attempt history. The regional KV CAS record is the shared authority truth across candidates. Tests model three candidate journals read

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-authority-permit-provenance-audit4` | Phase 1 authority mutation-permit provenance audit 4 | yes | Review the single-source boundary in `MutationAuthorityPermit`, all three `CreatePermit(command)` call sites, and the distinct canonical tag… |
| `phase1-authority-policy-completeness` | Phase 1 authority policy completeness shard | yes | - Replay now rejects a non-renewal acquisition request whose expected epoch or KV revision is below the reducer's persisted high-water truth… |
| `phase1-authority-read-provenance-audit3` | Phase 1 Authority read-intent provenance audit | no | An accepted leader read that can later restore a mutation permit and an ordinary genesis follower read emitted equal adapter-facing values: … |

## Budget and cost policy

**Live source:** `Budgets`

### Contract cores and primary packages

#### `phase1-budget-core` — Phase 1 budget and cost decision core

**Scope:** Implement the pure budget authorization and anomaly decision core from `docs/architecture/orchestrator.md:746-756`. It classifies typed resource/spend changes without estimating prices or performing provider actions.

**Outcome:** The pure anomaly detector accepts an explicit complete-inventory assertion and bounded, scoped, fresh observations. It reports typed findings for: - owned but undesired/orphaned resources; - owned unattached resources; - desired but missing owned resources; - billing without an owned resource; and - owned resources missing from billing.

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-budget-authorization-basis-audit4` | Phase 1 budget authorization basis audit 4 | yes | The budget engine selected one cell-usage observation, one global-usage observation, one node-class observation, and one price observation u… |
| `phase1-budget-policy-completeness` | Phase 1 budget policy completeness | yes | `BudgetProposal.IsWellFormed` previously rejected only `BudgetSafetyPurpose.Unspecified`. Undefined values such as `4` were treated as well … |
| `phase1-budget-provider-property-shard` | Phase 1 budget and provider ownership property/replay shard | no | Exercise the existing budget/cost and provider ownership/handoff pure cores with deterministic generated and replayed inputs. This shard str… |
| `phase1-budget-authorization-subject-audit` | Phase 1 budget authorization-subject audit handoff | yes | This pure-policy audit reviewed budget decision outputs for one replay identity ambiguity after the budget core, policy-completeness, and pr… |

## Compute autoscaling and survival

**Live source:** `Compute`

### Contract cores and primary packages

#### `phase1-compute-autoscaling-core` — Phase 1 compute autoscaling and regional survival core

**Scope:** Implement the pure regional compute scale-out/scale-in/replacement and survival-readiness state machines from `docs/architecture/orchestrator.md:623-756`. It composes typed scheduler/budget/provider evidence but performs no provider action.

**Outcome:** Implemented pure scale-out, scale-in, and regional-survival decision engines for `REQ-O011` and the `INV-005` proof/replay boundary. Inputs are immutable typed evidence; outputs are closed observe, persist-plan, authorize, request-create, enroll, ready, cordon, drain, deregister, detach/retain, revoke, terminate, audit, or hold intents. Every intent, decision, error, and trace has no public instance constructor and exposes public read-only inspection, so callers cannot forge an authorized mutati

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-compute-accepted-completion-provenance-audit` | Phase 1 compute accepted-completion provenance audit | no | Two complete, valid scale-out requests could differ in controller generation, artifact/template/demand/operation identity, persisted plan an… |
| `phase1-compute-autoscaling-property-shard` | Phase 1 compute autoscaling property shard | no | Audit existing example and property coverage, then add generated independent-oracle cases for ordered authorization denial, exact checkpoint… |
| `phase1-storage-compute-property-shard` | Phase 1 storage and compute deterministic property/replay shard | yes | The public constructor signature is unchanged. Callers that supplied more than 4,096 secret-version identities or node templates, infinite e… |
| `phase1-compute-audit2` | Phase 1 compute accepted-output audit handoff | yes | The scale-out and scale-in engines validated complete evidence but discarded part of it when constructing their authorizing outputs. Two acc… |
| `phase1-compute-survival-generation` | Phase 1 compute survival-generation anti-rollback handoff | yes | Survival validation compared the required bundle with its observed evidence but had no authoritative current accepted generation. After gene… |

## Native GitOps, CI, CD, and publish

**Live source:** `Delivery`

### Contract cores and primary packages

#### `phase1-delivery-core` — Phase 1 native GitOps, CI, and release decision core

**Scope:** Implement pure GitOps source reconciliation, CI trust-zone scheduling, artifact promotion, and release/CD correctness state machines from `docs/architecture/orchestrator.md:924-1010`. It emits typed source/runner/release intents only.

**Outcome:** Implemented pure GitOps source, CI runner, artifact promotion, and release rollout decision engines for `INV-005`. The engines consume caller-supplied typed evidence and emit closed fetch, verify, plan, dispatch, promote, stage, advance, rollback, or hold intents. They contain no Git, Forgejo, process, filesystem, network, clock, signing, approval, or provider implementation. Every emitted intent, decision, error, and trace has assembly-internal construction and public read-only inspection, so e

- Handoff recorded: yes

#### `phase1-reproducible-publish` — Phase 1 reproducible dual-architecture publish

**Scope:** Implement and verify locked, deterministic, self-contained single-file publishes for linux-x64 and linux-arm64 as required by `docs/architecture/orchestrator.md:1114-1180,1496-1510`. This is build reproducibility evidence only; it never executes or qualifies the ARM64 artifact.

**Outcome:** The reviewed .NET publish verifier completed a real double publish for `linux-x64` and `linux-arm64` from two byte-identical isolated input copies. Both per-RID repeat artifacts were byte-identical, and the architecture artifact digests were distinct. This is cross-publish evidence only. The ARM64 artifact was not executed. This handoff does not provide ARM64 runtime or L4 qualification, signing, release approval, or pre-deployment attestation.

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-ci-decision-properties` | Phase 1 CI trust-zone decision property shard | yes | Added four deterministic 1,000-case independent-oracle families for the existing pure CI decision surface: - exhaustive closed job-kind/trus… |
| `phase1-ci-dispatch-provenance-audit3` | Phase 1 CI dispatch provenance audit | no | A valid ProductValidation request in `UntrustedProduct` using runner sequence 20/capability `Compile` and a distinct valid TrustedBuild requ… |
| `phase1-ci-evidence-report-audit4` | Phase 1 CI evidence report accepted-output audit 4 | yes | Two otherwise accepted gate calls could supply different well-formed evidence subjects, matching expected-subject contexts, and the same cla… |
| `phase1-delivery-policy-completeness` | Phase 1 Delivery policy completeness shard | yes | These were pure accepted-output and evidence-binding defects. No adapter, deployment, cryptographic verification, or external-system behavio… |
| `phase1-delivery-stage-output-audit4` | Phase 1 delivery stage output audit 4 | yes | Two otherwise identical accepted staging requests with different valid rollout strategies produced structurally identical `StageReleaseInten… |
| `phase1-delivery-terrabase-properties` | Phase 1 delivery and TerraBase property/replay shard | yes | Added four deterministic 1,000-case property families covering immutable Delivery source evidence, promotion and rollout behavior, TerraBase… |
| `phase1-reproducible-publish-audit3` | Phase 1 reproducible-publish provenance audit 3 | yes | The public pure observation verifier could mint a successful `ReproduciblePublishResult` from entirely caller-authored process and file obse… |
| `phase1-delivery-source-signature-audit` | Phase 1 Delivery source-signature audit | yes | Source verification previously compared the proposed and observed opaque `SignatureId`, but `SourceEvidence` had no result or attestation pr… |

## Evidence gates and mutation foundation

**Live source:** `Evidence`

### Contract cores and primary packages

#### `phase1-accepted-output-construction-closure` — Phase 1 accepted-output construction-closure audit

**Scope:** Prevent callers outside the ControlPlane assembly from minting decisions, permits, mutation intents, or intent subjects without passing through the owning pure decision engine.

- Handoff recorded: package only

#### `phase1-mutation-foundation` — Phase 1 mutation-evidence foundation

**Scope:** Create a deterministic, fail-closed mutation project inventory, exclusion policy, and zero-claim report while the mutation tool remains unselected. Do not choose, install, restore, or run a candidate tool and do not claim a score.

**Outcome:** The four correctness-critical library projects are mandatory. The only exclusion is the exact Phase 0 composition-root source, bound by path and SHA-256 to a checked-in proof. - Closed allowed and forbidden exclusion catalogs. State transitions, validators, authority, fencing, deletion, retry, compensation, and adapter result classification can never be excluded. - A zero-claim report cross-checked against the existing supply-chain audit, which identifies dotnet-stryker 4.16.0 only as an unselec

- Handoff recorded: yes

#### `phase1-predeployment-evidence-core` — Phase 1 pre-deployment evidence core

**Scope:** Implement the canonical evidence manifest, exact-subject invalidation, policy decision, opaque-signature verification boundary, and deployment-gate verifier required by `docs/architecture/orchestrator.md:1114-1180`. This lane cannot mint production acceptance evidence or credentials.

**Outcome:** This is only the pure manifest, caller-policy, content-addressed-reuse, opaque-verification, and deployment-gate decision core. It performs no process, filesystem, network, environment, clock, CI, provider, signer, KMS, credential, or deployment mutation operation. It does **not** claim that an L0 or L0C lane has actually executed, that a production signer or KMS/CI identity has been qualified, that either architecture artifact is reproducible, or that any manifest/envelope is a deployable produ

- Handoff recorded: yes

#### `phase1-structured-trace-foundation` — Phase 1 structured traceability foundation

**Scope:** Replace lexical-only traceability with a strict structured manifest and dependency-free validator. Every one of the 43 registry IDs has exactly one entry whose owner and ordered acceptance layers match the registry, whose status is exactly `gap` or `linked`, and whose production, test, and evidence links use closed typed shapes. Gap entries are fir

**Outcome:** The repository now has a strict structured trace-link manifest and validator. All 43 registry IDs occur exactly once with owner and ordered acceptance-layer data checked against `requirements/registry.yaml`. All entries intentionally remain `gap`: current lexical matches do not provide a complete typed production-symbol, exact test-identifier, and evidence-artifact chain. No link was invented and no item was promoted. The canonical report therefore records 43 gaps, zero linked entries, zero acce

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-evidence-accepted-scope-audit` | Phase 1 evidence accepted-scope audit | yes | Two otherwise valid evidence-gate calls could use different manifest identities and different matching verified signer identities while reta… |
| `phase1-evidence-policy-completeness` | Phase 1 evidence policy completeness shard | no | Adversarially complete the existing pure pre-deployment evidence policy without claiming or executing any deployment evidence lane. |
| `phase1-snapshot-evidence-property-shard` | Phase 1 snapshot and pre-deployment evidence property/replay shard | no | Exercise the existing signed-snapshot restore and pre-deployment evidence pure cores with deterministic, independently checked generated cas… |
| `phase1-reconciliation-evidence-audit` | Phase 1 reconciliation dependency-evidence audit | yes | An eligible reconcile intent previously retained the target resource's complete observation, but each converged dependency proof retained on… |

## Messaging policy and NATS subjects

**Live source:** `Messaging`

### Contract cores and primary packages

#### `phase1-nats-l0c-foundation` — Phase 1 real-NATS L0C foundation

**Scope:** Provide a deterministic machine-readable L0C case inventory for dual-plane isolation; JWT/account/subject denial; JetStream stream and KV policy; three-region control gateways; duplicate, reorder, acknowledgement, and redelivery behavior; local R3 failure; N/N-1 compatibility; and snapshot/restore recovery. The dependency-free validator must enforc

**Outcome:** The checked candidate manifest has exact version/artifact metadata for two server candidates, two managed client candidates, and one CLI candidate. This is not an executable selected closure: - every server, client, and CLI `selected` value is false; - `nMinusOnePolicy` is null and the candidate pair is unexecuted; - no JWT/NKey generation/administration toolchain is selected or pinned; - the snapshot signing identity/key technology is unselected; - no pinned rootless-container toolchain observa

- Handoff recorded: yes

#### `phase1-nats-policy-core` — Phase 1 dual-NATS policy and membership core

**Scope:** Implement the pure dual-NATS topology, stream/bucket policy, membership replacement, and partition decision core from `docs/architecture/orchestrator.md:448-590`. It emits configuration/operation intents only and never starts or contacts NATS.

**Outcome:** The package output list initially omitted the `ReattachSurvivingStore` branch required by `docs/architecture/orchestrator.md`. The steward explicitly approved a closed `ReattachSurvivingStoreIntent`. It binds: - exact operation, plane, cell, cluster, recorded server/peer, and replacement placement evidence; - surviving store identity and positive observed store generation; - exact observed membership sequence and ownership epoch; - recorded owner, compatibility proof, and absence of a conflicting active attachmen

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-messaging-policy-properties` | Phase 1 messaging policy property/replay shard | yes | Pure policy only. No NATS/process/network/filesystem/cloud execution was added or tested, and no L0C claim is made. |
| `phase1-nats-policy-audit3` | Phase 1 NATS policy accepted-observation audit 3 | yes | The pure replacement policy accepted distinct operations while collapsing their initial or repeated observation commands to the same executa… |
| `phase1-nats-policy-provenance-audit4` | Phase 1 NATS replacement decision provenance audit 4 | no | Audit 3 bound an initial or repeated `ObserveClusterIntent` to its exact replacement operation. It did not cover accepted decision branches … |
| `phase1-messaging-policy-audit2` | Phase 1 Messaging/NATS policy audit handoff | yes | `DecideTopology` rejected a critical stream or bucket that did not meet the declared membership floor, replicated acknowledgement, and ackno… |
| `phase1-messaging-policy-audit3` | Phase 1 Messaging/NATS surviving-store evidence audit handoff | yes | the initially proven `369a3a1` counterexample onto the steward's current tree. - Changed only Messaging replacement contracts and decisions,… |

## Networking and routing policy

**Live source:** `Networking`

### Contract cores and primary packages

#### `phase1-networking-policy-core` — Phase 1 networking, VPN, DNS, and ingress policy core

**Scope:** Implement pure network intent, peering/VPN route ownership, DNS/LB backend, and exposure authorization decisions from `docs/architecture/orchestrator.md:873-879,1096-1110`. It emits typed network intents only.

**Outcome:** This is a pure policy core. It contains no VPN/provider/DNS/LB client, config text, key material, credential, command, callback, SDK, socket, process, filesystem/network I/O, clock, address pool, health threshold, or default exposure implementation.

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-networking-output-provenance-audit4` | Phase 1 networking accepted-output provenance audit 4 | yes | Final Release solution and five-suite verification are performed after the required exact-central rebase; record those final counts in the c… |
| `phase1-identity-network-properties` | Phase 1 identity and network deterministic property shard handoff | yes | This is bounded deterministic feature-shard evidence only and does not satisfy the full L0 thresholds. It does not select PKI algorithms, is… |
| `phase1-networking-policy-properties` | Phase 1 networking policy completeness shard handoff | yes | The audit proved that an otherwise approved public Product endpoint using plaintext `Http` reached `Verify/Completed`. Public customer HTTP … |

## Observability projection

**Live source:** `Observability`

### Contract cores and primary packages

#### `phase1-observability-projection-core` — Phase 1 observability and Grafana projection core

**Scope:** Implement pure telemetry admission/cardinality, regional aggregation health, alert routing, and exact immutable Grafana projection decisions from `docs/architecture/orchestrator.md:1041-1095`. It emits typed projection intents only.

**Outcome:** The control plane now has four pure observability decisions: bounded telemetry admission, regional metric/log/trace health aggregation, immutable Grafana desired-state projection, and alert routing. Every authorization binds exact operation, tenant, cell, signal, schema/rule digest, generation, and independently scoped completeness evidence applicable to that decision. Authorized decisions contain only passed trace reasons. Telemetry admission accepts only cataloged label keys and values classif

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-observability-projection-provenance-audit4` | Phase 1 observability managed-projection provenance audit 4 | no | `ObservedGrafanaResource` previously represented only resource identity, scope, generation, digest, broad projection kind, and ownership. It… |
| `phase1-observability-projection-audit3` | Phase 1 observability projection checkpoint audit | yes | The Grafana projection decision previously checked that desired state and inventory shared one candidate generation and inventory sequence. … |
| `phase1-observability-properties` | Phase 1 observability projection and authorization property shard | yes | This is bounded deterministic feature-shard evidence, not full L0 or deployment qualification. It starts no adapter, process, network, cloud instance, o… |

## Control operations

**Live source:** `Operations`

### Contract cores and primary packages

#### `phase1-operation-core` — Phase 1 fenced operation core

**Scope:** Implement a pure operation decision core for `INV-004` and `INV-005`: desired/observed reconciliation, fencing, durable journal decisions, and deterministic replay. It emits intents only and performs no I/O.

**Outcome:** Implemented a pure, append-only operation reducer for `INV-004`, `INV-005`, and the stale-writer protection in `INV-006`. Immutable commands carry explicit time, generation/resource version, observation identity, writer epoch, target, idempotency key, payload digest, and deadline. No wall clock, environment, filesystem, network, NATS, provider SDK, or arbitrary callback enters the public decision API. The journal models prepare, irreversible authorization, dispatch, recovery, observation, termin

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-control-operation-properties` | Phase 1 control/operation deterministic property shard | yes | - Added four deterministic, explicit-seed property families with 1,000 cases each for Authority, Operations, Reconciliation, and their cross… |
| `phase1-operations-audit3` | Phase 1 operations work-request continuity audit | yes | The pure operation engine now preserves a provider work-request identity once an `Unknown` or `InProgress` observation establishes one. A la… |
| `phase1-operation-policy-completeness` | Phase 1 operation policy completeness handoff | yes | This audit closes five pure operation-policy gaps for `INV-004`, `INV-005`, and `INV-006` without performing provider, NATS, filesystem, pro… |

## Phase 0 readiness evidence

### Contract cores and primary packages

#### `phase0-adr-readiness` — Phase 0 work package: ADR and toolchain readiness map

**Outcome:** The former readiness map represented all 24 initial ADR backlog items exactly once. Git history retains that result.

- Handoff recorded: yes

#### `phase0-arm64-runtime-readiness` — Phase 0 work package: ARM64 host and runtime readiness

**Outcome:** The readiness record compares Oracle Linux 9 and Ubuntu 24.04 LTS standard OCI aarch64 platform-image families without selecting either. Ubuntu 26.04 LTS is a watch item because Canonical documents ARM64 LTS support but the current cited OCI platform-image catalog does not list it. ext4 and XFS remain equally unqualified candidates. systemd remains coupled to the eventual host image; upstream and distribution containerd/runc tracks and upstream BuildKit 0.30 remain candidates with exact builds u

- Handoff recorded: yes

#### `phase0-ci-descriptor-inventory` — Phase 0 work package: runtime/build descriptor and CI policy inventory

**Outcome:** The deterministic inventory covers 10 pinned sibling repositories, 156 classified first-party descriptors, 2 referenced local build scripts, 9 delivery summaries, 4 production roles, 4 unresolved policy conflicts, and 4 open coverage gaps. Every descriptor is tied to its repository commit, path, Git blob, mode, and type. Exact line citations for roles and conflicts resolve inside pinned blobs. Ten adversarial fixtures include explicit dependency-lock and referenced-script omissions. TerraScale.I

- Handoff recorded: yes

#### `phase0-draft-cloud-adrs` — Phase 0 work package: draft cloud ownership ADRs 4 and 20

- Handoff recorded: package only

#### `phase0-draft-delivery-placement-adrs` — Phase 0 work package: draft GitOps and placement ADRs 13 and 18

- Handoff recorded: package only

#### `phase0-nats-readiness` — Phase 0 work package: NATS pins, compatibility, and L0C readiness

**Outcome:** Five tool candidates are recorded but unselected: servers 2.14.3 and 2.12.7, clients `NATS.Net` 3.0.0 and 2.8.2, and CLI 0.4.0. Linux amd64/arm64 server and CLI asset metadata is pinned to official release URLs, sizes, and SHA-256 digests. Client packages are pinned to official NuGet URLs and locally calculated SHA-256 digests. The owner-controlled N/N-1 policy remains null and the candidate pair remains unexecuted. Current/prior labels are inventory roles, not compatibility acceptance. The 27 c

- Handoff recorded: yes

#### `phase0-oci-readonly-inventory` — Phase 0 work package: read-only OCI residual inventory

- Handoff recorded: package only

#### `phase0-owner-decision-packet` — Phase 0 work package: owner decision and SLO freeze packet

**Scope:** Status: completed as an unanswered packet, then superseded on 2026-07-16 when the owner explicitly selected 1A–10A with reliability first. The measurable targets remain evidence-derived deployment-qualification inputs. - Predecessor commit: `f393dc4` - Contract version: proposed architecture dated 2026-07-13; all answers remain unset unless explici

**Outcome:** The packet preserves all ten owner questions and both options exactly as written in `docs/architecture/orchestrator.md:89-98`. Every record carries its source line and a SHA-256 over the four exact source cells. `recommended: A` represents the table heading only; all ten `answer` fields are null and validation rejects any checked-in default. There are 38 explicitly unset records: - 10 owner decisions and 19 measurable targets required before the affected contract/ADR tranche can freeze; - 2 Phase 0 planning input

- Handoff recorded: yes

#### `phase0-provider-qualification-schema` — Phase 0 work package: provider/TCO and OCI region qualification schema

**Outcome:** Created a fail-closed custom field-contract for the normalized OCI/AWS/GCP/Azure TCO and storage benchmark plus the OCI `>=20` eligible-region matrix. It is deliberately not labeled as JSON Schema. The contract enumerates all cost and region fields named by `docs/architecture/orchestrator.md`. The blank dataset keeps every empirical value unknown, all provider results incomplete/unqualified, the OCI eligible count at zero, the threshold claim false, and provider winner/selection `null`. The 26-entry source catalo

- Handoff recorded: yes

#### `phase0-registry-coverage-audit` — Phase 0 work package: requirement and state-machine coverage audit

- Handoff recorded: package only

#### `phase0-registry-v2-review` — Phase 0 work package: independent semantic registry v2 review

- Handoff recorded: package only

#### `phase0-source-contract-audit` — Phase 0 work package: product contract source audit

- Handoff recorded: package only

#### `phase0-supply-chain-pins` — Phase 0 work package: supply-chain and verification tool pins

**Outcome:** Created a fail-closed candidate evidence set for build, runtime, property, coverage, fuzz, mutation, signing, OCI artifact, SBOM, and vulnerability tooling: - `docs/audits/supply-chain/phase0-candidate-pins.md` - `testlab/pins/supply-chain-candidates.json` - `tools/TerraScale.Orchestrator.Tooling/TranslatedCommands.cs` - `tools/TerraScale.Orchestrator.Tooling/ToolingTests.cs` - `tools/phase0/supply-chain/fixtures/negative-cases.json` - `tools/phase0/supply-chain/README.md` The manifest records 1

- Handoff recorded: yes

#### `phase0-workaround-ledger` — Phase 0 work package: historical workaround ledger

- Handoff recorded: package only

#### `phase01-provider-handoff-determinism-audit` — Phase 0/1 provider handoff determinism audit

**Scope:** Close the proven pure-output gap where equivalent verified greenfield Pulumi handoff inventories authorized regional self-management but retained caller-dependent enumeration order in the accepted adapter intent.

**Outcome:** The handoff evaluator already compared Expected, Pulumi, and Regional inventories as sorted set-like projections. All proof checks could therefore accept independently permuted inventories. The emitted `EnableRegionalSelfManagementIntent`, however, retained the three original caller orders. Equivalent fully verified handoffs consequently exposed different adapter-facing sequences. `FreshBootstrapInventory` now applies the evaluator and fingerprint's canonical order at its defensive-copy boundary

- Handoff recorded: yes

#### `phase0-cloud-adrs` — Phase 0 cloud ADR draft handoff

**Outcome:** Drafted: - `docs/adr/0004-pulumi-provider-ownership.md` - `docs/adr/0020-provider-actuator-threat-model.md` ADR 0004 preserves the specification's two-owner boundary: Pulumi retains durable foundation and transfers an exact fresh-resource inventory through a signed, crash-resumable handoff before the regional actuator becomes the sole lifecycle owner. It rejects continuous dual reconciliation, historical-resource adoption, tag-based authority, and convention-only handoff. ADR 0020 scopes provide

- Handoff recorded: yes

## Protocol primitives and negotiation

**Live source:** `(Protocol project)`

### Contract cores and primary packages

#### `phase1-subject-grammar` — Phase 1 NATS subject grammar

**Scope:** Implement infrastructure-free NATS subject and permission-pattern grammar used by future generated account policies. This validates syntax and matching only; it does not select account topology, subjects, or permissions.

**Outcome:** `ConcreteSubject` and `SubjectPermissionPattern` are deliberately separate immutable types: - Concrete subjects require one or more nonempty dot-separated tokens and reject whitespace, control characters, unpaired UTF-16 surrogates, empty tokens, and either wildcard character anywhere. - Permission patterns apply the same bounded token grammar, allow `*` only as an entire one-token wildcard, and allow `>` only as the final entire token. - `SubjectPermissionPattern.Matches` performs ordinal, case

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-protocol-command-receipt-audit3` | Phase 1 Protocol accepted-command receipt audit | no | Before this audit, every accepted command returned the same complete public value: `CommandValidationResult { Error = None, IsValid = True }… |
| `phase1-protocol-contract-completeness` | Phase 1 protocol contract-completeness property shard | no | The accepted `phase1-protocol-fuzz-shard` and subject-grammar handoffs intentionally leave these transport decisions open. This shard does n… |
| `phase1-protocol-fuzz-shard` | Phase 1 deterministic protocol fuzz shard | yes | The protocol test project now runs deterministic generated valid and malformed inputs from explicit SplitMix-style seeds across every curren… |
| `phase1-protocol-negotiation-completeness` | Phase 1 protocol-negotiation completeness audit | yes | The pure N/N-1 compatibility decision now returns an immutable, construction-closed acceptance that binds the exact adjacent current/previou… |
| `phase1-protocol-primitives` | Phase 1 protocol primitives | yes | The tranche implements the draft `INV-005` command-admission model from `docs/architecture/orchestrator.md:580` without freezing a wire contract: - Strong non… |

## Provider ownership and actuators

**Live source:** `Providers`

### Contract cores and primary packages

#### `phase1-provider-ownership-core` — Phase 1 provider ownership and handoff decision core

**Scope:** Implement pure provider operation authorization and Pulumi-to-regional ownership handoff decisions from `docs/architecture/orchestrator.md:627-727`. The core emits typed intents only and never calls a provider.

**Outcome:** The control plane now has a pure fail-closed authorization boundary for provider operations. An immutable operation context binds the exact operation, regional scope, controller epoch, existing provider identity or idempotent create key, expected observation and generation, desired terminal state, approvals, caller-supplied deadline evidence, idempotency key, and permitted compensations. Bounded identities support both TerraScale canonical tokens and case-sensitive provider-native resource/work-

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-provider-create-observation-audit4` | Phase 1 provider create-observation audit 4 | yes | The same exact absent `ProviderCreateObservation` authorized independent create operations in different cells and compartments. Create evide… |
| `phase1-provider-ownership-completeness` | Phase 1 provider ownership completeness shard | yes | The audit proved a durable-authorization forgery path in the previous pure model: `ProviderCallEvidence` carried only a status and optional … |

## Reconciliation and resource contracts

**Live source:** `Reconciliation`

### Contract cores and primary packages

#### `phase1-reconciliation-core` — Phase 1 desired/observed reconciliation core

**Scope:** Implement a pure deterministic desired/observed state engine and dependency planner for Phase 1. It emits typed adapter intents only and owns no domain-specific mutation policy.

**Outcome:** ```text dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --no-progress git diff --check ``` - Solution build: 0 warnings, 0 errors. - Control Plane suite: 47 passed, 0 failed (16 reconciliation tests plus 31 existing operation/authority tests). - All five repository test

- Handoff recorded: yes

#### `phase1-resource-contracts` — Phase 1 resource contracts

**Scope:** Implement the draft, provider-neutral common resource metadata and closed admitted-role model described at `docs/architecture/orchestrator.md:393-449`. This tranche does not freeze serialization or select unresolved runtime/observability/VPN implementations.

**Outcome:** Branch: `phase1/resource-contracts`

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-reconciliation-policy-provenance-audit` | Phase 1 reconciliation policy-provenance audit | no | Two distinct, valid caller-supplied reconciliation policies authorized the same drift repair. They differed in allowed-kind and generation-f… |
| `phase1-reconciliation-property-shard` | Phase 1 reconciliation property/replay shard | no | Exercise the existing pure desired/observed reconciliation engine with independent generated oracles and a strict deterministic replay corpu… |
| `phase1-resource-projection-audit3` | Phase 1 resource projection audit 3 | yes | Two accepted built-in metrics descriptors selecting different catalog entries had distinct C# canonical identities but could only be describ… |

## Runtime health and self-update

**Live source:** `Runtime`

### Contract cores and primary packages

#### `phase1-runtime-selfupdate-core` — Phase 1 runtime lifecycle and self-update core

**Scope:** Implement pure admitted workload lifecycle decisions for native systemd/container runtimes plus orchestrator A/B self-update from `docs/architecture/orchestrator.md:359-390,843-879` and Phase 2/3 lifecycle requirements. It emits typed executor/bootstrap intents only.

**Outcome:** The control plane now has a pure, closed runtime decision boundary for reviewed native-systemd and digest-pinned OCI workloads. Inputs bind workload, allocation, node, operation, epoch, generation, architecture, host image, runtime version, artifact/signature/signing profile, configuration, secret versions, volumes, ports, admission policy, health policy, and complete node-inventory evidence. OCI activation binds the selected platform image digest independently from its manifest-list digest. Lif

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-runtime-observe-output-audit4` | Phase 1 runtime executor-observation output audit 4 | yes | Two fully valid response-lost lifecycle requests for the same operation and allocation but different executor nodes produced equal authorize… |
| `phase1-runtime-cleanup-audit` | Phase 1 runtime cleanup audit handoff | yes | `CleanupRuntimeIntent` previously retained only its operation identity and a derived array of ephemeral volume identities. It discarded the … |
| `phase1-runtime-health-intent-audit` | Phase 1 runtime health-intent audit handoff | yes | This audit reviewed the pure Runtime lifecycle and self-update decisions for one remaining accepted-output ambiguity after the cleanup-conte… |
| `phase1-runtime-selfupdate-completeness` | Phase 1 runtime self-update completeness shard handoff | yes | 1. Exact, explicitly `Incompatible` N/N-1 evidence after local verification was classified as a generic denial. The local-known-good rollbac… |
| `phase1-runtime-soak-audit` | Phase 1 runtime self-update soak audit handoff | yes | `SelfUpdateRequest.SoakDuration` was captured but never evaluated. A healthy update at `OldSlotRetainedUntilSoak` immediately emitted `Compl… |
| `phase1-runtime-upgrade-properties` | Phase 1 runtime self-upgrade deterministic property shard handoff | yes | This is bounded deterministic feature-shard evidence, not full L0 or deployment qualification. It starts no process, cloud instance, network, cloud, fil… |

## Deterministic scheduler

**Live source:** `(Scheduler project)`

### Contract cores and primary packages

#### `phase1-scheduler-availability` — Phase 1 scheduler availability policy

**Scope:** Implement pure scheduler hard-policy evaluators for quorum floors, disruption budgets, critical replica anti-affinity/topology spread, and caller-supplied N+1 reserve from `docs/architecture/orchestrator.md:307-323,619`.

**Outcome:** Branch: `phase1/scheduler-availability`

- Handoff recorded: yes

#### `phase1-scheduler-core` — Phase 1 deterministic scheduler core

**Scope:** Implement a pure, deterministic constrained least-waste scheduler kernel from `docs/architecture/orchestrator.md:593-607`. It schedules only supplied candidates and constraints; it does not own product placement or stateful move safety.

**Outcome:** Branch: `phase1/scheduler-core`

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-scheduler-audit2` | Phase 1 scheduler capacity/completeness audit | yes | The availability evaluator previously treated all resource rows as not applicable when `ReserveDisposition.MayConsume` was selected. Those r… |
| `phase1-scheduler-audit3` | Phase 1 scheduler observation-generation audit | yes | The availability evaluator previously received completeness and structural checks for a replica observation snapshot but no snapshot generat… |
| `phase1-scheduler-availability-provenance-audit4` | Phase 1 scheduler availability authorization provenance audit | no | Two valid placement requests with different replica, node, and failure-domain targets produced the same complete public admitted decision wh… |
| `phase1-scheduler-property-shard` | Phase 1 scheduler deterministic property/replay shard | yes | The existing placement API has no generation or fencing epoch. This shard proves rejection of stateful stale/fencing observations only throu… |

## Identity, PKI, vault, and security

**Live source:** `Security`

### Contract cores and primary packages

#### `phase1-identity-vault-core` — Phase 1 identity, PKI, and vault decision core

**Scope:** Implement pure enrollment, certificate/identity lifecycle, authorization, revocation, and encrypted-secret lease decisions from `docs/architecture/orchestrator.md:881-923`. No cryptographic provider or secret store is used.

**Outcome:** The control plane now has a pure default-deny decision boundary for enrollment, certificate lifecycle, closed capability authorization, encrypted-secret leases, and regional survival secret references. Enrollment binds the exact operation, principal, public subject-key identity, cell, role, principal generation, one-time bootstrap audience/status, attestation measurement and policy generation, regional issuer generation, and revocation generation. Consumed bootstrap evidence, stale/missing/confl

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-security-authorization-output-audit3` | Phase 1 security authorization output audit 3 | yes | Two exact accepted capability requests could use the same operation, principal ID, capability, resource scope, and generation numbers while … |
| `phase1-security-enrollment-generation-audit4` | Phase 1 security enrollment generation audit 4 | yes | Enrollment previously compared the expected principal generation only with the selected bootstrap and attestation generations. A request who… |
| `phase1-security-policy-properties` | Phase 1 security policy property shard | yes | This shard strengthens the pure `SecurityDecisionEngine` contract for enrollment, certificate lifecycle, capability authorization, secret le… |

## Snapshots and restore

**Live source:** `Snapshots`

### Contract cores and primary packages

#### `phase1-snapshot-core` — Phase 1 snapshot and restore core

**Scope:** Implement the pure snapshot acceptance/restore decision core from `docs/architecture/orchestrator.md:545-550`: snapshots bind schema version, signed stream position, state digest, and fencing epoch; restore refuses rollback.

**Outcome:** The core treats every candidate stream sequence less than or equal to the current accepted sequence as rollback, including when the candidate epoch is newer. Epoch is checked first, so an older epoch reports `StaleEpoch`; otherwise non-advancing stream position reports `StreamRollback`. This assumes one monotonic sequence space per typed stream identity and should be retained unless a future explicitly versioned stream-reset contract says otherwise.

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-snapshot-policy-completeness` | Phase 1 snapshot policy completeness | yes | The audit found one accepted-output anti-rollback defect. `SnapshotSignedMaterial.Generation` was authenticated and copied into an authorizi… |
| `phase1-snapshot-restore-provenance-audit3` | Phase 1 snapshot restore provenance audit | no | Two valid signed snapshots with different authorities, streams, schemas, signing keys, and signatures could produce the same complete public… |

## Storage lifecycle

**Live source:** `Storage`

### Contract cores and primary packages

#### `phase1-storage-lifecycle-core` — Phase 1 storage lifecycle and expansion core

**Scope:** Implement the pure storage identity, single-writer, create/attach, expansion, and deletion authorization state machines from `docs/architecture/orchestrator.md:758-841`. It emits typed provider/guest/application intents only.

**Outcome:** `PostDeleteAuditReady` is a pre-delete capability/readiness proof and gates the exact `Delete` intent. It is deliberately distinct from `PostDeleteAuditPassed`. Terminal completion requires both observed provider absence and the actual post-delete audit proof. A readiness proof can therefore never masquerade as deletion completion.

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-storage-create-output-audit4` | Phase 1 storage create output audit 4 | yes | Two fully valid provider-volume creation requests differing only in encryption-key reference produced equal accepted `Create` decisions. Equ… |
| `phase1-storage-planner-property-shard` | Phase 1 storage planner property and replay shard | no | Exercise the existing pure storage create, format, attachment, expansion, deletion, and crash-recovery planners with deterministic generated… |
| `phase1-storage-policy-audit2` | Phase 1 storage expansion policy audit 2 handoff | yes | This is Phase 1 pure-policy evidence only. It does not qualify provider, block-device, ext4/XFS, TerraBase, systemd, OCI, rootless container… |
| `phase1-storage-policy-audit3` | Phase 1 storage destructive-output audit 3 handoff | yes | This closes only the pure-policy binding of the accepted retention and verified-backup subject. It does not qualify a deletion adapter, prov… |

## TerraBase topology and recovery

**Live source:** `TerraBase`

### Contract cores and primary packages

#### `phase1-terrabase-core` — Phase 1 TerraBase topology and recovery core

**Scope:** Implement pure TerraBase topology, member lifecycle, upgrade, autoscaling, backup, and restore decisions from `docs/architecture/orchestrator.md:1012-1042` and the TerraBase/storage acceptance gates. It emits typed administration intents only.

**Outcome:** This is a pure decision core. It contains no TerraBase client, SQL/admin text, endpoint, credential value, arbitrary payload, callback, process, network/filesystem access, clock, thresholds, default releases, or mutation.

- Handoff recorded: yes

### Hardening, audits, and property shards

| Package | Title | Handoff | Summary |
|---|---|---|---|
| `phase1-terrabase-audit2` | Phase 1 TerraBase accepted-output audit 2 | yes | The audit found and closed three accepted-output classes plus an adjacent expected-parameter hole: - All seven entrypoints now reject a runt… |
| `phase1-terrabase-audit3` | Phase 1 TerraBase accepted upgrade output audit 3 | yes | Two fully successful upgrades on the same evidence scope but with different exactly matched current and target releases produced equal `Veri… |
| `phase1-terrabase-topology-provenance-audit4` | Phase 1 TerraBase topology provenance audit 4 | yes | Final Release solution and all-five-assembly verification are performed after the required root diff review and exact-central rebase. |
