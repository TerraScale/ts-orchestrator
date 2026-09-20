# OCI deployment readiness — 2026-09-20

**Do not start OCI deployment yet.** Local tests cover useful components, but
the production first-boot, resource ownership handoff, automatic regional
formation, and complete runtime qualification are not finished. No OCI
mutation or local OpenTofu apply was performed for this readiness work.

## Required ownership model

`ts-infra` is authoritative for supported regions and starts the first GRU
orchestrator. Orchestrator must then own the OCI resource lifecycle and create
autonomous regional orchestrator/NATS clusters, whose admitted hosts pick up
work automatically. `ts-auth` and TerraBase scale independently. Status and
metrics must expose needs, actions, and progress across these lifecycles.

Current `ts-infra` code emits generation-versioned region intent and contains
an explicitly disabled GRU-only seed estate and one private ARM64 controller.
It does not create SFO/FRA infrastructure. Runtime OCI fleet startup consumes
`TS_ORCH_REGION_INTENT_FILE` and rejects unsupported cells or mismatched OCI
endpoints/templates. This is startup validation; it neither distributes intent
updates nor creates regional clusters. OpenTofu still owns the seed resources.

The [bootstrap contract](../operations/control-bootstrap.md) defines the
required first boot and exact-resource handoff. A tag or output does not
transfer ownership. A signed adoption request, CI relinquishment without
destruction, durable state publication, and signed release receipt are still
needed before the controller may mutate the seed foundation.

## Verification evidence

These are working-tree results, not qualification of an immutable release.
Other changes are present in the shared checkouts. Rerun the final gates against
the exact release revision before deployment.

| Check | Result | Evidence/limit |
| --- | --- | --- |
| Orchestrator Release solution build, latest edits | Pass, 0 warnings/errors | `/tmp/ts-readiness-build-final2.log` |
| Region-intent authorization tests | 19 passed | `/tmp/ts-region-intent-tests.log`; strict shape, mappings, endpoints, bounded/private file |
| Operator-status projection tests | 4 passed before the additional missing-desired test | `/tmp/ts-operator-status-tests.log`; independent actual policy bounds and stale-decision rejection |
| Scheduler suite, latest edits | 106 passed, 0 failed | `/tmp/ts-scheduler-final.log`; provider failure isolation, cancellation, confirmation reset |
| OpenTofu format, validation, mocked plans | Pass; 7 tests passed | `/tmp/ts-infra-bootstrap-tests-final.log`; all test runs use mocked providers and `command = plan` |
| Refreshed read-only OCI plan, estate disabled | Pass; outputs only, no resource changes | `/tmp/ts-infra-region-plan.log`; passphrase available locally, never printed |
| Auth browser context cleanup regression | 1 passed | `/tmp/ts-auth-browser-cleanup.log`; page disposal now closes its isolated context |
| Auth admin authorization test after cleanup fix | 1 passed | `/tmp/ts-auth-admin-focused.log`; isolated pass does not establish the full-run timeout's cause |
| Full auth CI-equivalent run before cleanup fix | Incomplete, interrupted after approximately 29 minutes | `/tmp/tsauth-ci-equivalent.log`; one admin browser timeout recorded; exit 1, no completed totals |
| New full auth run after cleanup fix | Pending | `/tmp/tsauth-ci-cleanup-rerun.log`; bounded to 10 minutes, same serial concurrency as CI |
| Latest full orchestrator main suite | Pending | `/tmp/ts-orchestrator-main-final.log`; three opt-in live fleet/VM tests skipped |

Earlier completed orchestrator results, before the latest region/status/scaler
edits: main **952 passed, 3 live-test skips**; control plane **949 passed**;
protocol **165 passed**; scheduler **102 passed**; model **59 passed**. Focused
host convergence had 18 passes and admission 2 passes. These are component
results, not proof of a fresh OCI VM booting and serving work.

Earlier auth log `/tmp/tsauth-final-run2.log` completed with 325 passes and
49 failures (44 browser target-closed errors and five webhook/magic-link
failures). It is distinct from the later interrupted runs. Focused reruns of
webhooks (9 tests) and atomic magic-link consumption (1 test) passed. The
subsequent session 49559 was terminated with exit 137 and has no passing suite
result. Do not combine these runs into a green full-suite claim.

Prior focused service telemetry results: auth authenticated metrics 1 pass;
TerraBase metrics/readiness 2 passes. Real containerd execution and the final
external TerraBase/auth deployment remain unqualified.

## OCI inventory and configuration

Read-only OCI CLI 3.82.0 queries confirm READY subscriptions:

| Cell | OCI region | OCI key |
| --- | --- | --- |
| GRU | `sa-saopaulo-1` (home) | GRU |
| SFO | `us-sanjose-1` | SJC |
| FRA | `eu-frankfurt-1` | FRA |

The GRU availability domain is `YDvv:SA-SAOPAULO-1-AD-1`. The recorded TerraScale
compartment is `ocid1.compartment.oc1..aaaaaaaangcm4a4gp4epa2jec7mizqkomvgjnymdrxecimlroa42ozvk7cna`.
Earlier direct listings found no compute instances in that compartment in
these three regions, and no GRU VCN. Vault listing returned no entries in that
compartment. These observations are scoped to the queried compartment and do
not prove the whole tenancy is empty. Dynamic-group listing was denied, so
controller dynamic-group absence is **unconfirmed**.

OpenTofu is 1.12.6 with OCI provider 6.37.0. The private local state passphrase
exists and enabled the refreshed read-only plan. No state was edited manually.
Saved plan files are private local artifacts; state encryption alone does not
ensure saved plans are encrypted. The enabled configuration has been checked
with mocks only. It still needs actual pinned artifacts/images, bootstrap,
least-privilege IAM, private egress, quotas, Vault bindings, and cost review.

The estate now separates the TerraScale parent compartment from the tenancy
root used for dynamic groups and the Email Delivery compartment. Its retained
buckets disable versioning: Oracle explicitly disallows retention rules on
versioned buckets ([OCI retention documentation](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingretentionrules.htm)).
The current virtual-private Vault requires explicit resource/cost review.

## Authentication required before deployment

- **OCI controller:** Instance Principal. The dynamic group must match only
  controller instances; workload hosts need separately scoped permissions.
  Workstation API keys must not be installed on controllers. Prove allowed
  operations and denial outside the owned compartments/resources from OCI.
- **Regional NATS:** distinct controller, operator, infrastructure journal
  provisioner, journal writer, and host identities, with private NKey/mTLS
  material and exact regional subject permissions. The production regional
  runtime uses NKey files; existing JWT-based test fixtures do not by
  themselves prove its first-boot connection configuration.
- **Command and enrollment trust:** pinned signing keys, grant audience,
  certificate/node/region binding, fixed system project, and durable replay
  records. Production admission currently accepts a generation once and
  caches it for the process lifetime. Restart and credential renewal need a
  complete protocol; do not weaken the replay fence to bypass this gap.
- **Vault and workloads:** fetch pinned secret versions through scoped
  Instance Principals, verify digests, write restricted files, rotate and
  revoke credentials. Compose this path for NATS, TerraBase and auth secrets.
  The existing Infisical/file seam is not OCI Vault qualification.
- **Operator:** use authenticated
  `ts.orch.v2.<cell>.query.operator-status` through a read-only operator
  identity. Auth `/metrics` uses its dedicated `TS_AUTH_METRICS_KEY` in
  `X-TerraScale-Metrics-Key`, with no operator-key fallback.

## Blocking implementation and qualification

1. Complete the seed first boot: artifact verification, Instance Principal,
   scoped Vault retrieval, NATS startup, isolated journal, controller admission,
   and recovery after interruption at each stage.
2. Implement and qualify the CI/controller seed ownership transfer. Bootstrap
   IAM must not require an unknown new compartment ID in a manually supplied
   rule or allow the controller to widen its own tenancy permissions.
3. Compose regional network/storage/Vault/IAM and controller formation from
   supported-region intent, with durable generation fencing, resource ownership,
   idempotent retries, rollback, drain, and retained-data protections.
4. Prove fresh host enrollment and automatic admitted task pickup, then restart,
   credential renewal, node loss and replacement. Region support alone must
   never authorize work or confer membership.
5. Qualify generic auth scaling alongside stateful TerraBase placement. The
   status projection now uses configured fleet limits, absent/suspended desired
   state blocks allocation, and one workload's provider failure does not stop
   the other. Provider readiness still needs exact node/cell/artifact binding,
   and stateful retirement must prove drain and data safety.
6. Finish status and telemetry for foundation, handoff, regional enrollment,
   Vault rotation and every provider operation. Current workload aggregates and
   needs/actions/progress are useful but are not complete OCI lifecycle coverage.
7. Obtain completed green auth and orchestrator runs, then real containerd,
   external TerraBase/auth and multi-region VM receipts on the final artifacts.

## Final local gate

Run at reduced local priority; CI keeps normal priority. Use TUnit, not
`dotnet test`. Retain command, revision, exit code and test totals.

- Locked restore, format, Release build, architecture-specific single-file
  publish and vulnerability audit for orchestrator, TerraBase, and auth.
- Full TUnit suites including real NATS, authenticated operator query and
  permission denial, auth browser/security tests, and external TerraBase use.
- Local provider-to-first-boot rehearsal with deterministic OCI transports:
  lost responses, retry-token reuse, restart, ownership mismatch, IAM denial,
  polling timeout, partial failure and cleanup. Prove no duplicate VM.
- Real containerd pull/create/start/readiness/stop/delete on a disposable host;
  verify pinned digest, isolation, wrong-image rejection and secret redaction.
- Live local TerraBase fleet scale/heal, one-region and three-region VM
  formation/loss/heal; verify no leaked guests, taps, bridges or listeners.
- Independent auth/TerraBase target changes, cooldown, pending operations,
  drain, failure isolation and status/metric agreement. Exercise key rotation,
  backup/restore and the controller restart path.
- Mocked OpenTofu tests and a reviewed enabled **plan**, with an exact bootstrap
  artifact and least-privilege resource inventory. Applies remain CI-only.

## First live OCI qualification, after local readiness

Start with disposable GRU staging. Prove Instance Principal allow/deny behavior,
private connectivity, Vault access/denial, seed handoff, fresh node joining,
automatic task pickup, lost-create response recovery, controller restart, drain,
backup/restore and complete cleanup. Run auth security and tenant-isolation
probes over real TerraBase. Do not enable customer traffic or form SFO/FRA
clusters until the GRU receipt is reviewed. Live OCI checks cannot be marked
passed by mocked plans, transport tests, or local VM tests.
