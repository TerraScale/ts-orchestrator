# Shared goal acceptance ledger — 2026-09-26

## SwarmKit refactor work ledger — 2026-10-16

Scope: every requirement in [REFACTOR.md](../../REFACTOR.md). The older product
gates below remain historical acceptance records, not refactor qualification.
Integrator: `/root`, sole publisher and owner of shared module, app, entrypoint,
workflow and evidence changes. All owners use GPT 6.1 Sol, high reasoning.
Starting source: `98422b69`; no refactor gate is qualified.

| Item / accountable owner | State; ETA | Worktree and exact initial file claim | Output / integration evidence / blocker |
| --- | --- | --- | --- |
| START-OWN / `/root` (QA) | active; 5 minutes | main worktree; this ledger | Three isolated worktrees assigned below; shared files serialize through integrator. |
| CORE, CAP, DATA, WASM; START-EXEC / `/root/core_cap` | active; 45–60 minutes | `/tmp/ts-refactor-core`, `refactor/core`; new `internal/swarmruntime/{executor.go,controller.go,executor_integration_test.go}`, `docs/swarm-runtime.md`; worktree-only module changes | Narrow upstream executor and pinned runtime contract; real local containerd lifecycle/restart scenario. Containerd/runc absent initially; local prototype feasibility under investigation. Cloud qualification and stateful cutover remain unqualified. |
| NET, MESH / `/root/net_mesh` | active; 30–45 minutes | `/tmp/ts-refactor-net`, `refactor/net`; `internal/netbird/manager/{api.go,loop.go,sync.go,authority_integration_test.go}` | Per-write authority/cancellation and HTTP interrupted-write recovery. Inventory setup-key/backup/topology dependencies. Existing leadership boolean does not establish a durable authority epoch. |
| REL; START-DEPLOY / `/root/release_qa` | active; 35 minutes | `/tmp/ts-refactor-rel`, `refactor/rel`; `internal/release/cli/{apply.go,apply_integration_test.go}`, `docs/refactor-start-deploy.md` | Independent regional apply through real protocol boundaries; deployment-path audit. Main CI dispatches fleet deployment without runtime/HA qualification; runtime-affecting main publication awaits a concrete production gate. |
| OCI, OBS, QA; START-SCOPE, START-STORE / `/root` | active; first slice 30 minutes | main worktree; `internal/ociregion/imageimport/{import.go,sdk_standin_test.go}`, `internal/dashboard/{assets.go,layout.templ,layout_templ.go,dashboard_test.go,overview_test.go,lists_test.go}`, `internal/dashboard/assets/{dashboard.css,pico.min.css,VENDOR.md}`, `docs/cluster-visibility.md`; shared CI changes claimed before implementation | Preserve partial imports through restart with SDK/HTTP/file integration; consolidate embedded CSS; inventory resource authority and test migration. No current four-VM budget, live capacity authorization, or provider comparison evidence established. |

Live boundaries: no new paid resources, IAM permissions, credentials, secret
installation, production cutover or destructive cleanup are authorized by the
plan. Pending authority blocks only those live actions. Source implementation,
local isolated integration and metadata research continue independently.
START-STORE compares existing OCI semantics with Tigris before any backend
change; no cost advantage is claimed. CONNECT, RUNTIME, FUNCTIONS, STATEFUL and
COMPLETE remain open; package tests cannot qualify their live requirements.

**Overall: IN PROGRESS.** No milestone is complete. This ledger records the
workspace goal against the current shared worktrees; it does not qualify a
deployed candidate. Historical reports and component tests retain only their
stated scope.

**Acceptance completion: 0/16 gates verified (0%).** The fixed denominator is
the M0 exit gate plus D01–D15. A gate counts only when every required child
check passes on the required environment and immutable artifacts. This is
verified acceptance, not effort or source completion.

The 16-gate acceptance denominator is `{M0 exit, D01, D02, …, D15}`.
**Completed: none. Remaining:** M0 exit; D01 fresh deployment; D02 document
lifecycle/retry; D03 authorization/isolation; D04 replication; D05
persistence/S3 recovery; D06 update/failed rollout; D07 SQL; D08
queries/schemas/relationships; D09 reactive delivery; D10 backup/restore; D11
member lifecycle; D12 regional formation; D13 exhaustion/cleanup; D14 Scalar;
D15 management resource protection. M0 has no passing real-caller receipt,
and there is no immutable M1 candidate deployed to the required OCI ARM
environment. Recalculate only
when a whole top-level gate closes; source edits, component-suite passes,
historical receipts, and partial subchecks do not increase the numerator.

## Gates

One file per gate holds its child checklist, evidence and live results. The
status column records the read-only audit of 2026-10-01 (TerraBase
`b668b0c6`, ts-orchestrator `ff6d6677`, live R22 cell). It is not acceptance
and does not change the formal count above.

Use only **NOT STARTED**, **IN PROGRESS**, **BLOCKED**, or **VERIFIED**. A
`VERIFIED` entry requires the real caller, identified immutable artifacts and
configuration, required environment, reproducible command, and retained
behavioral evidence. None of the M1 scenarios below currently meets that bar.

| Gate | Milestone | Scenario | Owner lane | Audit 2026-10-01 status | Claim |
| --- | --- | --- | --- | --- | --- |
| [M0](gates/m0.md) | M0 | Reproducible integration candidate (exit) | A1 | **BLOCKED** | unclaimed |
| [D01](gates/d01.md) | M1 | Fresh OCI ARM deployment | L0 | **IN PROGRESS** | unclaimed |
| [D02](gates/d02.md) | M1 | Document lifecycle and retry | A2; live L0 | **IN PROGRESS** | A2, write-contract consumer fix only |
| [D03](gates/d03.md) | M1 | Authorization and isolation | A2; live L0 | **BLOCKED** | unclaimed |
| [D04](gates/d04.md) | M1 | Replication and partition recovery | A3; live L0 | **IN PROGRESS** | unclaimed |
| [D05](gates/d05.md) | M1 | Persistence, S3 and interrupted work | A3; live L0 | **IN PROGRESS** | unclaimed |
| [D06](gates/d06.md) | M1 | Update and failed rollout | A4; live L0 | **BLOCKED** | unclaimed |
| [D07](gates/d07.md) | M2 | SQL client contract | A5 | **IN PROGRESS** | unclaimed |
| [D08](gates/d08.md) | M2 | Queries, schemas and relationships | A5 | **IN PROGRESS** | unclaimed |
| [D09](gates/d09.md) | M2 | Reactive delivery and resume | A5 | **IN PROGRESS** | unclaimed |
| [D10](gates/d10.md) | M3 | Independent backup and restore | A8 | **IN PROGRESS** | unclaimed |
| [D11](gates/d11.md) | M3 | Resource and member lifecycle | A8 | **IN PROGRESS** | unclaimed |
| [D12](gates/d12.md) | M3 | Regional formation and control recovery | none (not authorized) | **NOT STARTED** | no lane |
| [D13](gates/d13.md) | M3 | Exhaustion and cleanup | A8 | **BLOCKED** | unclaimed |
| [D14](gates/d14.md) | M1 onward | Scalar documentation and interactive API testing | A6; live L0 | **IN PROGRESS** | A6 |
| [D15](gates/d15.md) | M1 | Management resource protection under workload pressure | A7; live L0 | **IN PROGRESS** | unclaimed |

## Pipeline targets

The [§7.2](../../../GOAL.md#72-pipeline-baseline-and-targets) targets sit
outside the 16 gates and stay visible until met. A target is met when three
consecutive `main` runs achieve it with all required checks intact.

| Target | Lane file | Audit 2026-10-01 |
| --- | --- | --- |
| T1 TerraBase `main` push → published release | [P1](pipeline/p1.md) | Not met |
| T2 TerraBase Fast | [P1](pipeline/p1.md) | Not met |
| T3 Orchestrator Go CI | [P2](pipeline/p2.md) | Not met |
| T4 Qualified ARM64 image build | [P3](pipeline/p3.md), [P4](pipeline/p4.md) | Not met |
| T5 CI → image handoff | [P3](pipeline/p3.md) | Met |
| T6 TerraBase pin bump into the image | [P3](pipeline/p3.md) | Partial |
| T7 Qualified image → controller A | [P6](pipeline/p6.md) | Partial |
| T8 Defects first seen on live OCI | [P5](pipeline/p5.md) | Not met |
| T9 TerraBase binary update on the preview | [P6](pipeline/p6.md) (with L0) | Not met |
| §7.1 priority rule: never lower build priority in CI | [P1](pipeline/p1.md) | Met |

## Lane claims

GOAL [§8.1](../../../GOAL.md#81-coordination-rules) records claims here and at
the top of each lane's evidence file until a tracker is chosen (OD-5). Release
a claim when pausing work.

| Lane | Agent | Branch | Start | Scope of the claim |
| --- | --- | --- | --- | --- |
| S0 | `terrascale-37` | `s0/ledger-split`, `s0/test-split` | 2026-10-01 | Ledger split and TerraBase process-test split |
| P1 | `terrascale-37` | `p1/fast-stability` | 2026-10-01 | T2 only |
| A2 | `terrascale-37` | `a2/schemaless-write-consumers` | 2026-10-01 | Write-contract consumer fix only |
| A6 | `terrascale-37` | `a6/d14-docs` | 2026-10-01 | D14 |
| P2, P3, P4, P5, P6 | unclaimed | | | |
| A1, A3, A4, A5, A7, A8 | unclaimed | | | |
| L0 | unclaimed | | | |

D12 has no lane until a separate authorization exists.

## Open decisions

Audit 2026-10-01 (not acceptance): none of
[OD-1 to OD-5](../../../GOAL.md#85-open-decisions-for-the-user) has a recorded
decision. OD-2 (launch-time delivery of deployment material) was implemented
in ts-orchestrator `9f52ca3f` without a recorded decision.

## Deferred scope and unresolved decisions

- Comparative benchmarks, performance thresholds, speed targets, and tuning are
  deferred until functional completion. Resource bounds, deadlines,
  backpressure, and capacity checks remain correctness safeguards.
- Optional model-assisted index advice and optimization studies are deferred;
  ordinary index correctness remains in scope when indexed queries are
  implemented.
- Regional Raft remains a separate proposal and is not an M1 dependency.
- The existing leaderless first-release profile is selected, but the precise
  two-member acknowledgment profile, failure-domain guarantee and supported
  production object-storage provider still require a concrete M1 decision and
  enforcement proof.
- Initial resource accounting is preliminary: the exact OCI compartment/resource
  IDs, selected image, production object provider, current free-allowance basis,
  and retained raw CLI/cost receipt must be bound into the candidate manifest.

Gate-specific decisions from this list now sit in their gate files:
[D07](gates/d07.md) (SQL, query and relationship semantics),
[D09](gates/d09.md), [D10](gates/d10.md) and [D15](gates/d15.md).

## Evidence layout and ownership

Evidence follows GOAL [§10](../../../GOAL.md#10-evidence-and-plan-maintenance):

- **This index** holds the gate table, the formal count, the live preview
  entries and the current handoff. Only L0 writes it. As minimal hot-file
  wiring ([§8.4](../../../GOAL.md#84-hot-files)), a lane changes only its own
  row of the lane-claims table.
- **Gate files** ([`gates/`](gates/)) hold one gate each: claim, status, child
  checklist, expected versus observed result, identities, receipts and the
  moved historical rows. The owning lane writes the file; L0 appends live
  results only under its `Live evidence (L0)` section.
- **Pipeline files** ([`pipeline/`](pipeline/)) hold one pipeline lane each,
  with current measurements against its §7.2 targets and the supporting runs.
  Only that lane writes it.
- **[History](shared-goal-history.md)** keeps superseded ledger sections
  verbatim. Nobody edits it; new evidence goes to the gate and pipeline files.

S0 split the single ledger (ts-orchestrator `8ea61a7d`) on 2026-10-01. No
evidence was removed; every section moved verbatim:

| Former section | Now |
| --- | --- |
| Header, formal count, R16–R22 entries, current handoff | This index |
| Later `ts-infra` ownership update | [History](shared-goal-history.md) |
| Historical checkpoint — 2026-09-29 02:54 UTC, including the full remaining-scope map | [History](shared-goal-history.md) |
| Source identity | Gate-specific rows to their gate and pipeline files; the rest in [history](shared-goal-history.md) |
| Status rules and milestone snapshot | Status rules and gate count here; milestone snapshot and critical path in [history](shared-goal-history.md) |
| M0 — integration candidate boundaries | [M0](gates/m0.md); builder publication to [P4](pipeline/p4.md) |
| M1 — deployed preview and operational protection | [D01](gates/d01.md)–[D06](gates/d06.md), [D14](gates/d14.md), [D15](gates/d15.md); dated refreshes to their gate, [P1](pipeline/p1.md), [P4](pipeline/p4.md) or [history](shared-goal-history.md) |
| Historical preliminary cost and inventory evidence | [History](shared-goal-history.md) |
| M2 — supported API backlog | [D07](gates/d07.md)–[D09](gates/d09.md); section preamble in [history](shared-goal-history.md) |
| M3 — operation, backups, lifecycle and regions | [D10](gates/d10.md)–[D13](gates/d13.md) |
| Deferred scope and unresolved decisions | Cross-gate items above; gate items to their gate files |
| Verification commands and evidence policy | [History](shared-goal-history.md) |

The current handoff below still says "older sections below" and "older ledger
rows below"; those sections are now in the history file and the gate files.
TerraBase's own requirement IDs remain in its
[evidence ledger](../../../terrabase/docs/evidence-ledger.md).

## Live preview entries

L0's dated live entries, newest first. They supersede the progress notes of
the current handoff that follows them.

## GRU preview refresh — 2026-10-01 (R22)

- **Cell.** Deployment `ts-preview-gru-20261001-r22`, ts-orchestrator
  `7aae8102` (Go CI #802), TerraBase `743c569` (CI #1049). This TerraBase
  build serves `/docs` as the Scalar reference alone (TerraBase PR #164).
  `inspect-foundation` passed first time, and `up` and `terrabase-deploy`
  ran without intervention.
- **Checks.**
  - The walkthrough passed 13/13.
  - 10 of 10 writes committed and read back across `api.terrascale.tech` and
    `gru.api.terrascale.tech`.
  - Controller A joined NetBird automatically.
  - `http://gru.api.terrascale.tech/` redirects to the Scalar-only reference.
- **Atlas.** At 07:00 UTC, Worker version `e9ce83ed` was deployed from an
  uncommitted, stale ts-atlas checkout and dropped the regional root redirect
  (421). It was replaced from origin/main `07f210a` (version `a1ab188c`).
  Production atlas deploys must come from a clean origin/main worktree.

## GRU preview with NetBird — 2026-09-30 (R21)

This entry records the first cell built from the reviewed NetBird-aware plan.
It supersedes the R20 state in the entry below.

- **Cell.** Deployment `ts-preview-gru-20260930-r21`, ts-orchestrator
  `cb8314f2` (Go CI #800), TerraBase `23ac1dc` (CI #1046).
  - `attempt.py up` ran with main's `preview.py`.
  - Its base plan is the reviewed `deploy/oci-region/plan.json` (`netbird`,
    `operator_gateway`, `public_api`, current network rules) combined with
    the live foundation resource IDs and `host_credential_secret`.
  - `inspect-foundation` passed, including the NetBird peering, gateway,
    egress, IAM and secret checks.
- **Foundation corrections.**
  - Runbook Apply step 3 was still pending: the control NSG allowed
    `10.251.0.0/24` (including the public API subnet) on 4222, 6222, 7422,
    8080 and 8443. It now allows only the private `/25` on 4222, 6222 and
    8443, plus the gateway `/32` on 4222.
  - The NetBird enrollment policy was in the parent `TerraScale`
    compartment. It was recreated with identical statements in the setup
    key's `terrascale-control` compartment (`7aae8102`).
- **NetBird enrollment.** All five servers joined automatically at boot:
  controllers A, B and C and both TerraBase hosts.
  - `terrascale-netbird-enroll.service` reported management and signal
    connected over the private LPG route, with `/etc/hosts` mapping
    `netbird.terrascale.tech` to `10.250.10.155`.
  - Both units are enabled, the peer identity persists in
    `/var/lib/netbird/config.json`, and no setup-key file remains.
  - Controller A was checked live over the break-glass bastion. The other
    four were checked from read-only boot-volume clones, deleted afterwards.
  - Controller A kept its public key, NetBird IP `100.123.36.145` and FQDN
    across a reboot, and the cell kept serving.
- **Customer checks.**
  - `terrabase-walkthrough` passed 13/13.
  - 20 of 20 authenticated writes committed and read back across
    `api.terrascale.tech` and `gru.api.terrascale.tech` in both directions
    (p50 1.8 s).
  - The Scalar reference renders completely on both hosts.
- **Open.**
  - Manager-side evidence needs the owner PAT: peer list and group
    membership, deletion of the default policy, the scoped
    `operators → gru-cell` policy on 22/4222/9465, and backup integrity.
  - Operator access through the gateway, including denial of 6222/8443,
    needs an enrolled operator device.
  - ts-rust #9 (TS-285) would revert the `.api.` regional hosts and the
    discovery-unavailable proxy fallback. It is on hold for an owner
    decision.

## GRU preview refresh — 2026-09-30 (R17–R20)

This entry supersedes the R16 open items below.

- **Write reliability.** R16–R18 writes could return `commit_uncertain` and
  fail-stop the member. Causes and fixes:
  - The host's native OCI root pin lapsed between reconciles:
    `a54cba54` refreshes it for the same validated desired state.
  - TerraBase treated retryable publication holds as fatal: TerraBase PR #156
    (`3ea833d`, CI #1036) keeps them retryable.
  - Artifact claims could expire before upload finished: `682a6705` signs a
    claim only after its bytes are stored.
  - Cloudflare returned 525 against the Ed25519 serving leaf: `ee92b9bf`
    switches the leaf to ECDSA P-256.
- **Serving flaps.** Hosts report about every 35 seconds, but host status
  discarded reports older than 30 seconds, so placement demoted and re-promoted
  healthy members. `a646a862` bounds every report-freshness check by one
  90-second `host.ReportMaxAge`.
- **R19.** ts-orchestrator `a646a862` (Go CI #796) with TerraBase `3ea833d`
  (CI #1036).
  - `attempt.py up` ran without intervention.
  - `terrabase-deploy` applied on its first attempt, and both seats served
    about six minutes later.
  - The walkthrough passed 13/13.
  - 29 of 30 authenticated writes through `gru.terrascale.tech` committed and
    read back through `api.terrascale.tech`; one request failed in transport.
  - Report ages up to 32 seconds no longer demote members.
- **Scalar reference.** `/docs` stayed on Scalar's loading skeleton in every
  browser. Scalar's standalone script auto-mounts an empty reference on the id
  `api-reference`, and the page used that id for its own mount. Fixed in:
  - TerraBase PR #158: mount on `terrabase-reference`, pin the new CSP hash,
    and test for the reserved id.
  - TerraBase PR #159: `withDefaultFonts: false`, so the strict `font-src`
    policy no longer logs violations.
  - Release: TerraBase `431991c`, CI #1040.
- **R20 (current).** ts-orchestrator `a646a862` (Go CI #796) with TerraBase
  `431991c` (CI #1040), deployment `ts-preview-gru-20260930-r20`.
  - `up` ran without intervention.
  - `terrabase-deploy` applied on its first attempt, and both seats served
    about five minutes later.
  - The walkthrough passed 13/13.
  - 20 of 20 writes through `gru.terrascale.tech` committed on their first
    attempt and read back through `api.terrascale.tech` (p50 1.9 s).
  - `http://gru.terrascale.tech/` redirects to `/docs`, and the Scalar reference
    renders completely in Chromium on `gru.terrascale.tech` and
    `api.terrascale.tech`.
- **Open.**
  - The serving proof requires the peer to have applied the local source
    sequence at report time. Under sustained writes a report can land
    mid-replication and briefly demote a member; the process is not restarted
    and desired state is re-applied unchanged.
  - Cloudflare Web Analytics injects a beacon that the docs CSP blocks.
    Disable Web Analytics for the zone.
  - In-place TerraBase rollout (`operator terrabase-update`) still needs the
    compatibility signer and update-actor decisions. Until then each TerraBase
    release rebuilds the cell, because the image packages `tb-server` as the
    native verifier.

## GRU preview deployment — 2026-09-30 (R16)

This dated entry records the first end-to-end GRU preview deployment. It
supersedes the progress notes of the 2026-09-29 handoff below; formal M0/D01–D15
acceptance still follows the rules above.

- **Cell.** Deployment `ts-preview-gru-20260930-r16`, object prefix
  `r16-20260930`, ts-orchestrator `ee92b9bf35` (Go CI #778), qualified image
  `ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaza4lnybisxknfks4q4zkbixatrct6cs3tuwrdxpl6gg3cho4kd5a`. `deploy/oci-region/attempt.py up` ran every phase without operator
  intervention: Ops launched controller A only, the founder launched B and C,
  every controller published its accepted-install marker, and continuity
  generation 2 and the operator config were installed automatically.
- **Workload.** `operator terrabase-deploy` with the attempt's qualified
  operator CLI admitted placement 405 for TerraBase `d2017ca` (CI #1012). The
  orchestrator launched both member hosts, created and attached their
  encrypted data volumes, initialized them and started TerraBase through
  signed desired state; both seats reached `serving` with serving proofs about
  seven minutes after the deploy. No member was reached by SSH.
- **Customer checks.** `operator terrabase-walkthrough` passed 13/13 (OpenAPI,
  missing/invalid/wrong-tenant credentials rejected, create, exact retry,
  cross-member read, update, delete and their replication).
- **Public API.** `https://gru.terrascale.tech` (Cloudflare → OCI NLB
  150.230.93.187:443 → members :9465) and `https://api.terrascale.tech`
  (ts-atlas regional router) serve `/docs` and `/openapi.json`. An
  unauthenticated read returns 401; an authenticated write through
  `gru.terrascale.tech` committed on its exact retry and was read back through
  `api.terrascale.tech`.
- **Open.** A write can return `commit_uncertain`; the member then drops out
  of serving and the orchestrator restarts it within about two minutes.
  Cloudflare's browser integrity check rejects clients that send a default
  library User-Agent (error 1010). TerraBase on Turso 0.8.1 (`d9fb897f`) is
  published but not yet rolled to this cell.

## Current handoff 2026-09-29

The root [`GOAL.md`](../../../GOAL.md) remains the goal authority. This dated
handoff supersedes progress observations in the 02:54 UTC checkpoint and older
sections below, while preserving their evidence and every M0/D01–D15
acceptance requirement. Substantial build, image, and bootstrap prerequisites
have passed; **formal acceptance remains 0/16**. No R5 controller or TerraBase
workload has a verified serving receipt. Current authorization is GRU
(`sa-saopaulo-1`) under the combined US$200/month qualification and preview
ceiling: Ops owns the regional foundation, credentials, image prerequisites,
and controller A only. After an explicit healthy A identity, authority, and
inventory handoff, `ts-orchestrator` owns B/C formation, workload hosts,
volumes, enrollment, and TerraBase deployment through signed desired state.

**Exact candidate pins.** Go/image qualification uses `ts-orchestrator`
`e631cd6b05578a50d23d85e31d20f52ec024a5e9`, tree
`13b9f81dc47459a63f8ccfad164cc1a2102110fb`, Go CI #701 and image CI
#702/run 11709/job 25246 attempt 1. Image #702 retained ARM64 QCOW2 SHA-256
`873105a00cb55aa8fc8c541d53093ff33d147fc2908f6a3682ab6c5d5ef5aa28`;
the signed R5 image receipt SHA-256 is
`dc271eb3b618899374c78ecfbf7f4783c77bc4b513c6bc0c754c07f8b66af873`.
Before this ledger edit, the local `ts-orchestrator` `main`/`origin/main`
implementation baseline was
`10c85e37aecd85591d1fa6c186d44049e34402ac`, tree
`71b33e2b6147db85282b84983a59adff27e5b2c7`. Its Go CI #704/run 11712
retained log records race tests, 45 Python tests, and both static builds, but
ends during Nixpkgs unpacking; the terminal CI result is **unknown**. Do not
substitute that main revision or its artifacts for the qualified `e631` image.
TerraBase `main` `470d1f898897d4a0cefc7d638ce8eb72f0ca73b8` passed CI
#1018/run 11711 (Fast 150 passed, 0 failed, 3 ignored; Release and Publish
passed). The first R5 OCI workload remains pinned to TerraBase
`d2017ca9668a650ec490dff3f79bd51b75bb6466` / CI #1012 with `Backup=nil`;
CI #1018 does not change the R5 image-input pin or supply a signed workload
placement or live OCI proof.

**Last authenticated OCI snapshot, with its limits.** Define private evidence
root `E` as
`/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/genesis-5e72567b-20260928`.
The manual inventory `E/r5-deployment/manual-inventory-preimport-r5.json`
(SHA-256 `50ad33e1f76da2622350fa4562266be864213b01d7ac0020d2667b1f659dcea2`)
was captured **2026-09-29 08:00:24 UTC, before R5 image import**. It lists 28
scoped resource rows, seven GRU buckets, and six AVAILABLE custom images at
2 billable GiB each. These categories are separate; they are not a total
deployed-resource count or a whole-tenancy zero check. The rows include five
instances: the existing `ts-forgejo-server` RUNNING and four older controller
attempts TERMINATED; five boot volumes: Forgejo AVAILABLE and four older ones
TERMINATED; one 50 GiB Forgejo data volume AVAILABLE. Its network rows are
four AVAILABLE NSGs, four route tables, three security lists, two subnets, two
VCNs, one service gateway, and one ASSIGNED public IP. The seven buckets are
`ts-forgejo`, `ts-forgejo-backup`, and five shared
`ts-preview-gru-20260926-{backup,head,ledger,material,terrabase-live}`
buckets. Forgejo and shared foundation retain their existing owners; neither
the A-only bootstrap nor cleanup may claim them as new R5 resources.

The saved foundation check `E/r5-deployment/foundation-preimport-r5.json`
(SHA-256 `75cc8f0c4d2bd85781e9d2f37f8ee0687d16df099a66d020006baa809f127d92`)
was inspected **08:01:14 UTC**. Its GRU tenancy is
`ocid1.tenancy.oc1..aaaaaaaae4zbeypc66rholaayphrk6h2eg7j4up6tfncehv6agji6o5v4yga`;
control, network, and workload compartments are respectively
`ocid1.compartment.oc1..aaaaaaaaifvroeyjgu4l5h5gy4qzv7t6yfbcbd3fwwqxmzbamqkbjc5nvria`,
`ocid1.compartment.oc1..aaaaaaaaw2igbgmgiwm7uq7awu4arpipym7y5xsw65zwlobf4xfyedykvw2q`,
and `ocid1.compartment.oc1..aaaaaaaas46bwgh6tamohp43vvtw3xmtcwfal34tmwk3zzx3tbxtepbnq5ma`.
The R5 seed plan names VCN
`ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6dz7gvnghd6a532ys3s3pdbpwxr3iqptdp2fyv5tj7ea`,
subnet
`ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaamqsca7442n6vrmros37z6hhpha2rct3bps2hgp2dml35cnu3djbq`,
shared controller NSG
`ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaanfaj2mqrjua5shofwm6uu2kl5dzbqaqyl3y4vc326j6vjiv5q67q`,
and seed SSH NSG
`ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaasmq3frwqq7mm2ewf52fafwdydychkqefxsr2yohu7koag2ljl3xa`.
The separately saved workload NSG readback names
`ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaadwza5moxpf3hdss64efjhfhrg5kadyuger5scecyfgm3ucgz4zna`
as AVAILABLE. The plan references two dynamic groups, three policies, one
Vault, and one KMS key; retained controller dynamic-group and policy readbacks
say ACTIVE. The R5 Vault exact-version readback verified **25/25** controller
secret references at **05:35:24 UTC**. Those are dated bindings, not proof
that every IAM/Vault resource is current. The signed R5 anchor instead pins
new deployment owner `ts-preview-gru-20260929-r5`, object namespace
`grxnmoqvrcdv`, and prefix `r5-20260929` within the shared head/ledger
buckets; the plan's `ts-preview-gru-20260926` owner tag identifies shared
foundation.

After that preimport inventory, cached `E/r5-deployment/image-available-r5.json`
recorded the **new** 2-billable-GiB image
`ocid1.image.oc1.sa-saopaulo-1.aaaaaaaa3nwsziponjnum4elqg2dxb2jjp575tpuublhbcq4jabxzbluu4hq`
AVAILABLE at its 08:10 UTC file readback. The final shape readback SHA-256
`877914fe33b314eb3f3ca300949f879634587cb08c2dbb83a5ea59623f12e819`
permits `VM.Standard.A1.Flex` at exactly 1 OCPU/6 GiB and
`VM.Standard.Ampere.Generic`. The signer rerun finished successfully at
**08:19:51 UTC** and produced the signed image receipt above, with saved
`verify-image` output covering the QCOW2 and embedded binary. A later
independent review passed receipt signature, delegation, scope, and expiry,
but this sandbox denied its fresh libguestfs extraction (`bind: Operation not
permitted`); it did not repeat the full image check. The preimport cost admission
`E/r5-deployment/cost-admission-preimport-r5.json` (SHA-256
`3f76c74127007aaf4c10612ab308fdda6c1151011f63ba18e7a9c8d4efec4260`)
forecast **US$90.46/month of US$200** at **08:00:33 UTC**, before R5 import
completion, and excludes the new 2-billable-GiB image. The admission expired
**08:15:33 UTC** and must be refreshed before launch. It is neither actual
billed cost nor a current postimport admission.

The historical failed-A cleanup receipt `E/failed-a-cleanup-receipt.json`
(SHA-256 `d7fbafaaf44ff455ea6bc949d9b29da7946aecec5237865f160ea2c71c669c0d`)
observed an older A and boot volume TERMINATED, `.11` released, eight older
objects preserved, and shared bastion/subnet/head/ledger/material resources
retained at **2026-09-28 20:42 UTC**. R4 is frozen. Its image, manifests,
placement/spec, and failed-attempt resource identities must not be reused for
R5; cleanup follows the current resource owner. The scoped preimport snapshot
and E's lack of R5 launch files do **not** establish that all current tenancy
instances are absent. There is no retained R5 A launch, B/C, or workload
serving evidence. One bounded live image GET during this ledger edit returned
no data and timed out after 12 seconds (exit 124); current OCI state remains
unknown. This session also cannot reach the user systemd bus, resolve Forgejo
DNS, or write private E. These access limits are distinct from a diagnosed
product defect; recover authorized operator access before live steps.

**Prepared but unsigned.** The independently reviewed private packet
`/tmp/ts-r5-offline-Dd9nlgMt` has [STATUS](/tmp/ts-r5-offline-Dd9nlgMt/STATUS.md)
and `SHA256SUMS` SHA-256
`5a85fdf5088508f636203fea07576a5617f7346df0f22b1f48e48de1a0273d69`.
It contains exact-schema `oci-region.json` SHA-256
`45ec4963ae192f58eb4abb9a9e348507f33f96783fd5133acf396db7ec2d961f`
and unsigned A/B/C candidate SHA-256 values
`7abc34f97af2f87bdd2305400d28d9fc5321283d0ad9869382753918a52c7dcb`,
`dca56bf62e7df31f6737afd304488b062c6c24fc13de1cbcfefbe3490c36484e`,
and `4d23b143721f03ec63fc45f7d5bb043110658ea295e4f7a953f674f4bf6a977f`.
Released `ts-bootstrap-e631` rendered all three controller configs offline.
No R5 region sidecar, signed A/B/C manifests, founder plan/selection, seed
reservation, or A launch receipt exists in private E as of this check. The
packet is review material, not live OCI admission. Private E contains the
durable build/import/signing and trust evidence; `/tmp` image bytes, readback
receipt, offline packet, M0/D10 packets and Go CI log are ephemeral. Preserve
or deliberately copy their hashes/bytes before temp cleanup. Never copy
Vault secret values or private keys into source or the public ledger.

**Proof deadlines (UTC, recheck at use).** The signed image receipt expires
**2026-09-30 08:19:30**; peer-receipt delegation **2026-10-01 07:36:59**;
bootstrap anchor **2026-10-02 05:20:29**; ledger delegation
**2026-10-02 13:20:24**; material record **2026-10-03 05:19:52**; release
image delegation and signed binary receipt **2026-10-06 07:03:53**. Expiry
requires renewed current proofs and exact dependent hashes. Source
`ts-release sign-image` can sign an unchanged retained image candidate into a
new output after its current Forgejo qualification, binary-receipt,
delegation, and byte checks pass; expiry alone does not require a CI or QCOW2
rebuild. A newly signed receipt changes `releaseReceiptSha256`, so regenerate
and re-review the unsigned manifest candidates before signing. Preserve the
old immutable receipt instead of overwriting it.

**Other active tracks.** M0 remains unaccepted: its pinned Go
`c4effe176e7b06ba7f9a40e83bb03cfbd952229f` / CI #697 is independent
of the R5 `e631` deployment image. R14 failed before a guest started and its
cleanup receipt says `CLEANUP_PASS`; R15 remains a plan-only HOLD with no
launch or joined Go→Rust write/read, while its no-guest metrics rehearsal and
cleanup passed. Continue M0 only after independent capacity and process
readback; it does not replace OCI D01. D10 Go Complete/catch-up remains an
unmerged scratch worktree plus stable `/tmp` snapshot. The old focused failure
log predates its current test assertions, so the exact host CAS rejection
predicate requires a bounded focused rerun after host-scope quiescence. Do not
weaken the production fence from that old log. There is no live clean restore
or PITR proof. TerraBase CI #1018 and these prerequisite advances do not
complete an acceptance gate.

**Next authorized sequence.** From a permitted operator environment, first
read current host/process and authority state; refresh authenticated GRU
image/shape, resource inventory, IAM/foundation/Vault, NSG/free-IP, and the
combined US$200 admission. Verify exact EMPTY HEAD, ledger and reservation
prefix/version state before any seed publication. Review the packet's region
sidecar against fresh readbacks; renew expiring proofs; construct, sign, and
verify exact R5 A/B/C manifests and founder/selection; run seed preflight and
reserve. Ops then bootstraps **A only**, proves it healthy and hands off its
identities, authority and inventory. `ts-orchestrator` then forms **B/C via
the founder**, creates the two distinct TerraBase hosts and their owned
volumes, enrolls them, and applies signed workload desired state. Prove an
authorized external write/read and the remaining M1–M3, D01–D15 scenarios
before changing 0/16. M0 may proceed in parallel only under independent
capacity and authorization.

Evidence index: private `E/r5-deployment/{manual-inventory-preimport-r5.json,
foundation-preimport-r5.json,cost-admission-preimport-r5.json,
image-available-r5.json,image-shapes-final-r5.json,
image-receipt.signed.json,image-receipt.verify-r5.txt}`;
`E/r5-material-prep/{bootstrap-anchor.signed.json,
peer-receipt-delegation.signed.json,ledger-delegation.signed.json}`;
`E/r5-go-release/{canary-release-image-delegation.signed.json,
canary-linux-arm64.receipt.json}`; ephemeral
`/tmp/ts-r5-image-artifacts-702/post-success-readback.receipt.json`
(SHA-256 `8a2afa539628e3309677d18ba36ca87ddd4efea712a6d65f0034f4f4599ca162`),
`/tmp/ts-r5-offline-Dd9nlgMt/STATUS.md`,
`/tmp/ts-orch-ci-run704.log` (SHA-256
`5aa19982c96263003f1bea8ae33cac0e65edc4b85c3af28e673f8b575053cff8`),
TerraBase [CI #1018 readback](../../../.qualification/terrabase-ci1018-470d1f8/qualification-readback.md),
`/tmp/ts-m0-full-r15-20260929/plan-only.json`, and
`/tmp/ts-d10-go-catchup-rerun-handoff-20260929.md`. The older ledger rows
below retain their dates and requirements; use this section for current
operational state.


## Delegated refactor integration — 2026-10-16

This roster supersedes the earlier owner assignments without changing their
historical evidence. `/root` coordinates only. `/root/qa_integrator` is the sole
shared-file and main integrator; all workers use `gpt-6.1-sol`, high reasoning.
QA source baseline: `7a7abb41`; isolated tree `/tmp/ts-refactor-qa`, branch
`refactor/qa`. No live refactor gate is qualified by these source assignments.

Preserved original-worktree changes at START-OWN: modified `REFACTOR.md`,
`docs/apps-machines.md`, `docs/evidence/shared-goal-acceptance-20260926.md`,
`docs/generic-workloads.md`; deleted `internal/machines/schedule.go` and
`schedule_test.go`; untracked local binary `terrascale-orchestrator`. QA does
not overwrite, stage or remove these pre-existing changes. The plan and
`AGENTS.md` remain human-owned.

| Owner / item | State; ETA | Isolated tree; exact claim / boundary | Evidence / remaining blocker |
| --- | --- | --- | --- |
| `/root/qa_integrator` / START-OWN and shared integration | active; initial inventory 15 min | `/tmp/ts-refactor-qa`; this ledger append, `go.mod`, `go.sum`, `.github/workflows/{ci.yml,deploy.yml}`, `Makefile`; named app/entrypoint handoffs only | Serialize exact-candidate integration and publication. Runtime main push awaits mandatory production-admission enforcement. |
| `/root/core` / CORE and START-EXEC | active; first slice 60 min | `/tmp/ts-orchestrator-core`; new `internal/swarmruntime/` production and integration files, `docs/evidence/core-runtime-contract.md` | SwarmKit/containerd lifecycle and restart identity; local runtime qualification only, no cloud authority inferred. |
| `/root/oci` / OCI and START-SCOPE | active; ETA retained by owner | `/tmp/ts-orchestrator-oci`; OCI feature files claimed by owner, excluding CAP seed/image-import files | Foundation and durable resource lifecycle; paid mutation remains blocked on exact footprint/budget authority. |
| `/root/net` / NET | active; ETA retained by owner | `/home/mariogk/Projects/TerraScale/ts-orchestrator-net`; `internal/netbird/manager/setupkey.go`, enrollment integration, new `internal/netbird/foundation/`, `deploy/netbird/manager/` | Vault-backed enrollment/bootstrap; live OCI foundation and approved recovery fixtures pending. |
| `/root/cap` / CAP | active; first contracts 20 min | `/tmp/ts-orch-cap`; `internal/nodescale/{pool.go,pool_oci.go,capacity.go}`, `internal/image/{inputs.go,guest.go,run.go,offline.go,promote.go}`, `internal/ocicost/node.go`, named seed/image-import handoffs | Role/architecture/shape pool identity and coherent pricing/image contracts; shared app callers integrate through QA. |
| `/root/rel` / REL and START-DEPLOY | active; ETA retained by owner | `/tmp/ts-refactor-rel`; release feature files and `scripts/ci/{deploy-fleet.sh,publish-qualification.sh}` with child-owned gate helper | Credential-free per-region exact candidate production admission, then admitted-cell deployment; live evidence unavailable remains refusal. |
| `/root/mesh` / MESH | active; 35–60 min | `/tmp/ts-orchestrator-mesh`; named `internal/natscell/{link.go,interregion.go,leaftopology.go,reconnect.go,accounts.go}`, membership feature, `globalcontrol/heartbeat.go`; explicit app handoff `region_registry.go`, `region_registry_test.go` | Admitted membership separate from heartbeat health, durable formation and loop-free leaf topology. |
| `/root/obs` / OBS | active; first slice 30 min | `/tmp/ts-orchestrator-obs` and isolated children; named catalog/history, dashboard metrics and CLI observe feature files | Real metric registry/history; shared app observations/journal wiring reserved to QA. |
| `/root/wasm`, `/root/data` / WASM and DATA | active; owner claims pending | Separate owner worktrees; no QA overlap claims | Function isolation and database fence/drain/restore contracts qualify independently; production cutover unqualified. |
| `/root/qa_integrator/test_inventory` / test conversion ledger + sdnotify | active; 12–20 min | `/tmp/ts-refactor-qa-sdnotify`; `internal/sdnotify/{sdnotify_test.go,extend_review_test.go}` | Complete tracked/vendor inventory plus real unixgram coverage before deleting isolated cases. |
| `/root/qa_integrator/capacity_tests` / CAP test migration | active; 25–40 min | `/tmp/ts-refactor-qa-capacity`; `internal/nodescale/{pool_oci_test.go,decide_test.go,rtt_test.go,scaler_test.go,store_test.go,signals_test.go}`, `internal/ocicost/node_test.go`, new named integration files | Real OCI HTTP/JetStream boundaries; consume CAP contracts, preserve invalid/missing capacity/price safety. |
| `/root/qa_integrator/artifact_tests` / retained artifact test migration | active; 20–30 min | `/tmp/ts-refactor-qa-artifact`; `internal/artifact/{touch_test.go,read_test.go,read_authoritative_test.go}`, new integration files | Real filesystem/HTTP boundaries before removing unit-only cases. |
| `/root/qa_integrator/runtimepriority_tests` / retained host priority migration | active; 20 min | `/tmp/ts-refactor-qa-runtimepriority`; `internal/runtimepriority/*_test.go`, new integration files | Real isolated subprocess/syscall behavior; no host-wide privileged mutations. |
| `/root/qa_integrator/storage_compare` / START-STORE | active; 20 min | `/tmp/ts-refactor-qa-storage`; new `docs/refactor-storage-comparison.md` only | Official prices plus actual OCI placement/copy/restore assumptions; no backend change or cheaper-provider claim. |
| `/root/qa_integrator/completion_audit` / independent requirements audit | active; 20 min | Read-only current plan/source/evidence inspection | Exhaustive requirement-to-owner/evidence matrix, unattended independent tasks and unresolved live gates. |

Publication boundary: the actual `ci.yml` main-push path dispatches `deploy.yml`
after retention. Missing configured repository credentials does not establish
production protection, because inherited secrets/OCI authority remain unknown.
Only documentation-only safe publication or runtime candidates admitted through
the mandatory exact-source/region/runtime/architecture gates may proceed. No
new paid capacity, IAM permissions, credential installation, production cutover,
or destructive recovery is authorized by this roster.


### Refactor handoff state — 2026-10-16, 20:05 UTC

All owners below remain on `gpt-6.1-sol`, high reasoning. This is a source and
local-scenario ledger, not live acceptance. CONNECT, RUNTIME, FUNCTIONS,
STATEFUL and COMPLETE remain open. No package-wide conversion, cloud capacity,
production restore, full-repository green run or spending authority is claimed.

**Integrated in QA candidate `02360dca`**, not yet published to main:

| Slice | Integrated QA commits; producer provenance | Evidence and limits |
| --- | --- | --- |
| Credential-free release admission and independent consumer qualification | `943a8ac3`, `8b3eaa9f`, `ff17fa4d`, `54e7c758`, `01ad811a`, `62173b01`, `bb886c9b` | Fleet workflow qualifies before credential-bearing deployment; signed exact source/artifact/build/region/environment/runtime/architecture proof requires runtime-HA and workload safety. Image/first-boot gap below is still open. |
| Concrete OCI read cancellation and retained mutation outcomes | `a5877de1`, `25529a7f`, `780a700a`, `02360dca`; originals `66fb8150`, `3c9b20d9`, `987f7ed8`, `2b0211b9` | REL original `987f7ed8`: full race CLI 23.382s, channel 3.372s, OCI client 3.547s. SDK original `2b0211b9`: focused signed-HTTP read/mutation race 2.285s. Arbitrary non-SDK object clients retain their original cancellable context. |
| Release fixture closure | `1e579b18`, `35d88a05`; originals `3485441f`, selected fixture hunks from `b9c71b18` | Selfupdate, selfupdate CLI and bootstrapstart passed at original `3485441f` (1.236s, 5.875s, 57.525s). Broad REL sequence branch was not replayed into the gate candidate. |
| Retained-feature migrations and inventories | sdnotify `97dc1a4f`, artifact `c5d1300d`, runtimepriority `5e9b620e`, recovery inventory `0cfb83cc`, storage comparison `26f8b548` | These are bounded slices. Full integration-only inventory remains open; unmatched security coverage is preserved until a real boundary replacement exists. |

The existing dirty main tree remains at `7a7abb41`; the latest read-only remote
main readback was `4ad1acf5`. Its human-owned dirty files and untracked binary
remain untouched. A reversible byte-verified dirty-tree preservation step is
required before any eventual main fast-forward. No push has occurred here.

**Ready/source-only handoffs; do not confuse copied helpers with implementation:**

| Owner / source | Actual implementation | Consumer/evidence status |
| --- | --- | --- |
| CAP | Pricing `92ed6f62`; catalog `7b91950b`; pools `54c0de0e` + `02f85128`; seed `dd43f068` + `36317ca8`; selection `fb2b3c2a` + `64a90a1b`; image `75df8fbc` + `baf79837` | `b0572378` and `ffcd45bc` were copied dependency/helper aggregates, not actual image/selection implementations. Actual image seven SDK scenarios passed 0.478s; selection twelve SDK scenarios passed 0.469s. Neither qualifies AMD64 boot or production runtime. |
| OBS and shared app | App integration branch `da1637f7`, with original OBS `c7997d16`, `e3c4b9d4`, `f96eff93`, `e5027185` and shared routes/callers | `0a810`/`9d1` copied catalog work did not establish complete OBS implementation. Focused actual HTTP catalog/CLI/dashboard checks at `da1637f7` passed 0.061s/0.187s/0.133s. Later `67dcd970` + `1e3b0cee` remain separate handoffs. Shared app is not yet in QA main candidate. |
| NET | Protected backup `0cb7a019`; enrollment escrow `70f11a18`; management fencing `a2ebbcc4`; DNS/GRU policy `c694e8f2` | `f651`/`289` were helper-only copies. Full NET checks and subsequent no-retry epoch-loss write fixes remain pending; no live restore or production bootstrap claim. |
| CORE dependencies and runtime | Shared module union `61968b3b` on `refactor/qa-modules`; actual node `27719b8f` + `e59a1eaa`, executor `c272bbed`, mapper `c08ec295`, deletion `960e8de5` | The old `01348c66` prototype must not be replayed. Modules are separately serialized, not in gate candidate. Actual corrected local manager/containerd/runc recovery passed 4.87s; no ARM/HA/cloud qualification. Actual app engine cutover still requires verified admission consumers. |
| QA imageimport and logs conversion | Imageimport `00f400f6`, depends actual CAP image source; logs worker has six test-only files pending final race check/commit | Imageimport full package passed 3.706s; logs plain package passed 4.074s. Neither source has been integrated into QA gate candidate yet. Capacity conversion recovery is owned by app integrator's capacity caller worker. |

**Current trust-sensitive source scopes:**

1. Cold bootstrap: immutable signed source and bootstrap-scoped OCI grant →
   private Vault escrow → typed sealed installation → managed-image prestart.
   Shared app owner requires the same verified grant through all steps;
   foundation-only authority cannot create a regional founder, and workers
   cannot found a cluster. Nonhome pre-config trust discovery and actual signed
   manifest/config startup consumption remain open. No fake entrypoint closes it.
2. Functions: admitted service → trusted controller `ProvisionQueue` →
   consume-only worker JWT → conditional Vault delivery → admitted Swarm Wasm
   task mount. Workers cannot create streams/consumers or receive controller
   credentials. CORE mount admission and actual qualified task producer remain
   open; helper-only provision/material code does not close FUNCTIONS.
3. Image boot: the effective selfupdate drop-in invokes `Prepare`/`Seed`, which
   seeds baked bytes without channel qualification; initial bootstrap currently
   uses signature-only `VerifyImageCurrent`. REL owns the narrow image receipt
   and sign-image independent production-proof closure; QA owns affected
   bootstrap/selfupdate fixtures. Weekly/manual image builds and promotion are
   separate consumers, so release-channel checks alone do not close START-DEPLOY.

**Retained local evidence** (not live qualification): SDK log
`/tmp/oci-sdk-race-2b0211b9.log`, SHA-256
`a8bebccd5aa1d987986ebb9ece17f9f2d1d712d98b26cc2567bee7915900634c`;
selfupdate closure `/tmp/ts-orch-gate-evidence/3485441f-selfupdate-closure.log`,
SHA-256 `13ddb21187b552197ee82b3fabdd43f333e831dbdfde457d9723475d4e30cb61`;
WASM race/ARM64-crossbuild/AMD64-build log `/tmp/ts-wasm-qualification.log`,
SHA-256 `88dc21d4fd2161693f839aaed47c5427dd8ec626a19e7d9220227ae2e2e0dfa6`.
Earlier failing `bb886c9b-release-closure.log` remains retained rather than
relabeled as success. Exact integrated candidate build is running separately;
no result is assumed before exit. START-SCOPE read-only inventory is retained
under `/tmp/ts-refactor-start-scope-20261016/`; approved paid provisioning,
new authority and destructive cloud operations remain unavailable.


### Image admission closure in progress — 2026-10-16

QA integrated source now `9feb2a59` (before this evidence-only append).
The following are source/local checks, not live qualification or publication:

| Boundary | Integrated provenance | Actual check |
| --- | --- | --- |
| Final-image receipt/current verifier and signer | Original `00e18a1c` → QA `9c7f7970`; original `5a4e7776`/`e38b295e` → QA `f28e06c1`/`ae70a249` | Focused receipt/historical/final-image race: release 1.139s, CLI 2.278s. Independent proof binds final QCOW2 digest, not just embedded binary. |
| Signed prelaunch OCI identity | Original `29e3fdc8` → QA `88313464` | Focused real retained-file/crypto/process race PASS 2.489s; wrong retained OCI image ID refused. |
| Image publication and interrupted evidence retrieval | Original `d8c20c8b`/`84bbaac9` → QA `fc7e7a69`/`801029a2`; publisher allowlist QA `7874afef` | Pipeline process scenario PASS 1.980s after atomic proof-last transport fix. Exact final-image proof is required after unsigned-byte retention and before release publication. |
| Initial controller/bootstrap fixtures | Original `75103b35` → QA `e82d952f` | Equivalent input candidate `473199ab`: bootstrapstart 61.009s, selfupdate 1.314s, selfupdate CLI 5.951s. |
| Fixed ARM promotion and other image fixtures | Original narrow `89e1281b` → QA `9feb2a59`; original `818c2c8c` → QA `1821c0e7` | Narrow promotion check pending. Bootstrap CLI 3.181s and cellspec 0.076s pass; fixturegen has three source-count failures because actual complete inventory exceeds its old 256-pin bound. Bounded cap correction and real signed-packet scenario are assigned. |

Five small raw logs and hashes are retained in
[`refactor-checks-20261016/`](refactor-checks-20261016/SHA256SUMS), rather than
requiring ephemeral `/tmp` logs to survive continuation. The separate original
`02360dca` binary build passed; SHA-256
`b4736db7c04fe64a08b074ef83a821b34f9bca24f5f92c307f65195aae655ac7`.
It predates image closure and is not the final publication build.

Two real prelaunch gaps remain assigned: founder peer refresh/SDK effects
must verify current selected image proof and clamp operation lifetime to that
proof; direct attempt `PhaseMembers` must verify the retained signed image,
final disk, exact OCI identity and current scope immediately before launch.
Positive and zero-mutation rejection scenarios are being checked. Normal
controller installation already precedes controller `Prepare`/`Seed`; no
impossible pre-execution self-trust ceremony is required. Promotion alone does
not close retained old-manifest launches. Main publication remains held.

Additional independent integration conversions: logs original `ce5fafe7` → QA
`87bde6be` (plain 4.074s, race 6.423s; 30 behavior cases mapped into 29 integrated
cases); stablemtime original `aa5959a5` → QA `b6fa9bca` (four real filesystem/Git
behavior groups, PASS 0.212s). These do not close the repository-wide unit ledger.

Current shared-app dependency remains explicit: OCI verified identity/foundation
must deliver admitted management endpoint and token authority to OBS's automatic
CLI resolver. Names and `RecordFromPlan` cannot infer that authority. Shared app
`c5958f9a` observability package passed 57.952s; CLI/dashboard compile was blocked
by missing release `ProductionProof` dependency, now routed to app integration.
No unchanged successful observability rerun is required for that compile fix.

### Independent admission enforcement checked — 2026-10-16

The narrow candidate closes admission before credential-bearing deployment,
final-image publication/import, founder SDK effects and retained direct-member
launches. It does not establish live runtime or workload qualification. Ordinary
release authority cannot replace the independent exact-candidate qualification.

| Boundary | Integrated source | Retained local result |
| --- | --- | --- |
| Founder effects | Original `57622f7b` → QA `1d0042a8` | Each selected-image check precedes SDK effects and limits the operation deadline to current selector/image authority. Real signed-proof positives and zero-mutation negatives passed. |
| Direct retained-member launch | Original `c827f68f` → QA `e3885178` | Current final disk, signed receipt, OCI image identity and exact scope are checked before launch; full attempt race passed on final code in 6.500s. |
| Independent binary qualification expiry | Original `559a85d8` → QA `1cceab55` | The consumer proof expires at the earliest release/qualification/delegation boundary. Actual selfupdate Stage refuses at that boundary before filesystem effects. Release, selfupdate and image race packages passed on `174ec196` in 3.204s/5.711s/1.228s. |
| Public raw OCI import | Original `edd6c1a6` → QA `c2eb7062` | Removed the unqualified public command and its callers. The already-qualified Attempt uses the typed SDK importer. Full attempt race 6.500s, real CLI dispatch refusal 1.158s and binary build passed. |
| Completed-import reuse ordering | Original `2cf58e1c` → QA `174ec196` | Rejected proof cannot enter the completed-import resume branch or print successful import progress; full image race passed in 1.228s. |

The final code build at `c2eb7062` has SHA-256
`261b26665161990465a3465720d4529b1bb09f0818f62dbc20e8cdc9bed30265`.
The earlier `1d0042a8` build passed and eleven of twelve full race packages
passed; bootstrap exceeded a cumulative three-minute package budget. Its
six-minute continuation also reached its package budget during runnable
signature verification, with no assertion or race report. These invocations
remain recorded as timeouts, not successful full-package runs.

The exact 238-test bootstrap registry and sequential timeout stack identify 93
preceding tests that completed without an emitted failure. The remaining 145
names were partitioned without overlap. Every remaining name now has explicit
race PASS evidence, including privileged reruns for all eight initially skipped
parents and ten initially skipped child cases. The first runtime shard reached
its cumulative budget after 25 explicit passes; only its three unfinished names
were continued. Full logs, exact selectors, ownership/capability follow-ups and
machine-readable counts are retained in
[`bootstrap-continuation/`](refactor-checks-20261016/bootstrap-continuation/RESULTS.md).

Bootstrap package source is unchanged between `1d0042a8` and `c2eb7062`;
transitive source is not wholly identical. The only changed transitive
production implementation is the independent binary expiry projection in
`release/production_receipt.go`. Bootstrap's four admission/selfupdate cases
that reach that API through Stage or qualification attachment were rerun on
`c2eb7062` and passed race in 3.546s. The image/founder verifier path is unchanged;
no blanket identity claim is made for the earlier 93-test prefix.

The zero-configuration guard against actual remote main `4ad1acf5` passed,
scanning 47 added configuration lines. Changed release/image scripts passed
shellcheck, and deployment/image workflows passed actionlint. Logs and hashes
remain in [`refactor-checks-20261016/`](refactor-checks-20261016/SHA256SUMS).

Additional complete test conversions preserve their original behaviors:
commandio original `1d5bf843` → QA `c85e30d6` uses real OS pipes/filesystem
(PASS 0.005s); tier original `c93482e6` → QA `a8719cae` uses bounded actual test
processes for all eleven modes (PASS 0.057s); logscan original `e936b728` → QA
`569975a9` uses actual journal/Fly fixture pipelines and CLI processes for all
six tests (PASS 0.217s). None changes production policy or closes the remaining
repository-wide test-classification work.

CONNECT, RUNTIME/HA, FUNCTIONS, STATEFUL and COMPLETE remain open. The actual
managed-runtime startup cutover, trusted regional automatic credential delivery,
complete infrastructure accounting, final native image qualification and live
regional/workload evidence are separate active work. Missing independent proof
continues to refuse production exposure; no paid provisioning, new IAM
authority, credential installation or destructive cloud action was performed.
