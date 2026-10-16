# All-region deployment: code review and simplification requirements

What this repo does: `ts-orch` provisions OCI infrastructure, embeds regional
NATS, admits signed releases and manages workload rollout. Its CLI and dashboard
are the operator interface. SwarmKit is the selected replacement for the current
custom scheduling and execution engine; that replacement is not implemented yet.

Reviewed 2026-10-16 at `35fde887`. Expected load: concurrent bootstrap and release
across GRU, San Jose (`sfo`) and FRA, controller restarts, overlapping retries and
one unavailable region. Healthy regions must progress independently within the
authorized footprint. More regions must not introduce unbounded API fanout.

## Scope

Mapped the README, module dependencies, CLI entrypoints, build/image/deploy
workflows and feature slices. Traced regional creation, discovery, release
application/publication, image imports, OCI client selection and capacity
validation. Read connected tests and the retained NATS fork rationale.

This is a static review of the connected deployment paths, not a line-by-line
audit of every file. Findings below are requirements for the replacement plan;
this change does not fix runtime behavior. Source links name the reviewed
baseline and may move as implementation proceeds.

## Must fix

### 1. One regional preflight failure blocks every signed-bundle deployment

**What this is:** [apply.go](../internal/release/cli/apply.go#L65) reads each
region's deployment scope serially before starting concurrent publication.

**Problem:** If FRA's status is missing, stale or unreadable, the command returns
before publishing GRU or SFO. The observation deadline already runs during this
preflight. Existing [regional isolation tests](../internal/release/cli/discovery_test.go#L26)
cover the older deploy/service-deploy paths, not this new apply path.

**Fix:** Check shared local trust/bundle invariants once; move remote scope,
regional admission, upload and observation into independent bounded workers.
Preserve shared revision/sequence checks, per-region architecture/environment
checks, signatures, validity budgets and conditional channel publication.

**If skipped:** A single broken region prevents a healthy fleet from receiving
an otherwise valid release.

### 2. Deployment discovery requires an online serving directory

**What this is:** [discovery.go](../internal/release/cli/discovery.go#L14) reads
the fixed [Atlas endpoint](../internal/atlas/discovery.go#L19); stale or empty
membership is refused. Regional scope also requires an existing status object.

**Problem:** Atlas unavailability stops discovery for all regions. A new region
without serving/status records cannot enter through this application path.

**Fix:** Use authenticated durable foundation/admitted membership for lifecycle
authority, with explicit partition and freshness rules. Separate provisioning
intent from serving observations; retain Atlas for routing and health. Do not
trust arbitrary cached data or treat the OCI region catalog as spend authority.

**If skipped:** Automatic deployment depends on a public service and records
that bootstrap itself has yet to produce.

### 3. A local completed-step journal is not continuous regional repair

**What this is:** [region creation](../internal/region/create.go#L86) runs a fixed
sequence with local plans and a local journal; completed stages are skipped at
[line 146](../internal/region/create.go#L146). GRU uses a separate founding path.

**Problem:** Delete or alter an owned resource after a successful run: rerunning
creation skips the completed stage. Losing the journal or starting another
operator does not transfer a shared operation owner.

**Fix:** Reuse typed feature functions behind the CLI and continuous controller.
Persist operation identity, resource IDs and fenced ownership durably; inspect
observed resources on retry. Run independent stages concurrently only after
their real prerequisites. Keep GRU recovery independent of the overlay it starts.

**If skipped:** Drift and controller failover still require operator repair even
if the initial command completes successfully.

### 4. NetBird setup-key recovery explicitly requires manual repair

**What this is:** [create.go](../internal/region/create.go#L323) creates a setup
key, puts it in Vault, then writes its local record. The adjacent comment
documents the crash window and manual workaround.

**Problem:** A crash after Vault succeeds but before the record is saved leaves
a key the rerun cannot replace. Unattended retry crosses the shortcut's stated
limit and cannot finish.

**Fix:** Recover the existing owned key/secret using stable operation identity
and scoped metadata. Persist recoverable progress before requesting another key;
reconcile partial external results under fenced ownership. Never rotate blindly
or print secret values to reconstruct state.

**If skipped:** A process crash can stop a region from automatically joining.

### 5. Release order is still a CI producer's counter

**What this is:** [channel verification](../internal/releasechannel/channel.go#L115)
binds `RunNumber` to signed qualification lineage; [publication](../internal/releasechannel/channel.go#L223)
uses it as the monotonic compare-and-swap order.

**Problem:** Move from a producer at run 500 to another at run 10: its legitimate
release is refused as stale. Independent counters can also collide for different
revisions. A webhook cannot solve the ordering contract.

**Fix:** Allocate one durable sequence at the trusted publishing boundary and
migrate the signed schema and retained regional floors together. Keep producer
run IDs as provenance. Do not reset floors, relabel old evidence or remove
lineage verification to make another producer pass.

**If skipped:** Producer independence breaks safe release ordering.

## Should fix

### 6. The production deployment workflow still fetches, builds and signs

**What this is:** [deploy-fleet.sh](../scripts/ci/deploy-fleet.sh#L42) downloads
fixed-repository GitHub assets, runs `make build`, configures Git authentication
and invokes legacy `release deploy` with signing access.
[TerraBase synchronization](../internal/app/operator_terrabase_sync.go#L27)
also binds a fixed repository and workflow; service deployment mixes source
verification, signing, uploading and application.

**Problem:** The deployed workflow cannot apply a qualified release during a
GitHub outage or without a source checkout/toolchain, despite `release apply`
already providing a narrower orchestrator consumer.

**Fix:** Qualify, build and sign once in the producer. Publish immutable signed
manifests and bytes; use an already trusted CLI and regional consumers to apply.
Extend the existing boundary across service roles and remove producer-specific
calls from apply/reconcile paths. Keep source verification before signing.

**If skipped:** A routine release retains build-time dependencies and duplicate
setup work on its critical path.

### 7. A1 assumptions prevent qualified alternative capacity

**What this is:** [pool recipes](../internal/nodescale/pool.go#L99) fix the shape
to A1; [plan validation](../internal/ociregion/plan.go#L360) rejects other shapes,
[seed validation](../internal/ociregion/seed.go#L247) requires ARM64, and
[node pricing](../internal/ocicost/node.go#L3) uses A1 SKUs.

**Problem:** An authorized region with exhausted A1 capacity cannot use an
otherwise qualified ARM or x86 alternative through these paths.

**Fix:** Qualify shape, architecture-specific image/artifact, runtime and price
as one contract. Keep A1 first and one capacity policy in code; discover supported
OCI offerings instead of assuming an A3 identifier or using emulation.

**If skipped:** Automatic region deployment stops at A1 availability, and a
partial shape-only change risks incorrect image admission or cost estimates.

### 8. Partial image-import success is omitted from the result manifest

**What this is:** [image imports](../internal/ociregion/imageimport/import.go#L485)
already fan out concurrently. After waiting, any regional error returns before
the aggregate result is serialized to `o.Out`.

**Problem:** Two imports succeed and one fails: successful OCI objects remain,
but this invocation writes no result manifest containing their identities.

**Fix:** Persist per-region results and errors as work completes and preserve
them on failure. Reconcile existing OCI identities on retry, retaining digest
checks and refusing to present a partial result as fleet success.

**If skipped:** Automation must rediscover successful work after partial failure.
This finding does not claim that existing import identity checks always recreate
images or that imports need new concurrency.

### 9. Provisioning retains Python CLI fallback and self-invocation

**What this is:** [foundation](../internal/ociregion/foundation/foundation.go#L78)
constructs the public API client, whose [default backend](../internal/ociregion/sdkcli/sdkcli.go#L34)
can [fall back to external `oci`](../internal/ociregion/publicapi/sdk.go#L143)
for unsupported commands/flags. [Regional creation](../internal/region/create.go#L497)
also launches the same executable as subprocesses and parses text results.

**Problem:** Unsupported non-secret OCI operations still require a Python CLI
on the operator host; subprocess success and output formatting become part of
the provisioning contract. This conflicts with the requested single CLI and
zero-switch final design. Secret-bearing operations already restrict fallback.

**Fix:** Inventory actual used operations, finish SDK coverage and call typed
feature APIs directly. Delete fallback selectors and obsolete parsers/callers
after parity is established; retain unsupported-operation errors and complete
flag validation. Do not replace them with another generic workflow framework.

**If skipped:** Dependency and behavior differences remain hidden until a
less-common recovery or provisioning operation is needed.

### 10. Documentation-only changes still enter the full build/deploy pipeline

**What this is:** [ci.yml](../.github/workflows/ci.yml#L3) explicitly checks and
deploys every main change, including documentation; its successful build path
dispatches fleet deployment.

**Problem:** A change confined to a non-embedded planning document still runs
the release-producing build path and can initiate a fleet rollout. It does not
change the desired runtime behavior but consumes release and observation work.

**Fix:** Derive release work from actual binary/embedded asset/trust/image inputs
and reuse the existing host-image input comparison. Retain documentation/policy
checks, source provenance and scheduled base-image refreshes. Define the input
graph once; no operator toggle or unsafe blanket exclusion of all Markdown.

**If skipped:** Planning edits continue to consume the full release critical
path and can trigger operational changes unrelated to their content.

## Dependency boundary and behavior to preserve

| Boundary | Target |
| --- | --- |
| Operator/apply/controller | `ts-orch`, scoped OCI/Vault and cluster APIs, admitted artifacts; no Go toolchain, source checkout, `gh`, Git or Python OCI CLI required to apply. |
| Publisher and host-image producer | Keep required source/CI verification, signing and architecture-specific build/image tools here. GitHub is a producer adapter; a webhook is only a notification. |
| Regional task engine | SwarmKit owns nodes/services/tasks/updates and regional Raft; a narrow containerd executor owns runtime lifecycle. Delete the old scheduler/runner and orphaned dependencies. NATS remains messaging/federation. |
| NetBird foundation | Dedicated GRU A1 service, recovered without depending on its own overlay; durable scoped credentials, off-host backup and fenced management remain necessary. |
| Embedded NATS fork | [Retained patches](../third_party/nats-server/README.terrascale.md) cover embedded startup, JWT admission, races and Raft identity. Remove the fork only after equivalent upstream behavior and compatibility are qualified. |

Preserve the older deploy path's regional failure isolation, conditional channel
publication, signature/digest/scope checks, writer/volume fencing and bounded
health/rollback decisions when porting behavior. Reuse existing image-import
parallelism and [host-image input change detection](../scripts/ci/image-inputs-changed.sh);
the current code does not unconditionally rebuild host images on every app change.

## Completion evidence

Use the acceptance table in [REFACTOR.md](../REFACTOR.md#evidence-required-before-claiming-simpler-or-faster).
Record cold/warm/retry timings, regional errors and successful recovery. Count
manual inputs, subprocesses, required services, transferred bytes and repeated
build/hash work before and after. Put real progress and missing/stale observations
in the shared CLI/dashboard API. Set numeric latency targets from measurements.

**Verdict:** Remove the fleet-wide preflight barrier and bootstrap discovery
cycle first; make provisioning recoverable, then finish the producer/apply and
SwarmKit boundaries. Preserve safety checks while deleting duplicate machinery.

**Lean:** Removal candidates are identified, but no line-count, dependency-count,
cost or speed savings were measured. No new dependency is needed for this plan.

**Not checked:** No builds, tests, benchmarks, live OCI/NetBird state, credentials,
production traffic or CI results were checked in this review. Dashboard internals,
all unrelated application/storage paths, vendored source and every source file
were not exhaustively audited. No runtime fix or performance result is claimed.
