# DATA writer/volume fencing qualification — 2026-10-16

Implementation candidate: `a5505a3277a275a9c67f5b06bc84dd269a33b410`.
Baseline: `7a7abb41`; branch: `refactor/data-fencing`.
Owner: DATA/fencing. Claimed paths: `internal/storage/failover/**` and this document.
Planning estimate: 25 minutes. No shared module, entrypoint, AGENTS or REFACTOR edits.

## Change and caller inventory

The reattach decider previously returned the first old-instance detach before
checking later attachment records. An old attachment followed by a foreign live
attachment could therefore cause an effect despite an unsafe complete inventory.
It now validates every observed record before selecting any old-instance action.
Foreign live attachments, wrong-volume records, incomplete identities, unknown
states and multiple live replacement attachments hold without effects.

`Decide` is called only by `Reattacher.Step`. The production failover caller at
this baseline is `internal/placement/reattach.go`; it supplies the expected epoch,
wraps the step in the active-workload effect context, and persists completion
under a fresh authority guard. No exported signature or caller/config change is
required for this fix. The retained OCI boundary is `internal/oci/volume_reattach.go`,
with regular attachment in `internal/oci/fleet.go`, and immutable mount permits in
`internal/oci/volume_init_journal.go`. No dependency was added.

## Contract for replacement lifecycle consumers

1. Call `Reattacher.Step` with the durable database/partition/volume identity,
   distinct old/replacement instance IDs and the same stable attach key on retry.
   Pass the epoch under which those inputs were read as `ExpectedEpoch`.
2. Retain the existing `authority.WithActiveWorkloadEffectContext` and active
   workload effect around the whole step. Nested OCI effects must join that
   epoch; they must not acquire a later epoch after leadership loss. OCI remains
   the journal/ownership/ETag/per-write fencing boundary.
3. An old writer is fenced only when the owned OCI instance is observed
   `TERMINATED`. Missing observations, authorization/network failure, `RUNNING`,
   `STOPPED` and `TERMINATING` never prove writer exclusion.
4. Wait for old attachments to be `DETACHED`; attach idempotently and wait for
   the sole replacement attachment to be `ATTACHED`. Grant mount-existing only.
   A SwarmKit task state, host silence or generic readiness is not writer proof.
5. Treat `StepHold`/`ErrVolumeHeld` and failed observations as blocked or failed
   work. Persist completion only after `StepDone` and a current authority guard.
   Preserve catch-up, drain, release admission and compatibility gates outside
   this narrow reattachment contract.

## Integration-only migration

Deleted `reattach_test.go`: five isolated tests plus their fake instance, volume,
permit and authority implementations. Replaced their safety behaviors with four
`TestIntegrationReattach*` scenarios in `reattach_integration_test.go`.

The real project components are `Reattacher`, `OCIBoundary`, `authority.Runtime`
and `oci.KVJournal`. They communicate with an embedded NATS server over its client
protocol and file-backed JetStream. The external fleet is a test-only simulator;
its observations and effects also cross JetStream, and permit writes use the
production immutable OCI journal. This does not exercise the OCI SDK/cloud.
Every scenario gets its own localhost endpoint and temporary durable store;
server/connection/authority cleanup is registered and the runner has a 120-second
bound. There are no remaining isolated unit tests in the claimed package.

| Scenario | Observed assertion |
| --- | --- |
| Persistent reattachment | Non-terminated/unobservable writers never change the attachment; terminated writer progresses through detach/wait/attach/wait/mount/done. |
| Interrupted operation | Lost attachment reply followed by full NATS restart discovers the accepted attachment without another attachment. A second restart retains the mount-existing permit and returns done under a newer authority epoch. |
| Whole-inventory rejection | Foreign live attachment after old attachment, wrong volume, duplicate replacement, unknown state and incomplete identity leave persistent observations unchanged. |
| Authority/input rejection | Real follower refuses effects; wrong expected epoch and authority release during observation fence detach, attach and mount separately. Incomplete/same-instance requests are refused. |

Checks run locally at low CPU priority; no unit tests were run:

```text
nice -n 19 go test ./internal/storage/failover -run '^TestIntegration' -count=1 -timeout=120s -v
PASS; package time 0.476s
nice -n 19 go test -race ./internal/storage/failover -run '^TestIntegration' -count=1 -timeout=120s
PASS; package time 1.822s
nice -n 19 go vet ./internal/storage/failover
PASS
```

`git diff --check` passed. The Modern Go CLI was read before Go edits; this slice
uses Go 1.27 `new(value)`, JSON v2, `t.Context()` and standard slices helpers.

## Remaining qualification boundaries

This is local failover-slice evidence, not STATEFUL acceptance or production
cutover evidence. QA must rerun these scenarios on the integrated candidate.
CORE must consume the lifecycle contract and retain one writer/task owner.
Real OCI ownership/attachment concurrency, cross-domain moves, provider failures,
three-manager quorum loss, full executor lifecycle, TerraBase catch-up/drain and
same-commit restore/on-disk/CPU compatibility still require their own evidence.
The integration fixture uses one local NATS node, not a regional HA proof.
No TerraBase binary was downloaded or executed; no live/cloud/destructive action
or production publication was performed. Main publication belongs to QA's
serialized integrator and retains the plan's qualification gates.
