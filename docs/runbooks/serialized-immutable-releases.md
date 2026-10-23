# Serialized immutable app releases

Production release success requires one row for every intended region, the
requested service/image digest, the pulled image's OCI revision matching the
verified GitHub OIDC commit, and each running task's ID, generation, node ID and
machine. A row's `ready: true` means its task answered the declared readiness
path. It does not prove an authenticated application operation.

## Before rollout

1. Build the immutable `ghcr.io/terrascale/<service>@sha256:<digest>` from the
   approved main commit. Publish `org.opencontainers.image.revision` in its image
   config; release verification rejects a missing or different revision.
2. Deploy the runtime ordering protection to every mesh founder before relying
   on it. Older runtimes do not enforce the persisted deployment watermark or
   rollback ancestry during peer sync.
   Keep the orchestrator rollout held until every signed app publisher is
   compatible. In particular, the dashboard publisher needs the revision label.
3. Use the existing app/environment GitHub concurrency group with cancellation
   disabled for production. Do not overlap manual releases of the same service.
4. Record the expected digest, full source revision, workflow run ID, intended
   regions and previous digest. Run `ts-orch release app --service <service>
   --image <immutable-image>` from the approved workflow. Do not place tokens in
   command arguments; the client mints its existing OIDC identity in memory.
5. Retain the JSON per-region runtime evidence. Stop on any failed/missing row,
   identity or digest mismatch, or revision mismatch. Authenticated per-target
   smoke remains pending until the user installs the scoped E2E credential via
   the approved user-run handoff. Do not substitute anonymous auth health or
   expand grants. Anonymous auth health intentionally omits exact build identity.

## Ordering and rollback

The shared state-directory service-spec lock covers the full read/update
transaction for local CLI and background mesh writers. SwarmKit metadata CAS
conflicts are retried with a fresh read; older mesh generations are rejected.
This lock only covers submission, so image pulls and readiness do not block
unrelated service submissions. An unchanged task may retain an older task
generation after a metadata-only reapply; evidence reports its actual generation
and accepts it only when the complete task spec and non-generation service
metadata match. Verification adds no forced restart.

Each mesh service persists its signed repository, workflow run ID, approved
image and revision. Lower run IDs and different artifacts from the same run are
rejected, even if they arrive with a newer wall-clock generation. Operator
applies/removals and automatic rollback retain the watermark. `deployment` is
the entry's signed release authority; operator entries leave it absent and inherit
only `deploymentFloor`. Peer sync and release state reads merge the highest
accepted floor independently of which entry wins, including from a losing
rollback. A winning operator update/removal therefore converges even if its node
missed a signed rollout and inherited a lower floor. Reconciliation waits for
both the winner and floor to persist. Signed entries still reject older runs,
different repositories and same-run artifact changes; inheriting a floor never
turns an operator entry into a signed release. Do not delete desired state to make
an old workflow succeed. A signed entry establishes its own run floor when no
separate inherited floor is present.

On release failure, the existing bounded rollback restores the previous spec.
Its compare-and-swap requires the failed release's generation still to be
current on each node; it cannot overwrite an intervening release or operator
apply. Rollback rows identify the actual restored image and its own OCI revision,
not the failed release's revision. A failed release remains failed after rollback.
The persisted rollback entry carries `rollbackOf`, the failed generation. Peer
sync and release state reads order it after that rollout but before any later
operator/release generation, even when the rollback's wall-clock generation is
higher. Thus a partially accepted rollback cannot replace an intervening update
or removal through anti-entropy; both nodes converge to that intervening entry.
Nodes that missed the failed rollout can still import its rollback. A failed
desired-state save restores the prior in-memory entry before it can be advertised
or reconciled; retry the apply after fixing persistence.

For fix-forward, publish a corrected commit in a newer workflow run. A rerun of
the same accepted run may retry only its identical image/revision. For an
explicit rollback to an older artifact, use the authorized root operator apply
path with the reviewed previous immutable spec; retain the watermark and collect
fresh runtime/readiness evidence. Do not use an old workflow rerun as rollback.

## Data shutdown evidence

`internal/swarmruntime/controller.go` keeps `dataStopGrace = 2 * time.Minute`.
Both bind-mounted tasks and qualified stateful tasks receive that full SIGTERM
grace; replacement waits until the predecessor exits. This change does not
shorten the grace or kill data tasks. The existing
`containerdDataTaskStopsGracefully` integration scenario verifies a task flushes
for 30 seconds, exits with status 0, and only then its replacement serves.
Run that scenario in the disposable containerd CI job; it was not exercised on
production for this change. A 30-second fixture is not proof of a 120-second live
shutdown. Preserve the full grace even when a bounded release/rollback reports
timeout, and inspect the actual task inventory before further action.

## Observed baseline (2026-10-23)

The public API health endpoint reported `region=gru`, `machine=gru-1-ctl-1` and
revision `888ea413c06f6452cccceab57c735fa35b4d850d`. Public auth health reported only
status and version. These are baseline observations, not proof that this change
has shipped or that an authenticated smoke passed.
