# Continuous delivery to running cells

Status: the opt-in TerraBase automation entry point is implemented; no live
timer, signing grant or rollout is enabled by this change. Binary-only
orchestrator self-update, the scoped auto-sign delegation, the staged rollout
state machine, resumable image promotion and independent managed-host image
qualification exist as opt-in foundations (see
[Binary-only self-update](#binary-only-self-update-opt-in)); each is off by
default. Image-based orchestrator replacement is still a proposed follow-up.

## Mechanism and trust boundaries

Use one operator-host timer per deployed TerraBase placement, with a reviewed
inventory covering every placement in each cell. Poll every minute; a
publication notification can wake the same timer sooner. CI only publishes
inputs. The operator host reaches Forgejo and controllers through existing
TLS/Bastion access, holds the narrowly scoped online operator keys, and runs
the single orchestrator binary. Controllers and hosts need no Forgejo route.
Do not put operator, compatibility, release-leaf or root keys in Actions.

Publication is not deployment authorization. Forgejo metadata and assets are
untrusted inputs until their source lineage, qualification and byte digests
are checked. The existing operator signature admits a TerraBase artifact;
the independent compatibility signature certifies the exact old/candidate
pair and durability profile. Controllers enforce the grants, authority epoch,
placement/seat pins and serving proofs. Hosts accept the signed desired
state. The operator-host journal prevents release switching and repeated
automatic attempts; controller state remains the authority for seat progress.

For ts-orchestrator, use **rolling replacement from signed images**. The
existing trust chain qualifies the binary, then binds its signed receipt to
an image, base, kernel, region and exact OCI image OCID. A binary receipt alone
does not authorize overwriting a running installation. Replacement preserves
that chain and the image's systemd, enrollment and volume-init environment.
There is currently no supported running-cell *replacement* executor (the
binary-only self-update below replaces the executable, not the image):

- `ts-orch oci-region attempt` signs new deployment manifests, founder plans and selections;
  it is a bootstrap tool, not an upgrade tool.
- Founder install continuity authorizes read-only restart of an **exact
  accepted install**. It cannot authorize another image, instance or manifest.
- Managed TerraBase placement holds a lost host without replacing it
  (`internal/placement/controller.go`). Image promotion or changing the
  image for future launches cannot upgrade existing hosts.

## Signing and approval sequence

| Input/action | Authority and gate |
| --- | --- |
| TerraBase publication | CI publishes tested binaries, `qualification.json` last, and must additionally publish the accepted `source-digest.json` bound to that qualification and server. Git tree SHA-1 is not the prepared-source SHA-256. |
| TerraBase automation grants | Human authorizes new root-bound signed controller config: update actor with `can_place_terrabase`, `can_update_terrabase_runtime`, repository/role/environment limits; separate compatibility actor with `can_certify_terrabase_compatibility`. Installing this config is a separately reviewed operation. |
| TerraBase per-seat Prepare | Online update key and independent compatibility key on the operator host, only after the approved compatibility policy has been satisfied. Existing `terrabase-update` signs both statements. |
| Orchestrator binary receipt | Human reviews exact qualified main source/run/job attempt and bytes; offline root issues source/architecture/environment-scoped delegation; local leaf owner runs `ts-orch release sign-binary`. |
| Orchestrator binary update receipt (opt-in) | Offline root issues a time-bounded (at most 31 days) binary update delegation scoped to environment, cells, architectures and descendants of a reviewed main revision (`ts-orch release sign-update-delegation`). The online leaf then signs any `ci.yml`-qualified descendant automatically (`ts-orch release sign-binary-update`). Nodes accept these receipts only with `--allow-scoped-auto-sign`. |
| Orchestrator image receipt | Existing image workflow builds and qualifies; authorized operator imports; offline root narrows the delegation to the cell/image OCID; local leaf owner signs and verifies the image receipt (`ts-orch image promote`). |
| Running-cell replacement plan | Proposed new offline-root-signed authorization pins predecessor install/instance, successor manifest/image receipt, same cell/deployment/slot, increasing generation, credentials/config digests, validity, resource budget and explicit rollback target. Existing continuity does not supply this authority. Root private keys stay offline. |

Forgejo has no authenticated protected-environment reviewer gate here
([releases.md](releases.md)). Retain independent review evidence externally.
Immediate automatic delivery of *arbitrary* orchestrator publications is
incompatible with the present per-source/per-image human signing gates.
Automatically discover and prepare candidates, then automatically execute
only the exact signed promotion and replacement authorization. Removing
those gates would be a new trust decision, outside this change.

## Implemented TerraBase entry point

After the decisions below, provision a full TerraBase checkout via `fj repo
clone`, the pinned admission `fj` extension from
`scripts/ci/prepare-fj-admission.sh`, operator config/keys and an existing
Bastion forward on the operator host. Invoke this command from a one-minute
timer with a one-hour service deadline longer than `--timeout`:

```sh
terrascale-orchestrator operator terrabase-sync \
  --config /var/lib/terrascale-operator/operator.json \
  --state /var/lib/terrascale-operator/terrabase-preview-p1 \
  --source-checkout /var/lib/terrascale-operator/terrabase-source \
  --compatibility-actor COMPATIBILITY_ACTOR \
  --compatibility-key /var/lib/terrascale-operator/compatibility.key \
  --nats-forward 10.251.0.11:4222=127.0.0.1:14222 \
  --wait 20m --timeout 55m
```

The command checks the checkout's origin, fetches main without force,
discovers non-draft `ci-<sha>-run-<id>` releases with `fj`, and selects the
newest published descendant of the completed source on main. Commit ancestry,
not run ID, determines newness. Rebuilds of identical source are ignored.
Multiple publications can coalesce before a rollout starts; an active rollout
is always completed before considering another release. A partial or unfinished
newest publication causes a retry on the next tick, with no admission.

It downloads the qualification, ARM64 server and `source-digest.json`, uses
the existing release verifier, and requires the matching successful
`fast.yml` run, successful Fast and publish jobs, and the publish log's exact
qualification-digest marker. Missing source digest fails closed; no source
claim is manufactured. It pins the qualification/binary/source digests in
`cd-active.json` before calling the existing signed updater end to end.

An owner-only state directory and kernel file lock serialize sync invocations
for a placement. Synced, immutable `cd-complete-<generation>.json` receipts
advance its source baseline only after both seats serve. Cancellation/timeouts
leave the active pin for resume. Changed assets, bad provenance, unreachable
Forgejo or unavailable forwarding never allow a different active candidate.
Input failures before admission retry without creating a stop marker.

The updater waits for a fresh serving proof from each seat, then soaks it
(`--soak`, default 5m): the seat must keep serving the candidate with the same
process before its peer is updated. A candidate that fails, exceeds the
controller's 15-minute proof deadline or fails its soak is recorded in
`known-bad/<digest>.json` before any rollback; every seat running it is
returned to its predecessor, the held seat first, and the updater fails. A
known-bad digest is never prepared again, and a rollback that is itself held
stays frozen rather than returning to the known-bad candidate (the controller
enforces this too via `rollback_of_held`). Remove the known-bad record only
after review.

The signed compatibility evidence is derived from both releases'
`compatibility` declaration in `qualification.json`
(`terrascale.terrabase.compatibility.v1`: persistent format, replication and
client-data versions with accepted ranges), retained per release in the state
directory. A release without a declaration fails closed unless the operator
passes `--assume-compatibility`, which restores the earlier unverified
assertion; incompatible declarations are always refused.

Transient updater failures (placement status or transport errors, leader
changes, a briefly unserving peer, an outcome wait that ended while the seat
was still prepared) are retried with backoff (`--transient-retries`) and keep
the active pin; they write `cd-transient.json` and escalate to
`cd-blocked.json` only after `--transient-block-after` (default 6h). Any
other non-cancellation updater error writes `cd-blocked.json`; later ticks
perform no rollout or discovery. Alert on nonzero exit, `cd-transient.json`
and stale active pins. After diagnosis, the authorized operator may archive/remove the stop
marker to resume the **same** active pin. A rejected candidate must be
withdrawn deliberately by disabling the timer, reconciling controller state
and archiving the active pin; never silently discard a pending operation.
Disable the timer before manual updates or journal maintenance. Binary
rollback requires the older release to read the persistent format.

## Proposed orchestrator replacement executor

Keep the cell/deployment identity, regional ledger and customer data. A durable
operator journal and controller authority CAS fence each predecessor and
successor. Run at most one controller replacement per cell, B then C then A
(seed last), requiring the other two controllers healthy and JetStream quorum
current. Fence the old process/instance before reusing its slot/IP/credentials;
transfer the seed's founder selection floor explicitly, never reset it. Admit
the successor through the new root-signed plan, wait for route/TLS/clock health,
all replicated authority/delivery state caught up and a fresh signed version
proof, and only then advance. Retain the old boot volume and install evidence
for the rollback window. A successor install needs its own root-signed restart
continuity; the predecessor's proof must never be reused.

Next replace managed hosts one seat per TerraBase partition at a time, with
the peer serving. Preserve volume/member/incarnation/material identities;
stop and fence the old runtime, detach its retained data volume, enroll the
successor from the signed image, reattach exclusively, advance host/session/
attachment/desired pins, and demand a fresh TerraBase serving proof before
the next seat. Do not create another database or format an existing volume.
Completion requires inventory and signed version proofs for **all three
controllers and every managed host**, including idle hosts. Newly enrolled
hosts use the approved image. A failed or ambiguous replacement stops the
cell; reconcile readback before retry, preserve the healthy quorum/peer, and
restore only the explicitly authorized predecessor with new fencing/generation
values. Never lower a selector floor. NATS/state-format changes require tested
mixed-version support and a proven rollback window; otherwise halt for a
reviewed migration. TerraBase and orchestrator rollouts must not overlap.

This executor requires changes to bootstrap admission/founder state, controller
host replacement and OCI fencing/volume handoff. None is implemented yet;
`internal/bootstrapstart`, `internal/oci`, the image-installed
`deploy/systemd` units and `deploy/oci-region` are unchanged. The ordering,
soak and rollback logic it needs exists in `internal/rollout` (below).

## Binary-only self-update (opt-in)

Most orchestrator changes touch only the binary, so they do not need a new
image, an OCI import or a re-bootstrap. `internal/selfupdate` replaces the
executable on a running node with an A/B layout:

```text
/var/lib/terrascale-orchestrator/
  releases/<sha256>/terrascale-orchestrator   read-only (0555), root-owned
  releases/<sha256>/receipt.json, delegation.json (or "baked")
  current -> releases/<sha256>                  what ExecStart runs
  activation.json                               pending switch, if any
  known-bad.json                                digests rolled back on this node
```

1. **Distribute.** The qualified binary (about 46 MB, under the 512 MiB
   artifact bound) is uploaded through the existing signed delivery artifact
   store. A controller fetches it by digest over NATS with per-chunk and
   object digest checks (`selfupdate.StageFromArtifactStore`).
2. **Stage.** `ts-orch selfupdate stage` verifies the release receipt
   (`internal/release`) for the node's environment, cell and architecture
   *before* keeping any byte, copies the binary while hashing it, requires the
   exact signed size and SHA-256, and renames a fully written temporary
   directory to `releases/<sha256>`. Every release path must be owned by root
   and not group- or world-writable; the unprivileged controller can execute
   but never replace its binary.
3. **Activate.** `ts-orch selfupdate activate --release <sha256> --unit <unit>
   --proof-window 5m --restart` writes `activation.json` (target, previous,
   deadline) and only then flips `current` with an atomic rename.
4. **Prove.** When `self_update_proof_file` is set, the new process signs a
   version proof after it is ready (controller: after host-controller
   readiness, with its response key; host: after start-up checks, with its
   identity key). The proof names the activation, unit, the digest of
   `/proc/self/exe` and the process ID, and is valid for 10 minutes.
5. **Confirm or roll back.** `selfupdate prepare` (root `ExecStartPre=+`) and
   the `terrascale-orchestrator-selfupdate-watchdog@<unit>.timer` (every 15 s)
   confirm the activation from a fresh proof signed by the unit's key. A
   missed deadline, or a target whose bytes no longer verify, records the
   digest in `known-bad.json` first, restores `previous`, and restarts the
   unit. A known-bad digest can never be staged or activated again on that
   node. Crash loops and hangs both end in rollback at the deadline.
   A proof confirms only while the process that signed it still runs, and
   `prepare` never confirms from a proof: it runs while the unit restarts,
   so the new process must prove itself again to the watchdog.
   A retried `activate` passes the same known-bad and byte checks as a fresh
   one and is refused after the deadline. An activation for a unit no
   watchdog matches is rolled back by any unit's watchdog five minutes after
   its deadline, so a mistyped `--unit` cannot block the node. An
   `activation.json` that does not decode (for example one written by a
   newer binary) cannot be confirmed: `prepare` restores its `previous`
   release when that still verifies, marks the target known bad, and moves
   the record aside as `activation.json.unreadable-<time>`.
6. **Prune.** After each `prepare`, release directories that are not
   current, not part of a pending activation, not the baked release, and
   either known bad or staged more than 24 hours ago are removed.

The image is unchanged: `deploy/systemd/selfupdate/` holds the drop-ins and
the watchdog timer, which an operator installs per node together with
`/etc/terrascale-orchestrator/selfupdate-<unit>.env` (see
`selfupdate.env.example`) and `self_update_proof_file`. A non-default
`--root` in the drop-ins must also be set as `self_update_root`, so the
process signs its proof under the same root. On first start
`prepare` seeds the image-baked `/usr/local/bin/terrascale-orchestrator` as the
first release, so the baked binary always remains a valid rollback target.
A node running both a controller and a host shares one `current` link; enable
self-update for one unit per node until per-unit links exist.

### Scoped auto-sign delegation

The per-source binary delegation requires an offline root signature for
every source revision. The scoped binary update delegation
(`internal/release/update_delegation.go`) is a separate root-signed document:

- one online leaf key, at most 31 days, one environment;
- explicit cells and architectures;
- only `TerraScale/ts-orchestrator`, `ci.yml`, `refs/heads/main`, and
  descendants of a pinned, reviewed `lineage_base` revision.

The leaf signs a `terrascale.release.binary-update.v1` receipt only after the
qualification manifest matches the binary, the Forgejo run succeeded and git
proves the source descends from the base and is on `origin/main`. The
`--source-checkout` origin must resolve to
`git.terrascale.tech/TerraScale/ts-orchestrator` (https or ssh), so a fork
cannot stand in for main. The delegated leaf must differ from the offline
root. A receipt never outlives its delegation; signing is refused when the
delegation has less than an hour left, and the CLI prints the effective
expiry. Consumers
verify the root signature, expiry, their own environment/cell/architecture,
the lineage fields and the exact delegation digest the receipt names. The
per-source verifier never accepts an update receipt. Nodes accept update
receipts only with `selfupdate stage --allow-scoped-auto-sign`; the default is
off. Rollout remains gated by version and health proofs.

### Staged rollout state machine

`internal/rollout` is the shared ordering core for TerraBase seats, workload
waves, controllers and hosts. Its pure transition function moves a durable
record through `pending → preflight → canary → canary-soak → batch(k) →
batch-soak → … → complete`, or `rolling-back → rolled-back`, `frozen` and
`aborted`:

- waves are planned so no wave holds two units of one group (both seats of a
  TerraBase pair, or two of three controllers), and the seed controller is
  replaced last and alone;
- a wave is promoted only after `min_healthy_reports` reports from one
  process incarnation over the soak window; a restart, a wrong digest, a
  failed or held unit, or a missed proof deadline starts a rollback;
- the record marks the target digest known bad in the same write that first
  orders a rollback, then returns every touched unit newest first, one at a
  time, always to the predecessor digest; a held rollback freezes the
  rollout and an operator resume only retries the rollback;
- records live in the `TS_ROLLOUTS` JetStream KV bucket, written by CAS on
  the revision after an authority `Guard` for the record's epoch; a cell slot
  allows one active rollout, and the cell keeps the known-bad list and a
  per-digest attempt budget.

Executors derive their next step from `NextActions`, whose operation IDs are
deterministic per rollout, unit, phase and attempt.

When the rollout store is enabled (`controller.rollouts.enabled`), managed
TerraBase update admission also refuses a candidate the cell's known-bad list
names (`placement.Config.KnownBad`). An unreadable list, or a store that has
not opened yet, refuses the update: admission fails closed. With the store
disabled nothing changes; the operator's `known-bad/` directory still applies.

### Rollout executor (library, not yet started by the controller)

`internal/rolloutexec` drives the state machine on the authority leader.
Nothing in this change starts it; the pieces are:

- **Executor.** Each tick, the leader loads the cell's active rollout, adopts
  it under its own epoch after a leader change (`Store.Adopt`), performs the
  record's `NextActions`, and commits the events it observed through the
  fenced store. A follower does nothing and forgets its leader-local memory.
  A `Program` lists rollouts in order; the next one starts only after the
  previous one completed, so `SelfUpdateProgram` runs the controllers (one per
  wave, the seed last) and then the hosts. A rollout that ends any other way
  stops the program.
- **Host grouping.** `HostUnits` puts hosts that share a TerraBase partition,
  directly or through other hosts, in one group, so a wave never takes two
  seats of a partition.
- **Gates.** Before preflight and every step the executor requires a fresh
  health proof from every group peer (on either side of the rollout) and
  checks its `Gate`. `ClusterGate` holds a step while the JetStream metadata
  group has no leader, an expected broker is offline, a controller restart
  would drop the metadata group below quorum, or any stream has no leader
  or a replica that is offline or not current (`natscell.StreamHealth`).
  For a controller step it also holds while a stream on the restarting
  broker would lose its quorum without it (an R1 or R2 stream there; every
  stream counts when `ClusterGate.ServerOf` cannot name the unit's
  broker). Preflight restarts no broker and skips this per-broker check. Stream state comes from each stream's leader
  through `STREAM.INFO`, which also reports a replica still catching up
  from an out-of-band snapshot, so remote-led streams are judged as
  strictly as local ones. A held step only waits; the phase deadline
  decides when waiting becomes a rollback. Each round commits expired
  deadlines before it derives any step, and a step whose deadline passed
  while its gates ran is not sent. Immediately before a step leaves the
  leader, the executor calls the authority `Guard` for the record's epoch,
  and the driver checks it again after its receipt lookup and signing,
  immediately before the step is sent, so a lease lost during the tick
  never moves a unit. A program step counts as done only if its completed
  record matches the step's spec (`Record.Matches`).
- **Signed health proofs** (`ts.orch.v1.<cell>.rollout.proof.<hash(unit)>`).
  A running unit signs `{cell, unit, binary digest, pid, start nonce,
  observed_at}` (trust domain `terrascale.orchestrator.rollout-health`, 2
  minute lifetime) while it is healthy. The collector accepts a proof only
  on its own unit's subject and from the unit's resolved keys, and only a
  proof younger than the freshness limit (60 s) completes anything. While a
  unit of the current wave that already reported has no fresh proof, no
  healthy report can complete the wave around it, and a unit that restarted
  after it reported is reported (and rolls the wave back) before any other
  unit's report is fed. A unit an earlier wave promoted whose fresh proof
  (newer than its last healthy report) serves another release rolls the
  rollout back before a later wave moves or completes, and while a promoted
  unit has no fresh proof on the target no healthy report completes a wave,
  so the rollout never completes around it. Proofs are ordered against
  phases, soak windows and steps by when the leader received them, on the
  leader's clock; the signed `observed_at` only bounds replay (a proof is
  fresh when it arrived within 60 s and was observed within 60 s plus the
  verified one-minute skew). A full collector
  reclaims units whose proofs expired before it refuses a new one. A proof
  on the target
  feeds `healthy`; a new incarnation on another release after the
  step feeds `unhealthy` (the watchdog rolled the unit back); a proof on the
  predecessor after a rollback step feeds `rollback-serving`. Controllers
  share the regional response key, so one controller can sign for another;
  that is within the controller trust domain.
- **Signed steps** (`ts.orch.v1.<cell>.rollout.step.<hash(unit)>`). The leader
  signs `{rollout, unit, operation, action, digest, replaces, epoch, proof
  window}`
  plus the release receipt (trust domain
  `terrascale.orchestrator.rollout-step`, scope bound to operation, action
  and unit). The signature expires after 2 minutes or at the step's phase
  deadline, whichever is sooner, so no agent applies a step after the
  leader gave up on it. The agent verifies it against the controller
  keys, refuses to act once the signed command has expired (staging is
  bounded by that expiry and the expiry is re-checked under the release
  lock before the selection changes), records the step's authority epoch
  durably in the release root
  (`authority-epoch`) and refuses a step from an older epoch, even after
  the agent restarted,
  restages a pruned release through its `Fetcher` (the receipt is verified
  by `selfupdate` against the node's own release roots before any byte is
  kept), then:
  - a forward step activates the target with `selfupdate.Activate` (proof
    gated, so the watchdog rolls an unproven target back) only while the
    unit runs the step's `replaces` release (the rollout's predecessor), so
    a still-valid step of an earlier rollout replayed after a later update
    settled is refused; a retry of a
    matching pending activation goes through `Activate` again, so an
    interrupted link flip is repaired;
  - a rollback restores the predecessor with `selfupdate.Restore`: it
    first writes a restore intent (`restore-<unit>.json`), then marks the
    rejected release known bad, records a restart obligation, moves the
    link and removes the intent. `selfupdate.Watch` (the watchdog and the
    unit's prepare step), `Activate` and `Restore` all finish an
    interrupted restore from its intent before they change anything, so
    its recovery never overwrites a newer selection.
    A rollback of a unit that never left the predecessor changes nothing but
    still marks the rejected release known bad on the node. It creates no
    pending activation, so a failed
    restart or missing proof can never let the watchdog return the node to
    the rejected release. A pending activation of the rejected release is
    rolled back exactly as the watchdog would.

  The restart obligation is durable before the link moves and is cleared
  only by the unit's own start (`selfupdate prepare`), so an agent that
  dies in between leaves the watchdog, and the next agent's retry, a
  restart to finish; an agent restarts the unit once per operation. Steps are idempotent per operation: a retry answers
  `pending` or `current`. The reply is unsigned and only says whether to wait; completion
  is proven by health proofs. A forged `refused` reply can at worst start a
  rollback (or freeze one), never move a unit forward.
- **Status** (`ts.orch.v1.<cell>.rollout.status`). Read-only JSON with the
  phase, waves, per-unit state, newest proof digest and current holds.
- **Journal.** Phase changes are journaled by the store; the executor adds
  gate holds, hold releases and every accepted step, chained under the
  release admission.

Remaining before it can run in a cell: a root step agent with NATS
credentials limited to its step subject (the controller runs unprivileged
and cannot write the release root), host steps and proofs over the host
session with the chunked artifact path, and a signed operator request that
supplies the program.

### Resumable image promotion

`ts-orch image promote --resume` continues in an existing `--out` directory
that `promotion-state.json` pins to the same image release (or directory) and
image digest. It always refreshes `SHA256SUMS` and small metadata, reuses the
qcow2, kernel, manifest, binary, qualification and base image only when their
SHA-256 matches the pinned digest, reuses the release tool built into `--out`
when its recorded digest and clean `vcs.revision` still match, reuses the
earlier signed binary receipt for `verify-binary`, and skips the upload and
import when `oci-import.json` records this image digest. Rerunning after the
image delegation is signed therefore no longer downloads or imports again.

### Independent managed-host image

By default the managed fleet's `image_id` must equal the controller's own
accepted boot image. With `controller.managed_host_image_receipt_file` and
`controller.managed_host_image_delegation_file`, the fleet instead qualifies
its configured image from that image's own root-delegated receipt (baked
roots, cell environment, exact OCID, region and shape architecture), plus the
existing OCI readback on every use. Changing `image_id` still makes hosts
launched from the previous image foreign to the fleet; an allow-list of
current and previous qualified images is a follow-up.

## Human decisions needed

1. Approve the update/compatibility key owners, separate actor identities,
   cell/repository/role/environment grants, expiry and revocation process;
   sign and install the updated controller config. Current GRU grants lack
   these capabilities. No key is generated or enabled by this PR.
2. Decide whether all eligible main releases assert mixed-version replication,
   client-data and persistent-format read/write compatibility with the
   deployed predecessor, including rollback. The implemented entry point
   relies on that explicit policy because the existing updater signs those
   assertions. If release-specific tested evidence is required, add and verify
   it before enabling automation; qualification success alone is insufficient.
3. Approve/publish TerraBase's accepted prepared-source digest recipe and
   release asset, and authorize trusting that producer. It is absent today.
4. Approve automatic rollout scope: cell/placement inventory, canary to
   production promotion, coalescing/skipping intermediate releases, one-minute
   polling, soak time (default 5m after the serving proof), maintenance windows,
   pause/alert owner and rollback policy. Install timers/forward supervision
   only after approval; no repository secret or CI-to-cell access is needed.
5. Review the orchestrator replacement authorization schema, root/leaf owners,
   source/image signing gates, budget, admission/fencing and seed-floor handoff,
   state-format compatibility and rollback criteria. Approve a separate runtime
   implementation PR before any running-cell orchestrator replacement.
6. The scoped auto-sign policy is approved in principle. Before use, choose
   the online leaf key owner and host, the reviewed `lineage_base`, the cells,
   architectures and expiry of the first binary update delegation, and which
   nodes install the self-update drop-ins with `--allow-scoped-auto-sign`.
   Binary-only self-update requires the new release to read the persistent
   NATS and authority state of its predecessor; halt for a reviewed migration
   otherwise.
