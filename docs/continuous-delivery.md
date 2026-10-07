# Continuous delivery to running cells

Status: the opt-in TerraBase automation entry point is implemented; no live
timer or signing grant is enabled by this change. The image puts
the controller and host on
[binary-only self-update](#binary-only-self-update). Production controllers
follow their region's [release channel](#automatic-fleet-deployment-ts-557-part-1)
by default and roll each CI release out to the controllers; hosts still move
only when a root-run step stages and activates a release. The scoped auto-sign
delegation, the staged rollout state machine, resumable image promotion and
independent managed-host image qualification exist as opt-in foundations;
each is off by default. Image-based orchestrator replacement is still a
proposed follow-up.

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

## Binary-only self-update

Most orchestrator changes touch only the binary, so they do not need a new
image, an OCI import or a re-bootstrap. `internal/selfupdate` replaces the
executable on a running node with an A/B layout:

```text
/var/lib/terrascale-orchestrator/
  releases/<sha256>/terrascale-orchestrator   read-only (0555), root-owned
  releases/<sha256>/receipt.json, delegation.json (or "baked")
  current -> releases/<sha256>                  what ExecStart runs
  known-good -> releases/<sha256>               runs the root steps (below)
  activation.json                               pending switch, if any
  known-bad.json                                digests rolled back on this node
```

1. **Distribute.** The qualified binary (about 46 MB, under the 512 MiB
   artifact bound) is uploaded through the existing signed delivery artifact
   store or the region's release channel. A controller fetches it by
   digest and a host gets it in chunks from the authority leader over its
   session; the step agent stages it only through the receipt and digest
   checks below (see [step delivery](#step-delivery)).
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
4. **Prove.** The new process signs a version proof after it is ready
   (controller: after host-controller readiness, with its response key; host:
   after start-up checks, with its identity key) and writes it to
   `self_update_proof_file`, by default `selfupdate-proof.json` in the unit's
   state directory (`/var/lib/terrascale-orchestrator-controller` or
   `/var/lib/terrascale-orchestrator-host`). The proof names the activation,
   unit, the digest of `/proc/self/exe` and the process ID, and is valid for
   10 minutes.
   A controller first passes restart admission, which accepts the image
   receipt binary or the `current` release when that release is root-owned
   with unchanged bytes, is not known bad, and carries a binary-update
   receipt for the controller's environment, cell and architecture. `stage`
   checked that receipt as current before keeping a byte, so admission
   checks it only historically, as it does the image receipt: a staged
   release keeps restarting after its delegation expires, and the
   known-bad list is how a release is withdrawn. A tampered release, or one
   staged under a per-source receipt (stage controller releases with
   `--allow-scoped-auto-sign`), fails admission, signs no proof and is
   rolled back; the baked release is admitted by the image receipt as
   before.
5. **Confirm or roll back.** `selfupdate prepare` (root `ExecStartPre=+`) and
   the `terrascale-orchestrator-selfupdate-watchdog@<role>.timer` (every 15 s,
   role `controller` or `host`) confirm the activation from a fresh proof
   signed by the unit's key. The watchdog reads that key, and any configured
   proof file, from the role's `/etc/terrascale-orchestrator/<role>.json`; it
   decodes only those fields, so a config written for a newer release still
   works with the image-baked binary. An absent or unusable config, or key,
   disables confirmation, never rollback. A
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

The image installs `deploy/systemd/selfupdate/`: both runtime units' drop-ins
and the watchdog template, with the `controller` and `host` timer instances
enabled, so a node needs no config field or other node-local file. A
non-default `--root` in the drop-ins must also be set as `self_update_root`,
so the process signs its proof under the same root. On first start
`prepare` seeds the image-baked `/usr/local/bin/terrascale-orchestrator` as the
first release, so the baked binary always remains a valid rollback target;
until a release is activated the units run the same bytes as before.
The image's units are fixed when it is built, but its self-update logic is
not. The image-baked binary is only the entry point of `prepare` and the
watchdog: it hands each step, with the same arguments, to the release the
`known-good` link names. Only a confirmation moves that link, so it names
the last release a unit proved with a version proof; a restore, a rollback
or an unreadable record never makes an unproven release the delegate. The
baked binary runs a step itself when there is no known-good release, it is
the baked one, it no longer verifies, it was rejected since, or it fails or
hangs the step (30 s), so a release with broken root steps degrades to the
image's logic. After a delegated step the baked binary still rolls back any
readable activation pending five minutes past its deadline and refuses to
start a current release that does not verify, so no release can switch
rollback off. Every release must keep accepting the units' arguments
(`TestImageUnitArgumentsStillRun`) and must move `known-good` when it
confirms (`TestKnownGoodMovesOnlyOnConfirmation`); deleting the link makes
the baked binary run the steps again.
Nodes that installed the earlier opt-in drop-ins by hand keep their
`selfupdate-<unit>.env` files and `@<unit>` timers until they are rebuilt
from this image.
A node running both a controller and a host shares one `current` link. While
one unit's activation is pending, `prepare` refuses to start the other unit
on its unconfirmed target; that unit's restart policy retries after the
activation resolves. A confirmation proves only the activated unit until
per-unit links exist.

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

### Rollout executor

`internal/rolloutexec` drives the state machine on the authority leader.
`controller.rollouts.executor` (with `enabled`) starts it on every controller
(see [below](#leader-run-controller-self-update)); the pieces are:

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
  reclaims units whose proofs expired before it refuses a new one. Within
  one incarnation proofs only move forward; a new incarnation whose clock
  reads earlier replaces the newest one after that one was quiet for two
  proof intervals, and an incarnation a newer one superseded is refused
  for as long as any proof it signed can still verify. A proof
  on the target
  feeds `healthy`; a new incarnation on another release after the
  step feeds `unhealthy` (the watchdog rolled the unit back); a proof on the
  predecessor after a rollback step feeds `rollback-serving`. Controllers
  share the regional response key, so one controller can sign for another;
  that is within the controller trust domain.
- **Signed steps** (the unit's `step.<hash(unit)>` key in `TS_ROLLOUTS`,
  see [step delivery](#step-delivery)). The leader
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

### Step delivery

The controller runs unprivileged and cannot write the release root, and the
node's root-run self-update watchdog has no NATS connection, so a step
travels through the replicated `TS_ROLLOUTS` bucket and the controller's
state directory. Every controller credential already reads and writes KV,
so material issued before this change carries steps too.

1. The leader's `KVDriver` signs the step and writes it under the unit's
   `step.<hash(unit)>` key. Until the unit's `step-reply.<hash(unit)>` key
   answers this operation, it asks the executor to retry; the next tick
   signs and writes the step again.
2. The unit's own controller (`Relay`, every 2 s) verifies the step against
   the controller keys, fetches the release binary it names when the node
   has not staged it (from the delivery artifact store, then the region's
   release channel; bytes that do not hash to the step's digest are
   dropped) and writes both to
   `/var/lib/terrascale-orchestrator-controller/rollout/`.
3. The watchdog timer (every 15 s, as root, delegated to the node's
   known-good release) runs the step agent (`ApplySpooled`) after its own
   check, so a stuck step never delays a rollback. It opens regular files
   beneath the spool only (`os.Root`, non-blocking, so no link or FIFO
   leads it elsewhere or stalls it); ignores a step that does not verify, so a stale copy
   never answers a later attempt of the same operation; stages a fetched
   binary only through `selfupdate.Stage`, which verifies the receipt
   against the node's baked roots and the exact bytes; and writes its reply
   to `/var/lib/terrascale-orchestrator/rollout-reply-<unit>.json`. The
   watchdog then serves the restart the step owes the unit.
4. The relay posts that reply to the unit's reply key. A reply carries the
   step's authority epoch, so a deposed leader's late copy of an operation
   never answers its successor.

A host cannot read the rollout bucket or publish proofs, so its steps and
proofs travel its signed host session instead. Every 5 s the agent sends the
`rollout` operation to the authority leader: its health proof, signed with
its registered identity key, and its step agent's newest reply; the leader
verifies the proof against the host's registration, posts the reply to the
host's reply key and answers with the host's pending step. The agent spools
it in `/var/lib/terrascale-orchestrator-host/rollout/` and fetches the
release it names in 256 KiB chunks (`rollout-binary`) from the leader's own
release root, which holds both the release a host moves to and the one it
may return to because the controllers moved first. The watchdog of the host
unit applies the step, verifying the leader's signature with the controller
key `host.json` pins.

The agent runs where the controller's executor runs, with the same default:
a production controller config without `controller.rollouts`, or one with
`executor`. It accepts scoped update receipts exactly when the leader does
(`allow_scoped_auto_sign`, on by default in production). Because the
watchdog is delegated to the known-good release, a node gains the agent with
its first confirmed release that has it; no image rebuild is needed.

Trust: the agent accepts steps signed with the regional controller response
key, which every controller holds. A compromised controller can therefore
sign steps for any node of its cell: it can activate a release already
staged there (each one verified against the node's roots when it was
staged), or record an authority epoch so high that the node refuses every
later step until root removes `authority-epoch` from the release root. It
can never stage bytes no receipt names. With the production default, the
online update leaf plus its root-signed scoped delegation is enough to run a
binary as root on every controller of the delegation's cells, architectures
and environment until the delegation expires: keep it short and narrow. A
signed config with an explicit `controller.rollouts` block without
`allow_scoped_auto_sign` opts a cell out.

### Leader-run controller self-update

The cell's desired orchestrator release is state in the replicated
`TS_ROLLOUTS` bucket, never baked: `release.desired` holds the newest
**generation** (binary digest, source revision and CI run its receipt names,
the receipt and delegation, actor, time) and the cell's pause; `release.gen.<N>` keeps a copy of each of the
last 64 generations. Generations only grow, every write is fenced by the
authority epoch, and a known-bad digest is never published. The KV schema
belongs to the cell spec (TS-556) and the store (TS-559); this is the
minimum the executor needs until they own it.

A production controller whose signed config has no `controller.rollouts`
block runs with `enabled`, `executor`, `allow_scoped_auto_sign` and `channel`
(`rolloutSettings`); a lab controller keeps all of them off, and an explicit
block is taken as written. With `controller.rollouts.executor`, every
controller signs a health proof
with the regional response key every 15 s and collects its peers' proofs
(the controller credential's `rollout.proof.*` subscription grant; material
issued before it lacks the grant, so preflight never passes and nothing
moves). The leader's executor derives its program from the desired
generation: once every controller freshly proves its release and those not
yet on the generation's release agree on theirs, it begins
`release-g<N>-controllers` for them, one controller per wave, the seed (from
the accepted founder install) last and alone, behind `ClusterGate`. A started
rollout keeps its units and predecessor; a controller that falls behind after
its generation completed waits for the next one. A
rollout whose proof deadline passes rolls every touched controller back
through `selfupdate.Restore` on the node and marks the digest known bad.
`rollout.DefaultPolicy` is as fast as a binary-only update allows (user
decision 2026-10-06): one canary soaks five minutes, then every later wave
takes as many units as quorum allows (three controllers still move one at a
time, the seed last) and soaks two minutes; a wave is promoted after three
healthy reports from one incarnation. A unit that restarts on another
release, or does not prove the target within ten minutes, rolls the rollout
back. Units prove themselves every 5 s, and the leader's executor acts as a
proof arrives or the rollout bucket changes (a new generation, a step reply,
an operator's request), not only on its 5 s tick. `controller.rollouts.policy`
overrides the policy, and a [cell spec](cell-spec.md) `rollout_policy` overrides
that on running controllers for the next rollout. Each controller relays its
own steps to its node's root step agent (see [step delivery](#step-delivery)).

Once the controllers completed, `release-g<N>-hosts` moves the hosts the
same way. A host joins the release program with its first `rollout`
exchange, which the leader records in the rollout bucket with the host's
registered key: a joined host that stops proving holds the host rollout
instead of being left out, a host whose binary predates host self-update
never holds a release, and a host replaced under its name is a stranger
until it proves with its new key. A host on a controller's VM shares the
controller's release root, so it is left out of the host rollout (a step
there would move the controller's link; the leader refuses its exchanges and
its watchdog applies no host step) and runs the controller's release from its
next restart. The leader accepts one exchange per host per proof interval
and replies of at most 4 KiB.

TerraBase hosts are grouped by their placement partition, or all together
when it is unknown, so a wave restarts one seat of a partition at a time
(restarting a host agent stops its members until the new agent recovers
them). Before each host step the leader also waits:

- while the host says an operator holds its restarts (TS-578: any
  `<role>-restart-hold` file in its state root); its agent spools no step
  meanwhile;
- with `controller.terrabase_seats`, while the seat controller has a seat
  out of rotation; and the seat controller starts no seat restart while a
  host rollout is active, so a TerraBase release waits for it;
- for a host with a TerraBase member, until every TerraBase member of the
  cell reports `running` (its `/readyz` included) at its desired generation
  within the report age: the previous host's member serves again before the
  next host restarts, a member down for any other reason holds every host
  step, and no TerraBase release is restarting a seat meanwhile.

The restarting seat is not drained first: the load balancer stops sending
it requests once its health check fails, and requests in flight to it fail;
routing host restarts through a seat drain needs the seat records to hold
one (TS-571). The steady-state check covers static TerraBase members
(`terrabase` desired), not managed placement members. A host accepts scoped
update receipts by default and has no separate opt-out; the leader, which
signs every step, honours the controller's `allow_scoped_auto_sign`.

The channel reports a generation complete once the controllers' rollout and
the hosts' completed. Hosts that cannot start their rollout (a joined host
does not prove itself, or the hosts run different releases) do not hold the
region: the report is complete, and its reason says why the hosts wait; a
host rollout that rolls back reports the generation failed.

Operators drive it with `ts-orch rollout`, signed requests on the host
registration subject that only the leader answers. Any trusted signer of the
signed controller config may read `status`; every other request needs the
signer's `can_roll_out_orchestrator` grant, since pausing, rolling back or
aborting a release changes what the controllers run.

- `publish --receipt F [--delegation F]`: the leader verifies the receipt
  with the image's release roots for this cell, environment and architecture
  and makes its binary the next generation. Scoped update receipts are
  admitted only with `controller.rollouts.allow_scoped_auto_sign`, set
  exactly when the nodes accept them. Republishing the newest binary changes
  nothing.
- `pause` / `resume`: a paused cell starts no further rollout; one in flight
  runs to completion or rollback, so a pause never strands a half-updated
  quorum. `resume` also retries the rollback of a frozen rollout.
- `rollback --to GEN`: re-verifies GEN's receipt, publishes its release
  again as a new generation and aborts a rollout in flight towards another
  release (its touched units return to their predecessor and its target
  becomes known bad); a retried request aborts it too. The cell then rolls
  forward to GEN's release; history is never rewritten.
- `status`: the desired release, the last ten generations and the leader's
  rollout status, including why nothing runs (`waiting`), and the leader's
  newest report to the release channel (`channel`).

### Automatic fleet deployment (TS-557, part 1)

Every merge to `main` is signed and published to every region by CI,
region by region; nothing is copied by hand. CI cannot reach a cell's
private NATS, so each region's release channel lives in its head bucket
(`<cell>-head`, for example `gru-1-head`), under `releases/v1/orchestrator/`
(`internal/releasechannel`):

```text
binaries/<sha256>   the static binary, written once (If-None-Match, read back)
channel.json        the region's current release: cell, environment, source
                    revision, ci.yml run number, the root-signed update
                    delegation and one leaf-signed update receipt per arch
status.json         the region leader's report: run, state (rolling |
                    complete | failed) and reason
```

1. `ci.yml` on `main` dispatches `deploy.yml` after the image dispatch, only
   while the repository variable `TS_AUTO_DEPLOY_CELLS` is set. It refuses
   a revision that is not on `main` before any secret is used, and builds
   the signer with private Go caches. A running deployment is never
   cancelled; a newer dispatch replaces one still pending, and one that a
   newer qualified revision overtook skips itself
   (`scripts/ci/image-superseded.sh` with `GATE_WORKFLOW=deploy.yml`).
2. `ts-orch release deploy` (`scripts/ci/deploy-fleet.sh`) checks the
   retained binaries against `qualification.json` and the successful
   Forgejo run, reads the update leaf key from OCI Vault, proves lineage
   and signs one update receipt per cell and architecture before any region
   sees the release. Each channel is checked with the consumer's own
   verification (`Channel.Verify`), and again right before it is published,
   as of the end of that region's rollout window: receipts that would expire
   mid-rollout stop the deployment (renew the update delegation).
3. Cells are deployed in the order given, the first being the canary: the
   binaries are uploaded, `channel.json` is replaced by compare-and-swap on
   its ETag (a channel never moves to a lower run, and a repeated deployment
   of the same run renews its receipts), and CI polls `status.json`
   until the region reports the run `complete`. A `failed` report, a newer
   run or no completion within 30 minutes stops the fleet rollout and fails
   the job; later regions never see the release.
4. `ts-orch release fleet-status --namespace NS` prints every region's
   channel and status as JSON lines.

The channel document is unsigned: a node acts only on the update receipts it
carries, which bind the cell, environment, architecture, digest, revision
and run under the root-signed delegation. `status.json` is telemetry; a
forged report can stop CI or move it to the next region, but no region
accepts a release without verifying it.

Inputs (repository variables unless noted): `TS_AUTO_DEPLOY_CELLS` (for
example `GRU SFO FRA`, canary first), `TS_AUTO_DEPLOY_ARCHES` (default
`arm64`), `TS_AUTO_DEPLOY_ENVIRONMENT` (default `production`),
`TS_OBJECT_NAMESPACE`, `TS_RELEASE_VAULT_ID`, `TS_RELEASE_LEAF_SECRET`,
`TS_RELEASE_UPDATE_DELEGATION` (the envelope from `ts-orch release
sign-update-delegation`, re-issued at most every 31 days),
`TS_DEPLOY_OCI_USER`, `TS_DEPLOY_OCI_TENANCY`, `TS_DEPLOY_OCI_FINGERPRINT`
and the secret `TS_DEPLOY_OCI_KEY`. The OCI user's group needs only:

```text
Allow group ts-orch-deploy to read secret-bundles in compartment <vault compartment> where target.secret.name = '<leaf secret>'
Allow group ts-orch-deploy to manage objects in compartment <cell>-control where all {target.bucket.name='<cell>-head', target.object.name='releases/v1/*', any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}
```

and each region's controllers `OBJECT_READ` on `releases/v1/*` plus
`OBJECT_CREATE`/`OBJECT_OVERWRITE` on `releases/v1/orchestrator/status.json`.

The region's authority leader follows its channel
(`controller.rollouts.channel`, on by default in production; TS-560) over
NATS. The cell's `TS_RELEASE_CHANNEL` KV bucket holds the channel document
under `orchestrator.channel.<CELL>` and the leader's newest report under
`orchestrator.status.<CELL>`. Every controller watches its cell's channel
key; the leader acts when the document changes and after every executor
tick, which also moves the report on as the rollout progresses. Nothing
polls:

1. It verifies the whole channel for its cell and environment with the
   cell's current roots (`Channel.Verify`), and admits the receipt for its
   architecture exactly as `ts-orch rollout publish` would.
2. A run newer than every run the cell published becomes the cell's next
   generation (actor `release-channel`). A run the cell already published
   maps to that generation; the newest one wins, so after an operator's
   `rollout rollback` the channel never publishes the rejected run again.
   An older run, or a release known bad in the cell, is refused.
3. It reports the generation's progress: `rolling` while its controller
   rollout runs (or waits to start, with the executor's reason), `complete`
   when it completed or every controller already proves the release, and
   `failed` when it was rolled back, aborted, frozen, refused or replaced by
   another generation first, or the channel does not verify or decode. A
   report that differs from the stored one is stored and published on
   `ts.orch.v1.<cell>.release.status` (`protocol.ReleaseStatusSubject`) for
   fan-in across regions; comparing with the stored report, not the
   leader's memory, replaces one a deposed leader left.

TS-562 replicates the bucket between orchestrators and announces releases
into it. Until it does, CI cannot reach the cell's NATS, so the leader
bridges the CI edge every 30 s: it copies `channel.json` from the region's
head bucket (the controller's OCI region and instance principal, the
namespace from Object Storage) into the channel key, and the stored report
back out to `status.json` when they differ (the head bucket keeps versions,
so an unchanged report is not rewritten; a stale or forged one is). Only
this edge reads Object Storage.

The rollout itself rolls a release that never becomes healthy back, marks it
known bad and reports `failed`, which stops CI before the next region. The
controllers fetch the binary from `binaries/<sha256>` in the same bucket, so
the delivery artifact store and its quota are not involved.

The reviewed controller policy statements
(`ociregion.RequiredControllerStatements`, which the attempt's material phase
applies) grant the controllers the channel:

```text
Allow dynamic-group gru-1-controllers to manage objects in compartment gru-1-control where all {target.bucket.name='gru-1-head', target.object.name='releases/v1/*', request.permission='OBJECT_READ'}
Allow dynamic-group gru-1-controllers to manage objects in compartment gru-1-control where all {target.bucket.name='gru-1-head', target.object.name='releases/v1/orchestrator/status.json', any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}
```

Limits of this part:

- A node gains the step agent with its first confirmed release that has it.
  A cell founded on an older image needs that release once by hand
  (`ts-orch selfupdate stage` and `activate --restart` on each controller,
  as root); from then on CI moves it.
- Hosts join the same way: the first release with host self-update reaches
  a host by hand, or with a rebuilt image.
- Forgejo repository secrets reach any workflow pushed to the repository,
  so every account with write access can obtain `TS_DEPLOY_OCI_KEY`, read
  the leaf and sign any binary for the delegation's cells, architectures and
  environment until it expires. Keep the delegation short and narrow; OCI
  KMS has no Ed25519 signing, so the leaf cannot stay in an HSM.
- A `channel.json` that does not decode, or names a higher run, stops every
  later deployment to that region until an operator inspects it (fail
  closed). The deployment covers at most three cells, the job timeout.
- Binaries are never deleted from `releases/v1/orchestrator/binaries/`; an
  Object Storage lifecycle rule should expire old ones.

### Automatic service releases (TS-610)

TerraBase and ts-auth deploy themselves the same way: when their `main` CI
is green, its `deploy` job hands the tested binary to every region's
orchestrator and the region rolls it out with no human step. One path
serves any native role; the leader's release rule for a role (its replica
count) is `serviceReleaseReplicas`.

```text
releases/v1/services/<role>/binaries/<sha256>   the binary, written once
releases/v1/services/<role>/release.json        the signed artifact claim
releases/v1/services/<role>/status.json         the region leader's report
```

1. The service's CI runs `ts-orch release service-deploy` (the
   `ts-orchestrator` CI binary its repository variables `TS_ORCH_RELEASE`
   and `TS_ORCH_SHA256` pin; bump both together): it reads the role's release key from OCI
   Vault, and for each cell in order, the canary first, uploads the binary
   to the cell's head bucket, signs a delivery artifact claim (digest, size,
   repository, commit, `git archive` tree digest, computed without local Git settings, cell, role, environment)
   and replaces `release.json` by compare-and-swap; a claim issued earlier
   than the one there never replaces it, unless that one is dated more
   than 5 minutes ahead, which every leader refuses. It then polls `status.json` until
   the cell reports the release `complete`. A `failed` report or no report
   within `--region-timeout` stops the rollout and fails the job; later
   cells never see the release.
2. Every 30 s the region's authority leader reads each role's
   `release.json` (`serviceReleases` in `internal/app`). A claim it has not
   seen must first verify at its issuance instant against a trusted signer
   of the cell whose grant or cell spec releaser entry covers the role,
   environment and repository (`delivery.Service.VerifyClaim`); one that
   does not, or is issued more than 5 minutes ahead, is reported `failed`
   and never moves the role's issuance watermark. An authentic claim must be
   issued after the role's last one and less than an hour ago. The leader
   then copies the binary out of the bucket and admits it
   (`delivery.Service.AdmitClaim`): the bytes must be the claimed ones.
3. It then rolls the role out exactly as `operator terrabase-release` and
   `operator ts-auth-release` do (`nativeDeployer`): the intent moves every
   replica to the digest, the readiness gate waits for every replica to
   report it `running` (which needs `/healthz` and `/readyz`), and a release
   that fails the gate is rolled back to the digest the replicas ran before
   and reported `failed`. The leader submits the intent for the claim's
   signer (`delivery.Service.SubmitVerified`); the delivery worker
   authorizes that signer again.
4. With the cell spec's [`release_fence`](cell-spec.md), the release
   restarts one node at a time, which colocated roles (gru-1: TerraBase and
   ts-auth on the same three controllers) need. Before it submits a release
   the leader marks it `fence.<role>.<release>` in `TS_RELEASE_CHANNEL`, and
   every controller's host restart gate holds a host's restart into a
   marked release until the leader writes that node's permit. For each node
   in turn, nodes with a recorded fence first (so a rollback returns the
   node that failed before it takes a serving one out), the leader takes
   the node's backends that are in rotation (by the node's host grant
   address; a node without one stays held) out of
   every fenced set (drain, the grace, then offline, since a drain alone
   keeps the load balancer's pooled connections), each change only while a
   backend of another node serves healthy in that set, checked right
   before the change; records them under `fenced.<node>`,
   with the load balancer they belong to and a `fencing` phase, before it
   changes the load balancer, and marks the record `fenced` once all are
   offline (a new leader finishes a `fencing` record before it permits the
   node); permits the node; waits until it
   reports the release `running`; returns its backends and waits for their
   health checks; and settles. A node that fails the release keeps its
   backends out of rotation and the release rolls back the same way, one
   node at a time; a new leader returns recorded backends, always to the
   load balancer recorded with them, and a cell spec that drops its fence
   returns every recorded backend before the release opens. Every load
   balancer change and permit is guarded by the authority epoch the leader
   started under, so a deposed leader stops. Once every node
   serves the release, its marks are removed, so later scaling is not held.
   The readiness gate of a fenced release gets, per node, the grace, the
   settle and 5 more minutes. Once every node serves a release, the marks
   and permits that failed or superseded sequences of the role's older
   releases left are removed. The operator's `terrabase-release` and
   `ts-auth-release` commands do not go through the fence: they restart
   every replica at once, so they are for breaking glass, with the
   backends drained by hand first.
   With TerraBase seats (`controller.terrabase_seats`) the seat controller
   keeps ordering TerraBase restarts and the fence sequences the other
   roles only, so one sequencer gates each role.
   The controllers' instance principal needs `use load-balancers` in the
   network compartment (`ociregion.RequiredControllerStatements`).
5. The leader records each step under `service.<role>.<CELL>` in
   `TS_RELEASE_CHANNEL` before it acts, so a new leader resumes the gate of
   a submitted release instead of starting it again, and mirrors the record
   to `status.json`. An intent an earlier leader submitted that the delivery
   worker has not accepted is fenced by its old epoch, so the new leader
   issues it again under its own epoch, above every generation committed
   since. A rollback is recorded before it is submitted, so a new leader
   finishes it and never issues the failed release again; a rollback that
   does not pass its gate keeps the release `rolling` and is retried, so
   only a rollback that serves reports `failed`. A recorded release resumes
   with its own replica count even if the cell spec changed since. A submitted
   release finishes, or rolls back, from its record before the channel is
   read, so neither a newer claim nor an unreadable bucket holds it, and a
   failed `status.json` write only logs; a
   failure to read hosts or state is retried on the next pass rather than
   failing the release.

Credentials: the service repositories hold one scoped OCI API key
(`TS_RELEASE_OCI_KEY`) for the IAM user `ts-service-release`, whose group may
only read the release key's secret and write `releases/v1/services/*` in the
head buckets:

```text
Allow group ts-service-release to read secret-bundles in compartment <vault compartment> where target.secret.name = 'ts-service-release-key'
Allow group ts-service-release to manage objects in compartment <cell>-control where all {target.bucket.name='<cell>-head', target.object.name='releases/v1/services/*', any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}
```

The release key is an Ed25519 PKCS#8 PEM in that Vault secret. Its public
key is a trusted signer of each cell (`ci-release` in the cell spec's
`signers`) with `roles` `terrabase` and `ts-auth`, the cell's environment
and `repositories` limited to the two source repositories; it cannot sign
orchestrator updates, register hosts or change the cell spec. The
controllers already read `releases/v1/*` in their head bucket and need
`OBJECT_CREATE`/`OBJECT_OVERWRITE` on
`releases/v1/services/*/status.json` too; both are in
`ociregion.RequiredControllerStatements`.

Limits of this part:

- Without a release fence a release writes every replica's desired at
  once, so every replica restarts together.
- Roles other than `terrabase` and `ts-auth` need a release rule first.
- Binaries are never deleted from `releases/v1/services/*/binaries/`; an
  Object Storage lifecycle rule should expire old ones.

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
existing OCI readback on every use. Changing `image_id` keeps hosts
launched from the previous image in the fleet while the cell spec's
`host_images` allow-list names it (see [image updates](image-updates.md)).

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
   nodes stage releases with `--allow-scoped-auto-sign`.
   Binary-only self-update requires the new release to read the persistent
   NATS and authority state of its predecessor; halt for a reviewed migration
   otherwise.
