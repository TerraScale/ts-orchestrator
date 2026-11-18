# Build and release boundaries

## Candidate preflight

After verifying fully received candidate bytes against the release digest, the
host runs `<candidate> release preflight` as its own user in its existing sandbox.
The hook currently succeeds without checks and has a 70-second execution bound.
A failed, timed-out or unexecutable candidate is refused before anything is
staged. If the exec meets `ETXTBSY` (another process still holds a descriptor
of the candidate open for writing, such as a child started while the file was
being written), it is retried for up to 5 seconds and then refused as a
`host_prerequisite` that is not a candidate preflight refusal. The candidate is
written without any process-wide lock, so commands the agent starts during a
slow write are not delayed. On refusal the installed binary, `.prev`, the trial, the run fence and the rollback
record stay as they were. The reply includes a scrubbed diagnostic, candidate
revision and SHA-256 digest, run id, run attempt and structured refusal kind.
Output is drained while only 4 KiB is retained; diagnostics contain valid UTF-8
without control characters.

`host_prerequisite` means this host could not complete verification or
installation: incomplete downloads, network errors, disk failures and candidate
preflight refusals have this kind. A damaged run fence is refused without
rewriting it. `release_integrity` means a signature, provenance identity, binary
digest, source ancestry or embedded revision failed verification.

Regional leaders read their region's OCIR release channel and send private
PullInstall requests. Each host verifies Sigstore provenance, the allowed main
workflow, transparency evidence, the channel seq, exact digest and revision
before installation. There is no public
push listener, worker relay or repair-push command. A refusal blocks that region;
later regions wait for the same tag's completed, baked fabric record. See
[platform releases](platform.md#releases) for the admission order.

## Regional OCIR release channel

Hosts install ts-orch releases from their own region's Oracle Cloud
Infrastructure Registry (OCIR); they make no GitHub API call on this path.

**Publish.** After the exact tree passed its merged PR's `all-green`, or
after main's lanes pass when that proof is absent, CI's `deploy/release-publish` job runs the
release's own amd64 binary:

1. `ts-orch release channel prepare` builds the release artifact (one OCI image
   manifest whose layers are `terrascale-orchestrator-linux-amd64`,
   `terrascale-orchestrator-linux-arm64` and `provenance.sigstore.json`, each
   named by its `org.opencontainers.image.title` annotation) and writes the
   channel document `channel.json`:
   `{"seq", "sha", "run", "artifact", "published_at"}`. `seq` is the workflow
   run number, so it grows with every run and stays the same when a job is
   rerun (step 5 of the runbook below covers a restarted run number); `artifact` is the artifact manifest's digest, which is the same in
   every region.
2. `actions/attest-build-provenance` signs `channel.json` keylessly with the
   same identity as the binaries
   (`TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main`, push,
   this commit and run) and the bundle is saved as `channel.sigstore.json`.
3. After C41's `ocir-login` action logs Docker in to `us-sanjose-1.ocir.io`,
   `eu-frankfurt-1.ocir.io` and `sa-saopaulo-1.ocir.io` (the app registry's
   hosts; staging shares us-sanjose-1) through GitHub OIDC token exchange,
   `ts-orch release channel publish` pushes the artifact as
   `orchestrator-release:ci-<sha>-run-<run>` and then the channel manifest
   (layers `channel.json` and `channel.sigstore.json`) as
   `orchestrator-release:stable` to every fleet region and to staging. Each
   destination is the app registry's repository for that region
   (`internal/appregistry`, namespace and prefix from `deploy/m1/registry.json`),
   so staging, which shares us-sanjose-1, has its own repository. It reads both
   back and verifies them the way a host does. A channel that already holds a
   higher seq, or this seq for this release, is left unchanged, so a rerun or a
   late older run never moves the channel back or writes a seq twice; the same
   seq for another release fails the job. Every region is tried; any failed
   region makes the job red.

The GitHub Release assets stay as they are for people; hosts no longer read
them.

**Install.** The regional leader reads `stable` from its region's
`orchestrator-release` repository, the same one the publisher wrote, through
the app registry client it shares with app pulls: a request to
`/20180419/docker/token` signed by the instance principal (with a signed
`Date` header) returns the bearer token. No file credential or GitHub token
exists on a host. After reading a signed OCIR release, the leader checks for
channel changes every 15 seconds. A poll that finds the same channel manifest
digest as the last one costs one small manifest read. The GitHub fallback keeps
its five-minute discovery interval and existing channel retry backoff. Once the
release is baked, unchanged-channel discovery skips host and regional health
sampling until the existing five-minute sweep is due. Active bake samples and
post-action waits keep their original cadence. A new channel is
verified in this order:

1. the channel bundle's certificate identity and issuer, transparency evidence
   and that it attests the exact `channel.json` bytes;
2. `seq` above the region's adopted seq (kept in the region's durable rollout
   record); an older seq, or the same seq naming another release, is refused as
   a replayed or rolled-back channel document;
3. the artifact manifest by its digest, its `provenance.sigstore.json` bundle
   (same identity, this commit and run) and that each binary layer's digest is
   the attested digest.

A document that fails step 1 or 2 is refused as a channel, against its manifest
digest only: nothing it names is trusted, so the rollout record keeps its
target, seq, `channel_seq` and bad list, and only its reason (logged at WARN)
changes. Whoever can write OCIR but cannot sign can stall the region's next
release this way, but cannot mark any release bad. Only a failure of step 3,
which the signed document pins by digest, marks that release bad. An artifact
the registry does not hold yet is not refused: the poll counts as an
unreachable channel and is retried.

Each host repeats the whole check itself when it receives the PullInstall (the
request carries the signed channel document and bundle), refuses a seq below its
own installed seq (`nats/release-seq.json` with the seq, tag and binary
digest, written before the binary is staged), downloads the binary blob with its own registry token and then runs the
unchanged staged install with probation. A host that already runs the target
binary but has not recorded its seq is asked to install it and answers
`current` without a restart. Lineage comes from the signed main identity and the
monotonic seq; there is no GitHub compare.

**Fallback while migrating.** Hosts still running a build that reads GitHub get
this build through the existing path. When the channel cannot be read (no
answer, an HTTP error, no `stable` tag yet) the leader logs
`release channel unreachable; using the GitHub release fallback` at WARN and
reads GitHub releases as before; it retries the channel after a backoff that
doubles from the poll interval up to eight times it, plus up to half of it as
jitter, and logs every fallback use at WARN. A refused channel never falls back.
When the channel later names the release the fallback rolled out with a higher
seq, the leader adopts it as the target, so every host records that seq through
a `current` install.
A host that missed the migration and still runs the older build cannot decode a
channel release; it needs one push of this build. A follow-up change deletes the
host-side GitHub code once every region has installed a release from its
channel.

**Metrics and alert.** Every host's orchestrator exporter (`peer-topology`
scrape) reports `ts_orch_release_installed_seq`: the seq of
`nats/release-seq.json` once that seq's binary is the installed binary and no
probation trial is pending, and 0 otherwise. A release that fails probation and
rolls back therefore reports 0 until the next release commits. Each manager
reports `ts_orch_release_channel_seq`, the newest seq its region accepted from a
verified channel document; an unsigned or replayed document leaves it unchanged.
`ReleaseStuck` (critical, normal alert mail route) fires when a region's highest
`channel_seq` stays above its lowest `installed_seq` for 30 minutes.

### Runbook: ReleaseStuck

1. `ts-orch observe` or the host's `nats/pull-rollout.json` shows the region's
   phase and reason. A refused release names the reason (bad signature, digest,
   replayed seq); a rolled-back release names the host and its probation error;
   `waiting` names the host that does not answer or is unhealthy.
2. A replayed or tampered channel (refused, reason names the seq or the
   attestation) needs the publishing run checked and a new green main run; never
   edit `stable` by hand.
3. A rolled-back release stays bad for the region; the next green main release
   moves the channel past it.
4. A host whose `installed_seq` stays at 0 runs a build from before the channel
   (push this build to it once), rolled back the channel's release in probation
   (step 3) or is still in probation.
5. Every release refused with `channel seq N (...) is not newer than the
   region's seq M` while N is small means `GITHUB_RUN_NUMBER` restarted: GitHub
   restarts it when `ci.yml` is deleted and recreated. Recover in one PR: change
   the `release channel prepare` step's seq argument in `ci.yml` to
   `$(( GITHUB_RUN_NUMBER + M ))`, where M is the highest
   `ts_orch_release_channel_seq` of any region. The next main run then publishes
   above every region's and host's seq; no production state is edited.

## Independent recovery

The node's updater retains its own executable as
`/usr/local/bin/terrascale-orchestrator.recovery` before staging a replacement.
It writes and verifies the recovery service and timer under their actual unit
names in the writable binary directory, then asks the service manager to link
and enable them. The agent unit stays unchanged. The manager performs the
linking, so installation works with `ProtectSystem=full` without a privileged
transient unit or a writable system unit directory in the agent sandbox.

The boot-enabled timer starts checking after 15 seconds and checks every minute.
It runs the retained updater independently of the candidate executable and its
service sandbox. A candidate can pass preflight and then fail before `Probe`;
that failure never advances the startup counter or starts its in-process timer.
The independent timer closes that gap. Recovery is installed by this updater
before the replacements it accepts; an older installing updater cannot provide
this protection for its first upgrade to this version.

Every release swaps the systemd unit together with the binary: the
candidate's preflight records its unit by digest, and the unit's pairing
step installs the recorded unit of whichever binary is about to start, so a
recovery or probation rollback to `.prev` also restores that binary's unit.
If the step cannot install the candidate's unit, the candidate exits before
`Probe` and the recovery timer restores `.prev` after about 12 minutes.
See [node.md](node.md#the-unit-follows-the-binary).

Each new trial stores a recovery window through its `installed` and
`recover_after` fields before the binary rename. The window includes the
loaded stop timeout, restart delay, the greater of the loaded start timeout and
the ten-minute planning window, two minutes of probation, and 30 seconds of
margin. The shipped bounds give 931 seconds. Trials without `recover_after`
receive 20 minutes.

Recovery measures this window from the candidate unit's first execution in the
current boot, using `ExecMainStartTimestampMonotonic` and `CLOCK_MONOTONIC`.
It persists that start, boot identity, release identity and window in
`nats/release-runtime` so repeated crashes do not reset the window. A new boot
gives the candidate a full window; time powered off and wall-clock corrections
do not consume it. The trial also stores, as `installed_by`, the
`ts-orch.service` invocation the install superseded. While the unit still
reports that invocation (the installer has exited and systemd has not started
the candidate yet, the `auto-restart` gap), the main start time belongs to the
installer, so the tick records nothing and leaves the candidate in place. The
recovery executable is the installing updater's copy, so this holds from the
first install an updater with `installed_by` makes. Idle ticks read the trial records first and never open the
agent binary when neither a trial nor a recovery intent exists.

After the window, recovery records a durable `nats/release-recovery` intent.
Before stopping the candidate, it settles committed staging and verifies that
the previous binary matches the trial. Missing or mismatched backups retain
the trial and intent, save a rollback failure and fail the recovery job while
the agent keeps serving. Staging errors also leave the serving agent running.
A later repair release remains installable.

Recovery re-reads identity and records after stopping, preserving a concurrent
confirmation or replacement. Every return after an attempted stop clears the
failed-start state and starts the service again, including rollback failures.
Rollback uses the existing identity check, rollback record, rename and directory
sync. Recovery removes its intent only after a successful restart. Interrupted
recovery resumes even if the rename already consumed `.prev`. An unconfirmed
updater preserves an existing recovery executable when accepting a repair;
when none exists, it installs the executable and unit pair with that repair.

`StartLimitIntervalSec=0` remains intentional: starts reaching `Probe` use the
durable startup counter, while the independent deadline bounds failures that
cannot reach it. A systemd rate limit could otherwise prevent the rollback
startup. Binary releases do not deliver or replace `ts-orch.service`; the
previous unit-swapping release architecture is not part of this updater.

## Updater records

An installed candidate is on probation until it serves. These files live in
`<state>/nats`, which `ts-orch node` and `ts-orch release recover` create
(mode 0700) before they read any record when it is missing; the previous binary sits beside the executable.

| File | Contents | Absent | Damaged |
| --- | --- | --- | --- |
| `<binary>.prev` | Hard link to the binary that was installed before the candidate. | No rollback target: a rollback that needs it leaves the candidate unconfirmed. | Not the build named in the trial: never restored; the candidate stays unconfirmed. |
| `nats/release-trial` | JSON object: `sha`, `run_id`, `installed`, `starts`; this release adds `sha256`, `previous` (revision and digest of `.prev`) and `failure`. | No probation, unless a rollback record names the running binary (see Probation). | The agent keeps serving, reports `unconfirmed` and never rewrites the file. It stays in place through a replacement that fails before its binary rename; after the rename the replacement hard-links it to the first free name of `release-trial.damaged`, `release-trial.damaged.1`, ... and then moves its own trial over it, so the trial is never absent and no archive is overwritten. |
| `nats/release-runtime` | Candidate identity, run, boot identity, monotonic first execution and recovery window. | Initialized from the unit when a trial exists and its candidate has started. | Recovery reports an error while the agent keeps serving. A different boot or release establishes a new runtime. |
| `nats/release-trial.staged` | A replacement's trial, same format, written before its binary rename. | Nothing staged. | Left as it is and ignored. |
| `<binary>.prev.staged` | Hard link to the binary that is installed while a replacement is staged; becomes `.prev` after the replacement's binary rename. | Nothing staged. | Not applicable (any file is only renamed or removed). |
| `nats/release-run-id` | Decimal run id of the newest staged release. | Any run is accepted. | Every different release is refused as `run_fence_damaged`, the refusal is saved in `release-attempt.json`, and the file is left as it is. To repair it, write the highest release run id ever installed on this host (the `run_id` of `release-trial` or `release-rolled-back` when either is present, otherwise the newest release run) as a decimal with no other text. |
| `nats/release-rolled-back` | JSON object: `sha`, `run_id`, `reason`; this release adds `sha256`. | No rejected run. | Logged; no rejected run is known. |
| `nats/release-attempt.json` | Last refusal of this host, with the identity of the binary installed at the time. | Nothing to report. | Nothing to report. |

"Damaged" means present but unreadable, not in the expected format (a JSON
object, or a decimal for the run fence), or without a release name (`sha` and
`run_id`) where one is required. Absent and
damaged are never treated alike.

### Transition from the previous updater

The updater that runs on hosts before this release writes the object trial with
`sha`, `run_id`, `installed` and `starts`, links the previous executable at
`<binary>.prev`, writes the decimal run fence after the swap and removes the
rollback record. It does not know the two staged files and never reads them. This release reads exactly those files: a trial without
`sha256` or `previous` names the candidate by revision, its `starts` counter
continues, and rollback restores `<binary>.prev` as the previous updater would.
The previous updater's fence refuses older runs here too.

This release writes the same formats. The fields it adds are ignored by the
previous updater, so a host rolled back to it reads the fence and the rollback
record it understands: it refuses the rejected run and every older run and
never reinstalls the rejected candidate. The previous updater names a trial by
revision only. This release never puts a trial in `release-trial` for a binary
that is not installed: a replacement's trial is staged under its own name and
moved into place only after the binary rename and its directory sync, and a
start that finds a trial naming another build of its own commit removes it once
the binary directory is synced, so the previous updater never counts starts on
a trial for another build of its own commit. A
later release may change the written format once every host runs a build that
reads it.

### Install and commit point

| Step | Failure before the binary rename | After the binary rename |
| --- | --- | --- |
| Download, digest verification, candidate preflight, candidate identity check | Refuse; nothing staged. | Not reached. |
| Write the staged trial `release-trial.staged`, then the run fence (each through a temporary file, file sync, rename and directory sync); link the installed binary at `<binary>.prev.staged` and sync its directory | Refuse and remove only the two staged files: the installed binary's trial, `.prev` and rollback record are byte for byte as before. The fence only rises, so the same run may retry. A crash here leaves the staged files; the next start removes them because the staged trial names a binary that is not installed. | Already complete. |
| Rename the candidate over the executable | Refuse. | **Commit point: the answer is `installed`.** |
| Sync the binary directory, then move into place: rename `<binary>.prev.staged` to `.prev` and sync the binary directory; archive a damaged trial; remove the rollback record; rename `release-trial.staged` to `release-trial` and sync the state directory | Not reached. | Each is best effort with a WARN; none changes the installed answer. The first failure stops the sequence and leaves the rest staged. |
| Collect worker replies; deliver and flush the reply; request restart | Not reached. | Best effort with a WARN. |

The staged trial names the candidate by revision, digest and run. At every
start, before reading `release-trial`, the agent looks at the staged trial. If
it names the installed binary, the start finishes the sequence in the order
above, each step a no-op when already done; if it names another binary, the
start syncs the binary directory and removes it with `<binary>.prev.staged`.

| Crash after | Binary that starts | What it finds |
| --- | --- | --- |
| Staged trial, fence or staged previous copy written | The installed binary | Its own trial, `.prev` and record unchanged; removes the staged files and continues its own probation. |
| Binary rename, before its directory sync completes | The candidate, or the installed binary if the rename was lost | The candidate finishes the move and starts on its staged trial; the installed binary is the row above. |
| Binary directory sync, `.prev` rename, record removal | The candidate | Finishes the move, then starts on probation with its trial and the replaced binary at `.prev`. |
| Trial rename or the final state directory sync | The candidate | Its own trial in place; normal probation. |

A build that does not know the staged names (the previous updater) started on
a crashed host after the binary rename and before the trial rename finds the
replaced binary's trial, removes it as not its own and serves without
probation. A watchdog armed when the
installed reply has been sent ends the old process 45 seconds later if its
ordinary shutdown (up to 30 seconds, closing edge connections in order) is
stuck; it takes no lock. With the service manager's 1-second restart and the
two-minute probation of the next start, the candidate serves or is rolled back
at most 166 seconds after the reply. The pull leader checks the actual running
revision, digest and health after restart. A second restart request while one is queued is
coalesced.

Staging and the rename hold the same lock as probation confirmation and the
probation deadline. A request is `current` only when the installed binary has
the release's revision and digest; another build of the same commit is
installed like any other release.

### Probation

Startup calls `Probe` before anything that can crash and later `NewHandler`;
both share one result per state directory and process. The release listener is
subscribed before startup calls `Served` once the agent is ready, so a release
can arrive and stage its trial before this start is confirmed. The running binary's identity (revision and SHA-256 of
one open file) is read once at start; the installed path is hashed again only
when its size, modification time or inode changes. An in-place rewrite that
keeps size, modification time and inode is not detected; the updater itself
only ever renames files into place. A trial naming another binary is ignored. At
start it is removed when it names another build of the running binary's commit,
or when a rollback record names it (the rollback finished); in both cases the
binary directory is synced first and the trial is kept if the sync fails.

Each start of the candidate before serving reads `starts` once, adds one and
writes the result once before continuing; the start rolls back when the value
it read plus one exceeds two, so the third start rolls back. Whatever that
write does (succeeds, fails before its rename, or renames without a durable
directory sync), the file afterwards holds the value read or that value plus
one, so one start consumes at most one allowance and a start whose write
failed consumes none. A failed write is logged and changes nothing else. Within
one process, a candidate that does not serve within two minutes of its start
rolls back; no stored wall-clock time is compared with the current time, so a
clock step neither shortens nor extends probation. On a host whose state
directory cannot be written, nothing rolls a candidate back: rollback needs a
writable rollback record. A candidate that runs but does not serve within two
minutes then keeps running and reports `unconfirmed`; one that crashes is
started again by the service manager every second without limit; and the
rollout reports that host as not serving or unconfirmed until its disk works.

Rollback checks that `.prev` is the build recorded in the trial (when the trial
records one), writes the rollback record, renames `.prev` over the candidate,
syncs the directory and exits so the service manager starts the restored
binary. The trial is removed only after that directory sync succeeds. A start
that finds a rollback record naming its own trial, or a rollback record naming
the running binary when no trial is left (the rename was lost but the trial's
removal persisted), completes that rollback. If `.prev` is missing, of another build or cannot be renamed, the
candidate keeps serving, the trial keeps the failure, no rollback record is
left, and the agent reports `unconfirmed` in version and health replies.

A binary that reached `Served` is confirmed: `Served` holds the installation
lock, reads the trial again and removes it, syncing its directory, whenever it
still names the running binary (revision, digest and run), whatever this
start's counter write did; a trial a replacement put in place meanwhile is left
untouched. The release is reported confirmed only after the removal is
durable. If the removal fails, version and health replies report
`unconfirmed`; when the trial is still on disk at the next start, that start
counts against it like any other start, so a served candidate whose trial
cannot be removed can still be rolled back on the start that exceeds two.

The probation deadline, a rollback and confirmation act only while the trial
on disk names this process's binary: each re-reads it under the installation
lock (a rollback finishing a recorded rollback with no trial left requires that
no trial has appeared). When a replacement has been committed meanwhile, the
deadline does nothing and the old process exits when its restart is
requested. An unconfirmed host is not a rollout barrier: rollout preflight
admits it when its health is otherwise `ok`, the region's result line carries
the reason in `unconfirmed`, and a replacement release installs over it. A
release that becomes unconfirmed during its own rollout fails that rollout.

### Alert delivery preparation

This updater release also introduces `ts-orch alert-delivery prepare`.
Run as root, it reads exactly the three approved alert references using the
host identity and writes `/run/ts-alert-delivery/{cloudflare_account_id_file,
cloudflare_email_token_file,ts_alerts_ntfy_topic_file}`. The directory must
be root-owned mode 0750 on tmpfs with swap disabled; the directory and files
use the `ts-alerts` group, and files are root-owned mode 0640. Unreadable
secrets fail preparation visibly without printing values. This release keeps
the relay's existing Vault reads. Once this updater is on a host, a relay unit
with the privileged preparation command can safely be installed and restarted:
preparation works and the unchanged relay ignores the files.

### Journey

The `updater-preflight` lane builds the previous updater from a pinned commit
and has it install this build, then checks probation, the fence and a rollback
to the previous updater's exact bytes, and that the previous updater refuses the
rejected run and older runs afterwards. It kills the install before and after
each staging step, the binary rename and its directory sync, each step that
moves the staged files into place (with the replaced binary itself on probation
and with a damaged trial), the rollback record, the rollback rename and the
confirmation, and fails each staging syscall, also while the replaced binary is
on probation; after every case it starts the binary on disk through `Probe`,
`NewHandler` and `Served` and asserts the state it reaches before retrying. It
also covers damaged trials and fences, refusals, worker silence, a broken first
host with a refusing worker, a replacement reaching an unconfirmed host, an
failed or unsynced start count on the first and the last allowed start, a
probation deadline that fires while a replacement holds the installation lock,
a busy candidate at exec, an unfinished rollback, a rollback whose directory
sync fails, a stale rollback record, private pull installation, two builds of one commit,
a pre-digest host, a slow shutdown with duplicate restart requests, a shutdown
stuck until the watchdog, and the previous updater installing this build again
after a rollback to it.
These lanes run outside the agent's unit sandbox; the first real rollout
confirms execution under that unit.

Once hosts run this updater, candidates older than the change introducing
`release preflight` cannot be released through this pipeline. Releases move
forward. Automatic probation rollback renames `.prev` directly, without
executing this hook.

## Upgrade gate

A release is published only if production's own updater can install it. Two
release-blocking lanes in the `e2e-m1` matrix prove this on every pull request
that changes runtime inputs and run again on main. Publication can reuse
the merged PR's successful gate only after proving identical trees; otherwise
these main lanes must finish before `deploy/release-publish`:

| Lane | Installed release | Release it must install |
| --- | --- | --- |
| `upgrade-previous` | N-1: the release the `upgrade-gate/previous` pin names, downloaded from GitHub and checked against its listed digest | N: this build |
| `upgrade-next` | N: this build | N+1: this build with its embedded `vcs.revision` replaced by a derived commit that descends from N, published one run later |

Each lane boots real `ts-orch node` processes in Oracle mode (the `oraclehost`
harness from the `oracle-regions` lane: IMDS, instance-principal federation,
Vault and the production unit): the gru, sjc and fra founders, whose mesh forms
the JetStream metadata group the pull updater stores its rollout in, and a
worker in sjc. sjc is first in the rollout order, so its manager and worker are
the hosts that must take the release. Like production regions, the fleet serves services
before the release appears: the lane applies `terrabase` and `e2e-whoami`
through the mesh, because a release older than the native regional mesh name
reports its edge unready without a route, and the updater rolls only while
every other host of the region is healthy. The lane hosts start fresh, without the old release
listener's `<state>/nats`: since C47 the updater creates its release state
directory itself, and the pin names a release that contains that fix. Once
both serve the installed release, the lane publishes the candidate. The
installed binary's own pull updater then has to do the rest, unchanged:

- find the candidate in GitHub's release list on its next five-minute poll;
- check the lineage against GitHub's comparison, N-1...N in `upgrade-previous` and N...N+1 in `upgrade-next`;
- verify the provenance bundle;
- roll the release out one host at a time over NATS, with the candidate
  preflight, staging, the binary rename and the restart;
- confirm it through probation.

The lane passes when both hosts serve the candidate's revision and digest, no
trial, staged trial or rollback record remains, and each host keeps the
replaced release at `terrascale-orchestrator.prev`. It fails when any of those
steps refuses or times out. That blocks publication when main's lane gate
is required; after an early publication it fails main and triggers its revert.

The GitHub the hosts reach is a stand-in, and its bodies are GitHub's own:

- the release list is `GET /releases?per_page=30` as GitHub answered it when
  the lane started, with the candidate added in the shape of a real release;
- the comparison pages are GitHub's real
  `compare/<N-1>...<N>?per_page=1&page=<n>` answers, at their real size.

A release list or comparison that outgrows what the installed updater reads
therefore fails the gate, as it would in production. On a pull request the
comparison is the one between the pin and the pull request's merge commit (the
commit the release will be), answered for the head commit the candidate was
built from. `upgrade-next` serves that same recorded comparison for N...N+1,
with the pin's commit rewritten to N and the last commit to N+1, so N's own
lineage check reads a body of real size and shape.

Recorded releases with a run ID at or above the candidate's (published by main
while the lane runs) are left out of the list, so the newest release is always
the candidate. When GitHub does not compare the pin as an ancestor of the
commit being released, the lane fails before any host starts and says to rebase
onto main.

The stand-in answers with an empty release list until the candidate is
published, so the first poll finds nothing rather than refusing a real release
whose bundle the lane cannot serve.

What the gate does not prove:

- **Production's provenance identity.** Every Sigstore trust root embedded in
  both binaries is replaced, byte for byte at the same length, by the lane's
  stand-in authority. This is the only way a published binary can accept a
  build that GitHub has not attested. The verifier code is unchanged; the
  identity it requires (`ci.yml` on `refs/heads/main`, push, run and commit) is
  signed by the stand-in.
- **The systemd recovery timer and unit pairing.** The harness answers the
  release path's `systemctl` and `systemd-analyze verify` requests for the
  recovery units and `ts-orch.service` in place of systemd. The `node-upgrade`
  and `recovery` lanes cover those under real systemd.

The gate follows the release path of whatever binary is installed. If the
release channel changes, for example to an OCI registry, the stand-in must
serve that channel too. Until it does, the gate fails, and that failure is
correct.

### Bumping the pinned N-1

`upgrade-gate/previous` is an annotated tag on the release's commit. Its
message is the release tag, for example
`ci-b60ccc99171132995225f7b8bcf5350176782e58-run-44061090529`. Each successful
`deploy/release-publish` moves it to the release it just published, unless the
pin already names a later run, so the next run proves that release can install
its successor. The pin moves on publication, not on installation: nothing in CI
notices when production stays behind it, because the lane never reads
production.

When production runs something else, for example when it is stuck on an older
release, point the pin at the release production reports, so the
gate proves the upgrade production actually faces:

```sh
release=ci-<sha>-run-<run id>
sha=${release#ci-}; sha=${sha%-run-*}
object=$(gh api repos/TerraScale/ts-orchestrator/git/tags -f tag=upgrade-gate/previous \
  -f message="$release" -f object="$sha" -f type=commit --jq .sha)
gh api --method PATCH repos/TerraScale/ts-orchestrator/git/refs/tags/upgrade-gate/previous \
  -f sha="$object" -F force=true
```

The release must be published, that is, it must carry
`provenance.sigstore.json`. The next `deploy/release-publish` moves the pin
forward again.

## Automatic reruns of release-blocking lanes

A failed `e2e-m1` lane gets exactly one automatic rerun in the same workflow
run, so one flaky attempt cannot hold main red and releases back for hours:

1. The lane's step runs with `continue-on-error`. When it fails or exceeds its
   timeout, the job:
   - writes a warning annotation;
   - adds a job summary line;
   - uploads the lane's matrix entry as `e2e-rerun-<attempt>-<lane>`.
2. `e2e-rerun-plan` takes, for each lane, the attempt of its latest job (so a
   partial `gh run rerun --failed`, such as the infrastructure rerun of
   `revert-red-main`, keeps first-attempt failures from earlier attempts),
   collects the entries of those attempts and records them in its job summary
   and in the artifact `e2e-reruns-<attempt>` (90 days: run, attempt, commit,
   event and lanes).
3. `e2e-m1 / <lane> (rerun)` runs each of those lanes once more, from the same
   agent build. Its job summary says either "passed its automatic rerun" (a
   recorded flake) or "failed its first attempt and its one automatic rerun".
   The second case stays red and names the lane.
4. `e2e-m1`, and through it `all-green` and publication's selected lane gate, passes
   only if every lane passed its first attempt or its rerun.

Only the `e2e-m1` matrix lanes are covered. `e2e-certificates` (one 30-minute
job) and the `caller-key` shards also block the selected lane gate, but they
run only when their own inputs change and were not the lanes that held main
red; covering them needs the same plan and rerun pair for each, a follow-up.

Because the rerun happens inside the run, the shared `revert-red-main` workflow
only sees a failed run after the second failure. A lane is never retried inside
its own script. A lane that is rerun often is a flaky test to fix: the
`e2e-reruns-*` artifacts list every rerun.

## Service credential releases

For existing hosts, use this order. At any failed check, stop before the next
step and repair that check; do not continue on the strength of an earlier
successful attempt. The previous checked step is the safe resting state.
If metadata rules are not active yet, do not install or enable them until step 7:
an old relay behind those restrictions cannot deliver alerts.

If metadata rules are already active, preserve the existing alert-relay exception
through step 6, including across restarts and reboots; step 7 removes that exception
only after those checks pass, and a failed check restores the prior exception
rather than removing the existing protections.


"Registered" means present in the region's node inventory. The revision gate
checks every host row in every region, fails on an unreachable region, inventory
error, empty inventory, missing reply or refusal, and prints each failing host.
A machine that never registered, or was removed from that inventory, is not
visible to this gate. Use the exact published 40-character revisions as
`A_REVISION` and `B_REVISION`; the gate is read-only and does not change release
push behavior. Step 1 uses the staged B binary because A does not yet have
this command; it reads A's existing mesh without installing B.

On a host that already has metadata protections, persist the relay exception in
a metadata-unit drop-in before advancing. These commands run as root and derive
the relay's service user; the post-start command inserts one IPv4 accept rule
after the unit has reloaded the persistent rules:

```sh
relay_user=$(systemctl show ts-alert-delivery.service --property=User --value)
relay_uid=$(id -u "$relay_user")
test "$relay_uid" -ne 0
metadata_unit=terrascale-ts-auth-metadata.service
dropin=/etc/systemd/system/$metadata_unit.d/relay.conf
install -d -m 0755 "/etc/systemd/system/$metadata_unit.d"
printf '[Service]\nExecStartPost=/usr/sbin/nft insert rule inet terrascale_metadata output ip daddr 169.254.169.254 meta skuid %s accept\n' "$relay_uid" > "$dropin"
chmod 0644 "$dropin"
systemctl daemon-reload
systemctl enable "$metadata_unit"
systemctl restart "$metadata_unit"
nft -n list chain inet terrascale_metadata output | grep "ip daddr 169.254.169.254 meta skuid $relay_uid accept"
sudo -u "$relay_user" curl --fail --max-time 5 -H 'Authorization: Bearer Oracle' -o /dev/null http://169.254.169.254/opc/v2/instance/
if sudo -u nobody curl --fail --max-time 5 -H 'Authorization: Bearer Oracle' -o /dev/null http://169.254.169.254/opc/v2/instance/; then
 exit 1
fi
```

The enabled unit and its drop-in restore the exception after every restart and
reboot. Repeat the rule and user-access checks after a restart and after a reboot.
Preserve existing persistent rules and their local additions through step 6.
The installer recognizes existing state from the installed binary, state
directory or existing rules (including symlinks); it creates rules only when
all are absent. An existing host without rules remains unrestricted until the
checked step-7 transition.

At step 7, after the step-6 checks, save the active rules and this drop-in before
replacing the rules and removing the exception:

```sh
transition_dir=$(mktemp -d /root/metadata-transition.XXXXXX)
rules=/etc/terrascale-orchestrator/ts-auth-metadata.nft
cp "$rules" "$transition_dir/rules.nft"
cp "$dropin" "$transition_dir/relay.conf"
ts-orch ts-auth metadata-rules > "$transition_dir/next.nft"
rm "$dropin"
install -m 0644 "$transition_dir/next.nft" "$rules"
systemctl daemon-reload
systemctl restart "$metadata_unit"
```

Review local additions before this deliberate replacement. Recheck root/agent
metadata access, blocked task access over IPv4 and IPv6, and real relay delivery.
If a check fails, restore that host's saved rules and drop-in, keeping the
previous protections and relay access across subsequent restarts and reboots:

```sh
install -m 0644 "$transition_dir/rules.nft" "$rules"
install -m 0644 "$transition_dir/relay.conf" "$dropin"
systemctl daemon-reload
systemctl restart "$metadata_unit"
```

Repeat the rule, relay-user and other-user checks above and restore delivery
before continuing. For a host without prior rules, step 7 installs the generated
rules and unit for the first time; undo only that new installation if its checks
fail.

1. Release A, the updater-preflight release, alone. Run the staged B binary
   on a host with mesh access for the read-only gate:
   `sudo /path/to/candidate-B status revision "$A_REVISION"` exits zero. Check regional health
   with `ts-orch status` as well. Stopping here is safe: the relay retains
   its existing metadata access, still reads Vault, and A supplies preparation.
2. Grant reconciliation narrows the earlier broad policy; it is not only
   additive. Before running B's `ts-orch region add`, preserve the earlier
   broad grants in the separate active policy `ts-orch-hosts-vault-transition`
   in the same compartment. The reconciler reads it and refuses to narrow
   unless it contains every current managed-policy statement. It uses the
   managed policy's ETag for the update; it never changes the retained policy.
   Read or update failures preserve the earlier effective grants. Removing
   existing host compartments from the dynamic group is refused as well. Run `ts-orch region add` for each affected region
   to add the exact grants. Gate: run the candidate B binary as host root on
   every affected host: `sudo /path/to/candidate-B release preflight secrets`.
   This runs the same regional secret reads as B's full release preflight,
   using that host's instance identity, including approved shared references
   and the relay's three references where required by the host's region.
   It writes no secret files, prints no values, and exits non-zero naming a
   reference that cannot be read. It leaves the later installed-unit check
   for step 3 and full activation preflight. Only after this gate passes on
   every host remove the retained broad policy; a failed gate leaves the
   broad policy in place. Stopping here is safe: the running binary and relay
   are unchanged and their required reads have passed.
3. On the host running the relay, install B's
   `deploy/observability/production/ts-alert-delivery.service` and run
   `systemctl daemon-reload`. Gate:
   `systemctl show ts-alert-delivery.service --property=ExecStartPreEx --value`
   shows `/usr/local/bin/ts-orch alert-delivery prepare` with
   `flags=privileged`, corresponding to
   `ExecStartPre=+/usr/local/bin/ts-orch alert-delivery prepare`.
   This unit can be installed any time after step 1 because A already provides
   its preparation command. Stopping here is safe: the running relay is
   unchanged and the command exists for its next restart.
4. Restart the relay once. Gate: the service remains active and a real test
   delivery arrives (use `ts-orch alert-delivery subscribe` in an interactive
   terminal and confirm receipt). Preparation now writes the protected files,
   while A's relay ignores them and still reads Vault. Stopping here is safe:
   delivery and preparation work, and the relay retains metadata access
   through the preserved exception if metadata rules are already active.
5. Release B through the normal release path. Gate:
   `ts-orch status revision "$B_REVISION"` exits zero. Stopping here after
   the check is safe: the running relay continues delivering, its new binary
   and privileged preparation unit are installed, and the prior metadata
   boundary and relay exception remain in place. A refused or partial attempt
   is not a completed step; preserve that boundary and repair before retrying.
6. Restart the relay. Gate:
   `stat -c '%U:%G %a %n' /run/ts-alert-delivery /run/ts-alert-delivery/*`
   shows directory `root:ts-alerts 750` and three files `root:ts-alerts 640`
   (never print contents), `curl --fail http://127.0.0.1:9094/healthz` returns
   200, and a real test delivery arrives. Stopping here is safe: B's relay now
   reads only the validated files and its delivery works without metadata.
7. Only after those checks pass, install or enable metadata rules where they
   are absent, or remove the preserved alert-relay exception where rules are
   already active, one host at a time. After each host, gate the next on tasks
   being unable to reach metadata over IPv4 and IPv6, root and the agent still
   reaching it, and alert delivery succeeding again. Stopping after each
   checked host is safe because B's relay uses files. On a failed check, stop
   and restore the prior alert-relay exception if rules were already active,
   retaining the existing protections. For newly installed rules, undo only
   that host's new rule change. Verify the step-6 state and repair before
   continuing.

Every successfully checked step is a safe resting state. A failed relay restart
in steps 4 or 6 is not safe until delivery is restored. Preserve existing metadata
protections and the relay exception, or keep metadata unrestricted if rules are
not yet active; repair preparation or file validation, restart and recheck delivery.
A failed step-7 host must return to the verified step-6 state as described above.

Before switching the host binary, the private pull installer and the M1 installer
execute the candidate's `release preflight`. It checks the installed relay
unit's effective preparation command where the relay is installed. On OCI hosts
it reads every secret referenced by the candidate's regional service manifests
with that host's own instance identity. Failed secret reads retry after 250 ms
within one shared 60-second budget, inside the updater's 70-second outer bound.
Missing grants, unavailable secrets or a missing privileged preparation command
refuse that host's release before activation. The host retains its binary, unit
and running process; the staged candidate is removed. Release output and
`ts-orch status` name the candidate, release attempt and refusal reason without
secret values. A later attempt replaces the refusal record; a successful attempt
clears it. Hosts without an OCI platform identity have no regional Vault grants
to check. Status inventory remains diagnostic; the operator must apply the per-host revision gate above before advancing.

## GitHub producer verification

The GitHub verification workflow checks out the event's exact Git revision and
requires a clean tree. Its producing job audits the package graphs and builds
and checks both static release binaries (`make release-check`). Pull requests
run `make lint` (formatting, templ output, `go vet`, shellcheck and policy
checks) and the node E2E (job `e2e-m1`), which every main push runs
again before `release-push`. The workflow installs the Go version in the `go`
line of `go.mod` with `actions/setup-go`, and `.mise.toml` pins the same version
for local development; `make lint` fails when `go.mod`, `.mise.toml` and
`DefaultGoVersion` in `internal/release/receipt.go` disagree. Run
`bash scripts/ci/audit-dependencies.sh source` with that Go to scan the package
and test graphs of the root module and the three `third_party` replacements,
and `bash scripts/ci/audit-dependencies.sh release` after `make release-check`
to scan both release binaries; `lint` runs both on every pull request,
`Lint cache` on every main push, and the producing job runs them on main before
it publishes. No advisory is ignored.
The `go` lines of `third_party/*/go.mod` are minimums for the vendored modules,
so an upward compiler move leaves them unchanged.

Release admission requires the exact successful run and one uniquely named
producing job from its qualification manifest. Independent workflow checks,
including the configuration policy check, may run alongside it. Admission reads
that producing job's logs by job ID and requires its exact retained-manifest
digest marker; another job's success or log cannot qualify the release.

The same job then cross-compiles one static executable for Linux amd64 and one
for Linux arm64 with cgo disabled. It checks the ELF machine type, absence of a
dynamic interpreter and linked libraries, the embedded Git revision, and
SHA-256 digests. It prints a `SHA256SUMS` receipt in the job log.
After those checks, the job retains both exact binaries with a qualification
manifest that records the source revision and tree, Go version, module-file
digests, successful workflow/job run identity, and each artifact's size and
SHA-256.
