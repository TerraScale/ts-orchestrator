# Regional rollout bake

Install the orchestrator release in every target region before rolling a service.
Older orchestrators advertise readiness without evaluating a bake.

Every mesh service rollout observes a fixed thirty-second bake after exact task
readiness, sampling every two seconds. Each sample may take up to five seconds
(an HTTPS readiness probe plus control reads), independent of the interval. Dependency probes may recover for up to
thirty seconds from the first failed observation, including when another
service rolls during this bake. Every such failed sample resets the healthy
clock: recovery must be followed by a full thirty-second
healthy bake before another region can advance. A continuous dependency failure
at thirty seconds holds the generation. A flapping dependency may keep the bake
waiting for its healthy window for up to two more minutes (150 seconds in all).
A bake that fails only on dependency recovery is reported `excused`
(`dependencyOnly` in its verdict). It holds later regions of that service, just as a candidate failure does; other services keep their own gates. Candidate, catalog-anchor,
writer-wait and log-coverage failures always hold immediately, including during
dependency recovery.

Samples verify the same running tasks
and their readiness, global ts-auth readiness, and dashboard readiness including
its auth and TerraBase dependencies. This respects gru-only auth placement.
TerraBase also checks newly appended task stdout/stderr for catalog-anchor
failures and slow writer waits (the engine logs waits of at least five seconds).
Missing or rotated log coverage holds the bake. Raw log contents, environments,
credentials and readiness response bodies never enter bake evidence.

Each region retains `mesh/bake-<service>-<generation>.json` under its state
directory: image digest, actual tasks and revision, elapsed readiness timings,
bake start/end, healthy-window start, sample count, checks and failure reason.
Tolerated dependency failures retain their count and last checks in
`recoverySamples` and `recoveryChecks`, even when the bake eventually passes.
The release response
includes these fields; the CLI prints bake timing, and the journal records
`regional rollout bake verdict`. The JSON file is the retained evidence.

App CI releases receive acceptance promptly and poll the authenticated operation
until its terminal verdict. The client refreshes its short-lived credential and
reconnects after connection loss; polls retain the same signed rollout and bake
generation. Acceptance alone never makes CI pass. A completed rollback remains
failed across handler restart. A higher signed `run_attempt` of the same run
retries the run with its rebuilt digest, also while the earlier attempt serves
or bakes (builds are not reproducible). Older runs and attempts cannot replace newer state.
The CLI exits successfully for an older signed run refused at admission or a
release whose failed regions were all superseded during bake or waiting behind
such a region. The newer release retains its own verdict. Unfinished bakes print
`bake unfinished` instead of a duration.

The regional observation budget is readiness + 30 seconds + the 150-second
maximum bake. Three 180-second readiness budgets plus one parallel rollback
fit within the 25-minute handler deadline. An app with the default 60-second
readiness needs at most 12 minutes in three regions. A healthy
region with a 10-second startup and short pull now finishes in under 60 seconds;
dependency recovery and readiness failures may take longer.

An unfinished, failed or dependency-only bake cannot admit another region for
that service. A missing earlier region also holds advancement. A completed bake
admits the next region only while the candidate still serves its desired
replicas and readiness endpoint. Reconciliation probes services concurrently,
with a 300 ms deadline per service and a two-second refresh interval. Mesh state
replies read the cached results and their observation timestamps without network
calls. A result older than five seconds fails closed: this allows two missed
refreshes without retaining a healthy result through a longer outage. The turn
rule also rejects expired observations when it consumes the reply.

An orchestrator restart during an unfinished bake restarts its full window only
if no regression was observed. Each failed observation is persisted immediately,
before a terminal verdict, so an interrupted bake that saw a candidate or
dependency regression stays held across restart. Dependency recovery may still
complete a healthy window in the running process. A completed failed or excused
bake stays terminal. Evidence-write failures retry persistence without
reevaluating the candidate.

Fix forward by publishing a corrected image through the existing authorized
release path. After repairing a dependency, dispatching the same image again
creates a fresh generation and evaluates a new bake. Unsigned operator canary
holds remain until service resume; resume still evaluates the bake. Signed
releases use the same per-service turn and serving gates without stamping a
manual hold. The first region follows the stored order when the service declares
regions, including TerraBase; otherwise the founded-region order applies. Signed
releases restore the embedded all-region placement only for services whose
embedded declaration targets every region and which had no operator hold.
A signed release clears an inherited operator hold while retaining its placement.
No region name is fixed in the gate.
Each subsequent region requires the same evidence from every earlier region.
Later regions retain their serving tasks during a failure. TerraBase updates
pause on failure, and neither mesh apply nor signed release automatically restores
an older storage binary. Signed release, runtime identity and peer admission
checks still apply.

## When a rollout stays held

Fix a first region that is not serving; later regions then advance by themselves
when its successful bake and fresh serving result are available. Clear a failed
or excused first bake by dispatching the release again with the same digest; this
creates a new generation. There is no skip. Service resume clears an operator
canary hold and does not replace the signed release dispatch path.

The retired operator terrabase update placement path is outside the active
SwarmKit mesh deployment path; this gate is implemented in the latter.

After a TerraBase release completes, its CI client names the service in its release
health request. Every release health request checks mesh health, SwarmKit node
readiness and readable services. A named request also checks that service's
replicas and readiness endpoint; an unrelated replica shortage does not block it.
An unnamed orchestrator-binary request keeps the host checks and ignores the
replica-shortage clause. Deployment lag excludes TerraBase until the monitor reads
the manual release-only job; a skipped release step in its normal main job is
an expected wait for manual dispatch.
