# Regional rollout bake

Install the orchestrator release in every target region before rolling a service.
Older orchestrators advertise readiness without evaluating a bake.

Every mesh service rollout observes a fixed thirty-second bake after exact task
readiness, sampling every two seconds. Dependency probes may recover for up to
thirty seconds from the first failed observation, including when another
service rolls during this bake. Every such failed sample resets the healthy
clock: recovery must be followed by a full thirty-second
healthy bake before another region can advance. A continuous dependency failure
at thirty seconds holds the generation. Repeated interruptions cannot extend
the bake beyond ninety seconds. Candidate, catalog-anchor,
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
may retry after rollback, including with a rebuilt digest; a serving or baking
run cannot change its digest. Older runs and attempts cannot replace newer state.
The CLI exits successfully for an older signed run refused at admission or a
release whose failed regions were all superseded during bake or waiting behind
such a region. The newer release retains its own verdict. Unfinished bakes print
`bake unfinished` instead of a duration.

The regional observation budget is readiness + 30 seconds + the 90-second
maximum bake. Three 180-second readiness budgets plus one parallel rollback
fit within the 21-minute handler deadline; CI jobs allow 25 minutes. A healthy
region with a 10-second startup and short pull now finishes in under 60 seconds;
dependency recovery and readiness failures may take longer.

An unfinished or failed bake cannot admit another region. A missing earlier
region also holds advancement. Failed bakes survive restart and reconciliation;
a clean orchestrator shutdown during an unfinished bake restarts its full window.
A crash with no durable verdict holds for a fresh generation.
Evidence-write failures retry persistence without reevaluating the candidate.

Fix forward by publishing a corrected image through the existing authorized
release path. After repairing a dependency, a new apply of the same image also
creates a fresh generation and evaluates a new bake. Existing canary holds remain
until `service resume`; resume still evaluates the bake. Later regions retain
their serving tasks during a failure. TerraBase updates pause on failure, and
neither mesh apply nor signed release automatically restores an older storage
binary. Signed release, runtime identity and peer admission checks still apply.

The retired `operator terrabase update` placement path is outside the active
SwarmKit mesh deployment path; this gate is implemented in the latter.
