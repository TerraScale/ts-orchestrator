# Regional rollout bake

Install the orchestrator release in every target region before rolling a service.
Older orchestrators advertise readiness without evaluating a bake.

Every mesh service rollout observes a fixed five-minute bake after exact task
readiness, sampling every ten seconds. Samples verify the same running tasks
and their readiness, global ts-auth readiness, and dashboard readiness including
its auth and TerraBase dependencies. This respects gru-only auth placement.
TerraBase also checks newly appended task stdout/stderr for catalog-anchor
failures and slow writer waits (the engine logs waits of at least five seconds).
Missing or rotated log coverage holds the bake. Raw log contents, environments,
credentials and readiness response bodies never enter bake evidence.

Each region retains `mesh/bake-<service>-<generation>.json` under its state
directory: image digest, actual tasks and revision, elapsed readiness timings,
bake start/end, sample count, checks and failure reason. The release response
includes these fields; the CLI prints bake timing, and the journal records
`regional rollout bake verdict`. The JSON file is the retained evidence.

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
