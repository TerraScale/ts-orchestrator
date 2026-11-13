# Regional rollout bake

Install this orchestrator release on every target founder before rolling a
service, so every participant enforces and persists the same verdict protocol.

Every service generation requires a successful bake in every earlier target
region before the next region applies it. An earlier region that stays down
holds later regions until it returns or is removed from the placement. The
placement declaration and its order determine the targets.

A bake samples every two seconds after exact task readiness. It passes only
after thirty seconds of consecutive healthy samples. A single failed sample
resets the healthy clock and records its count, checks and last reason in the
receipt. No failed sample is discarded. All probes follow this rule, including
candidate readiness, control access, dependency readiness and log coverage.

A bake fails in either of two ways:

- The same probe fails in two consecutive samples, even if its reason changes.
- The full healthy window has not completed within ten minutes of the first
  sample. The named total bound is MaxBakeWindow.

These rules govern observation after readiness. Failure to establish readiness
or verify the signed image identity refuses the rollout before sampling and
retains a failed rollout receipt.

The receipt retains the first-sample timestamp, total sample count, failed-sample
count, last failure, consecutive failures per probe and healthy-window start.
An observer restart requires a fresh full healthy window. It retains the first
sample and consecutive-failure evidence, so restarting cannot extend the total
bound or erase the previous failed sample. An interrupted observation is
unfinished, rather than a failure that requires an operator.

Samples verify the same running tasks and their readiness. Services with
application dependencies also check the relevant readiness endpoints. The
database service checks appended task stdout and stderr for catalog-anchor and
writer-wait regressions and verifies that log coverage remains readable.
Raw log contents, environments, credentials and readiness response bodies are
excluded from retained bake evidence.

## Sticky failures

A hold means a failed service generation cannot advance to later regions, even
if its readiness subsequently recovers. Failed generations are terminal.
An observer publishes a failed verdict for the service and generation to every
other reachable region's founder in parallel with writing its own receipt.
A receiving founder durably stores the verdict in mesh/bake-holds.json before
acknowledging it. The ledger retains the reporting region and generation.
A later passed verdict from a region that reported failure for that generation
is refused and logged.

The observation is handled when either the observer durably saves it locally or
another founder acknowledges a durable copy. Until one succeeds, the observer
retries both operations, pauses observation, and reports only failed, unsaved.
The observer retains its failure in memory while persistence is unavailable.
Peer state exchange also carries sticky verdicts so a restarted observer learns
them again.

The invariant is: a failure seen for generation G holds later regions for G
unless both the observer's disk and its links to every other region failed at
once and it then restarted.

Each region retains mesh/bake-SERVICE-GENERATION.json under its state directory.
The receipt contains the image digest, actual tasks and revision, elapsed
readiness timings and bake evidence. Mesh state replies also require a fresh
cached serving observation after a successful bake. Serving is readiness seen
from inside the region, not a customer query from outside. It does not prove
external routing, customer authentication or a successful customer database
query. Missing or stale serving evidence holds advancement.

## Clearing a hold

Repair the cause, then dispatch the signed release workflow with the same
digest or a corrected image. Only an authenticated release verified by the
release handler may admit a new generation while the service is held.
Each founder durably records the held generation it replaces and the new
generation's release run, attempt, revision and image in its hold ledger before
accepting the replacement. This applies to founders that learned the failure
from another region.

There is no other way to clear a failed bake, including when the code host is
unavailable: the rollout remains held until the signed workflow can run.
A local unsigned service apply is refused and names the held generation and
the required release workflow. Service resume clears a canary hold only; it
cannot clear a failed bake. A new generation receives its own observation
window; older failed generations remain in the ledger and cannot hold the
new generation after its signed acceptance. No automatic database downgrade
is performed.

Signed releases retain the existing placement policy. Each subsequent region
requires evidence from every earlier region. Regions waiting behind a hold
retain their serving tasks.

## Release health

Both named service health and unnamed binary-release health check the mesh,
the container runtime API, SwarmKit node readiness and readable services.
The runtime call shares the existing health deadline. A stopped daemon fails
health even while cached node readiness and shim-owned tasks remain alive.
Named health additionally checks the requested service's replicas and readiness
endpoint. An unrelated replica shortage does not fail that named check.
