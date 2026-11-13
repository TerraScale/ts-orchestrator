# Regional rollout bake

Only generations created by a release operation are baked and can be held.
The operation starts at the authenticated release handler and carries the
repository, run, attempt, revision and immutable image in its deployment record.
Plain service applies, including first installs and services without a release
path such as the network management server, wait for readiness but are not
baked and cannot acquire a bake hold; they can be applied again.

A released generation reaches a later region only when every earlier target
region reports a finished, passed bake and fresh serving evidence for that exact
generation. The placement declaration determines the targets and their order.
An earlier region that stays down holds later regions until it returns or is
removed from placement. Waiting regions keep their existing serving tasks.

## Observation and local holds

After exact task readiness, a bake samples every two seconds and passes after
30 seconds of consecutive healthy observations. A failed sample restarts that
healthy window and records its count, checks and last reason. A bake fails when
the same probe fails in every sample for at least 15 seconds, with at least
three consecutive failed samples (`BakeFailureDuration`), or when no full healthy
window completes within ten minutes of the first recorded sample
(`MaxBakeWindow`). Two failed samples alone do not fail a bake.

The ten-minute bound uses wall-clock time, including time the observer was down.
An interrupted bake remains unfinished and runs a full new window on restart;
the first-sample time, total counters and last failure remain recorded, while
consecutive probe streaks and the healthy window start again. Readiness or image
revision failure before observation also refuses that released generation and
retains a failed rollout receipt.

A hold lives only in the region that observed the failure, in its own durable
`mesh/bake-SERVICE-GENERATION.json` receipt. That receipt retains the image,
tasks, running revision, readiness timings, first sample, counters, last reason
and finished verdict. A persisted failed verdict survives observer restarts and
subsequent readiness recovery. Founders neither publish verdicts for persistence
by peers nor import peer holds through state exchange; later regions ask earlier
regions for their current verdict and serving evidence.

If writing a failure fails, the observer retains it in memory, retries the local
write, reports failed, unsaved for that generation, and never continues or passes
that window while it lives; if it restarts before saving, the unfinished receipt
requires a full new window whose result stands.
This is acceptable because a persistent regression fails the new window again,
and a transient regression receives the same treatment as a transient failure in
any new observation window.

Samples verify the same running tasks and their readiness. Services with
application dependencies also check their relevant local readiness endpoints.
The database service checks appended task stdout and stderr for catalog-anchor
and writer-wait regressions and verifies readable log coverage. Raw logs,
environments, credentials and readiness response bodies are not retained.

A passed bake alone does not prove serving: state replies additionally require
fresh readiness evidence from inside the region. That evidence proves the
requested service has its required running replicas and its configured readiness
endpoint answers successfully, when one is configured. It does not prove
external routing, customer authentication or a successful customer database
query. Missing, stale or failing serving evidence prevents advancement even
after a bake passed.

## Clearing a hold

Repair the cause, then release again with the same digest or a corrected image.
A held service admits a new generation only through a release declaration with
its deployment record; before admission, the observing founder durably journals
which held generation it replaces and the new release identity in the failed
receipt. A plain `service apply`, configuration roll or `service resume` cannot
bypass the hold: the founder refuses it, names the held generation and instructs
the operator to release again. Resume only clears an ordinary canary hold.

The release handler verifies the release signature. Founders trust declarations
relayed by other members of the mesh, as they do for every other declaration;
the deployment record is not independent proof of signature verification.
This rule stops an operator’s routine local apply from bypassing a hold; it is
not a defence against a compromised mesh member.

The new released generation re-bakes every region, taking about 30 seconds per
region plus readiness time. Old failed receipts remain as local history and do
not hold the newer admitted generation. No automatic database downgrade occurs.
If the authenticated release path is unavailable, a released service’s hold
remains until that path is available again.

## Release health

Named service health and unnamed binary-release health check the mesh,
container runtime API, SwarmKit node readiness and readable services. Independent
host health checks run concurrently within the existing health deadline; a
failed check or a check that misses the deadline fails health. A stopped runtime
fails health even while cached node readiness and shim-owned tasks remain alive.
Named health additionally checks the requested service’s replicas and readiness
endpoint. An unrelated replica shortage does not fail that named check.
