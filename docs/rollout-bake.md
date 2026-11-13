# Regional rollout bake

Only generations carrying an authenticated service release declaration can need a
bake. Plain service applies wait for readiness and cannot create a bake hold.
The agent's binary release is outside service baking.

Each region derives whether a released generation needs a bake from its durable
local service history. An earlier generation in its local declaration journal or
receipts, or an earlier retained signed release, requires a bake. The journal is
local, records declarations targeted to this region before reconciliation, and
survives removal and recreation. Local history journals and bake verdicts are never imported from peers. There is no stored or synchronised first-install classification.

With no earlier local history, a region waits for readiness without baking or
creating a receipt. Its fresh reply reports the generation serving and no bake
required, allowing later regions to advance. A region newly added to an existing
service does not bake its first local generation; regions with earlier local
history still bake that same generation. The next release bakes in every region
that now has that history.

## Observation budget

After exact task readiness, observations run every two seconds. A bake passes
after 30 seconds of consecutive healthy observations. Failed samples reset that
healthy window and record checks, counts and the last failure. The same probe
failing for at least 15 seconds and at least three consecutive observations
produces a finished failure. Two bad samples alone cannot fail a bake.

Healthy windows, failure streaks and the ten-minute cap on each window use
monotonic elapsed time in one process. Wall-clock steps in either direction do
not change those decisions. Receipt timestamps are diagnostic values, not a
deadline or a measure of elapsed time across restarts.

A generation has a budget of three observation windows. Before starting each
window, the region durably saves its start and the number of previously
interrupted windows. A restart, exit or ending context leaves the started window
unfinished. Before another window can start, that interruption is counted and
saved. The third interruption saves a finished failure saying the bake could
not complete; a fourth window cannot start. The counter never resets for that
generation, including after declaration metadata changes.

Thus observation consumes at most three ten-minute windows of running time
before passing or being held. This bound excludes downtime, readiness waits and
time spent persisting evidence. A lifetime's ten-minute cap itself saves a
failure. An interruption starts a complete new healthy window; prior samples
cannot provide an early pass. If advancing the budget cannot be saved, no
observation window starts: the region reports failed and unsaved.

## Local holds and serving evidence

A hold belongs only to the region that observed it, in its durable
`mesh/bake-SERVICE-GENERATION.json` receipt. The receipt retains the signed release
identity, interruption count, readiness timings, tasks, running revision,
observations and terminal verdict. A saved failure survives readiness recovery
and restarts. Failure writes that cannot complete stay failed and unsaved in
memory and are retried locally; that observer never changes them to a pass.
A restart before saving must reserve another window from the durable budget.

Later regions require every earlier target to provide fresh serving evidence
for exactly the requested generation and, where locally required, a finished
saved passing bake. Missing, stale or failing serving evidence blocks admission
even after a pass. Replies expose the most recent admission decision, its
generation, earlier region and missing evidence. Those decisions are diagnostic
and local; they do not provide admission authority.

Serving evidence checks the service's required running replicas and configured
readiness endpoint. It does not prove external routing, customer authentication
or a customer database query. An absent earlier region blocks later ones until
it returns or placement changes. Waiting regions retain their serving tasks.

Bake samples check the same running tasks and readiness, relevant local
application dependencies, and readable database task log coverage for
catalog-anchor and writer-wait regressions. Raw logs, credentials, environments
and readiness response bodies are not retained.

## Clearing a hold

A hold admits replacement only by a signed release with a higher generation and
a strictly newer run, then attempt. Replays, older releases, plain applies and
resume are refused before desired-state changes. The failed receipt durably
journals the replacement generation and release before desired state changes.

For a receipt without a release identity, the region recovers and saves the
identity from the held generation's local desired declaration or journal. If
neither retains it, a signed release with a higher generation may replace the
hold, following the rule under which that older hold was created.

The release handler verifies the signature. Founders trust declarations relayed
by mesh members; a deployment record is not independent signature proof. This
prevents routine operator applies from bypassing a hold, without defending
against a compromised member. Holds stay local and no automatic database
downgrade occurs. Receipts of older failures remain history after replacement.

## Release health

Named-service and binary-release health check the mesh, container runtime API,
SwarmKit node readiness and required readable host observations concurrently
within the health deadline. Named checks also verify only the requested service's
replicas and readiness; unrelated service shortages do not fail them.

Host observations expire after five seconds. An expired in-flight read is
abandoned so a fresh read may start. At most two abandoned reads may remain
running; requests fail fast at that bound until a read completes. Late results
cannot overwrite fresh observations. An unreadable required filesystem or
missing fresh host observation fails health. A successful fresh read restores
health without restarting the agent.

## Standalone observation lane

Run `bash test/e2e/m1/rollout/run.sh /path/to/ts-orch` with Go, containerd, runc
and network namespace tools available. The independent lane builds its journey,
prepares images, state and namespaces, and reports elapsed seconds. The rollout
entry in the CI matrix runs this lane.

Clock controls inject wall readings through a journey-only Go build overlay
while preserving monotonic readings. They do not change the runner's clock or
add a product configuration switch.
