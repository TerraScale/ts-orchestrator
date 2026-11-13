# Regional rollout bake

Every service generation bakes in every target region before that region reports
it ready for admission elsewhere. This includes first installations, recreated
services, newly added regions and regions with no local history or bake records.
No history journal or first-install classification participates in admission.
Plain service applies also bake; the agent binary release is outside this path.
A healthy first installation costs one 30-second observation window per target
region, in order, in addition to startup, readiness and evidence delivery time.

The bake protects the other regions. In the first region the new generation has
already replaced the old one when observation starts: the runtime update policy
stops the old task. A failed bake holds the generation from spreading and does
not bring the old generation back. This is also main's behavior. Keeping the old
generation serving until the candidate passes is a separate change.

## Observation and interruption budgets

After exact task readiness and local release identity validation, observations
run every two seconds. A bake passes after 30 seconds of consecutive healthy
observations. Failed samples reset that window and retain checks and counts.
The same probe failing for at least 15 seconds and at least three consecutive
observations saves a finished failure. Validation failure is also saved as a
failure and cannot advertise admission readiness.

Healthy windows, failure streaks and the ten-minute observation-loop bound use
monotonic elapsed time within one process. Receipt timestamps are diagnostic;
they do not measure elapsed time across processes. A probe blocked in a
filesystem call is not interrupted by this bound. Runtime RPCs and readiness
HTTP calls use request contexts; dependency HTTP additionally has a three-second
client timeout. Log open, stat and section reads, control-socket CA reads in the
bake path, receipt reads/writes and directory scans are synchronous and are not
interrupted by context cancellation. The ten-minute bound is consequently not
an unconditional duration bound on a rollout or even a blocked probe.

A generation has three observation attempts. Before each window the region saves
its start and the count of earlier interrupted windows. An unfinished start on
restart counts as an interruption and logs that a failure may not have been
saved. The third interruption saves a finished hold; no fourth window starts.
Metadata changes do not reset the count. An interrupted attempt starts a full
new healthy window. If the budget write fails, observation does not start and
the region reports failed and unsaved. Downtime, readiness and persistence are
outside the observation budget.

A rollback to the previous build followed by a forward update loses the
interruption count if the previous build rewrites the receipt: that build drops
the new fields. The generation then receives a fresh budget.

## Local holds and admission evidence

A hold belongs to the observing region in its local
mesh/bake-SERVICE-GENERATION.json receipt. A saved failure survives readiness
recovery and restart. A failure that cannot be written stays failed and unsaved
in memory while persistence is retried. After a crash only durable information
survives. An unfinished receipt consumes another interruption and logs the
possibility of an unsaved failure before a fresh window; it does not prove
whether the lost in-memory verdict was a failure. The interruption count records
that uncertainty. Losing the receipts themselves requires baking again.

Later regions require every earlier target to report the exact generation
serving and a saved passing bake. Missing or failing evidence blocks admission.
The requester sends a random nonce and accepts an echoed nonce only within five
seconds measured from sending on its own monotonic clock. It never compares
clocks between regions. Each observer expires its own local serving samples
using its local monotonic clock. For rolling updates, a nonce-free reply is
accepted only in main's existing shape, without serving, bakeRequired, admission
or unsaved fields; its ready map is used as main uses it. A reply containing the
new fields must echo the nonce. Wrong nonces are always rejected.

Admission evidence is trusted on mesh membership: any authenticated mesh
participant can answer. It is not signed by the originating region. This is also
true on main; origin authentication is a separate change. Admission decisions
are local diagnostics, not independent authority.

Serving checks cover required replicas and configured readiness endpoints, not
external routing, customer authentication or a customer database query. Samples
check exact running tasks, relevant local application dependencies and readable
TerraBase task logs for catalog-anchor and writer-wait regressions. Raw logs,
credentials and readiness response bodies are not retained.

If the first region in the placement order is unavailable, later regions cannot
admit the release. Existing tasks in waiting regions remain in place. Recover
the first region, or publish a placement change excluding/reordering the
unavailable region; the resulting generation still bakes in its target order.
There is no automatic bypass.

## Clearing a hold

A held generation admits replacement only with a higher generation and a
strictly newer signed run, then attempt. Replays, plain applies and resume are
refused before desired-state changes. The failed receipt saves its replacement
identity first. A receipt from main without a release identity can recover it
only from that generation's retained local desired declaration. If none remains,
a higher signed generation follows the older hold's admission rule. No history
journal or retained floor is used to derive a first-install exemption.

## Release health and known limits

Host memory, filesystem observations and the SwarmKit CA-file read share a
five-second bounded sampler. At most two abandoned samples may remain running;
requests fail at the cap until one completes. Late results cannot replace fresh
observations. Health uses the sampled CA for both SwarmKit reads and the named
service check, so blocked CA-file reads cannot accumulate per request. Runtime
RPCs use the health context; named-service checking follows host/runtime checks.
Checks are not a concurrent aggregate with an unconditional duration guarantee.
Node-list status reads in the general health report are synchronous too.

State replies still read receipts inside the subscription callback. Bake
filesystem probes remain synchronous, and reconciliation still holds locks
across disk and network calls. These limitations are not addressed here.

## Journey lanes

rollout.sh covers observation, holds and signed replacement;
rollout-install.sh covers installation, nonce admission, interruption budgets
and health sampling. Each has its own ten-minute CI matrix entry. Their runner
prints measured lane seconds. Clock changes use a journey-only build overlay
that preserves monotonic readings; product code has no clock switch or test hook.
The older-receipt journey uses main's receipt types and writer at commit
dc098b1fca6faf0b3ab683f76f45c16e541e5f00, rather than deleting a field from a
current receipt.
