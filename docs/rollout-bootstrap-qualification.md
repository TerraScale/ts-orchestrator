# Pinned regional bootstrap: local qualification, production HOLD

Local candidate `8bd5ee9018feb1980d6629bc18c908f9e7ff521c` implements the scoped
executor fence and pinned replacement driver. Its new critical proofs pass five
repeats, including the race detector. Affected Fast packages pass. No production
mutation, publication, watcher restart, workflow re-enable or account load occurred.

The [proof manifest](rollout-bootstrap-qualification.json) records exact source
hashes, commands, raw-log hashes and evidence paths. Builds/tests ran through
`ts-heavy-any` on mariogk-dev. The companion monorepo report is
`benchmark/bench/2026-11-06-zdt-bootstrap.md`: eleven engine Slow drills ×5,
actual b443 Program on retained primary data, Fast 66/66 plus native 4/4.

## Fence and physical exit proof

The Slow integration starts three real Swarm managers and three real workers,
with CA admission, scheduler, dispatcher, Raft/agent persistence and STOP_FIRST
updates. Its container runtime is a contract fake backed by actual OS processes;
it never downloads or runs TerraBase in this repository.

All six nodes retain their exact source task/service/node/fingerprint/image and
PID/start ticks in fsynced atomic journals. A new service intent is published in
all three regions. Every source stays alive. All six Swarm daemons then restart
on the same state, while the external processes survive. The journals still
refuse ordinary prepare/start/stop/terminate/remove/reap mutations.

The selected follower alone is stopped through the driver's private capability.
The process receives TERM and is physically reaped; its /proc identity is checked
before normal dispatch can start its successor. The five other original processes
remain alive. The non-race five-repeat run recorded 20–29 blocked lifecycle calls
per repeat; physical exit preceded new admission in every run. The final five
repeats also pass under `-race`.

Separate Store proofs lose the exit response, reopen the journal as a new
operator/executor, and verify that replacement cannot start without affirmative
exit evidence. The deadline is retained across reconnect. Corrupt records, expired
budgets and grants for another task/action fail closed. A successful replacement
keeps the executor/publication fence in place.

The production adapter additionally requires containerd to report the captured
container gone/stopped, with task/service/fingerprint labels matching. A missing
API response is an error, not an exit certificate. This adapter compiles and is
covered at its contract boundary; a real production containerd installation has
not been exercised by this local proof.

## Signed staging and durable ingress

The existing authenticated app-release handler retains the exact armed candidate
and provenance instead of publishing a fleet update. Stage requires both admitted
regional nodes' durable jobs to name the same immutable image, owner and epoch.
Missing peer fence and mismatched epoch both refuse publication. The tested valid
case uses the ordinary service applier; ordinary reconciliation remains fenced.
The selected replacement is assigned by Swarm, never synthesized by operator JSON.

The edge holds one selection per region in a separate fsynced ingress journal.
A follower replacement preserves owner service. Before owner replacement, the
edge checks pinned ownership and readiness, primes the upgraded follower to the
writer's applied data, retains its hold, drains admitted response bodies and closes
idle backend connections. It never invokes legacy `/drain` or changes ownership.

The HTTP proof keeps a real response open and proves hold completion waits for
the body. A new edge instance on the same directory refuses public and internal
requests despite losing all in-memory locks. Release fails until the barrier is
reacquired and pinned writer/readiness is verified. Both staging and edge restart
proofs pass ×5, and the final source passes ×5 under the race detector.

## Findings retained in the evidence

The first race run failed because vendored Swarm's default scheduler filters
were mutable global instances. Concurrent regional managers overwrote each
other's task reservations, constraints and platform filters. `NewPipeline` now
constructs its own filter objects. The complete affected proof passes five race
repeats after this fix; no race suppression or test serialization was added.

The whole Fast invocation also found failures in existing `bootstrapstart`
installation-identity fixtures, the image arm64 `/usr/sbin/nft` metadata fixture,
and protected member-status staging permissions. The same named failures
reproduce on **untouched `2142b1f30`**, in a separate dev-host checkout. These are
parked baseline failures, not a green whole-Fast claim. Affected packages pass:
`swarmruntime`, `natscell/mesh`, `edge`, `app`, `cli`, `handoff` and
`rolloutmaintenance`; the slow six-node proof is separate from Fast.

## Implemented operator surface and remaining deployment gates

The new root-only local CLI is:

```text
ts-orch bootstrap-maintenance <status|arm|arm-stopped|stage|replace> --state DIR
```

Arm takes a finite job ID, current source task, immutable target image and retained
owner/epoch. The daemon derives runtime pins and process identity itself. Stage
pre-pulls through existing admission before the 60 s replacement budget starts.
Replace persists each phase, drains, stops, proves exit, awaits normal assignment,
prepares, rechecks exit, starts, verifies and releases ingress. A timeout retains
both fences. There is no forced-kill grant, automatic rollback or deadline reset.

**This is not an executable production GO.** The old orchestrators lack this
endpoint/fence. Installing a new daemon normally restarts embedded NATS, which
must not cause old b443 watchers to replay the retained hazardous platform keys.
No tested hot-installation procedure is claimed. The cold offline arming action
and coordinated maintenance alternative are described below. The two stale keys
remain untouched; production execution still requires independent review and GO.

There is deliberately no fence-removal command yet. Before normal rollouts resume,
qualify reconciliation to the exact already-running signed image, rejection of stale
desired intents, and an explicit safe completion/recovery procedure. An expired
budget must not invite journal editing, CAS-back or an old lease-unaware writer.
The updated `.cos/zdt-20261105/deploy-plan-v2.md` on delta records the cold
maintenance barriers and actual commands. Independent review and final parent GO
remain required. Three live zero-error/p99 rollout proofs and acceptance HANDOFF are
still outstanding; notice durability (#1104) is not claimed by these tests.

## Coordinated cold maintenance revision

The approved installation approach now stops all six legacy processes during one
announced maintenance window, proves their physical exit, checksums and backs up
all retained DBs, deletes only the two audited stale platform keys, then installs
the orchestrator and starts pinned owners and followers. It preserves owner node,
epoch, data and R10 holds. Each step has an abort and b443 retained-data rollback.
The full plan is `.cos/zdt-20261105/deploy-plan-v2.md` on delta; it supersedes v1.
No announcement, key deletion, restart or deployment has been performed.

Commit `7897a49ea` adds the root-only offline `arm-stopped --manifest FILE` action
for the staged new executable. It refuses a live captured process or available
containerd socket and persists both local executor and regional owner ingress
journals before the new daemon starts. Exact initial retries are idempotent;
partial failure leaves a fence. The all-six exit proof remains an operator
prerequisite, and the independent maintenance gate stays closed through data and
application verification. The live systemd graph must prove that stopping
containerd leaves embedded NATS available for the two-key cleanup.

The new process/socket/journal tests pass **five race-detector repeats** on delta,
followed by all seven affected Fast packages (longest 11.905 s). This candidate
remains based on current main `2142b1f30`. The rebased engine on `a811367bd` passes
66/66 TerraBase and 4/4 native Fast; all five rebased patches are content-identical.
Raw logs, source digests and exact commands are in delta's
`.cos/zdt-20261105/qualification/v2-fast.{md,json}`. These are local qualification
results, not proof of production systemd/containerd installation or rollback.
Independent review of the added offline action, Version:0 guard and v2 plan and
explicit user GO remain required. Executor fences stay retained afterward until
separately approved desired-state reconciliation; normal rollout proofs remain
outstanding.

## v2 cold-maintenance review qualification

The reviewed cold plan now has executable gates in
[scripts/maintenance](../scripts/maintenance/README.md). They qualify ten executions
(two critical cases ×5) on dev hosts, covering real isolated nft apply/undo,
pidfd TERM→KILL exit, encrypted backup readback, real dev JetStream conditional
DEL and stale-revision refusal. Three 64MiB backup/transport repeats also pass
exact off-host SHA/size readback. These are local proofs, not production mutations.

The parked full-Fast failures are fixed without weakening permissions: public
fixtures explicitly set their expected modes under umask077; privileged staging
checks protected parent components and still refuses symlink escapes. The final
full Fast run passes 892 cases/346 shards with zero failures. Five repeats of each
affected package pass too. Exact sources/logs are in
`.cos/zdt-20261105/qualification/v3-{maintenance,engine}-proof.json` on delta.

The updated deploy-plan-v2.md spells out the original all-peer desired/floor/bake
and offline Swarm restore set, retained latest JetStream/protocol/prepared keys,
restart-label gate, TERM20s/KILL5s stop and hard abort deadlines. Both branches are
rebased on fresh origin refs. All 13 engine Slow drills pass ×5, including both
publication crash cuts and v2→real-b443→v2 on retained files.

Workers remain **derived, not read back**: the actual OCI launch unit/runtime
matches provisioning source and image identity, but existing Run Command stayed
ACCEPTED despite RUNNING plugins. No SSH access was added. The parent must decide
that gate, and usable six-node control, full inventories, production backup timing
and exact green-main CI remain prerequisites. No deployment, workflow enable,
stale-key deletion or live rollout is authorized by these local results.
