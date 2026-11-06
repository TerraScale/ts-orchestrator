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
ts-orch bootstrap-maintenance <status|arm|stage|replace> --state DIR
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
No tested hot-installation or offline-prearm procedure exists yet. The two stale
keys remain untouched, and no early-deletion safety decision is made here.

There is deliberately no fence-removal command yet. Before execution, qualify
reconciliation to the exact already-running signed image, rejection of stale
desired intents, and an explicit safe completion/recovery procedure. An expired
budget must not invite journal editing, CAS-back or an old lease-unaware writer.
The updated `.cos/zdt-20261105/deploy-plan.md` on delta records these gates and
the actual implemented commands. Independent review and final parent GO remain
required. Three live zero-error/p99 rollout proofs and acceptance HANDOFF are
still outstanding; notice durability (#1104) is not claimed by these tests.
