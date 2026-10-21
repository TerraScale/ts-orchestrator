# TS-783 release observation policy

Qualification gets 10 minutes and forward deployment gets 20 minutes. These
are maximums: clean serving evidence promotes automatically. Recovery gets
its own deadline. Build, artifact retention, signature validity and transport
retry settings are distinct from observation.

The first policy PR covers the orchestrator binary and the native TerraBase
and ts-auth release channels. It does **not** complete TS-783: the remaining
policy paths, rollback command/button, retained configuration and live drill
are still required.

## Before and after this PR

Baseline: `d7b1a4885f25564a0c54e2f1929de3eb5bc92183` on `origin/main`.

| Path or setting | Before | After |
| --- | --- | --- |
| Image qualification, `scripts/ci/qualify-image.sh` | 2,400 seconds, environment override | Fixed 600 seconds across all selected suites; override deleted |
| Image workflow job timeout | 205 minutes | 175 minutes: 100 for upstream gate, 10 for qualification, 65 for build/release |
| Orchestrator release CLI wait | 2 hours; CI passed 30 minutes | Fixed 20 minutes across concurrent regions; `--region-timeout` deleted |
| Native service release CLI wait | 30 minutes, overridable | Fixed 20 minutes across concurrent regions; `--region-timeout` deleted |
| Orchestrator controller and host programs | Each starts independent deadlines and observation | One persisted deadline from signed receipt issuance, shared by controllers and hosts |
| Region publication/admission | Each region starts its own clock | CI signs all receipts/claims with one start; admission preserves it |
| Static TerraBase readiness | max(10 minutes, 5 minutes × replicas), plus fence allowances | Fixed maximum 20 minutes, including sequencing and canary checks |
| Static ts-auth readiness | 10 minutes plus fence allowances | Fixed maximum 20 minutes, including sequencing and canary checks |
| Native service leader replay | Restarts the readiness wait | Only time left until the persisted claim's issuance + 20 minutes |
| `controller.rollouts.policy` / cell-spec `rollout_policy` | Signed config / KV can override every stage | Members and their handlers deleted; unknown members are refused |
| Native recovery after deadline | Can inherit a short remaining forward wait | Fresh 20-minute readiness budget and independent context |

Orchestrator stages remain pending → preflight → canary → canary observation
→ batches → complete, with rollback/frozen terminal paths. The fixed
thresholds are one canary, at most 512 units per batch, 5-minute canary
observation, 2-minute observation per later wave, three healthy reports from
one process incarnation, and 10-minute preflight/proof/recovery deadlines.
Every forward phase is clipped to the shared 20-minute deadline; later waves
cannot buy additional time. Quorum grouping and seed-last ordering remain
required. Missing fresh serving proof at the deadline starts recovery once a
unit has moved. Expiry during pending/preflight aborts without marking the
untested binary known bad. An untouched abort refunds its reserved attempt
once. A newer qualifying CI run with newer signed issuance can retry that
same binary in a fresh generation, including a host-only program whose
controllers were already current. At least one untouched aborted stage is
required, and every existing stage must be untouched. Exact replays and
active/partly promoted programs cannot renew the deadline. Manual publication
also preserves the receipt's authenticated issuance time.

A crash after reservation but before record creation leaves a permanent
ID marker in the original v1 format. The stage ID resolves to an immutable
desired or retained release generation, which proves its target. Every new reservation requires a published controller or host stage;
admission checks its target, kind and signed start before charging an attempt.
Existing full records resume without a generation lookup. Executor ticks
recover both an unmarked reservation and a marker-before-clear crash before
planning the program. Reclamation refunds only that generation's target in
the CAS that clears its matching slot. Admission, recovery and publication
are serialized on the leader's shared store; authority fencing still guards
every write. Pruning checks authority after reading the slot and immediately
before deleting a generation. It preserves the active stage's generation.
Proof lookup includes every readable retained generation beyond the normal
64-copy window. It checks the desired stage first, derives older stage IDs
locally, and reads only the matching validated generation. Admission and
reservation recovery never inventory operational history. Historical hashing
cost grows with generation distance and stops on context cancellation. A fresh signed
CI run can retry under the one-attempt policy. A record-free ID cannot
be resumed from the incoming spec. An arbitrary orphan with no retained
release binding is tombstoned and cleared without refunding historical counts.
Retention pins retry the complete generation inventory if a listed key
disappears or publication changes the desired KV revision during collection.
Purging can follow the desired write, so a missing key retries even if that
revision is unchanged. Invalid data and other read errors still fail closed;
persistent missing keys or revision changes return a bounded conflict for the
next channel tick to retry, without locking publication across the inventory.
This detects revision changes visible to the KV reader; it does not provide
an atomic snapshot across replicated KV reads.
Malformed or misbound markers remain refused.
The dashboard release report identifies abandonment as a failed untouched
rollout and directs CI to issue a new release.

Executor ticks and health reports occur every 5 seconds; proof freshness is
20 seconds, new-process quiet time is 10 seconds, signed proof lifetime is
2 minutes with 1 minute of signature clock skew. Step relays poll every
2 seconds, step signatures last 2 minutes with 30 seconds of skew, and step
dispatch has a 30-second transport timeout. These do not extend observation.
Verified release receipts within their 1-minute signature clock-skew allowance
wait for local issuance time. The channel reports rolling/waiting before
publishing a generation; a manually published future desired release waits in
the executor without reserving an attempt or moving a unit. Native service
claims likewise wait within their 5-minute allowance. All preserve the signed
deadline; excessive skew and untrusted receipts/claims are refused.
The existing manual rollback refuses a target whose authenticated receipt is
still future, since rollback assigns a fresh generation start.
An unsubmitted native claim is refused once its signed observation window
expires, before admission and again before intent persistence. An already
persisted intent retains conservative recovery because hosts may have changed.

## Remaining policy paths

| Path | Baseline behavior | TS-783 work remaining |
| --- | --- | --- |
| Managed TerraBase `terrabase-sync` / `terrabase-update` | 1-hour sync deadline, 20-minute wait per seat, configurable 5-minute soak, transient retries and 6-hour block threshold | Persist one release deadline; remove timing switches and repeated observation; preserve safe recovery |
| NetBird agents | 19 minutes per node: 10-minute drain, 3-minute install and three 2-minute check/confirm/return phases; independent 6-minute recovery | Bound the whole release across nodes; preserve independent connectivity recovery |
| Machines API / generic workloads | Separate reconciliation; health timing fields have no runtime consumer | Add serving evidence and release-wide observation/rollback rather than claiming schema fields provide it |
| Firecracker/runtime-priority qualification | Several independent scenario deadlines and caller-provided durations | Bound release qualification without weakening fixture/evidence checks |
| `ts-dashboard` | Fly app; deployment workflow lives in ts-dashboard | Integrate its release/rollback boundary and retain native-login ancestry protection (at least Fly v98 / #180) |

Embedded NATS and the operator dashboard follow the orchestrator binary.
`ts-atlas` and `ts-status` are external Cloudflare Workers rather than native
service-channel roles. The native channel currently recognizes only
TerraBase and ts-auth; other services need an explicit supported release path.
The [remaining baseline timer inventory](rollout-timer-inventory.md) records
the CLI/config switches, thresholds, qualification stages, CI timers and
transport/recovery boundaries in those paths.

## In-place deployment prerequisites and evidence

Before this CLI reaches service CI, land the caller/argument-contract updates
in [TerraBase #139](https://git.terrascale.tech/TerraScale/terrabase/pulls/139)
and [ts-auth #68](https://git.terrascale.tech/TerraScale/ts-auth/pulls/68).
They remove `--region-timeout` and pass the deployment guard; auth's full
660-test check passed. TerraBase's compile failures also occur on unchanged
main and are documented in #139. Older pinned helpers accept the omission;
their deadlines change only when the helper pins advance. Coordinate
TerraBase's pin update with TS-773. There is no compatibility flag in the new CLI.

Retired policy members are rejected rather than ignored. Before deploying,
inspect the target's signed controller config and current NATS KV cell spec,
remove any retired members through their existing signed replacement path,
and verify fresh proofs and an agreed predecessor. No serving cell is
re-founded or rebuilt. Startup fails closed if the stored spec is rejected;
it cannot discard persisted signer restrictions and use bootstrap defaults.

The rollout slot and permanent markers retain their original v1 format.
There are no new required digest members, migration, dual decoder or
empty-member compatibility branch. A new leader can read an earlier writer's
active record, preserve its observation clock, adopt its epoch and settle it.
An idle audit alone would not prove this: the installing rollout itself
creates an active reservation. Lost historical generation/attempt ownership
cannot authorize a refund. This slice changes no live rollout data and starts
no update. The [raw rollout-store audit](evidence/ts783-rollout-storage-20261010.md)
records additional deployment boundaries in the actual GRU/SJC stores.

Read-only inspection on 2026-10-09 around 21:02 UTC found all six GRU/SJC
controllers healthy and ready, with 24/24 authenticated dashboard checks
passing. GRU reported mixed builds (`1e57e6c17362` and `93c6b7e3df4f`); SJC
reported `107e060af74f`. GRU's mixed predecessor blocks a normal agreed-source
rollout. These are target checks, not TS-783 rollout/rollback evidence.
The [live configuration audit](evidence/ts783-policy-config-20261009.md) at
22:02:06 UTC verified all six installed signed config pins and actual current
KV records: GRU generation 14/revision 26 and SJC generation 10/revision 10.
No retired policy members are present; no signed replacement is needed for
that state. Explicit persisted signer restrictions remain intact.

No TS-783 live write or timed drill has occurred. Resolve the release-path
precondition without taking over TS-746's recovery work, recheck live config
before deployment, then record real qualification, promotion and rollback
timestamps in the follow-up PR.
