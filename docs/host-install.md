# Host install timing: policy first

C33 phase 1 changes the desired NLB health policy only: 2 s interval, 1 s
timeout, two failed observations (one retry). `internal/nlbhealth` derives a
candidate bound of `interval × threshold + timeout + margin = 2 × 2 + 1 + 1
= 6 s`. The one-second margin is a scheduling/propagation allowance, not an
OCI data-plane SLA. No runtime code uses this bound in phase 1.

Runtime remains exactly on main: 20 s propagation, then 5 s of HTTP shutdown,
25 s edge share and a 30 s process budget. Listeners, Postgres proxy/key
handling, readiness, observation cadences and the restarts lane are unchanged.
There is no startup or stop-time OCI read guard. Phase 1 claims no measured
per-host install speedup and does not change existing connection handling.

## Apply after release

After the joint release and phase-1 merge/release are green, ops uses the new
CLI's `ts-orch region apply <label> nlb`. The PR contains exact read-before,
apply and settings/health verification commands for GRU, SJC and FRA.
Read back all three sets in every region: interval 2000 ms, timeout 1000 ms,
retries 1, FIVE_TUPLE, instant failover false, active preference false, with
healthy peers. Observe withdrawal through the public NLB and complete requests
on existing flows under healthy-peer load. Do not infer convergence from
settings alone. No worker production mutation is authorized by this change.

Old reconcilers can restore slow probes until their leaders run the new
policy. Verify again after those writers are gone. The unchanged 20 s runtime
remains throughout this phase, including rollback and mixed versions.

Oracle's SDK model/reference describes milliseconds and retry semantics
without numeric timing minima. Ops must confirm API acceptance and measured
withdrawal. The old configuration remains available in the read-before record.
Fail-open remains true: if every peer is unhealthy, new flows can reach
unhealthy hosts. Instant failover remains off, preserving existing-flow routing.

## Measurement and observation cadences

The baseline journal and retained rollout record show SJC shutdown-to-host-gate
42.584 s, with installed-to-ready samples 42.586 s and 46.247 s. The PR retains
the phase table. A later read of the current synchronous loopback `/readyz`
captured 131 HTTP 200 samples: p50 105.232 ms, p99 283.939 ms, max 449.645 ms.
Those ordinary-traffic samples are not stress or network latency guarantees.
The historical two abandoned HTTPS connections cannot be classified from the
old warning; phase 1 adds no connection-state tracking.

| Journal phase | Observation | Main → phase 1 cadence | Actual check | C33b candidate |
| --- | --- | --- | --- | --- |
| Startup → routes ready | Inventory consumer | 5 s → 5 s | Read inventory, refresh due proof, probe local services, update routes | 1 s |
| Startup → health ready | Readiness worker | 3 s → 3 s | Probe routes, ingress and listeners | 1 s |
| Health OK → host gate | Host gate | 2 s → 2 s | Compare host/regional health; retain four healthy seconds | 1 s |
| Swarm ready → inventory published | Manager producer | 5 s → 5 s | Read control-plane services and publish inventory | unchanged |

These observation ticks do real checks. The 20 s propagation allowance does
not read OCI state. Any later speedup must distinguish those phases and be
measured from the journal's shutdown start to the retained host-gate timestamp.

## C33b boundary

Shorten runtime only after the fast policy is verified everywhere. Design the
dependent loopback :8081 drain and race-free Postgres command admission/idle
closing first. Register BackendKeyData before the client can use it, but count
ReadyForQuery completion after successful client writes. Cover these boundaries
in the existing journey, retain C27's NATS ordering and normal exit under 30 s,
then update restarts expectations alongside the runtime change.
