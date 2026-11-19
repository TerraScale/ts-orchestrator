# Host install timing

At stop the edge first fails its NLB health endpoint, keeps accepting and
serving during withdrawal, then closes admission. Established work drains
separately. `internal/nlbhealth` defines a 2 s interval, 1 s timeout and two
failures (one retry). Its bound is `2 s × 2 + 1 s + 1 s = 6 s`, including
the final timeout and one second for scheduling/propagation. A stop just after
a successful probe needs both failed observations. This is not a promise of
withdrawal within 2–3 s; data-plane convergence still needs ops verification.

The address-Host `/readyz` reads cached readiness; a background worker probes
backends. A healthy backend taking 1.2 s no longer makes the NLB request wait
1.2 s. Named-host and detailed operator checks remain synchronous. Draining
health returns 503 before the stop-time policy API read begins.

A bounded SJC production read on 2026-11-19 captured 131 HTTP 200 responses
from loopback `/readyz`: p50 105.232 ms, p99 283.939 ms, max 449.645 ms.
These are current-binary samples under ordinary traffic, not stress or network
latency guarantees. The journey also measures 100 fresh cached NLB probes
with HTTP responses and a Postgres query held.

## Admission and established work

C27's edge share stays 25 s and the process budget stays 30 s. HTTP closes
idle connections and waits for active responses within that share. Verified
fast withdrawal closes admission at 6 s while a 15 s response still finishes.
The unverified 20 s window retains at least five seconds for completion.
Indefinite SSE and hijacked WebSockets retain bounded closure at 25 s. The
final five seconds remain for NATS and cleanup. The one-second systemd
restart backoff is unchanged.

Postgres accept-loop exit no longer closes established connections. Idle
sessions close; active queries finish and ReadyForQuery reaches the client
before an idle session closes. Idle-in-transaction sessions remain until idle
outside the transaction or client closure. Session overruns are reported at
the edge share rather than force-closed on accept-loop return.

The planned-stop journey holds HTTP and a Postgres query across admission
closure, releases them at 15 s and checks complete responses, plus idle
Postgres closure. Held SSE and WebSocket retain bounded exit. The manager
restarts lane reads the effective window from the health response header,
checks health 503 with successful application responses during propagation,
and retains normal exit under 30 s.

## Policy first, binary second

Ops must apply and verify the new NLB policy in every production region
before COS opens this PR's merge hold. The PR has exact read-before, apply
and verify commands for the approved candidate CLI's `region apply <label>
nlb` pass. Faster probes with today's 20 s runtime are safe.

The production binary reads the owned regional NLB through fleet at startup
and again after health withdrawal begins. All three sets must match the new
health policy, FIVE_TUPLE, instant failover false and active preference false.
Unreadable, missing or differing settings retain 20 s with a warning. The
stop-time recheck covers an old reconciler restoring slow probes after
startup. Recheck/reapply after old leaders upgrade and during rollback.
There are no new runtime OCI writes or drain permissions. The effective
window appears in `X-TerraScale-Drain-Milliseconds`.

Oracle's [SDK reference](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/network_load_balancer/models/oci.network_load_balancer.models.HealthCheckerDetails.html)
and Go model document units/retries without numeric timing minima. API
acceptance and measured convergence remain ops gates; the worker made no
production changes. Existing flows stay on the unhealthy host with instant
failover off. New flows avoid it while a peer stays healthy. Fail-open still
routes to unhealthy backends if all fail; a config read cannot prove traffic
withdrawal or exclude simultaneous failures. Verify public NLB traffic under
load with healthy peers before relying on the bound.

## Timing attribution

The baseline journal and retained rollout record show 42.584 s shutdown to
host-gate pass on SJC, with another installed-to-ready sample of 46.247 s.
The PR retains the full phase table. These observation cadences do real work:

| Journal phase | Observation | Old → new cadence | Actual check |
| --- | --- | --- | --- |
| Startup → routes ready | Inventory consumer | 5 s → 1 s | Read inventory, refresh due proof, probe local services, update routes |
| Startup → health ready | Readiness worker | 3 s → 1 s | Probe routes/ingress/listeners and cache the verdict |
| Health OK → host gate pass | Host gate | 2 s → 1 s | Compare host/regional health, retaining four healthy seconds |
| Swarm ready → inventory published | Manager producer | 5 s → 5 s | Read services and publish inventory |

Shorter propagation saves fourteen seconds when established work does not
extend stop: roughly 29–32 s per host before observation savings, about 30 s
as an estimate. Work can still retain the edge until 25 s. Timing is never
achieved by shortening its completion budget. Measure from `node shutdown
started` to `host release gate passed`, distinct from the regional bake gate.
The gate log includes installed timestamp and elapsed time.

The historical two abandoned HTTPS connections cannot be classified.
New warnings count new/active/idle/hijacked states; the deliberate local
held streams identify one active SSE and one hijacked WebSocket.
