# Host install timing

The NLB health checker and planned-stop drain share `internal/nlbhealth`:
2 s interval, 1 s timeout, one retry. The drain covers an initial probe and
its retry, the final response timeout, and one second for probe scheduling
and health-state propagation: `2 s × (1 + 1) + 1 s + 1 s = 6 s`.
The margin is a conservative scheduling allowance, not an OCI convergence
guarantee; verify actual withdrawal during the controlled production rollout.

Health endpoints return 503 during propagation while application listeners
continue serving. HTTP shutdown still gets five seconds after propagation.
Inventory refresh, readiness reconciliation, and host-gate sampling run once
per second. The gate still requires four seconds of healthy observations and
checks regional services. The one-second systemd restart delay remains the
restart backoff for repeated failures.

The fleet NLB pass keeps FIVE_TUPLE routing, instant failover disabled, and
active/standby preference disabled. Existing flows stay on the unhealthy host
instead of moving to another backend. The TCP reset option applies only when
instant failover is enabled. New flows avoid the unhealthy backend while
another backend is healthy. Fail-open remains enabled: if every backend is
unhealthy, the NLB can send new flows to unhealthy hosts. One-at-a-time rollout
and the pre-install regional gate are required; this is not a guarantee for
simultaneous backend failures.

Oracle's [SDK health-checker documentation](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/network_load_balancer/models/oci.network_load_balancer.models.HealthCheckerDetails.html)
and the vendored Go SDK describe units and retry semantics but publish no
numeric minimum for interval or timeout. The 2000/1000 ms values have not been
submitted to the production API by this change. Confirm API acceptance and
read back the settings before relying on the shorter drain. Oracle documents
[health-check withdrawal](https://docs.oracle.com/en-us/iaas/Content/NetworkLoadBalancer/HealthCheckPolicies/health-check-policy-management.htm)
and [backend-set behavior](https://docs.oracle.com/en-us/iaas/Content/NetworkLoadBalancer/BackendSets/update-backend-set.htm).

## Production application

The current CLI for the fleet pass is `ts-orch region apply <label> nlb`.
Run the commands in the PR with the green merged binary and approved operator
credentials. The worker must not execute them. Capture the read-before state,
apply the NLB pass, and read again after its work requests complete. All three
backend sets must show interval 2000, timeout 1000, retries 1, FIVE_TUPLE,
instant failover false, and active-backend preference false.

Complete this before any process running the new binary stops with the
six-second drain. The first install stops the old process using its old drain;
rollback or a following install can stop the new process. The shortened
runtime must not be considered safe against an unapplied old NLB policy.

Observe one host's `/readyz` becoming unhealthy at the NLB while another
backend remains healthy. Send requests over existing flows and fresh
connections through the NLB, verify successful in-flight response completion,
and confirm fresh connections go to the healthy host before listeners close.
Stop rollout if API validation fails, a set retains the old policy, or
withdrawal exceeds six seconds. There is no runtime OCI permission addition,
backend drain mutation, or compatibility flag.

## Measurement

For release `7e9e29d6d243bf9b84b7c27139a8f6400ffc6b5e`, the production journal
on `ts-sjc-1` shows shutdown beginning at 2026-11-18 21:32:18.414770 UTC,
exit at 21:32:43.417412, systemd starting at 21:32:44.736214, mesh ready
at 21:32:46.649908, systemd ready at 21:32:47.479611, edge ready at
21:32:51.207304, and release health OK at 21:32:52.930417. Its retained
`nats/pull-rollout.json` records host ready at 21:33:00.998911772:
42.58 s from shutdown start. The other host's installed-to-ready interval was
46.25 s. The PR contains the full phase table and read-only OCI evidence.

The six-second propagation window removes fourteen seconds from those
samples. The one-second sampling removes additional observation latency;
expect roughly 29–32 seconds per host before those sampling savings. Treat
about thirty seconds as an estimate until the first controlled rollout.
The `host release gate passed` log records installed time and elapsed time.

The old journal reported two abandoned HTTPS connections without their HTTP
states. Their classification cannot be reconstructed. Go HTTP shutdown closes
idle keep-alives; the warning alone does not prove idle-only connections, so
the five-second allowance is retained. New warnings include new, active,
idle, and hijacked connection counts. The planned-stop E2E completes a finite
in-flight response during propagation and retains bounded closure of an
indefinite SSE stream and a hijacked WebSocket. Arbitrarily long-lived streams
are still bounded by the existing shutdown policy.
