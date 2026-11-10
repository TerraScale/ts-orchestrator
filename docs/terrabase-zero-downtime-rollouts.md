# TerraBase rollouts with two nodes per region

Status: candidate implementation under qualification. The live acceptance proof is pending.
The earlier static-seat/L7 load-balancer design has been replaced by the regional
mesh and per-request edge routing described here.

## Ownership and replication

Each region has one writer, chosen by a quorum-backed compare-and-set in the
`terrabase-region-owners` JetStream bucket. Admission requires a recent quorum
renewal. The other node follows the writer through normal region replication,
including databases homed in the same region. It retains its R10 acknowledgement
holds; promotion never overwrites its system database with its peer's file.

The follower forwards customer requests to the regional writer. Both nodes can
therefore receive HTTP requests, while only the fenced owner applies writes.
Regional ownership also selects the node other regions contact for replication
and forwarding. A logical catalog snapshot carries admission policy and tenant
metadata needed for the first request after promotion.

## Replacement sequence

Swarm updates one task at a time. Before a running TerraBase task receives
SIGTERM, its executor asks the regional founder for a drain through NATS. Missing
membership, an unavailable drain coordinator, or an unready peer denies the stop.

1. Prime the candidate's catalog and replicas while the old writer serves.
2. Hold new edge requests in a bounded, cancellation-aware queue. Existing
   requests keep their admission lease through response-body completion.
3. Drain the source's direct HTTP ingress too, then fence new local writes and
   finish open native write transactions. Freeze its replica pulls before sampling
   final applied positions.
4. Require the survivor to prove matching database incarnations and applied
   revisions at or beyond every sampled source position. `/readyz` alone never
   authorizes stopping a node. For writer replacement, prepare local primaries
   from the proven replicas and transfer logical catalog records atomically.
5. Commit the regional owner CAS. The new owner acquires database leases and
   renews write admission. Keep the barrier until it reports Writer and Ready
   and every admitted peer has observed that owner and epoch. This prevents a
   remote forwarder from retaining the old home address across listener shutdown.
6. Route queued and new requests to that survivor, then SIGTERM the old process.
   The next replacement must pass the same peer proof against the newly started
   node. There is no shadow process or simultaneous use of a node's data directory.

Replacing a follower still verifies the surviving writer against the follower's
frozen applied positions. A failed pre-CAS handoff confirms ownership through the
quorum before resuming the source. An ambiguous outcome leaves writes fenced.

The edge routes each internal HTTP/2 request independently, so pooled auth and
dashboard connections do not remain pinned to a process being replaced.

## Evidence and acceptance

The acceptance load offers five writes and five
reads per second in each of gru, sjc and fra, without retrying measured requests.
Latency includes time waiting from the scheduled arrival. Missed arrivals count
as failures. Final inventory reconciles acknowledged writes and duplicate IDs.

Acceptance requires three recorded replacement windows,
complete load coverage, zero failed requests and p99 below 500 ms in every
region and operation for every repeat. Each window includes ten seconds before
replacement and sixty seconds after completion, including post-rollout errors
and recovery. Cleanup must be confirmed. Record source/target revisions, actual
task replacements, and drain/promotion/readiness timestamps with the live report.

TerraBase Slow tests exercise two real app listeners, promotion and handback,
and a subprocess killed while its native write transaction is open before COMMIT.
The crash drill checks exact acknowledged IDs after restart and promotion.
It does not claim automatic regional crash takeover.

Final pre-ship qualification on engine source `e6c076621` passed all five
measured repeats of both regional Slow tests (10 tests total, suite times
11.136 / 10.996 / 10.325 / 11.234 / 11.591 seconds). The existing R10
`InRegionAckDrillTests` also passed (13.524 seconds). Logs:
`/tmp/zdt-final-slow.log` on beta. The shipping candidate differs only in
initializer whitespace and rebased documentation. Orchestrator full Fast
passed 885 cases across 343 shards, longest shard 4.29 seconds; log:
`/tmp/zdt-orch-fast3.log` on beta. These are development proofs; the three
live rollout measurements remain pending.

## Boundaries

This candidate covers HTTP request routing and planned TerraBase task replacement.
PostgreSQL and native wire sessions need their own session-aware routing/drain
proof before they can be called zero-downtime. Region bootstrap remains documented
in [region-bootstrap.md](region-bootstrap.md). Durable notice replay across
orchestrator/NATS restarts (#1104) is separate and has not been proven here.
