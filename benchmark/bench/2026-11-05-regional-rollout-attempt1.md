# Regional rollout: first measured candidate failed

Engine `4ca02445eddca974fd970d7026271a91a0f1315d`; orchestrator
`9fd04b8335aaba3daf4557c01e6718ece2690feb`. This attempt does not count toward
three required passing rollouts. Release run 42114021125, attempt 2, rebuilt the
same engine revision and began actual SJC process replacement.

Fixed offered load: 5 writes and 5 reads/second/region, no request retries;
12,840 total measured requests (2,140 per operation per region). Latency includes
client scheduling and admission waits. Source image digest
`sha256:efe06fd2f87bbdd60592ae2fa94f9b0d91980bb8304a49531c29d76f0dbfbe56`;
SJC target `sha256:9b545b77206d552ed9dbf12b3eb703c54ddfa2635d196955abfa011287884eda`.

| Region | Write failures | Read failures | Write p99 ms | Read p99 ms |
|---|---:|---:|---:|---:|
| GRU | 0 | 0 | 147 | 134 |
| SJC | 35 | 36 | 3468 | 3467 |
| FRA | 0 | 0 | 737 | 701 |

SJC phases (2026-11-05 UTC): replacement requested 21:55:47.518030774;
edge drained 21:55:48.398174652; source fenced 21:55:48.587242;
writer moved to `ts-sjc-2`, epoch 2, 21:55:55.358725;
surviving writer verified 21:55:55.364977035. Five database positions were proven.
The edge held requests for 6.97 seconds, then released the backlog together.
All 71 failures were HTTP 429, completing between 21:55:56.008162 and
21:55:56.388943 UTC. No failures occurred in the final 30 seconds of the load.
Maximum SJC latency was 7.67 seconds.

The replacement subsequently stalled: the SJC worker's old serving container
`ts-l92mve1kkycoas4wfavtptf8y` retained ports 6432/8080 after its Swarm assignment
disappeared. Health alone showed six ready listeners; task inventory exposed the
stalled worker replacement. Future completion checks require both inventories.

All three final inventories exactly matched 6,385 acknowledged IDs and their
(region, sequence) values; zero missing, unexpected, or changed rows. Sorted-ID
SHA-256: `aff0e77f693011896cb8457881ecc13219a4109e68c4cbb45b6c8f1cf215409d`.
Database deletion returned 204. The probe stopped; no proof load remains active.

Raw evidence on beta: `/tmp/zdt-fixed-failed1.jsonl`,
`/tmp/zdt-first-source-handoff.jsonl`, `/tmp/zdt-first-rollout-health.jsonl`.
FRA latency also included first-use TLS connections as the thread pool expanded;
the next harness uses a warmed, bounded four-connection pool per region while
continuing to include all pool waits in offered latency.

DECISION: resume edge admission when the promoted candidate is ready, retain the
source completion barrier before SIGTERM, pace queued arrivals, retry temporary
drain failures, and retire retained predecessors through the same peer proof.
Reason: the measured attempt exposed both a backlog burst and an orphaned live
process; neither may be hidden by health-only completion checks.
