# Regional rollout baseline, 2026-11-05

This is the failing baseline, not acceptance of the proposed rollout change. No ZDT changes were deployed for this run.

Offered load: 5 writes/s and 5 reads/s per region, gru/sjc/fra, 1,200 seconds, no request retries. One all-region database, home gru. Fixed-rate probe revision c0c72d839. Load started 19:50:12.496Z. The first implementation used an unbounded executor queue; its latency measures request execution and excludes queued schedule delay. Preserve that limitation when comparing with the corrected bounded probe. Every one of the 36,000 offered requests produced a record.

| Region | Operation | Requests | Failed | p99 ms | HTTP counts (0 = transport failure) | Last failed completion UTC |
| --- | --- | ---: | ---: | ---: | --- | --- |
| gru | write | 6000 | 260 | 202.117 | {200: 5740, 0: 25, 429: 235} | 19:56:50.050 |
| gru | read | 6000 | 324 | 129.195 | {200: 5676, 0: 21, 429: 303} | 19:56:50.197 |
| sjc | write | 6000 | 324 | 683.463 | {200: 5676, 429: 295, 400: 2, 0: 27} | 19:56:50.386 |
| sjc | read | 6000 | 315 | 647.824 | {200: 5685, 429: 294, 400: 2, 0: 19} | 20:06:48.522 |
| fra | write | 6000 | 273 | 693.915 | {200: 5727, 0: 27, 429: 246} | 19:56:50.349 |
| fra | read | 6000 | 333 | 675.121 | {200: 5667, 429: 314, 0: 19} | 19:56:50.415 |

SJC returned two write 400s and two read 400s. First captured SJC write 400: request `01M6PM9Q1HN9SG47JT796G84BR`, sequence 603, 10,503.293 ms client duration, machine ts-sjc-1. Errors and throttling persisted after the restart; bounded recovery and absence of backlog are part of acceptance.

The raw log remains at beta `/tmp/zdt-baseline.jsonl`, SHA-256 `c69cc2b24802050320ba27214cdbcad557433f52faddfef6f837485eb3ae4ba2`. Final inventory encountered a transport disconnect; the finally block deleted the owned database `01M6PM5WXB7P7N3MM27B9HJVDS`, HTTP 204. The synthetic account remains active only for subsequent measurements and must be deleted after proof.

The fixed probe counts saturation as failed offered arrivals, bounds concurrency to 96, includes schedule delay in latency, supports graceful interruption, and preserves summaries when inventory fails. A separate run will observe #1105 deployment; its failures remain baseline observations.
