# Task readiness reporting

The agent probes every running task whose container specification names a readiness path. It resolves that exact task's endpoint rather than a shared service port. Ordinary tasks without a readiness path are not observed. Qualified storage members have a fixed readiness path, /v1/member/status, on their bound Unix endpoint and use verified runtime identity.

Each host completes one round across its tasks, then waits ten seconds. Each task is probed once per round, with at most one probe goroutine per task. Endpoint and runtime identity resolution have a five-second bound, separate from a fresh fifteen-second HTTP deadline. Qualified members also verify identity after the exchange with a separate five-second bound. Requests do not follow redirects, use an environment proxy, or reuse connections.

An unanswered observation means the endpoint accepted the request but sent no response before the HTTP deadline. An unavailable endpoint, connection, or runtime identity is unobserved, never a failure. An unobserved round breaks the measured consecutive period. Any answer, including HTTP 503, clears that period on the first answering round: a task answering “not ready” is alive; readiness failure is a separate condition already exposed by readiness monitoring.

## Signals and alerting

- `ts_orch_task_unresponsive_seconds{task,service}` rises from the start of the first unanswered request, as soon as that observation completes. It does not wait for the warning threshold. It is zero after an answer or an unobserved round.
- `ts_orch_task_readiness_others_answered{task,service}` is one when another watched task on the host answered in the same round, zero otherwise. For an unresponsive task, one indicates an isolated failure; zero means no other watched task answered, which can also mean peers were unobserved or absent. This is information for operators only.
- `ts_orch_task_readiness_unobserved_total{task,service}` counts rounds without a usable observation.

The service label is the declared service name, or the existing runtime role for qualified members (terrabase). Each watch removes all its series when it closes. A new watch, including after an agent restart, starts with empty evidence. Agent restarts retain task processes and serving continuity.

After four minutes of consecutive unanswered observations, the agent writes one warning per episode with the task ID and whether other tasks answered. The first answer clears the episode. Unknown intervals reset the gauge but do not produce repeated episode warnings before an answer. There is no attachment grace; with host round and HTTP bounds, a newly hung task is normally reported within about five minutes. The gauge is available earlier so alerts can choose their own threshold.

The installed operational rules page critically for `service="terrabase"` and warn for other services when the gauge reaches 240 seconds. They add no further pending period. Scrape and rule evaluation intervals add their own delivery delay.

The prober only reports. It never stops, restarts, or replaces a task, and never changes ingress eligibility. It cannot detect a task that answers its readiness endpoint while failing real work, or a task without a readiness path.

## Journey

The readiness lane freezes tasks with SIGSTOP on two isolated hosts. It checks reporting within 4m50s, a rising gauge before the threshold, exactly one warning, unchanged process IDs for over 6m15s, both peer-answer cases, and clearing on thaw. It also checks slow endpoint resolution, slow qualified-member identity resolution with a healthy four-second response, non-success answers, and series cleanup. The restart lane retains the quick continuity check. The readiness lane has a ten-minute job limit; its measured runtime is printed in the job log.
