# Continuous task readiness

Tasks with a declared readiness endpoint are probed throughout their lifetime after a one-minute start grace. A probe has a 15-second deadline, with at least ten seconds between probes. Only a request fully written without any first response byte before its deadline contributes to the consecutive five-minute unresponsive window. Any answered probe, including HTTP 503, or another error resets that window. A missing observation interval resets it as well.

Tasks that own no data, such as identity or dashboard services without mounts, are failed and replaced after this window. The original process is stopped before failure is reported. Replacement preparation waits one minute after a readiness failure, doubling after repeated failures to a fifteen-minute cap. Thirty minutes of successful probes clears that history.

Databases, stateful or qualified members, and any task with a mount are only observed by this watch. It never fails, stops or replaces them, regardless of peer readiness. The gauge `ts_orch_task_unresponsive_seconds{task,service}` reports the current unresponsive window in seconds, returns to zero when the predicate clears, and is removed when observation ends. The watch logs once on crossing five minutes and once when that window clears. An operator decides how to respond. Probe results and deadlines never enter the qualified task's execution scope or lifecycle error path; existing status calls and their timeouts retain their meaning.

Readiness metrics are exported on the private orchestrator and host metrics listeners. An alert rule for this gauge belongs to the monitoring change.

Stopping and starting an agent, including during an orchestrator release, leaves assigned task processes running. The M1 journey checks the same process IDs while stopped and after startup, along with replacement of a frozen task without data and retention, rising telemetry and recovery of a frozen task with a data mount.
