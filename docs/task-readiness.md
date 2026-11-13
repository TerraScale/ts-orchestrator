# Continuous task readiness

After a one-minute start grace, each host resolves a watched task's exact endpoint under its own five-second bound, then starts a fresh fifteen-second HTTP probe. Rounds collect all concurrent probes before evaluating witnesses, windows, correlation, and at most one replacement authorization, with ten seconds between the end of one host round and the start of the next, keeping due tasks in the same round. Failed or timed-out lookups are not observations and contribute no failure evidence. A task using a dynamic PORT needs a readable, valid, nonzero task port label; the shared service port is never substituted.

A failing observation means the request reached that exact task, was fully written, and received no first response byte before its deadline. It advances the five-minute replacement window only when another watched task on this host answers in that round; owners and services without replacement permission also count as witnesses. For the host's only watched task, the prober instead uses the agent's loopback health endpoint as witness. Suspect rounds and unavailable endpoints pause evidence; a witnessed observed non-failure clears the replacement window. Any answering probe, including HTTP 503, independently clears the reporting clock and replacement window even without a witness.

A task is failing with evidence in a round only when its probe goes unanswered and that round has a witness. Replacement of task A is vetoed if any other eligible task accumulates at least sixty seconds of overlapping failing rounds during A's current failing window; a single failed probe, an unwitnessed failure, or absence from the round contributes no overlap.

Automatic replacement requires the boolean readiness.replaceWhenUnresponsive to be true in the service declaration, an explicit readyPath, positively established absence of data ownership, five minutes of witnessed unanswered probes, no qualifying correlation, and an available host budget. The field defaults to false when absent. An operator can add the following section to a stateless service declaration:

~~~json
"readiness": {
  "replaceWhenUnresponsive": true
}
~~~

The field is intended for stateless services with more than one way to be served or that are quick to restart. The authentication service and dashboard are the intended first users. This change adds the field to no deployed service declaration: rolling out the agent alone replaces nothing. Apply refuses a true value on a service with any mount or storage binding, with an error explaining that the service owns data; a declared readiness path is also required. Inspection preserves the field, and configuration rolls carry it in the task template and service labels. An older node rewriting the declaration without this field makes the service ineligible, the safe direction.

Every watched task is observed and reported regardless of this field. Databases, qualified or stateful members, TerraBase tasks, and every task with a mount are retained. Unknown ownership, including an error determining it, is retained. An authorized replacement stops the original process before reporting the normal failure to the scheduler. Readiness observer errors and deadlines never enter a qualified member's execution scope or lifecycle error path.

Each watched task has a ts_orch_task_unresponsive_seconds{task,service} gauge. Once the five-minute reporting threshold is crossed, it reports wall time since the first unanswered observation, including suspect rounds, independently of witnessed replacement evidence. It returns to zero on the first answering probe, witnessed or not, and disappears when observation ends. Each retained episode logs one warning and one "task readiness unresponsive window cleared" line when it answers again.

| Situation | Operator sees | Action |
| --- | --- | --- |
| Data owner | not replaced: data owner, duration gauge | Retained |
| Unknown ownership | not replaced: ownership unknown, duration gauge | Retained |
| Service has not requested replacement | not replaced: service has not requested replacement, duration gauge | Retained |
| No task or local witness answered | not replaced: no witness answered, duration gauge | Retained; no new evidence |
| Eligible sibling overlaps for at least sixty seconds of witnessed failure | not replaced: correlated with N other tasks, duration gauge | Retained for this failing window |
| Host budget used or cannot be safely established | not replaced: host replacement budget unavailable, duration gauge | Retained and reconsidered |
| Exact endpoint unavailable within five seconds | ts_orch_task_readiness_unobserved_total{task,service} increments per skipped round; one "task readiness not observed: exact task endpoint unavailable" warning per watch | No observation |

Each host authorizes at most one replacement across all services in any fifteen minutes. The budget is serialized and synced to persistent agent state before authorization, survives agent and host restarts, and denies replacement for unreadable or invalid records. Denied tasks keep their evidence and are reconsidered. After authorization, slot preparation waits one, two, four, eight, then fifteen minutes after repeated readiness failures. Thirty minutes of successful witnessed observations clears this per-slot history.

Decisions are per host. A fault affecting several hosts can lead each host to replace one eligible task. A readiness handler that hangs on a dependency while its task still serves traffic can cause replacement when that task alone fails and witnesses answer. Services should bound their own readiness checks.

Metrics are exported on the orchestrator and host metrics listeners; alert rules belong to monitoring configuration.

The main M1 lane keeps the quick process and service continuity, keys, and data retention checks across agent restart, with a fifteen-minute job limit. A separate timed lifecycle job runs on changes to liveness, controller, backoff, endpoint, ownership, service readiness configuration, member-readiness client, lifecycle lane, or CI workflow paths, and nightly. The required all-green check waits for the timed job when it runs, accepts its intentional skip otherwise, and retains the existing failure and cancellation semantics for every other job. The lifecycle uses the real product constants, including the fifteen-minute budget, with no product test switches.
