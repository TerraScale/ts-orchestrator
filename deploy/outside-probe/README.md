# Outside probe

Cloudflare invokes `ts-orchestrator-outside-probe` with `*/5 * * * *`, outside
OCI. GitHub Actions has no schedule; its manual workflow reads the latest report.
The Worker checks global api, dash, auth and pg names and every regional api and
pg name in `deploy/m1/regions.json`. HTTP readiness bodies and regional identity
are validated. PostgreSQL names require a verified direct TLS connection to port
5432 through `cloudflare:sockets`, matching the previous probe's TLS check.

The secret `TS_ALERTS_NTFY_TOPIC` retains its Actions name and its value from OCI
Vault `gru-1-ts-alerts-ntfy-topic`. The monitoring heartbeat is read from the same
HMAC-derived ntfy topic as the relay. No synthetic notification reaches the phone.
Only confirmed production incidents and their recovery publish to the phone topic.

A SQLite Durable Object serializes runs and persists open incidents, their first
observation and last accepted page. Endpoint failures need consecutive scheduled
observations at least four minutes apart. A known monitoring heartbeat must be
ten minutes old; a missing or unreadable heartbeat must persist for ten minutes.
An open incident pages at most once every thirty minutes. A fresh report clears
the corresponding incident and sends one recovery for an incident that paged.
Notification failure leaves the incident available to the next scheduled run.
Provider acceptance followed by a process crash can still duplicate a page.

The Durable Object alarm watches completed probe reports independently of cron.
Reading the initial report arms it even before the first cron invocation. Ten
minutes without a completed report opens the `outside probe` incident. Starting
a probe does not postpone that deadline. The alarm examines only that incident;
it never infers an endpoint failure from missing observations. The next completed
run clears it. Both cron and alarms depend on Cloudflare being operational; this
does not provide a watchdog for a complete Cloudflare outage.

The read-only Worker root returns the last 24 scheduled runs with scheduled,
started and completed Unix millisecond timestamps, sanitized outcomes, and open
incident timestamps. It exposes neither the topic nor credentials. HTTP requests
cannot start a probe or publish a notification. Responses are not cached.
Cloudflare's fixed `observability.enabled` and `logs.enabled` settings retain every scheduled run for diagnosis.

## Deploy and verify

Use an authenticated `cf` session, from this directory on the pushed revision:

```sh
npm ci --ignore-scripts
cf deploy --dry-run
cf deploy --secrets-file /dev/stdin
```

Pipe a JSON object with the single `TS_ALERTS_NTFY_TOPIC` property into the last
command directly from OCI Vault; never put the value in an argument or log.
Subsequent deployments preserve the installed Worker secret. `cf deploy` applies
the cron trigger and provisions the SQLite Durable Object namespace.

Read the returned workers.dev URL once to arm the initial watchdog. After six
scheduled runs, retrieve its report and record each UTC start and completion
time in the PR. Consecutive scheduled minutes must be five minutes apart;
consecutive actual starts and completions must be at most 360 seconds apart.
The six observations must come from the deployed revision, with no intervening
deployment. Inspect every outcome, the latest heartbeat age and open incidents.
Do not force a failure or send a test page to obtain alert-delivery evidence.
