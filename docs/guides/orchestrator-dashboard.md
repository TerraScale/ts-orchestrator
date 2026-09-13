# Orchestrator observer dashboard

The observer is a read-only Datastar dashboard for operators. It is served by
the standalone `cmd/orchestrator-dashboard` binary and has no mutation routes.
The UI is embedded in the binary, uses one stylesheet, ApexCharts for charts,
Lucide for icons, and the Monocraft font.

Run it on a Tailscale-connected host:

```bash
go run ./cmd/orchestrator-dashboard
```

The default listener is `0.0.0.0:18447`, so the dashboard is available at
`http://<tailscale-ip>:18447`. Set `TS_ORCH_DASHBOARD_LISTEN` to choose another
address. `/healthz` is the only non-UI endpoint that does not return state.

The dashboard has no demo or fallback data. For a live orchestrator projection,
write the `dashboard.State` JSON schema to an owner-readable file and set
`TS_ORCH_DASHBOARD_STATE_FILE`. The dashboard reloads that file every two
seconds and pushes changes to connected browsers over SSE. The file must
contain observations only; credentials and customer data must never be written
to it.

The dashboard deliberately does not connect to NATS or provider APIs from the
browser. A future runtime adapter should build this projection from the
orchestrator's existing snapshots and publish it to the file or to a dedicated
read-only source.
