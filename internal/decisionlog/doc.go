// Package decisionlog is the decision journal of one regional cell: a record
// of what the orchestrator decided, why, and what came of it.
//
// Any slice that makes an automated decision calls
//
//	decisionlog.Record(ctx, decisionlog.Decision{...})
//
// Record is best effort. It never blocks on the network, never returns an
// error and never changes the outcome of the decision it describes: the
// decision is queued on a bounded in-memory queue and a background writer
// publishes it to the cell's replicated TS_DECISIONS JetStream stream. A full
// queue drops the record and counts it in ts_orch_decisions_dropped_total.
// Before a controller installs its Journal (and in processes that never do,
// such as one-shot CLI commands) records go to the structured log instead.
//
// Every controller tails the stream, so any member can answer queries for
// the whole region. Queries filter by region, kind, actor, subject and time
// and follow parent/child chains (release -> canary -> batch -> complete).
// Other regions are queried over NATS request/reply on
// ts.orch.v1.<region>.obs.decisions through regionlink.Links.
//
// The journal is read-only telemetry. Nothing in it is admission evidence,
// and nothing in the control plane reads it back to decide anything.
//
// See docs/decision-journal.md for the call pattern.
package decisionlog
