// Package devfake generates a realistic, moving, three-region world (GRU,
// SFO, FRA) for previewing the dashboard locally: cluster snapshots with
// controllers, NATS and JetStream, TerraBase placement, OCI API counters, a
// day of metric history, release rollouts, decision chains, insights and
// events.
//
// It is for local development only. The production binary never imports it:
// the only importer is cmd/ts-dashboard-preview, which builds only with the
// dashboardpreview build tag, and a test in this package fails if
// cmd/terrascale-orchestrator ever links it. Nothing here touches NATS, OCI
// or the disk.
//
// The fake still drives the real read-side code: snapshots go through the
// real history sampler and store, insights come from the real rule engine,
// region summaries from the real regionview provider and summaries from the
// real summarizer.
package devfake
