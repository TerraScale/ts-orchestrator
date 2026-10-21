// Package devfake generates a moving, three-region world (GRU, SJC, FRA)
// for dashboard tests: cluster snapshots with
// controllers, NATS and JetStream, TerraBase placement, OCI API counters, a
// day of metric history, release rollouts, decision chains, insights and
// events.
//
// Every fixture is in a _test.go file, so executable builds cannot import it.
// Nothing here touches NATS, OCI or the disk.
//
// The fake still drives the real read-side code: snapshots go through the
// real history sampler and store, insights come from the real rule engine,
// region summaries from the real regionview provider and summaries from the
// real summarizer.
package devfake
