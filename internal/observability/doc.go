// Package observability is the leaf slice for metrics, health, structured
// logging, the in-memory event bus and cross-member telemetry of one regional
// cell. It imports no other feature slice: slices that measure something own a
// metrics.Set or produce one of the view-model types below, and the app wiring
// composes them into a Collector.
//
// The dashboard consumes only the interfaces in providers.go:
//
//   - SnapshotSource returns this member's MemberSnapshot.
//   - ClusterSource returns a ClusterSnapshot gathered from every controller of
//     the cell over NATS (ts.orch.v1.<cell>.obs.snapshot).
//   - EventSource returns recent notable events and streams new ones.
//
// Everything here is read-only. Nothing in this package mutates OCI, placement
// or authority state, and nothing it serves is used as admission evidence.
//
// The HTTP listener serves /metrics, /healthz and /readyz on a private
// address only: loopback by default, or an explicitly configured private
// address, such as a VCN or NetBird (10.200.0.0/16) one. Unspecified, CGNAT
// and public addresses are rejected.
package observability
