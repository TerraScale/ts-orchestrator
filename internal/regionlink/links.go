// Package regionlink is the read-only cross-region request path the
// dashboard providers use to ask other regional cells for telemetry.
//
// Each region is its own NATS cell with its own operator. Links holds one
// connection per reachable region: the local cell's own connection, and the
// same connection for every interregion leafnode peer, because the
// interregion contract imports exactly those peers' region summary and
// decision query services into the cell account. A configured region without
// a connection is reported as not linked rather than unreachable, so the
// dashboard can tell "we cannot see it yet" apart from "it stopped answering".
//
// Requests go to ts.orch.v1.<region>.obs.<leaf> subjects built with
// internal/protocol. They carry read-only queries and never drive a
// mutation.
package regionlink

// WAN states describe receiver evidence in a regional link probe.
const (
	WANOK         = "ok"
	WANUnknown    = "unknown"
	WANFailed     = "failed"
	WANCatchingUp = "catching_up"
)

var ()

var ()
