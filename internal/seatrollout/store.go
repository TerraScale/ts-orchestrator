// Package seatrollout restarts the TerraBase seats of a cell one at a time
// without dropping a request (TS-571): a seat is drained on the public load
// balancer before its host may restart it, and returns to rotation once it
// serves again. This file holds the durable per-seat records that the load
// balancer publisher and the host restart gate read.
package seatrollout

import (
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Bucket is the replicated KV bucket with one record per seat, keyed by
// node. It is durable so a new leader keeps a seat drained that its
// predecessor drained, instead of returning it to rotation mid-restart.
const Bucket = "TS_TERRABASE_SEATS"

// ErrInvalid reports a malformed or misplaced seat record. Readers fail
// closed on it: no backend set is published and no restart is granted.
var ErrInvalid = errors.New("seat record is invalid")

// Seat is one seat's rollout state.
type Seat struct {
	Node string `json:"node"`
	// Drain keeps the seat drained on the public load balancer.
	Drain bool `json:"drain,omitzero"`
	// DrainedAt is when Drain was set; in-flight requests get a grace
	// from it.
	DrainedAt time.Time `json:"drained_at,omitzero"`
	// Permit is the highest desired generation the seat's host may restart
	// its member into.
	Permit uint64 `json:"permit,omitzero"`
	// Epoch is the authority epoch the record was written under.
	Epoch uint64 `json:"epoch"`
}

// Reader observes existing seat records without mutation or restart authority.
type Reader struct {
	kv     jetstream.KeyValue
	leader nats.JetStreamContext
}
