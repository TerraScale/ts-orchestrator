package app

import (
	"context"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/nats-io/nats.go/jetstream"
)

// A release fence (TS-610, the cell spec's release_fence) restarts a
// service release one node at a time. Before the leader submits a release
// it marks the release sequenced in the release channel bucket; every
// controller's host restart gate then holds a host's restart into it until
// the leader permits that node. The leader takes the nodes in turn: it
// fences the node's backends that are in rotation on the load balancer
// (drain, then offline after the grace), permits the node, waits until the
// node serves the release, returns the backends and waits for their health
// checks, then settles before the next node. A backend is fenced only
// while the set's quorum guard (min_serving backends of other nodes) serves
// healthy. The fenced backends are recorded before the load balancer
// changes, so a new leader returns them.
//
// Node operations and controller rollouts take nodes out the same way. A
// node's record names its holders: release, rollout and maintenance. Its
// backends return only when the last holder lets go.

// Holders of a node's fence.

type releaseFence struct {
	kv     jetstream.KeyValue
	hosts  seatrollout.Hosts
	fencer authority.Fencer
	// spec returns the cell spec's release fence, nil without one, and the
	// private address of each granted node.
	spec func() (*cellspec.ReleaseFence, map[string]string)
	// open returns the load balancer client; it is opened on first use.
	open func(context.Context) (lb.API, error)
	// seats reports TerraBase seats (controller.terrabase_seats), which
	// sequence TerraBase themselves.
	seats bool
	// sleep waits for a grace or a poll; tests shorten it.
	sleep func(context.Context, time.Duration) error

	mu  sync.Mutex
	api lb.API
	// nodes serializes the fences and restores of each node; quorum
	// serializes taking any backend out, so two nodes never pass the
	// quorum guard on the same observation.
	nodes  sync.Map
	quorum sync.Mutex
}
