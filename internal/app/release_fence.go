package app

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
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

func sequencedKey(role string, release uint64) string {
	return "fence." + role + "." + strconv.FormatUint(release, 10)
}

func fencedKey(node string) string { return "fenced." + node }

// Holders of a node's fence.

// releaseOf is the release a desired or report generation belongs to: a
// reconciled role's release-scoped generation, or the generation itself.
func releaseOf(generation uint64) uint64 {
	if release := workload.ReleaseOf(generation); release > 0 {
		return release
	}
	return generation
}

// fencedBackend is one backend a fence takes out of rotation.
type fencedBackend struct {
	// LoadBalancerID is the load balancer the backend was taken from; it
	// returns there whatever the cell spec names since.
	LoadBalancerID string `json:"load_balancer_id"`
	Set            string `json:"set"`
	IP             string `json:"ip"`
	Port           int    `json:"port"`
	// Weight and Backup are the backend's own, restored with it.
	Weight int  `json:"weight,omitzero"`
	Backup bool `json:"backup,omitzero"`
	// Offline is set once the backend is out of rotation.
	Offline bool `json:"offline,omitzero"`
	// Keep the admitted quorum when the live spec is changed or removed.
	Minimum int `json:"min_serving,omitempty"`
}

// fenceRecord is a node's fence, recorded before the load balancer
// changes: every backend taken, or being taken, out of rotation, and who
// holds it out.
type fenceRecord struct {
	Backends []fencedBackend `json:"backends"`
	Holders  []string        `json:"holders,omitempty"`
}

// releaseFence is the leader's side of a release fence. Every change it
// makes is guarded by the authority epoch it started under, so a deposed
// leader stops.
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
