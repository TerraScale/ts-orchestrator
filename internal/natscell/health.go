package natscell

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// ClusterObservation is a point-in-time, read-only view of this broker's
// routes and JetStream metadata group. ExpectedPeers are the signed broker
// server names; it is empty in a lab without BrokerIDs.
type ClusterObservation struct {
	ServerName    string
	Running       bool
	ExpectedPeers []string
	Routes        []string
	MetaLeader    string
	MetaSize      int
	MetaQuorum    int
	MetaPeers     []MetaReplica
}

// ErrJetStreamDisabled reports a running embedded server whose JetStream is
// not enabled, for example after a store failure shut JetStream down.
var ErrJetStreamDisabled = errors.New("embedded JetStream is disabled")

// ObserveCluster reads Routez and Jsz from the embedded server. It never
// mutates cluster state and is safe to call from a periodic supervisor.
func (r *Runtime) ObserveCluster() (ClusterObservation, error) {
	if r == nil || r.server == nil {
		return ClusterObservation{}, errors.New("cluster observation requires an embedded regional NATS server")
	}
	observation := ClusterObservation{ServerName: r.serverName, Running: r.server.Running(),
		ExpectedPeers: slices.Clone(r.brokerNames)}
	if !observation.Running {
		return observation, nil
	}
	if routes, err := r.server.Routez(nil); err == nil {
		for _, route := range routes.Routes {
			if route != nil && route.RemoteName != "" && !slices.Contains(observation.Routes, route.RemoteName) {
				observation.Routes = append(observation.Routes, route.RemoteName)
			}
		}
		slices.Sort(observation.Routes)
	}
	info, err := r.server.Jsz(nil)
	if err != nil {
		return observation, err
	}
	if info.Disabled {
		// JetStream was never enabled or was shut down after a store
		// failure, which also clears JetStreamIsClustered while the NATS
		// server keeps running. Never present that as a healthy group.
		return observation, ErrJetStreamDisabled
	}
	if info.Meta == nil {
		if !r.server.JetStreamIsClustered() && len(r.brokerNames) <= 1 {
			// A standalone broker is its own single-member metadata group.
			observation.MetaLeader, observation.MetaSize, observation.MetaQuorum = r.serverName, 1, 1
		}
		return observation, nil
	}
	observation.MetaLeader = info.Meta.Leader
	observation.MetaSize = info.Meta.Size
	observation.MetaQuorum = info.Meta.QuorumNeeded
	observation.MetaPeers = metaReplicas(info.Meta.Replicas)
	return observation, nil
}

// maxLaggingStreams bounds the names LaggingStreams returns.
const maxLaggingStreams = 8

// laggingStreamTimeout bounds one stream info request; a stream whose
// leader does not answer in time counts as lagging.
const laggingStreamTimeout = 2 * time.Second

// LaggingStreams lists the cell account's replicated streams that could lose
// availability if one more broker restarted now: a stream whose leader does
// not answer, and a stream with any offline or not-current replica. Each
// stream's state comes from a STREAM.INFO request, which its leader answers
// for every replica, including out-of-band catchup that the local Jsz
// monitoring view does not show; so streams led by other brokers are judged
// as strictly as this broker's own. The rollout gate holds a controller step
// while any stream is listed.
func (r *Runtime) LaggingStreams(ctx context.Context) ([]string, error) {
	if r == nil || r.server == nil || !r.server.Running() || r.js == nil {
		return nil, errors.New("embedded regional NATS server is not running")
	}
	if info, err := r.server.Jsz(nil); err != nil {
		return nil, err
	} else if info.Disabled {
		return nil, ErrJetStreamDisabled
	}
	lister := r.js.StreamNames(ctx)
	var names []string
	for name := range lister.Name() {
		names = append(names, name)
	}
	if err := lister.Err(); err != nil {
		return nil, fmt.Errorf("list streams: %w", err)
	}
	slices.Sort(names)
	var lagging []string
	for _, name := range names {
		requestCtx, cancel := context.WithTimeout(ctx, laggingStreamTimeout)
		stream, err := r.js.Stream(requestCtx, name)
		cancel()
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil || StreamLagging(stream.CachedInfo()) {
			lagging = append(lagging, name)
			// One name already holds the gate; stop before more slow
			// requests to leaderless streams can block the caller.
			if len(lagging) == maxLaggingStreams {
				return lagging, nil
			}
		}
	}
	return lagging, nil
}

// StreamLagging reports whether a stream, as its leader describes it, has
// no leader or a replica that is offline or not current (including a
// replica still receiving an out-of-band snapshot). An unreplicated stream
// is never lagging.
func StreamLagging(info *jetstream.StreamInfo) bool {
	if info == nil {
		return true
	}
	cluster := info.Cluster
	if cluster == nil {
		return false
	}
	if cluster.Leader == "" {
		return true
	}
	for _, peer := range cluster.Replicas {
		if peer == nil || peer.Offline || !peer.Current {
			return true
		}
	}
	return false
}

// PeerRoutes returns the production seed-route shape: every signed controller
// route except this node's own. NATS bootstraps the JetStream metadata group
// with max(2, len(routes)) expected peers, which for an odd cluster size N
// gives the same quorum (N-1)/2+1 as N/2+1, so omitting the self route never
// lowers the safety threshold. Tests use this helper so they exercise the
// exact shape that signed controller configs carry.
func PeerRoutes(routes []string, self string) []string {
	peers := make([]string, 0, len(routes))
	for _, route := range routes {
		if route != self {
			peers = append(peers, route)
		}
	}
	return peers
}
