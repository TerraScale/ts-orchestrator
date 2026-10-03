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

// maxLaggingStreams bounds how many lagging streams StreamHealth reports
// before it stops asking: one already holds a rollout step.
const maxLaggingStreams = 8

// streamInfoTimeout bounds one stream info request; a stream whose leader
// does not answer in time counts as lagging.
const streamInfoTimeout = 2 * time.Second

// StreamState is one stream as its leader reports it.
type StreamState struct {
	Name string
	// Peers are the brokers holding a replica, the leader included.
	Peers []string
	// Lagging is set for a stream without an answering leader, or with a
	// replica that is offline or not current (see StreamLagging).
	Lagging bool
}

// StreamHealth reports the cell account's streams for the rollout gate.
// Each stream's state comes from a STREAM.INFO request, which its leader
// answers for every replica, including out-of-band catchup that the local Jsz
// monitoring view does not show; so streams led by other brokers are judged
// as strictly as this broker's own. It stops after maxLaggingStreams lagging
// streams, so slow requests to leaderless streams cannot block the caller
// once the answer is already "hold".
func (r *Runtime) StreamHealth(ctx context.Context) ([]StreamState, error) {
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
	var states []StreamState
	lagging := 0
	for _, name := range names {
		requestCtx, cancel := context.WithTimeout(ctx, streamInfoTimeout)
		stream, err := r.js.Stream(requestCtx, name)
		cancel()
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		state := StreamState{Name: name, Lagging: true}
		if err == nil {
			info := stream.CachedInfo()
			state.Lagging = StreamLagging(info)
			state.Peers = streamPeers(info, r.server.Name())
		}
		states = append(states, state)
		if state.Lagging {
			if lagging++; lagging == maxLaggingStreams {
				break
			}
		}
	}
	return states, nil
}

// streamPeers lists the brokers holding a replica of a stream; an
// unclustered stream lives on this broker only.
func streamPeers(info *jetstream.StreamInfo, self string) []string {
	if info == nil || info.Cluster == nil {
		return []string{self}
	}
	var peers []string
	if info.Cluster.Leader != "" {
		peers = append(peers, info.Cluster.Leader)
	}
	for _, peer := range info.Cluster.Replicas {
		if peer != nil && peer.Name != "" && !slices.Contains(peers, peer.Name) {
			peers = append(peers, peer.Name)
		}
	}
	slices.Sort(peers)
	return peers
}

// StreamLagging reports whether a stream, as its leader describes it, has
// no leader or a replica that is offline or not current (including a
// replica still receiving an out-of-band snapshot). An unreplicated stream
// is never lagging; whether it survives a restart is a separate question
// the rollout gate answers from its peers.
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
