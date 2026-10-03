package natscell

import (
	"errors"
	"slices"

	"github.com/nats-io/nats-server/v2/server"
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

// LaggingStreams lists replicated streams that could lose availability if
// one more broker restarted now: a stream without a leader, and a stream
// this broker leads with an offline or not-current replica. Replica state of
// streams led elsewhere is not judged, because a follower's view of it can
// be stale. The rollout gate holds a controller step while any is listed.
func (r *Runtime) LaggingStreams() ([]string, error) {
	if r == nil || r.server == nil || !r.server.Running() {
		return nil, errors.New("embedded regional NATS server is not running")
	}
	info, err := r.server.Jsz(&server.JSzOptions{Accounts: true, Streams: true})
	if err != nil {
		return nil, err
	}
	if info.Disabled {
		return nil, ErrJetStreamDisabled
	}
	name := r.server.Name()
	var lagging []string
	for _, account := range info.AccountDetails {
		if account == nil {
			continue
		}
		for _, stream := range account.Streams {
			cluster := stream.Cluster
			if cluster == nil || len(cluster.Replicas) == 0 && cluster.Leader != "" {
				continue
			}
			behind := cluster.Leader == ""
			if cluster.Leader == name {
				for _, peer := range cluster.Replicas {
					behind = behind || peer == nil || peer.Offline || !peer.Current
				}
			}
			if behind && len(lagging) < maxLaggingStreams {
				lagging = append(lagging, stream.Name)
			}
		}
	}
	slices.Sort(lagging)
	return lagging, nil
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
