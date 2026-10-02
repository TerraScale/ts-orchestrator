package natscell

import (
	"errors"
	"slices"
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
	if info.Meta == nil {
		if !r.server.JetStreamIsClustered() {
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
