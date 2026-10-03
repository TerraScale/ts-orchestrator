// Package clusterhealth supervises the regional controller cluster after
// startup. It reads broker route and JetStream metadata views, classifies the
// cluster's health against the signed broker set, and reports structured
// status. It never mutates cluster membership.
package clusterhealth

import (
	"slices"
	"time"
)

// Peer is one remote JetStream metadata peer as seen by the local broker.
type Peer struct {
	Name    string
	Current bool
	Offline bool
	Active  time.Duration
	Lag     uint64
}

// Observation is one read-only snapshot from the local broker. Expected holds
// the signed broker server names and is empty when none were configured.
type Observation struct {
	ServerName string
	Running    bool
	Expected   []string
	Routes     []string
	MetaLeader string
	MetaSize   int
	MetaQuorum int
	Peers      []Peer
}

// StaleContact is the metadata leader's lost-contact bound: the vendored NATS
// server stops reporting a peer current once it has not been heard from for
// its lost-quorum interval (ten seconds).
const StaleContact = 10 * time.Second

// Phase is the coarse cluster state a readiness probe or alert can key on.
type Phase string

const (
	// PhaseHealthy: a metadata leader exists, every signed broker is online and
	// current, the metadata group size equals the signed set, and no unknown
	// peer is present.
	PhaseHealthy Phase = "healthy"
	// PhaseDegraded: a metadata leader exists, but a signed broker is offline
	// or lagging, the group size differs, or an unknown peer appeared.
	PhaseDegraded Phase = "degraded"
	// PhaseNoLeader: no JetStream metadata leader is visible. This covers both
	// initial joining and quorum loss; Online tells them apart.
	PhaseNoLeader Phase = "no_leader"
	// PhaseStopped: the local embedded broker is not running.
	PhaseStopped Phase = "stopped"
	// PhaseUnknown: the local broker could not be observed.
	PhaseUnknown Phase = "unknown"
)

// LaggingPeer is a reachable peer that is not caught up with the leader.
type LaggingPeer struct {
	Name string `json:"name"`
	Lag  uint64 `json:"lag"`
}

// Status is the evaluated cluster health. All name lists are sorted server
// names so equal states compare equal and log lines stay stable.
type Status struct {
	ObservedAt   time.Time     `json:"observedAt"`
	Phase        Phase         `json:"phase"`
	ServerName   string        `json:"serverName,omitempty"`
	MetaLeader   string        `json:"metaLeader,omitempty"`
	MetaSize     int           `json:"metaSize"`
	QuorumNeeded int           `json:"quorumNeeded"`
	Expected     []string      `json:"expected,omitempty"`
	Online       []string      `json:"online,omitempty"`
	Offline      []string      `json:"offline,omitempty"`
	Missing      []string      `json:"missing,omitempty"`
	Lagging      []LaggingPeer `json:"lagging,omitempty"`
	Unknown      []string      `json:"unknown,omitempty"`
	Unrouted     []string      `json:"unrouted,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// Healthy reports whether the cluster is fully formed and caught up.
func (status Status) Healthy() bool { return status.Phase == PhaseHealthy }

// sameState ignores the observation time so supervisors log transitions only.
func (status Status) sameState(other Status) bool {
	return status.Phase == other.Phase && status.ServerName == other.ServerName &&
		status.MetaLeader == other.MetaLeader && status.MetaSize == other.MetaSize &&
		slices.Equal(status.Online, other.Online) && slices.Equal(status.Offline, other.Offline) &&
		slices.Equal(status.Missing, other.Missing) && slices.Equal(status.Unknown, other.Unknown) &&
		slices.Equal(status.Unrouted, other.Unrouted) && status.Error == other.Error &&
		slices.EqualFunc(status.Lagging, other.Lagging, func(a, b LaggingPeer) bool { return a.Name == b.Name })
}

// Evaluate classifies one observation. A peer is lagging when its reported lag
// exceeds lagThreshold operations, or when this broker's Raft view shows it out
// of contact (see peerLagging).
//
// Missing lists signed brokers absent from the metadata peer set entirely
// (never joined or removed); Offline lists signed brokers the metadata group
// knows but currently marks offline. Unknown lists metadata peers outside the
// signed set, such as a renamed slot or a stale identity.
func Evaluate(observation Observation, lagThreshold uint64, now time.Time) Status {
	status := Status{ObservedAt: now, ServerName: observation.ServerName, MetaLeader: observation.MetaLeader,
		MetaSize: observation.MetaSize, QuorumNeeded: observation.MetaQuorum,
		Expected: sortedUnique(observation.Expected)}
	if !observation.Running {
		status.Phase = PhaseStopped
		return status
	}
	expected := make(map[string]bool, len(status.Expected))
	for _, name := range status.Expected {
		expected[name] = true
	}
	known := map[string]bool{observation.ServerName: true}
	online := []string{observation.ServerName}
	var offline, unknown []string
	for _, peer := range observation.Peers {
		if peer.Name == "" || peer.Name == observation.ServerName || known[peer.Name] {
			continue
		}
		known[peer.Name] = true
		if len(expected) != 0 && !expected[peer.Name] {
			unknown = append(unknown, peer.Name)
		}
		switch {
		case peer.Offline:
			offline = append(offline, peer.Name)
		default:
			online = append(online, peer.Name)
			if peerLagging(observation, peer, lagThreshold) {
				status.Lagging = append(status.Lagging, LaggingPeer{Name: peer.Name, Lag: peer.Lag})
			}
		}
	}
	var missing []string
	for _, name := range status.Expected {
		if !known[name] {
			missing = append(missing, name)
		}
	}
	routed := map[string]bool{observation.ServerName: true}
	for _, name := range observation.Routes {
		routed[name] = true
	}
	var unrouted []string
	for _, name := range status.Expected {
		if !routed[name] {
			unrouted = append(unrouted, name)
		}
	}
	status.Online, status.Offline = sortedUnique(online), sortedUnique(offline)
	status.Missing, status.Unknown, status.Unrouted = missing, sortedUnique(unknown), unrouted
	slices.SortFunc(status.Lagging, func(a, b LaggingPeer) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	sizeMatches := len(status.Expected) == 0 || status.MetaSize == len(status.Expected)
	switch {
	case status.MetaLeader == "":
		status.Phase = PhaseNoLeader
	case len(status.Offline) == 0 && len(status.Missing) == 0 && len(status.Unknown) == 0 &&
		len(status.Lagging) == 0 && sizeMatches:
		status.Phase = PhaseHealthy
	default:
		status.Phase = PhaseDegraded
	}
	return status
}

// peerLagging judges a peer only from facts this broker's Raft view actually
// has. Only the metadata leader tracks follower progress: it reports a peer
// current exactly when its lag is zero, or not current with zero lag when it
// has not heard from the peer recently. A follower knows only whether it has
// heard from the leader recently, and always reports other followers as not
// current with zero lag, which carries no information about them.
//
// On the leader, NATS also clears Current once a peer has not been heard from
// for its lost-quorum interval, independently of lag, and Offline can stay
// false until the remote-server sweep. A peer whose last contact (Active) is
// that stale is therefore out of contact even when its lag is within the
// tolerated threshold.
func peerLagging(observation Observation, peer Peer, lagThreshold uint64) bool {
	if peer.Lag > lagThreshold {
		return true
	}
	switch {
	case observation.MetaLeader == observation.ServerName:
		return !peer.Current && (peer.Lag == 0 || peer.Active > StaleContact)
	case peer.Name == observation.MetaLeader:
		return !peer.Current
	default:
		return false
	}
}

func sortedUnique(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := slices.Clone(names)
	slices.Sort(out)
	return slices.Compact(out)
}
