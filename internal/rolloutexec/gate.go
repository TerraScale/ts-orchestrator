package rolloutexec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

// ErrGateHeld reports that a step must wait; it is never a failure of the
// rollout. The phase deadline bounds how long a step can wait.
var ErrGateHeld = errors.New("rollout step is held by a cluster safety gate")

// Gate is checked immediately before every preflight and unit step. An
// error holds the step until a later tick.
type Gate interface {
	Check(ctx context.Context, record rollout.Record, unit string) error
}

// ClusterObserver is the embedded broker's read-only cluster view.
type ClusterObserver interface {
	ObserveCluster() (natscell.ClusterObservation, error)
	LaggingStreams() ([]string, error)
}

// ClusterGate holds a step until the JetStream metadata group has a leader,
// every expected broker is online, the group keeps its quorum without one
// more broker (the one a controller step restarts), and no replicated
// stream is leaderless or lagging on this broker.
type ClusterGate struct {
	Cluster ClusterObserver
}

// Check implements Gate.
func (g ClusterGate) Check(_ context.Context, record rollout.Record, _ string) error {
	if g.Cluster == nil {
		return fmt.Errorf("%w: no cluster view", ErrGateHeld)
	}
	observation, err := g.Cluster.ObserveCluster()
	if err != nil {
		return fmt.Errorf("%w: observe cluster: %v", ErrGateHeld, err)
	}
	if !observation.Running || observation.MetaLeader == "" {
		return fmt.Errorf("%w: the JetStream metadata group has no leader", ErrGateHeld)
	}
	// This broker is running and counts itself; MetaPeers lists the others.
	online := 1
	for _, peer := range observation.MetaPeers {
		if peer.Name != observation.ServerName && !peer.Offline && !peer.Pending {
			online++
		}
	}
	if expected := len(observation.ExpectedPeers); expected > 0 && online < expected {
		return fmt.Errorf("%w: %d of %d brokers are online", ErrGateHeld, online, expected)
	}
	if record.Kind == rollout.KindController && observation.MetaQuorum > 0 && online-1 < observation.MetaQuorum {
		return fmt.Errorf("%w: restarting one controller would lose JetStream quorum (%d online, quorum %d)",
			ErrGateHeld, online, observation.MetaQuorum)
	}
	lagging, err := g.Cluster.LaggingStreams()
	if err != nil {
		return fmt.Errorf("%w: read stream health: %v", ErrGateHeld, err)
	}
	if len(lagging) > 0 {
		return fmt.Errorf("%w: streams are not current: %s", ErrGateHeld, strings.Join(lagging, ", "))
	}
	return nil
}
