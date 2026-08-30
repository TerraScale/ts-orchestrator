// Port of src/TerraScale.Orchestrator/ControlPlane/Runtime/NatsRuntimeLifecycleAuthorityGate.cs
package control

import (
	"context"
)

// NatsRuntimeLifecycleAuthorityGate maps the sampled regional authority state
// to the lifecycle gate without exposing authority internals.
type NatsRuntimeLifecycleAuthorityGate struct {
	cell      RuntimeLifecycleCellId
	authority *RegionalAuthorityCoordinator
}

func NewNatsRuntimeLifecycleAuthorityGate(cell RuntimeLifecycleCellId,
	authority *RegionalAuthorityCoordinator) (*NatsRuntimeLifecycleAuthorityGate, error) {
	if authority == nil {
		return nil, argumentNil("authority")
	}
	return &NatsRuntimeLifecycleAuthorityGate{cell: cell, authority: authority}, nil
}

func (g *NatsRuntimeLifecycleAuthorityGate) ReadAsync(ctx context.Context,
	requestedCell RuntimeLifecycleCellId) (RuntimeLifecycleAuthority, error) {
	if ctx.Err() != nil {
		return RuntimeLifecycleAuthority{}, ctx.Err()
	}
	if requestedCell != g.cell {
		epoch, err := NewRuntimeEpoch(1)
		if err != nil {
			return RuntimeLifecycleAuthority{}, err
		}
		return NewRuntimeLifecycleAuthority(RuntimeLifecycleAuthorityStatusUnavailable, epoch)
	}
	return NatsRuntimeLifecycleAuthorityGateMap(g.authority.Snapshot())
}

// NatsRuntimeLifecycleAuthorityGateMap ports the internal static Map helper.
func NatsRuntimeLifecycleAuthorityGateMap(snapshot RegionalAuthoritySnapshot) (RuntimeLifecycleAuthority, error) {
	epochValue := uint64(1)
	if snapshot.Epoch > 0 {
		epochValue = uint64(snapshot.Epoch)
	}
	epoch, err := NewRuntimeEpoch(epochValue)
	if err != nil {
		return RuntimeLifecycleAuthority{}, err
	}
	var status RuntimeLifecycleAuthorityStatus
	switch {
	case snapshot.Ready:
		if snapshot.State == "leader" && snapshot.IsLeader && snapshot.Epoch > 0 {
			status = RuntimeLifecycleAuthorityStatusReadyLeader
		} else if snapshot.State == "follower" || !snapshot.IsLeader {
			status = RuntimeLifecycleAuthorityStatusFollower
		} else {
			status = RuntimeLifecycleAuthorityStatusNotReady
		}
	case snapshot.Error != nil || snapshot.State == "fenced":
		status = RuntimeLifecycleAuthorityStatusUnavailable
	default:
		status = RuntimeLifecycleAuthorityStatusNotReady
	}
	return NewRuntimeLifecycleAuthority(status, epoch)
}
