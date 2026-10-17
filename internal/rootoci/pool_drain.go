package rootoci

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
)

const (
	OperationBeginPoolDrain      Operation = "begin_pool_drain"
	OperationRefreshPoolDrain    Operation = "refresh_pool_drain"
	OperationPoolDrainChallenges Operation = "pool_drain_challenges"
	OperationStorePoolDrainStop  Operation = "store_pool_drain_stop"
	OperationGuardPoolExecution  Operation = "guard_pool_execution"
)

type PoolDrainView struct {
	Child     drainwire.PoolChild `json:"child"`
	Phase     string              `json:"phase"`
	SHA256    string              `json:"sha256"`
	ExpiresAt time.Time           `json:"expires_at"`
}

type PoolDrainSelector struct {
	InstanceID         string `json:"instance_id"`
	ExecutionSessionID string `json:"execution_session_id"`
}

type PoolDrainQuery struct {
	Executions []PoolDrainSelector `json:"executions"`
}

type PoolDrains interface {
	BeginPoolDrain(context.Context, Call, drainwire.PoolChild) (PoolDrainView, error)
	RefreshPoolDrain(context.Context, Call, drainwire.PoolChild) (PoolDrainView, error)
	PoolDrainChallenges(context.Context, Call, PoolDrainQuery) ([]drainwire.DrainStopChallenge, error)
	StorePoolDrainStop(context.Context, Call, drainwire.SignedStop) error
	GuardPoolExecution(context.Context, Call, drainwire.ExecutionHold) error
}

func (client *Client) BeginPoolDrain(ctx context.Context, child drainwire.PoolChild) (PoolDrainView, error) {
	var view PoolDrainView
	err := client.invoke(ctx, OperationBeginPoolDrain, child, &view)
	return view, err
}

func (client *Client) RefreshPoolDrain(ctx context.Context, child drainwire.PoolChild) (PoolDrainView, error) {
	var view PoolDrainView
	err := client.invoke(ctx, OperationRefreshPoolDrain, child, &view)
	return view, err
}

func (client *Client) ReadChallenges(ctx context.Context, holds []drainwire.SignedHold) ([]drainwire.DrainStopChallenge, error) {
	query := PoolDrainQuery{}
	for _, hold := range holds {
		query.Executions = append(query.Executions, PoolDrainSelector{InstanceID: hold.Hold.InstanceID, ExecutionSessionID: hold.Hold.ExecutionSessionID})
	}
	var challenges []drainwire.DrainStopChallenge
	err := client.invoke(ctx, OperationPoolDrainChallenges, query, &challenges)
	return challenges, err
}

func (client *Client) StoreStop(ctx context.Context, stop drainwire.SignedStop) error {
	return client.invoke(ctx, OperationStorePoolDrainStop, stop, new(struct{}))
}

func (client *Client) GuardStart(ctx context.Context, hold drainwire.ExecutionHold) error {
	return client.invoke(ctx, OperationGuardPoolExecution, hold, new(struct{}))
}

func validPoolDrainRequest(request wireRequest) bool {
	switch request.Operation {
	case OperationBeginPoolDrain, OperationRefreshPoolDrain:
		var child drainwire.PoolChild
		return decodePayload(request.Payload, &child) == nil && child.Validate() == nil
	case OperationGuardPoolExecution:
		var hold drainwire.ExecutionHold
		return decodePayload(request.Payload, &hold) == nil && hold.Validate() == nil
	case OperationPoolDrainChallenges:
		var query PoolDrainQuery
		if decodePayload(request.Payload, &query) != nil || len(query.Executions) > drainwire.MaxDrainTasks {
			return false
		}
		for _, execution := range query.Executions {
			if !validSelector(execution.InstanceID) || !validSelector(execution.ExecutionSessionID) {
				return false
			}
		}
		return true
	case OperationStorePoolDrainStop:
		var stop drainwire.SignedStop
		return len(request.Payload) <= 32<<10 && decodePayload(request.Payload, &stop) == nil &&
			stop.Challenge.Validate(time.Now()) == nil && len(stop.CertificateChain) > 0 && len(stop.CertificateChain) <= 8 &&
			len(stop.Signature) > 0 && len(stop.Signature) <= 1024
	default:
		return false
	}
}

func dispatchPoolDrain(ctx context.Context, backend PoolDrains, call Call, request wireRequest) (any, error) {
	switch request.Operation {
	case OperationBeginPoolDrain, OperationRefreshPoolDrain:
		var child drainwire.PoolChild
		if err := decodePayload(request.Payload, &child); err != nil {
			return nil, err
		}
		if request.Operation == OperationBeginPoolDrain {
			return backend.BeginPoolDrain(ctx, call, child)
		}
		return backend.RefreshPoolDrain(ctx, call, child)
	case OperationPoolDrainChallenges:
		var query PoolDrainQuery
		if err := decodePayload(request.Payload, &query); err != nil {
			return nil, err
		}
		return backend.PoolDrainChallenges(ctx, call, query)
	case OperationStorePoolDrainStop:
		var stop drainwire.SignedStop
		if err := decodePayload(request.Payload, &stop); err != nil {
			return nil, err
		}
		return struct{}{}, backend.StorePoolDrainStop(ctx, call, stop)
	case OperationGuardPoolExecution:
		var hold drainwire.ExecutionHold
		if err := decodePayload(request.Payload, &hold); err != nil {
			return nil, err
		}
		return struct{}{}, backend.GuardPoolExecution(ctx, call, hold)
	default:
		return nil, ErrInvalid
	}
}
