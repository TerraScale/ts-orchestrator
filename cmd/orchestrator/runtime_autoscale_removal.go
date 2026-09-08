package main

import (
	"context"
	"errors"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// autoscaleRemovalOwner resolves every provider mutation against the current
// fenced target, including after restart. An in-memory desired count is never
// sufficient to choose the member or the journal operation to retire.
type autoscaleRemovalOwner struct {
	controller *autoscale.Controller
	owner      ocireconcile.MemberRemovalOwner
}

type autoscaleRemovalProgress interface {
	AutoscaleRemovalOutcome(context.Context, autoscale.Target) (autoscale.RemovalOutcome, error)
}

func (o *autoscaleRemovalOwner) RemoveMember(ctx context.Context, operation string, member ocireconcile.ObservedMember, survivors []ocireconcile.ObservedMember) error {
	target, found, err := o.controller.Target(ctx, member.Region)
	if err != nil {
		return err
	}
	if found && target.RemovalOperationID != "" {
		if !validAutoscaleRemovalTarget(target) || member.ID != target.RemovalResourceID || member.Index != target.RemovalSlot {
			return errors.New("autoscale: provider removal does not match retained target")
		}
		operation = target.RemovalOperationID
	}
	return o.owner.RemoveMember(ctx, operation, member, survivors)
}

func (o *autoscaleRemovalOwner) AutoscaleRemovalOutcome(ctx context.Context, target autoscale.Target) (autoscale.RemovalOutcome, error) {
	progress, ok := o.owner.(autoscaleRemovalProgress)
	if !ok {
		return autoscale.RemovalPending, nil
	}
	return progress.AutoscaleRemovalOutcome(ctx, target)
}

func validAutoscaleRemovalTarget(target autoscale.Target) bool {
	return target.Region != "" && target.RemovalOperationID != "" && target.RemovalResourceID != "" && target.RemovalHostID != "" && target.RemovalIncarnation != "" && target.RemovalSlot == target.Members+1
}

// AutoscaleRemovalOutcome resumes the exact journaled operation even if the
// member has disappeared from OCI list results. Only the removal owner's exact
// terminal provider read can advance this durable journal to complete.
func (r *productionHostRemoval) AutoscaleRemovalOutcome(ctx context.Context, target autoscale.Target) (autoscale.RemovalOutcome, error) {
	if r == nil || r.owner == nil || !validAutoscaleRemovalTarget(target) {
		return autoscale.RemovalPending, errors.New("autoscale: removal completion binding is unavailable")
	}
	operation, err := r.owner.Journal.Load(ctx, target.RemovalOperationID)
	if errors.Is(err, hostremoval.ErrMissing) {
		return autoscale.RemovalPending, nil
	}
	if err != nil {
		return autoscale.RemovalPending, err
	}
	if operation.OperationID != target.RemovalOperationID || operation.ResourceID != target.RemovalResourceID {
		return autoscale.RemovalPending, hostremoval.ErrConflict
	}
	if operation.Stage == hostremoval.StageCancelled {
		return autoscale.RemovalCancelled, nil
	}
	if operation.Stage == hostremoval.StageComplete {
		if r.completed != nil {
			if err := r.completed(ctx, operation.OperationID); err != nil {
				if errors.Is(err, errBrokerGrantsPending) {
					return autoscale.RemovalPending, nil
				}
				return autoscale.RemovalPending, err
			}
		}
		return autoscale.RemovalCompleted, nil
	}
	member := ocireconcile.ObservedMember{ID: target.RemovalResourceID, Region: target.Region, Index: target.RemovalSlot}
	if err := r.RemoveMember(ctx, target.RemovalOperationID, member, nil); err != nil && !errors.Is(err, hostremoval.ErrCancelled) {
		if errors.Is(err, hostremoval.ErrPending) || errors.Is(err, provider.ErrComputeTerminationPending) || errors.Is(err, errBrokerGrantsPending) {
			return autoscale.RemovalPending, nil
		}
		return autoscale.RemovalPending, err
	}
	operation, err = r.owner.Journal.Load(ctx, target.RemovalOperationID)
	if err != nil {
		return autoscale.RemovalPending, err
	}
	if operation.OperationID != target.RemovalOperationID || operation.ResourceID != target.RemovalResourceID {
		return autoscale.RemovalPending, hostremoval.ErrConflict
	}
	switch operation.Stage {
	case hostremoval.StageComplete:
		return autoscale.RemovalCompleted, nil
	case hostremoval.StageCancelled:
		return autoscale.RemovalCancelled, nil
	default:
		return autoscale.RemovalPending, nil
	}
}

// The factory's compute closure and the worker constructor receive copies of
// productionGlobalWorkerConfig. This shared binding publishes the final lease-owned
// removal adapter to that real closure without copying an obsolete nil owner.
type computeRemovalOwnerBinding struct {
	mu    sync.RWMutex
	owner ocireconcile.MemberRemovalOwner
}

func (b *computeRemovalOwnerBinding) Bind(owner ocireconcile.MemberRemovalOwner) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.owner = owner
}
func (b *computeRemovalOwnerBinding) RemoveMember(ctx context.Context, operation string, member ocireconcile.ObservedMember, survivors []ocireconcile.ObservedMember) error {
	b.mu.RLock()
	owner := b.owner
	b.mu.RUnlock()
	if owner == nil {
		return errors.New("compute: durable removal owner is not bound")
	}
	return owner.RemoveMember(ctx, operation, member, survivors)
}
