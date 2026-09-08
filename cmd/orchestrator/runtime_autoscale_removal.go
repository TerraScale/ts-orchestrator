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
	AutoscaleRemovalComplete(context.Context, autoscale.Target) (bool, error)
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

func (o *autoscaleRemovalOwner) AutoscaleRemovalComplete(ctx context.Context, target autoscale.Target) (bool, error) {
	progress, ok := o.owner.(autoscaleRemovalProgress)
	if !ok {
		return false, nil
	}
	return progress.AutoscaleRemovalComplete(ctx, target)
}

func validAutoscaleRemovalTarget(target autoscale.Target) bool {
	return target.Region != "" && target.RemovalOperationID != "" && target.RemovalResourceID != "" && target.RemovalHostID != "" && target.RemovalIncarnation != "" && target.RemovalSlot == target.Members+1
}

// AutoscaleRemovalComplete resumes the exact journaled operation even if the
// member has disappeared from OCI list results. Only the removal owner's exact
// terminal provider read can advance this durable journal to complete.
func (r *productionHostRemoval) AutoscaleRemovalComplete(ctx context.Context, target autoscale.Target) (bool, error) {
	if r == nil || r.owner == nil || !validAutoscaleRemovalTarget(target) {
		return false, errors.New("autoscale: removal completion binding is unavailable")
	}
	operation, err := r.owner.Journal.Load(ctx, target.RemovalOperationID)
	if errors.Is(err, hostremoval.ErrMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if operation.OperationID != target.RemovalOperationID || operation.ResourceID != target.RemovalResourceID {
		return false, hostremoval.ErrConflict
	}
	if operation.Stage == hostremoval.StageComplete {
		if r.completed != nil {
			if err := r.completed(ctx, operation.OperationID); err != nil {
				if errors.Is(err, errBrokerGrantsPending) {
					return false, nil
				}
				return false, err
			}
		}
		return true, nil
	}
	member := ocireconcile.ObservedMember{ID: target.RemovalResourceID, Region: target.Region, Index: target.RemovalSlot}
	if err := r.RemoveMember(ctx, target.RemovalOperationID, member, nil); err != nil {
		if errors.Is(err, hostremoval.ErrPending) || errors.Is(err, provider.ErrComputeTerminationPending) || errors.Is(err, errBrokerGrantsPending) {
			return false, nil
		}
		return false, err
	}
	operation, err = r.owner.Journal.Load(ctx, target.RemovalOperationID)
	if err != nil {
		return false, err
	}
	return operation.OperationID == target.RemovalOperationID && operation.ResourceID == target.RemovalResourceID && operation.Stage == hostremoval.StageComplete, nil
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
