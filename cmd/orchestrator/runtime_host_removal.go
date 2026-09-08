package main

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
)

// productionHostRemovalConfig is the deliberately narrow handoff from the
// live GRU composition to the OCI reconciler. Every effectful callback is
// supplied by an admitted production component; this adapter owns only the
// durable stage choreography.
type productionHostRemovalConfig struct {
	// Observe resolves authenticated provider identity metadata (revision/ETag,
	// generation and evidence) for an exact OCI instance. User freeform tags
	// are never accepted as proof.
	Observe              func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error)
	Inventory            func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error)
	Replace              func(context.Context, hostremoval.Replacement) error
	Revalidate           func(context.Context, string, string, uint64) error
	Fence                func(context.Context, string, string, []hostremoval.Replacement) error
	Terminate            func(context.Context, string, string) error
	ReconcileTermination func(context.Context, string, string) error
}

type exactOCIMemberObserver interface {
	ObserveMember(context.Context, string) (ocireconcile.ObservedMember, error)
}

type exactOCITerminationReconciler interface {
	ReconcileMemberTermination(context.Context, string, string) error
}

func newProductionOCITerminationReconciler(gateways map[string]ocireconcile.ComputeGateway) func(context.Context, string, string) error {
	return func(ctx context.Context, id, etag string) error {
		for _, gateway := range gateways {
			observer, observes := gateway.(exactOCIMemberObserver)
			reconciler, reconciles := gateway.(exactOCITerminationReconciler)
			if !observes || !reconciles {
				continue
			}
			current, err := observer.ObserveMember(ctx, id)
			if !errors.Is(err, ocireconcile.ErrMemberTerminated) || current.ID != id || current.LifecycleState != "TERMINATED" {
				continue
			}
			return reconciler.ReconcileMemberTermination(ctx, id, etag)
		}
		return errors.New("runtime host removal: exact terminal OCI reconciliation is unavailable")
	}
}

// newProductionOCITerminator binds termination to an exact provider reread.
// Unknown or replaced instances fail closed; callers retry the same journal
// operation and perform this reread again.
func newProductionOCITerminator(gateways map[string]ocireconcile.ComputeGateway) func(context.Context, string, string) error {
	return func(ctx context.Context, id, etag string) error {
		for _, gateway := range gateways {
			observer, ok := gateway.(exactOCIMemberObserver)
			if !ok {
				continue
			}
			current, err := observer.ObserveMember(ctx, id)
			if err != nil && !errors.Is(err, ocireconcile.ErrMemberTerminated) {
				continue
			}
			if current.ID != id || current.LifecycleState == "" {
				continue
			}
			if err := gateway.TerminateMember(ctx, id, etag); err != nil {
				return err
			}
			return nil
		}
		return errors.New("runtime host removal: exact OCI member is unavailable or replaced")
	}
}

type productionHostRemoval struct {
	completed   func(context.Context, string) error
	terminateFn func(context.Context, string, string) error
	reconcileFn func(context.Context, string, string) error
	owner       *hostremoval.Owner
	observeFn   func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error)
}

var _ ocireconcile.MemberRemovalOwner = (*productionHostRemoval)(nil)

func newProductionHostRemoval(config productionHostRemovalConfig, journal *hostremoval.Journal) (*productionHostRemoval, error) {
	if journal == nil || config.Observe == nil || config.Inventory == nil || config.Replace == nil || config.Revalidate == nil || config.Fence == nil || config.Terminate == nil || config.ReconcileTermination == nil {
		return nil, errors.New("runtime host removal: durable inventory, transition, fence and termination providers are required")
	}
	return &productionHostRemoval{observeFn: config.Observe, terminateFn: config.Terminate, reconcileFn: config.ReconcileTermination, owner: &hostremoval.Owner{
		Journal: journal, Inventory: config.Inventory, Replace: config.Replace,
		Revalidate: config.Revalidate, Fence: config.Fence,
	}}, nil
}

func (r *productionHostRemoval) RemoveMember(ctx context.Context, operationID string, member ocireconcile.ObservedMember, survivors []ocireconcile.ObservedMember) error {
	if r == nil || r.owner == nil {
		return errors.New("runtime host removal: owner is unavailable")
	}
	if operationID == "" {
		return errors.New("runtime host removal: operation identity is missing")
	}
	retained, loadErr := r.owner.Journal.Load(ctx, operationID)
	if loadErr != nil && !errors.Is(loadErr, hostremoval.ErrMissing) {
		return loadErr
	}
	if loadErr == nil {
		if retained.ResourceID != member.ID {
			return hostremoval.ErrConflict
		}
		if retained.Stage == hostremoval.StageComplete {
			if r.completed != nil {
				return r.completed(ctx, operationID)
			}
			return nil
		}
	}
	observedMember, err := r.observe(ctx, member)
	terminal := errors.Is(err, ocireconcile.ErrMemberTerminated)
	if terminal && (loadErr != nil || retained.Stage != hostremoval.StageFenced || observedMember.ResourceID != retained.ResourceID || observedMember.Identity != retained.MemberIdentity || observedMember.Generation != retained.Generation) {
		return hostremoval.ErrConflict
	}
	if err != nil && !terminal {
		return err
	}
	if loadErr == nil {
		observedMember.ProviderETag = retained.ProviderETag
	}
	observedMember.ResourceID = member.ID
	generation := observedMember.Generation
	observations := make([]hostremoval.MemberObservation, 0, len(survivors))
	for _, candidate := range survivors {
		if loadErr == nil {
			break // Resume the retained survivor inventory, not a new provider list.
		}
		observation, observeErr := r.observe(ctx, candidate)
		if observeErr != nil {
			return observeErr
		}
		observation.ResourceID = candidate.ID
		observations = append(observations, observation)
	}
	// Keep provider resource identity separate from the SPIFFE identity used by
	// placement. Bind callbacks per invocation so concurrent removals cannot
	// redirect one another's termination target.
	owner := r.ownerFor(member, observedMember)
	if err := owner.RemoveMember(ctx, operationID, observedMember, generation, observations...); err != nil {
		return err
	}
	// The relocation admission fence outlives the overlay commit and is only
	// released after exact OCI termination is durably recorded.
	if r.completed != nil {
		return r.completed(ctx, operationID)
	}
	return nil
}

func (r *productionHostRemoval) ownerFor(member ocireconcile.ObservedMember, observedMember hostremoval.MemberObservation) *hostremoval.Owner {
	owner := *r.owner
	owner.Observe = func(ctx context.Context, identity string) (bool, error) {
		if identity != observedMember.Identity {
			return false, hostremoval.ErrConflict
		}
		current, err := r.observe(ctx, member)
		terminal := errors.Is(err, ocireconcile.ErrMemberTerminated)
		if err != nil && !terminal {
			return false, err
		}
		if current.Identity != observedMember.Identity || current.Region != observedMember.Region || current.Slot != observedMember.Slot || current.Generation != observedMember.Generation {
			return false, hostremoval.ErrConflict
		}
		if terminal && current.ResourceID != member.ID {
			return false, hostremoval.ErrConflict
		}
		return !terminal, nil
	}
	owner.Terminate = func(ctx context.Context, identity string) error {
		if identity != observedMember.Identity {
			return hostremoval.ErrConflict
		}
		return r.terminateFn(ctx, member.ID, observedMember.ProviderETag)
	}
	// Close the provider mutation journal before releasing the removal fence.
	// This separate port cannot issue another DELETE after a lost response.
	owner.ReconcileTermination = func(ctx context.Context, identity string) error {
		if identity != observedMember.Identity || r.reconcileFn == nil {
			return hostremoval.ErrConflict
		}
		return r.reconcileFn(ctx, member.ID, observedMember.ProviderETag)
	}
	return &owner
}

func (r *productionHostRemoval) observe(ctx context.Context, member ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
	return r.observeFn(ctx, member)
}

// hostRemovalTransitionPorts documents the exact authenticated providers used
// by the runtime factory. It intentionally does not provide mock readiness or
// proof values; absent providers keep removal fail closed.
type hostRemovalTransitionPorts struct {
	Relocation *productionHostRelocation
	Gateways   map[string]ocireconcile.ComputeGateway
	Observers  map[string]func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error)
}

func newProductionHostRemovalFromPorts(ports hostRemovalTransitionPorts, journal *hostremoval.Journal) (ocireconcile.MemberRemovalOwner, error) {
	if len(ports.Observers) == 0 {
		return nil, errors.New("runtime host removal: authenticated OCI observers are required")
	}
	var observe func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error)
	observe = func(ctx context.Context, member ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
		if fn := ports.Observers[member.Region]; fn != nil {
			return fn(ctx, member)
		}
		return hostremoval.MemberObservation{}, errors.New("runtime host removal: Region observer is unavailable")
	}
	if !ports.Relocation.valid() {
		return nil, errors.New("runtime host removal: relocation providers incomplete")
	}
	ports.Relocation.Removal = journal
	terminate := newProductionOCITerminator(ports.Gateways)
	owner, err := newProductionHostRemoval(productionHostRemovalConfig{Observe: observe, Inventory: ports.Relocation.Capture, Replace: ports.Relocation.Replace, Revalidate: ports.Relocation.Revalidate, Fence: ports.Relocation.Fence, Terminate: terminate, ReconcileTermination: newProductionOCITerminationReconciler(ports.Gateways)}, journal)
	if err != nil {
		return nil, err
	}
	owner.completed = func(ctx context.Context, operation string) error {
		return ports.Relocation.Admission.FinishPlacementRelocation(ctx, operation+"/placement")
	}
	return owner, nil
}
