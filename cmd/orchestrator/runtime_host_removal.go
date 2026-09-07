package main

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

// productionHostRemovalConfig is the deliberately narrow handoff from the
// live GRU composition to the OCI reconciler. Every effectful callback is
// supplied by an admitted production component; this adapter owns only the
// durable stage choreography.
type productionHostRemovalConfig struct {
	// Observe resolves authenticated provider identity metadata (revision/ETag,
	// generation and evidence) for an exact OCI instance. User freeform tags
	// are never accepted as proof.
	Observe    func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error)
	Inventory  func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error)
	Replace    func(context.Context, hostremoval.Replacement) error
	Revalidate func(context.Context, string, string, uint64) error
	Fence      func(context.Context, string, string, []hostremoval.Replacement) error
	Terminate  func(context.Context, string) error
}

type exactOCIMemberObserver interface {
	ObserveMember(context.Context, string) (ocireconcile.ObservedMember, error)
}

// newProductionOCITerminator binds termination to an exact provider reread.
// Unknown or replaced instances fail closed; callers retry the same journal
// operation and perform this reread again.
func newProductionOCITerminator(gateways map[string]ocireconcile.ComputeGateway) func(context.Context, string) error {
	return func(ctx context.Context, id string) error {
		for _, gateway := range gateways {
			observer, ok := gateway.(exactOCIMemberObserver)
			if !ok {
				continue
			}
			current, err := observer.ObserveMember(ctx, id)
			if err != nil {
				continue
			}
			if current.ID != id || current.LifecycleState == "" {
				continue
			}
			if err := gateway.TerminateMember(ctx, id); err != nil {
				return err
			}
			return nil
		}
		return errors.New("runtime host removal: exact OCI member is unavailable or replaced")
	}
}

type productionHostRemoval struct {
	owner     *hostremoval.Owner
	observeFn func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error)
}

var _ ocireconcile.MemberRemovalOwner = (*productionHostRemoval)(nil)

func newProductionHostRemoval(config productionHostRemovalConfig, journal *hostremoval.Journal) (*productionHostRemoval, error) {
	if journal == nil || config.Observe == nil || config.Inventory == nil || config.Replace == nil || config.Revalidate == nil || config.Fence == nil || config.Terminate == nil {
		return nil, errors.New("runtime host removal: durable inventory, transition, fence and termination providers are required")
	}
	return &productionHostRemoval{observeFn: config.Observe, owner: &hostremoval.Owner{
		Journal: journal, Inventory: config.Inventory, Replace: config.Replace,
		Revalidate: config.Revalidate, Fence: config.Fence, Terminate: config.Terminate,
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
	return owner.RemoveMember(ctx, operationID, observedMember, generation, observations...)
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
		return r.owner.Terminate(ctx, member.ID)
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
	Admission  *databaseadmission.NATSJournal
	Gateways   map[string]ocireconcile.ComputeGateway
	Observers  map[string]func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error)
	Placement  *productionPlacement
	Transition *productionPlacementTransition
	Issuer     interface {
		Head(context.Context, string) (placementtransition.Signed, error)
		Prepare(context.Context, placementtransition.Request) (placementtransition.Signed, error)
		Issue(context.Context, placementtransition.Request, *placementtransition.Signed, []placementtransition.Signed) (placementtransition.Signed, error)
	}
	Inventory  func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error)
	Replace    func(context.Context, hostremoval.Replacement) error
	Revalidate func(context.Context, string, string, uint64) error
	Fence      func(context.Context, string, string, []hostremoval.Replacement) error
	Terminate  func(context.Context, string) error
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
	if ports.Inventory == nil && ports.Admission != nil {
		inventory, revalidate, err := newProductionHostRemovalInventory(ports.Admission, journal)
		if err != nil {
			return nil, err
		}
		ports.Inventory, ports.Revalidate = inventory, revalidate
	}
	terminate := ports.Terminate
	if terminate == nil {
		terminate = newProductionOCITerminator(ports.Gateways)
	}
	replace, fence, err := productionHostRemovalCallbacks(ports)
	if err != nil {
		return nil, err
	}
	if ports.Replace == nil {
		ports.Replace = replace
	}
	if ports.Fence == nil {
		ports.Fence = fence
	}
	owner, err := newProductionHostRemoval(productionHostRemovalConfig{Observe: observe, Inventory: ports.Inventory, Replace: ports.Replace, Revalidate: ports.Revalidate, Fence: ports.Fence, Terminate: terminate}, journal)
	if err != nil {
		return nil, err
	}
	return owner, nil
}
