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

// newProductionOCIObservationResolver binds removal evidence to an exact OCI
// reread. The list observation supplies the admitted slot/Region; the exact
// reread supplies provider ETag and ownership. Missing either fails closed.
func newProductionOCIObservationResolver(gateway ocireconcile.ComputeGateway) func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
	exact, ok := gateway.(exactOCIMemberObserver)
	if !ok {
		return nil
	}
	return func(ctx context.Context, listed ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
		current, err := exact.ObserveMember(ctx, listed.ID)
		if err != nil {
			return hostremoval.MemberObservation{}, err
		}
		if current.ID != listed.ID || current.CompartmentID == "" || current.ETag == "" || listed.Region == "" || listed.Index < 1 {
			return hostremoval.MemberObservation{}, errors.New("runtime host removal: exact OCI observation is incomplete")
		}
		return hostremoval.MemberObservation{}, errors.New("runtime host removal: accepted generation resolver is required")
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
	survivorIDs := make([]string, 0, len(survivors))
	for _, candidate := range survivors {
		survivorIDs = append(survivorIDs, candidate.ID)
	}
	observedMember, err := r.observe(ctx, member)
	if err != nil {
		return err
	}
	generation := observedMember.Generation
	observations := make([]hostremoval.MemberObservation, 0, len(survivors))
	for _, candidate := range survivors {
		observation, observeErr := r.observe(ctx, candidate)
		if observeErr != nil {
			return observeErr
		}
		observations = append(observations, observation)
	}
	return r.owner.RemoveMember(ctx, operationID, observedMember, generation, observations...)
}

func (r *productionHostRemoval) observe(ctx context.Context, member ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
	return r.observeFn(ctx, member)
}

// hostRemovalTransitionPorts documents the exact authenticated providers used
// by the runtime factory. It intentionally does not provide mock readiness or
// proof values; absent providers keep removal fail closed.
type hostRemovalTransitionPorts struct {
	Admission *databaseadmission.NATSJournal
	Issuer    interface {
		Head(context.Context, string) (placementtransition.Signed, error)
		Prepare(context.Context, placementtransition.Request) (placementtransition.Signed, error)
		Issue(context.Context, placementtransition.Request, *placementtransition.Signed, []placementtransition.Signed) (placementtransition.Signed, error)
	}
}
