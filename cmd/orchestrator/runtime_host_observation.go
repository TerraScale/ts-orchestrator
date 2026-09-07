package main

import (
	"context"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// newProductionDurableMemberObserver resolves an exact OCI instance through
// the durable provider ownership journal. The journal's signed launch receipt
// is the only source of the accepted SPIFFE identity; OCI tags and display
// names are deliberately ignored.
func newProductionDurableMemberObserver(ownership provider.DurableOwnershipEvidence, gateway ocireconcile.ComputeGateway) func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
	exact, ok := gateway.(exactOCIMemberObserver)
	if ownership == nil || !ownership.AuthoritativeDurable() || !ok {
		return nil
	}
	return func(ctx context.Context, listed ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
		current, err := exact.ObserveMember(ctx, listed.ID)
		if err != nil && !errors.Is(err, ocireconcile.ErrMemberTerminated) {
			return hostremoval.MemberObservation{}, err
		}
		terminal := errors.Is(err, ocireconcile.ErrMemberTerminated)
		if terminal && current.LifecycleState != "TERMINATED" {
			return hostremoval.MemberObservation{}, errors.New("runtime host observation: terminal evidence is incomplete")
		}
		if current.ID != listed.ID || current.ETag == "" || current.CompartmentID == "" {
			return hostremoval.MemberObservation{}, errors.New("runtime host observation: exact OCI observation is incomplete")
		}
		record, found, err := ownership.Lookup(ctx, provider.ProviderResourceId{Value: current.ID})
		if err != nil {
			return hostremoval.MemberObservation{}, err
		}
		if !found || record.ResourceId.Value != current.ID || record.CompartmentId.Value != current.CompartmentID || record.Generation.Value == 0 || record.ServerIdentity == "" {
			return hostremoval.MemberObservation{}, errors.New("runtime host observation: durable OCI identity binding is unavailable")
		}
		if listed.Region != "" && record.CellId.Value != "" && listed.Region != record.CellId.Value {
			return hostremoval.MemberObservation{}, errors.New("runtime host observation: OCI identity binding is outside the declared cell")
		}
		observed := hostremoval.MemberObservation{ProviderETag: current.ETag, ResourceID: current.ID, Identity: record.ServerIdentity, Region: listed.Region, Slot: listed.Index, Generation: record.Generation.Value, EvidenceRefs: []string{current.ETag}}
		if terminal {
			return observed, ocireconcile.ErrMemberTerminated
		}
		return observed, nil
	}
}
