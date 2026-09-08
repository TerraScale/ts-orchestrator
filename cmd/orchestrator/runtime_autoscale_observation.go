package main

import (
	"context"
	"slices"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// productionAutoscaleObservationSource binds telemetry identities to durable
// enrollment and provider ownership. Display names and mutable tags cannot
// create an admitted identity or redirect a removal to a replacement instance.
type productionAutoscaleObservationSource struct {
	source               autoscale.ObservationSource
 proof *productionAutoscaleRemovalProofProducer
	enrollments          func(context.Context) (enrollment.State, error)
	gateways             map[string]ocireconcile.ComputeGateway
	ownership            provider.DurableOwnershipEvidence
	check                func(context.Context) error
	environment, cluster string
}

func newProductionAutoscaleObservationSource(session globalWorkerSession, source autoscale.ObservationSource, gateways map[string]ocireconcile.ComputeGateway, ownership provider.DurableOwnershipEvidence, environment, cluster string) (autoscale.ObservationSource, error) {
	if source == nil || len(gateways) == 0 || ownership == nil || !ownership.AuthoritativeDurable() || environment == "" || cluster == "" {
		return nil, autoscale.ErrUnavailable
	}
	journal, err := enrollment.NewJournal(authorityjournal.Config{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId})
	if err != nil {
		return nil, err
	}
	return &productionAutoscaleObservationSource{source: source, enrollments: journal.Read, gateways: gateways, ownership: ownership, check: session.CheckEffectAuthority, environment: environment, cluster: cluster}, nil
}

func (s *productionAutoscaleObservationSource) Observe(ctx context.Context, region string) ([]autoscale.Observation, error) {
	if s == nil || ctx == nil || s.source == nil || s.enrollments == nil || s.check == nil || s.ownership == nil || !s.ownership.AuthoritativeDurable() {
		return nil, autoscale.ErrUnavailable
	}
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	observations, err := s.source.Observe(ctx, region)
	if err != nil {
		return nil, err
	}
	state, err := s.enrollments(ctx)
	if err != nil {
		return nil, err
	}
	gateway := s.gateways[region]
	exact, ok := gateway.(exactOCIMemberObserver)
	if !ok {
		return nil, autoscale.ErrUnavailable
	}
	members, err := gateway.ListMembers(ctx)
	if err != nil {
		return nil, err
	}
	result := slices.Clone(observations)
	seenNodes, seenSlots, seenResources := map[string]bool{}, map[int]bool{}, map[string]bool{}
	for i := range result {
		observation := &result[i]
		if !observation.Authenticated || observation.HostID == "" || seenNodes[observation.HostID] {
			return nil, autoscale.ErrUnavailable
		}
		seenNodes[observation.HostID] = true
		var enrolled enrollment.Record
		for _, candidate := range state.Records {
			if candidate.NodeID != observation.HostID {
				continue
			}
			if enrolled.NodeID != "" {
				return nil, autoscale.ErrUnavailable
			}
			enrolled = candidate
		}
		if enrolled.NodeID == "" || enrolled.Environment != s.environment || enrolled.Cluster != s.cluster || enrolled.Region != region || enrolled.Slot < 1 || enrolled.Generation == 0 || enrolled.Public == nil || enrolled.Retirement != nil || seenSlots[enrolled.Slot] {
			return nil, autoscale.ErrUnavailable
		}
		seenSlots[enrolled.Slot] = true
		var selected ocireconcile.ObservedMember
		for _, candidate := range members {
			if candidate.Index != enrolled.Slot || candidate.LifecycleState == "TERMINATED" {
				continue
			}
			if selected.ID != "" {
				return nil, autoscale.ErrUnavailable
			}
			selected = candidate
		}
		if selected.ID == "" || seenResources[selected.ID] {
			return nil, autoscale.ErrUnavailable
		}
		seenResources[selected.ID] = true
		// Exact provider reads contain immutable identity and state, not slot or
		// Region metadata. The enrollment-to-ownership join below supplies those.
		current, err := exact.ObserveMember(ctx, selected.ID)
		if err != nil {
			return nil, err
		}
		if current.ID != selected.ID || current.Index != 0 && current.Index != enrolled.Slot || current.Region != "" && current.Region != region || current.LifecycleState != "RUNNING" || current.ETag == "" || current.CompartmentID == "" {
			return nil, autoscale.ErrUnavailable
		}
		id, err := provider.NewProviderResourceId(current.ID)
		if err != nil {
			return nil, err
		}
		owned, found, err := s.ownership.Lookup(ctx, id)
		if err != nil {
			return nil, err
		}
		identity := enrollment.Identity(enrolled, "member")
		if !found || owned.ResourceId != id || owned.CellId.Value != region || owned.CompartmentId.Value != current.CompartmentID || owned.Generation.Value != enrolled.Generation || owned.MemberID != enrolled.MemberID || owned.ServerIdentity != identity {
			return nil, autoscale.ErrUnavailable
		}
		observation.MemberSlot, observation.ProviderResourceID, observation.EngineID = enrolled.Slot, current.ID, identity
 observation.ProviderGeneration=enrolled.Generation
 observation.Proof.ResidencyVerified,observation.Proof.QuorumVerified=false,false
 observation.Proof.Removal=nil
	}
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	if s.proof != nil {return s.proof.Produce(ctx,region,result)}
 return result, nil
}
