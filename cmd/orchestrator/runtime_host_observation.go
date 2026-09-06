package main

import (
	"context"
	"errors"
	"fmt"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
)

// newProductionAcceptedMemberObserver binds OCI membership to the accepted
// placement journal. Provider tags and ETags identify the instance only; the
// durable placement receipt supplies the generation used by removal CAS.
func newProductionAcceptedMemberObserver(journal *databaseadmission.NATSJournal, gateway ocireconcile.ComputeGateway) func(context.Context, ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
	exact, ok := gateway.(exactOCIMemberObserver)
	if journal == nil || !ok {
		return nil
	}
	return func(ctx context.Context, listed ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
		current, err := exact.ObserveMember(ctx, listed.ID)
		if err != nil {
			return hostremoval.MemberObservation{}, err
		}
		if current.ID != listed.ID || current.ETag == "" || current.CompartmentID == "" || listed.Region == "" || listed.Index < 1 {
			return hostremoval.MemberObservation{}, errors.New("runtime host removal: exact OCI observation is incomplete")
		}
		records, err := journal.List(ctx)
		if err != nil {
			return hostremoval.MemberObservation{}, err
		}
		var generation uint64
		var evidence []string
		for _, record := range records {
			if databaseadmission.ValidateRecord(record) != nil {
				return hostremoval.MemberObservation{}, errors.New("runtime host removal: invalid admission record")
			}
			for _, target := range record.PlacementTargets {
				if target.ServerIdentity != listed.ID || target.AcceptedGeneration == 0 {
					continue
				}
				if generation != 0 && generation != target.AcceptedGeneration {
					return hostremoval.MemberObservation{}, fmt.Errorf("runtime host removal: conflicting accepted generations for %s", listed.ID)
				}
				generation = target.AcceptedGeneration
				if target.AcceptedProofDigest != "" {
					evidence = append(evidence, target.AcceptedProofDigest)
				}
			}
		}
		if generation == 0 {
			return hostremoval.MemberObservation{}, errors.New("runtime host removal: accepted placement generation is unavailable")
		}
		return hostremoval.MemberObservation{Identity: listed.ID, Region: listed.Region, Slot: listed.Index, Generation: generation, EvidenceRefs: evidence}, nil
	}
}
