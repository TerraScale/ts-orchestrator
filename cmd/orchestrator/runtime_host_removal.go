package main

import (
	"context"
	"errors"
	"strconv"

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
	Inventory  func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error)
	Replace    func(context.Context, hostremoval.Replacement) error
	Revalidate func(context.Context, string, string, uint64) error
	Fence      func(context.Context, string, string, []hostremoval.Replacement) error
	Terminate  func(context.Context, string) error
}

type productionHostRemoval struct{ owner *hostremoval.Owner }

var _ ocireconcile.MemberRemovalOwner = (*productionHostRemoval)(nil)

func newProductionHostRemoval(config productionHostRemovalConfig, journal *hostremoval.Journal) (*productionHostRemoval, error) {
	if journal == nil || config.Inventory == nil || config.Replace == nil || config.Revalidate == nil || config.Fence == nil || config.Terminate == nil {
		return nil, errors.New("runtime host removal: durable inventory, transition, fence and termination providers are required")
	}
	return &productionHostRemoval{owner: &hostremoval.Owner{
		Journal: journal, Inventory: config.Inventory, Replace: config.Replace,
		Revalidate: config.Revalidate, Fence: config.Fence, Terminate: config.Terminate,
	}}, nil
}

func (r *productionHostRemoval) RemoveMember(ctx context.Context, operationID string, member ocireconcile.ObservedMember, survivors []ocireconcile.ObservedMember) error {
	if r == nil || r.owner == nil {
		return errors.New("runtime host removal: owner is unavailable")
	}
	generationText := member.FreeformTags["terrascale-generation"]
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if err != nil || generation == 0 {
		return errors.New("runtime host removal: observed member generation is missing")
	}
	if operationID == "" {
		return errors.New("runtime host removal: operation identity is missing")
	}
	survivorIDs := make([]string, 0, len(survivors))
	for _, candidate := range survivors {
		survivorIDs = append(survivorIDs, candidate.ID)
	}
	observations := make([]hostremoval.MemberObservation, 0, len(survivors))
	for _, candidate := range survivors {
		candidateGeneration, _ := strconv.ParseUint(candidate.FreeformTags["terrascale-generation"], 10, 64)
		observations = append(observations, hostremoval.MemberObservation{Identity: candidate.ID, Region: candidate.Region, Slot: candidate.Index, Generation: candidateGeneration, EvidenceRefs: []string{candidate.FreeformTags["terrascale-observation-ref"]}})
	}
	return r.owner.RemoveMember(ctx, operationID, hostremoval.MemberObservation{Identity: member.ID, Region: member.Region, Slot: member.Index, Generation: generation, EvidenceRefs: []string{member.FreeformTags["terrascale-observation-ref"]}}, generation, observations...)
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
