package main

import (
	"context"
	"encoding/json/v2"
	"google.golang.org/protobuf/proto"
	"slices"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

// currentDatabaseJournal projects accepted successor placements without
// rewriting database admission history. Mutation methods remain owned by the
// embedded admission journal; only placement consumers use this read view.
type currentDatabaseJournal struct {
	*databaseadmission.NATSJournal
}

func (j *currentDatabaseJournal) List(ctx context.Context) ([]databaseadmission.Record, error) {
	if j == nil || j.NATSJournal == nil {
		return nil, databaseadmission.ErrJournalUnavailable
	}
	return j.NATSJournal.CurrentRecords(ctx)
}

func (d *productionDatabase) currentRecords(ctx context.Context) ([]databaseadmission.Record, error) {
	if d == nil || d.lifecycleJournal == nil {
		return nil, databaseadmission.ErrJournalUnavailable
	}
	if d.currentJournal != nil {
		return d.currentJournal.List(ctx)
	}
	return d.lifecycleJournal.List(ctx)
}

// relocatedDatabaseRecords builds the successor view only after every target
// accepted the relocation. CommitPlacementRelocation verifies its signatures and
// predecessor tuple atomically against the still-fenced admission state.
func relocatedDatabaseRecords(operation placementrelocation.Operation) ([]databaseadmission.Record, error) {
	if len(operation.Acceptances) != len(operation.Plan.Targets) || placementrelocation.ValidateOperation(operation) != nil {
		return nil, databaseadmission.ErrInvalid
	}
	proof, err := json.Marshal(operation.Accepted)
	if err != nil {
		return nil, err
	}
	out := make([]databaseadmission.Record, 0, len(operation.Plan.Records))
	for _, historical := range operation.Plan.Records {
		record := historical
		record.Targets = nil
		record.PlacementTargets = nil
		for _, target := range operation.Plan.Targets {
			receipt := new(pb.PlacementAcceptanceResponse)
			if proto.Unmarshal(operation.Acceptances[target.ServerIdentity], receipt) != nil {
				return nil, databaseadmission.ErrInvalid
			}
			record.PlacementTargets = append(record.PlacementTargets, databaseadmission.PlacementTarget{ServerIdentity: target.ServerIdentity, MemberID: target.MemberID, Region: target.Region, Proposal: slices.Clone(target.Proposal), AcceptedReceipt: slices.Clone(operation.Acceptances[target.ServerIdentity]), AcceptedProof: slices.Clone(proof), AcceptedRevision: receipt.ProposalRevision, AcceptedEpoch: receipt.Epoch, AcceptedGeneration: receipt.Generation, AcceptedProofDigest: receipt.ProofDigest, Proposed: true})
			if !slices.Contains(record.Request.Regions, target.Region) {
				continue
			}
			var provision *databaseadmission.Target
			for _, old := range historical.Targets {
				if old.Region == target.Region {
					value := old
					provision = &value
					break
				}
			}
			if provision == nil {
				return nil, databaseadmission.ErrInvalid
			}
			provision.ServerIdentity, provision.MemberID, provision.Proposal = target.ServerIdentity, target.MemberID, slices.Clone(target.Proposal)
			provision.Installed = true
			record.Targets = append(record.Targets, *provision)
		}
		if databaseadmission.ValidateRecord(record) != nil {
			return nil, databaseadmission.ErrInvalid
		}
		out = append(out, record)
	}
	return out, nil
}

// relocationUsageSource exposes the already authenticated candidate records
// while lifecycle stream authority remains in the admission journal.
type relocationUsageSource struct {
	*databaseadmission.NATSJournal
	records []databaseadmission.Record
}

func (s relocationUsageSource) List(context.Context) ([]databaseadmission.Record, error) {
	return slices.Clone(s.records), nil
}
