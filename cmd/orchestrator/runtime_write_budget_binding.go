package main

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

// productionBudgetTarget follows accepted successor placement and lifecycle
// state. Operator policy cannot promote a follower or retarget an allocation.
func productionBudgetTarget(database **productionDatabase) writeBudgetTargetResolver {
	return func(ctx context.Context, envelope writebudget.AllocationEnvelope) (databaseadmission.Target, error) {
		if database == nil || *database == nil || (*database).lifecycleJournal == nil {
			return databaseadmission.Target{}, writebudget.ErrUnavailable
		}
		record, err := (*database).AcceptedRecord(ctx, envelope.Grant.DatabaseID)
		if err != nil {
			return databaseadmission.Target{}, err
		}
		_, resources, err := (*database).lifecycleJournal.LifecycleResources(ctx)
		if err != nil {
			return databaseadmission.Target{}, err
		}
		return acceptedBudgetTarget(record, resources, envelope)
	}
}

func acceptedBudgetTarget(record databaseadmission.Record, resources []databaselifecycle.Resource, envelope writebudget.AllocationEnvelope) (databaseadmission.Target, error) {
	grant := envelope.Grant
	// Pool work arrives in the members' lowercase region form while the
	// admitted record carries uppercase regions; the binding judges identity,
	// not which transport side minted the casing.
	regionsMatch := len(record.Request.Regions) == len(grant.Regions) && slices.EqualFunc(record.Request.Regions, grant.Regions, strings.EqualFold)
	if databaseadmission.ValidateRecord(record) != nil || record.State != "ready" || record.DatabaseID != grant.DatabaseID || record.Request.TenantID != grant.OrganizationID || !regionsMatch || grant.WriterEpoch == 0 || envelope.Placement == "" {
		return databaseadmission.Target{}, writebudget.ErrInvalid
	}
	var active *databaselifecycle.Resource
	for _, resource := range resources {
		if resource.DatabaseID == record.DatabaseID && resource.OrganizationID == record.Request.TenantID && resource.ProjectID == record.Request.ProjectID && resource.Environment == record.Request.Environment && resource.ParentDatabaseID == record.Request.ParentDatabaseID && slices.Equal(resource.Regions, record.Request.Regions) && !resource.CreatedAt.IsZero() && resource.DeletedAt.IsZero() && resource.UsageStoppedAt.IsZero() && !resource.AccessRevoked {
			active = &resource
		}
	}
	if active == nil {
		return databaseadmission.Target{}, writebudget.ErrInvalid
	}
	for _, target := range record.Targets {
		if target.MemberID != grant.HolderID || !target.Installed {
			continue
		}
		streamActive := false
		for _, stream := range active.Streams {
			if stream.Region == target.Region && stream.Epoch == grant.WriterEpoch && !stream.StartedAt.IsZero() && stream.StoppedAt.IsZero() {
				streamActive = true
			}
		}
		if !streamActive {
			return databaseadmission.Target{}, writebudget.ErrInvalid
		}
		accepted := false
		for _, placement := range record.PlacementTargets {
			if len(placement.AcceptedReceipt) == 0 || placement.AcceptedRevision == 0 || placement.AcceptedGeneration == 0 || placement.AcceptedEpoch != grant.WriterEpoch || placement.AcceptedProofDigest != envelope.Placement {
				return databaseadmission.Target{}, writebudget.ErrInvalid
			}
			if placement.MemberID == target.MemberID && placement.ServerIdentity == target.ServerIdentity {
				accepted = true
			}
		}
		stage := new(pb.PlacementStageRequest)
		if !accepted || proto.Unmarshal(target.Proposal, stage) != nil || stage.Proposal == nil || stage.Proposal.Epoch != grant.WriterEpoch {
			return databaseadmission.Target{}, writebudget.ErrInvalid
		}
		for _, assignment := range stage.Proposal.Assignments {
			if assignment.Database == record.DatabaseID && assignment.Tenant == record.Request.TenantID && assignment.Project == record.Request.ProjectID && assignment.Region == target.Region && assignment.WriterMember == target.MemberID {
				return target, nil
			}
		}
	}
	return databaseadmission.Target{}, writebudget.ErrInvalid
}
