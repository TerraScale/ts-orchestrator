package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type databaseUsageDelivery struct {
	Target       databaseadmission.Target
	Registration databaseadmission.UsageRegistration
}

// planDatabaseUsage derives registrations only from the immutable placement,
// admission records, and lifecycle journal. It has no allocation or delivery
// side effects.
func planDatabaseUsage(record databaseadmission.Record, records []databaseadmission.Record, resources []databaselifecycle.Resource, proofDigest string, now time.Time) ([]databaseUsageDelivery, error) {
	if len(record.PlacementTargets) == 0 || proofDigest == "" || now.IsZero() {
		return nil, databaseadmission.ErrInvalid
	}
	var canonical []byte
	var proposal *pb.PlacementProposal
	var declarations []*pb.PlacementDatabaseDeclaration
	for _, target := range record.PlacementTargets {
		stage := new(pb.PlacementControlServiceStageRequest)
		if len(target.Proposal) == 0 || proto.Unmarshal(target.Proposal, stage) != nil {
			return nil, databaseadmission.ErrInvalid
		}
		p, err := tbep.CanonicalPlacement(stage.Proposal)
		if err != nil {
			return nil, err
		}
		stage.Proposal = p
		stage.ExpectedRevision = 0
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(stage)
		if err != nil {
			return nil, err
		}
		if canonical == nil {
			canonical, proposal, declarations = encoded, p, stage.Declarations
		} else if !bytes.Equal(canonical, encoded) {
			return nil, databaseadmission.ErrConflict
		}
	}
	if proposal == nil || proposal.Environment != record.Request.Environment {
		return nil, databaseadmission.ErrInvalid
	}
	if len(proposal.Assignments) == 0 || len(declarations) == 0 {
		if len(proposal.Assignments) == 0 && len(declarations) == 0 {
			return nil, nil
		}
		return nil, databaseadmission.ErrConflict
	}
	if err := validateDatabaseDeclarationsAgainstProposal(declarations, proposal); err != nil {
		return nil, err
	}

	// Records are the authority for residency, since declarations intentionally
	// contain only scope and selected Regions.
	recordByScope := map[string]databaseadmission.Record{}
	databaseOwners := map[string]string{}
	addRecord := func(r databaseadmission.Record) error {
		if databaseadmission.ValidateRequest(r.Request) != nil || r.Request.Environment != proposal.Environment || r.DatabaseID == "" {
			return databaseadmission.ErrInvalid
		}
		key := usageScope(r.Request.TenantID, r.Request.ProjectID, r.DatabaseID)
		owner := r.Request.TenantID + "\x00" + r.Request.ProjectID
		if prior, ok := databaseOwners[r.DatabaseID]; ok && prior != owner {
			return databaseadmission.ErrConflict
		}
		databaseOwners[r.DatabaseID] = owner
		if prior, ok := recordByScope[key]; ok && (!reflect.DeepEqual(prior.Request, r.Request) || !prior.CreatedAt.Equal(r.CreatedAt)) {
			return databaseadmission.ErrConflict
		}
		recordByScope[key] = r
		return nil
	}
	for _, r := range records {
		if err := addRecord(r); err != nil {
			return nil, err
		}
	}
	if err := addRecord(record); err != nil {
		return nil, err
	}

	declarationByScope := map[string]*pb.PlacementDatabaseDeclaration{}
	for _, declaration := range declarations {
		if declaration == nil || !slices.IsSorted(declaration.SelectedRegions) || slices.ContainsFunc(declaration.SelectedRegions, func(region string) bool { return region == "" }) {
			return nil, databaseadmission.ErrInvalid
		}
		key := usageScope(declaration.Tenant, declaration.Project, declaration.Database)
		owner := declaration.Tenant + "\x00" + declaration.Project
		if prior, ok := databaseOwners[declaration.Database]; ok && prior != owner {
			return nil, databaseadmission.ErrConflict
		}
		databaseOwners[declaration.Database] = owner
		if _, ok := declarationByScope[key]; ok {
			return nil, databaseadmission.ErrConflict
		}
		declarationByScope[key] = declaration
	}
	resourceByScope := map[string]databaselifecycle.Resource{}
	for _, resource := range resources {
		key := usageScope(resource.OrganizationID, resource.ProjectID, resource.DatabaseID)
		owner := resource.OrganizationID + "\x00" + resource.ProjectID
		if prior, ok := databaseOwners[resource.DatabaseID]; ok && prior != owner {
			return nil, databaseadmission.ErrConflict
		}
		databaseOwners[resource.DatabaseID] = owner
		if _, ok := resourceByScope[key]; ok {
			return nil, databaseadmission.ErrConflict
		}
		resourceByScope[key] = resource
	}
	memberRegions := map[string]string{}
	memberTargets := map[string]databaseadmission.Target{}
	for _, target := range record.PlacementTargets {
		if target.MemberID == "" || target.Region == "" || target.ServerIdentity != "spiffe://terrascale.tech/"+proposal.Environment+"/terrabase-member/"+proposal.Cluster+"/"+target.MemberID {
			return nil, databaseadmission.ErrInvalid
		}
		if _, exists := memberTargets[target.MemberID]; exists {
			return nil, databaseadmission.ErrConflict
		}
		memberTargets[target.MemberID] = databaseadmission.Target{ServerIdentity: target.ServerIdentity, MemberID: target.MemberID, Region: target.Region}
	}
	for _, region := range proposal.Regions {
		if region == nil || len(region.Members) != 2 {
			return nil, databaseadmission.ErrInvalid
		}
		for _, member := range region.Members {
			if _, ok := memberRegions[member]; ok {
				return nil, databaseadmission.ErrConflict
			}
			memberRegions[member] = region.Region
			target, ok := memberTargets[member]
			if !ok || target.Region != region.Region {
				return nil, databaseadmission.ErrConflict
			}
		}
	}
	if len(memberRegions) != len(memberTargets) {
		return nil, databaseadmission.ErrConflict
	}

	seenAssignments := map[string]bool{}
	var out []databaseUsageDelivery
	for _, assignment := range proposal.Assignments {
		if assignment == nil || assignment.WriterMember == "" || assignment.FollowerMember == "" || assignment.WriterMember == assignment.FollowerMember {
			return nil, databaseadmission.ErrInvalid
		}
		key := usageScope(assignment.Tenant, assignment.Project, assignment.Database)
		if seenAssignments[key+"\x00"+assignment.Region] {
			return nil, databaseadmission.ErrConflict
		}
		seenAssignments[key+"\x00"+assignment.Region] = true
		r, ok := recordByScope[key]
		if !ok {
			return nil, databaseadmission.ErrConflict
		}
		declaration, ok := declarationByScope[key]
		if !ok || !slices.Equal(declaration.SelectedRegions, sortedUnique(r.Request.Regions)) {
			return nil, databaseadmission.ErrConflict
		}
		resource, ok := resourceByScope[key]
		if !ok || resource.Environment != proposal.Environment || resource.OrganizationID != assignment.Tenant || resource.ProjectID != assignment.Project || resource.DatabaseID != assignment.Database || resource.ParentDatabaseID != r.Request.ParentDatabaseID || resource.CreatedAt.IsZero() || !resource.CreatedAt.Equal(r.CreatedAt) || resource.CreatedAt.After(now) || !slices.Equal(resource.Regions, declaration.SelectedRegions) {
			return nil, databaseadmission.ErrConflict
		}
		if !resource.DeletedAt.IsZero() {
			if !resource.AccessRevoked || !resource.UsageStoppedAt.Equal(resource.DeletedAt) || resource.DeletedAt.Before(resource.CreatedAt) || resource.DeletedAt.After(now) {
				return nil, databaseadmission.ErrConflict
			}
			continue
		}
		if resource.AccessRevoked || !resource.UsageStoppedAt.IsZero() || !resource.RoutingComplete {
			return nil, databaseadmission.ErrConflict
		}
		var stream *databaselifecycle.Stream
		for i := range resource.Streams {
			candidate := &resource.Streams[i]
			if candidate.Region != assignment.Region || !candidate.StoppedAt.IsZero() {
				continue
			}
			if stream != nil || candidate.Epoch != proposal.Epoch || candidate.StartedAt.IsZero() || candidate.StartedAt.Before(resource.CreatedAt) || candidate.StartedAt.After(now) || candidate.Partition == "" {
				return nil, databaseadmission.ErrConflict
			}
			stream = candidate
		}
		if stream == nil {
			return nil, databaseadmission.ErrConflict
		}
		for _, member := range []string{assignment.WriterMember, assignment.FollowerMember} {
			if memberRegions[member] != assignment.Region {
				return nil, databaseadmission.ErrConflict
			}
			target := memberTargets[member]
			out = append(out, databaseUsageDelivery{
				Target:       target,
				Registration: databaseadmission.UsageRegistration{SchemaVersion: 1, Environment: proposal.Environment, TenantID: assignment.Tenant, ProjectID: assignment.Project, DatabaseID: assignment.Database, MemberID: member, Region: assignment.Region, SelectedRegions: slices.Clone(declaration.SelectedRegions), Residency: normalizedResidency(r.Request.Residency), Partition: stream.Partition, StreamEpoch: stream.Epoch, PlacementProofDigest: proofDigest, OperationID: usageOperation(proofDigest, assignment.Tenant, assignment.Project, assignment.Database)},
			})
		}
	}
	slices.SortFunc(out, func(a, b databaseUsageDelivery) int {
		return cmp.Or(cmp.Compare(a.Registration.DatabaseID, b.Registration.DatabaseID), cmp.Compare(a.Registration.Region, b.Registration.Region), cmp.Compare(a.Registration.MemberID, b.Registration.MemberID))
	})
	for _, delivery := range out {
		if err := databaseadmission.ValidateUsageRegistration(delivery.Registration); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func usageScope(tenant, project, database string) string {
	return tenant + "\x00" + project + "\x00" + database
}
func normalizedResidency(value string) string {
	if value == "" {
		return "none"
	}
	return value
}
func sortedUnique(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}
func usageOperation(digest, tenant, project, database string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{digest, tenant, project, database}, "\x00")))
	return "database-usage-" + hex.EncodeToString(sum[:])
}
