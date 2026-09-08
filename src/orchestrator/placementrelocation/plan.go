// Package placementrelocation retains successor placement independently of
// immutable database admission history. A plan covers one entire placement
// scope; all databases move in the same accepted epoch.
package placementrelocation

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

var (
	ErrInvalid  = errors.New("placement relocation: invalid plan or evidence")
	ErrConflict = errors.New("placement relocation: immutable operation conflict")
	ErrMissing  = errors.New("placement relocation: operation missing")
)

type Target struct {
	ServerIdentity string
	MemberID       string
	Region         string
	Proposal       []byte
}

type Plan struct {
	OperationID         string
	AdmissionDigest     string
	RemovedIdentity     string
	ReplacementIdentity string
	Request             placementtransition.Request
	PriorProof          placementtransition.Signed
	PriorStage          []byte
	Records             []databaseadmission.Record
	Targets             []Target
}

// BuildInput contains authenticated, durable placement and admitted transport
// inventory. Revisions must include every successor target, including zero for
// a target authoritatively known never to have staged placement.
type BuildInput struct {
	OperationID     string
	RemovedIdentity string
	Replacement     Target
	PriorProof      placementtransition.Signed
	PriorStage      []byte
	// Records must come from admission.RelocationRecords and be reserved by
	// BeginPlacementRelocation before any effect. Only that authoritative
	// snapshot can establish that omitted scopes completed retirement.
	Records   []databaseadmission.Record
	Revisions map[string]uint64
}

func Digest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return BytesDigest(encoded), nil
}
func BytesDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func Build(input BuildInput) (Plan, error) {
	var prior placementtransition.Proof
	old := new(pb.PlacementStageRequest)
	if input.OperationID == "" || json.Unmarshal(input.PriorProof.Payload, &prior, json.RejectUnknownMembers(true)) != nil || prior.Kind != "accepted_epoch" || proto.Unmarshal(input.PriorStage, old) != nil || old.Proposal == nil || old.Proposal.Epoch != prior.Request.Epoch || old.Proposal.Generation != prior.Request.Generation || old.Proposal.Epoch == ^uint64(0) || old.Proposal.Generation == ^uint64(0) {
		return Plan{}, ErrInvalid
	}
	priorDigest, err := placementtransition.RequestDigest(prior.Request)
	if err != nil || priorDigest != prior.RequestDigest {
		return Plan{}, ErrInvalid
	}
	canonical, err := tbep.CanonicalPlacement(old.Proposal)
	if err != nil {
		return Plan{}, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(canonical)
	if err != nil {
		return Plan{}, err
	}
	prefix := "spiffe://terrascale.tech/" + canonical.Environment + "/terrabase-member/" + canonical.Cluster + "/"
	if prior.Request.ScopeID != canonical.Environment+"/"+canonical.Cluster || input.Replacement.ServerIdentity != prefix+input.Replacement.MemberID || input.Replacement.MemberID == "" || input.Replacement.ServerIdentity == input.RemovedIdentity {
		return Plan{}, ErrInvalid
	}
	removed := ""
	for _, member := range prior.Request.Members {
		if member.PlacementDigest != BytesDigest(encoded) {
			return Plan{}, ErrConflict
		}
		if member.Identity == input.Replacement.ServerIdentity {
			return Plan{}, ErrConflict
		}
		if member.Identity == input.RemovedIdentity {
			removed = member.Region
		}
	}
	if removed == "" || removed != input.Replacement.Region || !strings.HasPrefix(input.RemovedIdentity, prefix) {
		return Plan{}, ErrInvalid
	}
	// Completed inactive scopes can remain in the preceding accepted epoch.
	// Drop them only from the successor built from the authoritative active
	// snapshot; active database roles and residency remain immutable.
	active := activeDatabases(input.Records)
	canonical.Assignments = slices.DeleteFunc(canonical.Assignments, func(a *pb.PlacementDatabaseAssignment) bool { return !active[a.Database] })
	for _, declaration := range old.Declarations {
		if declaration == nil {
			return Plan{}, ErrInvalid
		}
	}
	old.Declarations = slices.DeleteFunc(old.Declarations, func(d *pb.PlacementDatabaseDeclaration) bool { return !active[d.Database] })
	removedID := strings.TrimPrefix(input.RemovedIdentity, prefix)
	replaced := 0
	for _, region := range canonical.Regions {
		for i, member := range region.Members {
			if member == removedID {
				if region.Region != removed {
					return Plan{}, ErrConflict
				}
				region.Members[i] = input.Replacement.MemberID
				replaced++
			}
		}
	}
	if replaced != 1 {
		return Plan{}, ErrConflict
	}
	for _, assignment := range canonical.Assignments {
		if assignment.WriterMember == removedID {
			assignment.WriterMember = input.Replacement.MemberID
		}
		if assignment.FollowerMember == removedID {
			assignment.FollowerMember = input.Replacement.MemberID
		}
	}
	canonical.Epoch++
	canonical.Generation++
	canonical, err = tbep.CanonicalPlacement(canonical)
	if err != nil {
		return Plan{}, err
	}
	encoded, err = (proto.MarshalOptions{Deterministic: true}).Marshal(canonical)
	if err != nil {
		return Plan{}, err
	}
	records := slices.Clone(input.Records)
	slices.SortFunc(records, func(a, b databaseadmission.Record) int { return cmp.Compare(a.DatabaseID, b.DatabaseID) })
	admissionDigest, err := Digest(records)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{OperationID: input.OperationID, AdmissionDigest: admissionDigest, RemovedIdentity: input.RemovedIdentity, ReplacementIdentity: input.Replacement.ServerIdentity, PriorProof: input.PriorProof, PriorStage: slices.Clone(input.PriorStage), Records: records, Request: placementtransition.Request{OperationID: input.OperationID, ScopeID: prior.Request.ScopeID, PriorEpoch: prior.Request.Epoch, Epoch: canonical.Epoch, Generation: canonical.Generation}}
	for _, seats := range canonical.Regions {
		for _, member := range seats.Members {
			identity := prefix + member
			revision, found := input.Revisions[identity]
			if !found || revision == ^uint64(0) {
				return Plan{}, ErrInvalid
			}
			request, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&pb.PlacementStageRequest{ExpectedRevision: revision, Proposal: canonical, Declarations: old.Declarations})
			if err != nil {
				return Plan{}, err
			}
			plan.Targets = append(plan.Targets, Target{ServerIdentity: identity, MemberID: member, Region: seats.Region, Proposal: request})
			plan.Request.Members = append(plan.Request.Members, placementtransition.Member{Identity: identity, Region: seats.Region, PlacementDigest: BytesDigest(encoded)})
		}
	}
	slices.SortFunc(plan.Targets, func(a, b Target) int { return cmp.Compare(a.ServerIdentity, b.ServerIdentity) })
	slices.SortFunc(plan.Request.Members, func(a, b placementtransition.Member) int { return cmp.Compare(a.Identity, b.Identity) })
	if err := ValidatePlan(plan); err != nil {
		return Plan{}, err
	}
	return clone(plan), nil
}

func ValidatePlan(plan Plan) error {
	if plan.OperationID != plan.Request.OperationID || plan.RemovedIdentity == "" || plan.ReplacementIdentity == "" || plan.RemovedIdentity == plan.ReplacementIdentity || len(plan.Records) == 0 || len(plan.Targets) != len(plan.Request.Members) {
		return ErrInvalid
	}
	if _, err := placementtransition.RequestDigest(plan.Request); err != nil {
		return ErrInvalid
	}
	digest, err := Digest(plan.Records)
	if err != nil || digest != plan.AdmissionDigest {
		return ErrInvalid
	}
	var prior placementtransition.Proof
	if json.Unmarshal(plan.PriorProof.Payload, &prior, json.RejectUnknownMembers(true)) != nil || prior.Kind != "accepted_epoch" || prior.Request.ScopeID != plan.Request.ScopeID || prior.Request.Epoch != plan.Request.PriorEpoch || prior.Request.Generation >= plan.Request.Generation {
		return ErrInvalid
	}
	priorDigest, err := placementtransition.RequestDigest(prior.Request)
	if err != nil || priorDigest != prior.RequestDigest {
		return ErrInvalid
	}
	oldStage := new(pb.PlacementStageRequest)
	if proto.Unmarshal(plan.PriorStage, oldStage) != nil || oldStage.Proposal == nil || oldStage.Proposal.Epoch != prior.Request.Epoch || oldStage.Proposal.Generation != prior.Request.Generation {
		return ErrInvalid
	}
	expected, err := tbep.CanonicalPlacement(oldStage.Proposal)
	if err != nil {
		return ErrInvalid
	}
	oldBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(expected)
	if err != nil {
		return ErrInvalid
	}
	for _, member := range prior.Request.Members {
		if member.PlacementDigest != BytesDigest(oldBytes) {
			return ErrInvalid
		}
	}
	active := activeDatabases(plan.Records)
	expected.Assignments = slices.DeleteFunc(expected.Assignments, func(a *pb.PlacementDatabaseAssignment) bool { return !active[a.Database] })
	prefix := "spiffe://terrascale.tech/" + expected.Environment + "/terrabase-member/" + expected.Cluster + "/"
	if !strings.HasPrefix(plan.RemovedIdentity, prefix) || !strings.HasPrefix(plan.ReplacementIdentity, prefix) {
		return ErrInvalid
	}
	oldID, newID := strings.TrimPrefix(plan.RemovedIdentity, prefix), strings.TrimPrefix(plan.ReplacementIdentity, prefix)
	for _, region := range expected.Regions {
		for n, id := range region.Members {
			if id == oldID {
				region.Members[n] = newID
			}
		}
	}
	for _, assignment := range expected.Assignments {
		if assignment.WriterMember == oldID {
			assignment.WriterMember = newID
		}
		if assignment.FollowerMember == oldID {
			assignment.FollowerMember = newID
		}
	}
	expected.Epoch, expected.Generation = plan.Request.Epoch, plan.Request.Generation
	expected, err = tbep.CanonicalPlacement(expected)
	if err != nil {
		return ErrInvalid
	}
	oldMembers := map[string]placementtransition.Member{}
	for _, member := range prior.Request.Members {
		oldMembers[member.Identity] = member
	}
	removed, found := oldMembers[plan.RemovedIdentity]
	if !found {
		return ErrInvalid
	}
	delete(oldMembers, plan.RemovedIdentity)
	if _, found := oldMembers[plan.ReplacementIdentity]; found {
		return ErrInvalid
	}
	declarations := map[string]*pb.PlacementDatabaseDeclaration{}
	assignments := map[string][]*pb.PlacementDatabaseAssignment{}
	for i, target := range plan.Targets {
		member := plan.Request.Members[i]
		if target.ServerIdentity != member.Identity || target.Region != member.Region || target.ServerIdentity == plan.RemovedIdentity {
			return ErrInvalid
		}
		if target.ServerIdentity == plan.ReplacementIdentity {
			if target.Region != removed.Region {
				return ErrInvalid
			}
		} else if old, found := oldMembers[target.ServerIdentity]; !found || old.Region != target.Region {
			return ErrInvalid
		} else {
			delete(oldMembers, target.ServerIdentity)
		}
		stage := new(pb.PlacementStageRequest)
		if proto.Unmarshal(target.Proposal, stage) != nil || stage.Proposal == nil || stage.Proposal.Epoch != plan.Request.Epoch || stage.Proposal.Generation != plan.Request.Generation || stage.ExpectedRevision == ^uint64(0) {
			return ErrInvalid
		}
		canonical, err := tbep.CanonicalPlacement(stage.Proposal)
		if err != nil || !proto.Equal(canonical, expected) {
			return ErrInvalid
		}
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(canonical)
		if err != nil || BytesDigest(encoded) != member.PlacementDigest || canonical.Environment+"/"+canonical.Cluster != plan.Request.ScopeID || target.ServerIdentity != "spiffe://terrascale.tech/"+canonical.Environment+"/terrabase-member/"+canonical.Cluster+"/"+target.MemberID {
			return ErrInvalid
		}
		if i == 0 {
			for _, declaration := range stage.Declarations {
				if declaration == nil || declarations[declaration.Database] != nil {
					return ErrInvalid
				}
				declarations[declaration.Database] = declaration
			}
			for _, assignment := range canonical.Assignments {
				assignments[assignment.Database] = append(assignments[assignment.Database], assignment)
			}
		} else {
			first := new(pb.PlacementStageRequest)
			if proto.Unmarshal(plan.Targets[0].Proposal, first) != nil || !proto.Equal(first.Proposal, stage.Proposal) || len(first.Declarations) != len(stage.Declarations) {
				return ErrInvalid
			}
			for n, d := range first.Declarations {
				if !proto.Equal(d, stage.Declarations[n]) {
					return ErrInvalid
				}
			}
		}
	}
	if len(oldMembers) != 0 || len(declarations) != len(plan.Records) || len(assignments) != len(plan.Records) {
		return ErrInvalid
	}
	for i, record := range plan.Records {
		if databaseadmission.ValidateRecord(record) != nil || (i > 0 && plan.Records[i-1].DatabaseID >= record.DatabaseID) {
			return ErrInvalid
		}
		declaration := declarations[record.DatabaseID]
		if declaration == nil || declaration.Tenant != record.Request.TenantID || declaration.Project != record.Request.ProjectID || !slices.Equal(slices.Sorted(slices.Values(declaration.SelectedRegions)), slices.Sorted(slices.Values(record.Request.Regions))) {
			return ErrInvalid
		}
		actual := assignments[record.DatabaseID]
		if len(actual) != len(record.Request.Regions) {
			return ErrInvalid
		}
		for _, assignment := range actual {
			if assignment.Tenant != record.Request.TenantID || assignment.Project != record.Request.ProjectID || !slices.Contains(record.Request.Regions, assignment.Region) {
				return ErrInvalid
			}
		}
	}
	return nil
}

func clone[T any](value T) T {
	encoded, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(encoded, &result)
	return result
}

func activeDatabases(records []databaseadmission.Record) map[string]bool {
	active := make(map[string]bool, len(records))
	for _, record := range records {
		active[record.DatabaseID] = true
	}
	return active
}
