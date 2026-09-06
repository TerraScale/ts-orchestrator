package databaseadmission

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/oklog/ulid"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// AllocatePlacementStreams commits the lifecycle streams required by an
// already accepted placement proof. Partitions are generated only inside the
// fenced journal transaction and are retained by the committed event.
func (journal *NATSJournal) AllocatePlacementStreams(ctx context.Context, record Record, proofDigest string, now time.Time) error {
	if journal == nil || journal.journal == nil {
		return ErrJournalUnavailable
	}
	return journal.journal.Transact(ctx, true, func(state *journalState) error {
		return allocatePlacementStreams(state, record, proofDigest, now)
	})
}

func (journal *MemoryJournal) AllocatePlacementStreams(ctx context.Context, record Record, proofDigest string, now time.Time) error {
	if journal == nil {
		return ErrJournalUnavailable
	}
	return journal.lifecycleTransact(ctx, func(state *journalState) error {
		return allocatePlacementStreams(state, record, proofDigest, now)
	})
}

func allocatePlacementStreams(state *journalState, record Record, proofDigest string, now time.Time) error {
	if state == nil || !validDigest(proofDigest) || now.IsZero() {
		return ErrInvalid
	}
	proposal, declarations, err := allocationProposal(record)
	if err != nil {
		return err
	}
	if proposal.Environment != record.Request.Environment {
		return ErrConflict
	}
	if len(proposal.Assignments) == 0 && len(declarations) == 0 {
		// Only the synthetic empty-cluster bootstrap has no owned database.
		if record.DatabaseID != "" || len(record.Targets) != 0 {
			return ErrConflict
		}
		return nil
	}
	if len(proposal.Assignments) == 0 || len(declarations) == 0 {
		return ErrConflict
	}
	if persisted, ok := state.Records[ScopeKey(record.Request)]; !ok || ValidateRecord(record) != nil || !ImmutableEqual(persisted, record) {
		return ErrConflict
	}
	if err := allocationDeclarations(declarations, proposal); err != nil {
		return err
	}
	assignments := map[string][]string{}
	for _, assignment := range proposal.Assignments {
		if assignment == nil || assignment.Tenant == "" || assignment.Project == "" || assignment.Database == "" || assignment.Region == "" {
			return ErrInvalid
		}
		key := allocationScope(assignment.Tenant, assignment.Project, assignment.Database)
		assignments[key] = append(assignments[key], assignment.Region)
	}
	for _, key := range slices.Sorted(maps.Keys(assignments)) {
		regions := assignments[key]
		slices.Sort(regions)
		if len(regions) == 0 || len(slices.Compact(slices.Clone(regions))) != len(regions) {
			return ErrConflict
		}
		parts := strings.Split(key, "\x00")
		if len(parts) != 3 {
			return ErrInvalid
		}
		resourceKey := databaselifecycle.Key(databaselifecycle.Identity{Environment: proposal.Environment, OrganizationID: parts[0], ProjectID: parts[1], DatabaseID: parts[2]})
		resource, ok := state.Lifecycle.Resources[resourceKey]
		resourceRecord, recordOK := allocationRecord(state.Records, proposal.Environment, parts[0], parts[1], parts[2])
		if !ok || !recordOK || resource.Identity != (databaselifecycle.Identity{Environment: proposal.Environment, OrganizationID: parts[0], ProjectID: parts[1], DatabaseID: parts[2], ParentDatabaseID: resourceRecord.Request.ParentDatabaseID}) || !resource.CreatedAt.Equal(resourceRecord.CreatedAt) || resource.CreatedAt.After(now) || !slices.Equal(sortedAllocationRegions(resourceRecord.Request.Regions), resource.Regions) || !slices.Equal(resource.Regions, declarationRegions(declarations, parts[0], parts[1], parts[2])) {
			return ErrConflict
		}
		if !resource.DeletedAt.IsZero() {
			if !resource.AccessRevoked || !resource.UsageStoppedAt.Equal(resource.DeletedAt) || resource.DeletedAt.Before(resource.CreatedAt) || resource.DeletedAt.After(now) {
				return ErrConflict
			}
			continue
		}
		if resource.AccessRevoked || !resource.UsageStoppedAt.IsZero() {
			return ErrConflict
		}
		for _, region := range regions {
			if !slices.Contains(resource.Regions, region) {
				return ErrConflict
			}
		}
		operation := allocationOperation(proofDigest, key, proposal.Epoch)
		if prior, ok := state.Lifecycle.Events[resource.Environment+"/"+resource.OrganizationID+"/"+operation]; ok {
			if prior.Identity != resource.Identity || prior.Kind != "streams" || prior.At.After(now) || !sameAllocationRegions(prior.Streams, resource.Streams, proposal.Epoch, regions) {
				return ErrConflict
			}
			continue
		}
		streams := slices.Clone(resource.Streams)
		for _, region := range regions {
			started := now
			if !slices.ContainsFunc(streams, func(stream databaselifecycle.Stream) bool { return stream.Region == region }) {
				// The resource existed from CreatedAt before the first routing event;
				// preserve that billable interval without inventing a later start.
				started = resource.CreatedAt
			}
			if err := appendAllocationStream(&streams, region, proposal.Epoch, resource.CreatedAt, started); err != nil {
				return err
			}
		}
		event := databaselifecycle.Event{OperationID: operation, Kind: "streams", Identity: resource.Identity, At: now, Streams: streams}
		if err := databaselifecycle.Apply(&state.Lifecycle, event); err != nil {
			return err
		}
	}
	return validateReservedCapacity(*state)
}

func allocationProposal(record Record) (*pb.PlacementProposal, []*pb.PlacementDatabaseDeclaration, error) {
	if len(record.PlacementTargets) == 0 || validatePlacementTargets(record) != nil {
		return nil, nil, ErrInvalid
	}
	var canonical []byte
	var proposal *pb.PlacementProposal
	var declarations []*pb.PlacementDatabaseDeclaration
	for _, target := range record.PlacementTargets {
		stage := new(pb.PlacementControlServiceStageRequest)
		if proto.Unmarshal(target.Proposal, stage) != nil {
			return nil, nil, ErrInvalid
		}
		p, err := tbep.CanonicalPlacement(stage.Proposal)
		if err != nil {
			return nil, nil, err
		}
		stage.Proposal, stage.ExpectedRevision = p, 0
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(stage)
		if err != nil {
			return nil, nil, err
		}
		if canonical == nil {
			canonical, proposal, declarations = encoded, p, stage.Declarations
		} else if !bytes.Equal(canonical, encoded) {
			return nil, nil, ErrConflict
		}
	}
	return proposal, declarations, nil
}

func allocationDeclarations(declarations []*pb.PlacementDatabaseDeclaration, proposal *pb.PlacementProposal) error {
	seen := map[string]bool{}
	for _, declaration := range declarations {
		if declaration == nil || !canonicalID.MatchString(declaration.Tenant) || !canonicalID.MatchString(declaration.Project) || !canonicalID.MatchString(declaration.Database) || len(declaration.SelectedRegions) == 0 || !slices.IsSorted(declaration.SelectedRegions) || len(slices.Compact(slices.Clone(declaration.SelectedRegions))) != len(declaration.SelectedRegions) {
			return ErrInvalid
		}
		key := allocationScope(declaration.Tenant, declaration.Project, declaration.Database)
		if seen[key] {
			return ErrConflict
		}
		seen[key] = true
	}
	assigned := map[string][]string{}
	for _, assignment := range proposal.Assignments {
		if assignment == nil || !canonicalID.MatchString(assignment.Tenant) || !canonicalID.MatchString(assignment.Project) || !canonicalID.MatchString(assignment.Database) {
			return ErrInvalid
		}
		key := allocationScope(assignment.Tenant, assignment.Project, assignment.Database)
		assigned[key] = append(assigned[key], assignment.Region)
	}
	if len(seen) != len(assigned) {
		return ErrConflict
	}
	for key, regions := range assigned {
		slices.Sort(regions)
		if !slices.Equal(regions, declarationRegions(declarations, strings.Split(key, "\x00")[0], strings.Split(key, "\x00")[1], strings.Split(key, "\x00")[2])) {
			return ErrConflict
		}
	}
	return nil
}

func declarationRegions(declarations []*pb.PlacementDatabaseDeclaration, tenant, project, database string) []string {
	for _, declaration := range declarations {
		if declaration.Tenant == tenant && declaration.Project == project && declaration.Database == database {
			return declaration.SelectedRegions
		}
	}
	return nil
}
func allocationRecord(records map[string]Record, environment, tenant, project, database string) (Record, bool) {
	for _, record := range records {
		if record.Request.Environment == environment && record.Request.TenantID == tenant && record.Request.ProjectID == project && record.DatabaseID == database {
			return record, true
		}
	}
	return Record{}, false
}
func allocationScope(tenant, project, database string) string {
	return tenant + "\x00" + project + "\x00" + database
}
func allocationOperation(digest, scope string, epoch uint64) string {
	sum := sha256.Sum256([]byte("terrascale.lifecycle-allocation.v1\x00" + digest + "\x00" + scope + "\x00" + fmt.Sprint(epoch)))
	return "streams-" + hex.EncodeToString(sum[:])
}
func sortedAllocationRegions(regions []string) []string {
	sorted := slices.Clone(regions)
	slices.Sort(sorted)
	return sorted
}

func appendAllocationStream(streams *[]databaselifecycle.Stream, region string, epoch uint64, created, started time.Time) error {
	if started.Before(created) || epoch == 0 {
		return ErrConflict
	}
	hadRegion, active := false, -1
	for i, stream := range *streams {
		if stream.Region != region {
			continue
		}
		hadRegion = true
		// Only a retained allocation event can authorize reuse of an epoch.
		if stream.Epoch >= epoch {
			return ErrConflict
		}
		if stream.StoppedAt.IsZero() {
			if active >= 0 || !started.After(stream.StartedAt) {
				return ErrConflict
			}
			active = i
		} else if stream.StoppedAt.After(started) {
			return ErrConflict
		}
	}
	if hadRegion && active < 0 {
		return ErrConflict
	}
	partition, err := ulid.New(ulid.Timestamp(started), rand.Reader)
	if err != nil {
		return err
	}
	if active >= 0 {
		(*streams)[active].StoppedAt = started
	}
	*streams = append(*streams, databaselifecycle.Stream{Region: region, Partition: partition.String(), Epoch: epoch, StartedAt: started})
	return nil
}

// A completed allocation remains retryable after later transitions close its
// streams. Closed history and identity must still be represented exactly.
func sameAllocationRegions(event, current []databaselifecycle.Stream, epoch uint64, regions []string) bool {
	allocated := make(map[string]bool, len(regions))
	for _, prior := range event {
		if prior.Epoch > epoch {
			return false
		}
		index := slices.IndexFunc(current, func(stream databaselifecycle.Stream) bool {
			return stream.Region == prior.Region && stream.Partition == prior.Partition && stream.Epoch == prior.Epoch
		})
		if index < 0 {
			return false
		}
		stream := current[index]
		if !stream.StartedAt.Equal(prior.StartedAt) || (!prior.StoppedAt.IsZero() && !stream.StoppedAt.Equal(prior.StoppedAt)) {
			return false
		}
		if prior.Epoch == epoch {
			if allocated[prior.Region] || !slices.Contains(regions, prior.Region) || !prior.StoppedAt.IsZero() || !canonicalID.MatchString(prior.Partition) {
				return false
			}
			allocated[prior.Region] = true
		}
	}
	return len(allocated) == len(regions)
}
