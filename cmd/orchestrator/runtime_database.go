package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// This topology is resolved from admitted deployment configuration, never from
// database-create input. Writer roles are explicit, independent of seat order.
type productionDatabaseRegion struct {
	Region           string
	Writer, Follower productionDatabaseHost
	Vault            keylease.ProvisionTarget
}
type productionDatabaseHost struct{ ServerIdentity, MemberID string }
type productionDatabaseConfig struct {
	ReadinessKeys                     map[string]databaseadmission.ReadinessKey
	Inventory                         databaseInventoryFileConfig
	BranchRestoreKeys                 map[string]databaseadmission.ReadinessKey
	Environment, Cluster, CatalogPath string
	Regions                           []productionDatabaseRegion
	Authorize                         func(context.Context, databaseadmission.Request) error
	AuthorizeDeletion                 func(context.Context, databaseadmission.DeleteRequest) error
	ActivatePlacement                 func(context.Context, databaseadmission.Record) error
}
type productionDatabase struct {
	inventoryConfig      databaseInventoryFileConfig
	inventoryEnvironment string
	inventory            *productionDatabaseInventory
	lifecycleJournal     *databaseadmission.NATSJournal
	lifecycleService     *databaseadmission.Service
	pipeline             *databaseadmission.Pipeline
	service              *databaseadmission.Service
	deletion             *databaseadmission.DeletionWorkflow
	deletionService      *databaseadmission.Service
	check                func(context.Context) error
	mu                   sync.Mutex
	failure              string
}

func newProductionDatabase(config productionDatabaseConfig, session globalWorkerSession, placement *productionPlacement) (*productionDatabase, error) {
	if config.Environment == "" || config.Cluster == "" || config.CatalogPath == "" || len(config.Regions) == 0 || config.Authorize == nil || config.AuthorizeDeletion == nil || placement == nil {
		return nil, errors.New("runtime database: admitted topology, catalog and project authorization required")
	}
	seenHosts, seenRegions := map[string]bool{}, map[string]bool{}
	for _, region := range config.Regions {
		if seenRegions[region.Region] || !slices.Contains([]string{"GRU", "SFO", "FRA"}, region.Region) {
			return nil, databaseadmission.ErrInvalid
		}
		seenRegions[region.Region] = true
		for _, host := range []productionDatabaseHost{region.Writer, region.Follower} {
			if seenHosts[host.ServerIdentity] || placement.publishers[host.ServerIdentity] == nil || host.ServerIdentity != "spiffe://terrascale.tech/"+config.Environment+"/terrabase-member/"+config.Cluster+"/"+host.MemberID {
				return nil, databaseadmission.ErrInvalid
			}
			seenHosts[host.ServerIdentity] = true
		}
	}
	journal, err := databaseadmission.NewNATSJournal(databaseadmission.NATSJournalConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId})
	if err != nil {
		return nil, err
	}
	placementJournal, err := placementpublisher.NewNATSJournal(placementpublisher.NATSJournalConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId})
	if err != nil {
		return nil, err
	}
	readiness, err := newProductionReadiness(config.ReadinessKeys, session, placement.config.Targets)
	if err != nil {
		return nil, err
	}
	pipeline, err := databaseadmission.New(databaseadmission.Config{
		Readiness: readiness,
		Journal:   journal, CatalogPath: config.CatalogPath, CheckAuthority: session.CheckEffectAuthority,
		Authorize: func(ctx context.Context, r databaseadmission.Request) error {
			if r.Environment != config.Environment {
				return databaseadmission.ErrInvalid
			}
			return config.Authorize(ctx, r)
		},
		Plan: func(ctx context.Context, r databaseadmission.Record) (databaseadmission.Plan, error) {
			return config.plan(ctx, r, journal, placementJournal)
		},
		BranchRestore:     productionBranchRestore(config.BranchRestoreKeys, session.Connection),
		Install:           databaseadmission.RemoteInstall(session.Connection),
		ActivatePlacement: config.ActivatePlacement,
		AcceptPlacement: func(ctx context.Context, host, operation string, proposal *pb.PlacementStageRequest) error {
			if err := validateDatabaseProposal(ctx, journal, host, operation, proposal); err != nil {
				return err
			}
			return placement.Accept(ctx, host, operation, proposal)
		},
	})
	if err != nil {
		return nil, err
	}
	deletion := &databaseadmission.DeletionWorkflow{Journal: journal, Policy: databaseDeletionPolicy(func(ctx context.Context, request databaseadmission.DeleteRequest) (databaseadmission.DeletionPolicyDecision, error) {
		if request.Environment != config.Environment {
			return databaseadmission.DeletionPolicyDecision{}, databaseadmission.ErrInvalid
		}
		if err := session.CheckEffectAuthority(ctx); err != nil {
			return databaseadmission.DeletionPolicyDecision{}, err
		}
		if err := config.AuthorizeDeletion(ctx, request); err != nil {
			return databaseadmission.DeletionPolicyDecision{}, err
		}
		return databaseadmission.DeletionPolicyDecision{}, nil
	}), Stopper: databaseadmission.RemoteDeletionStopper(session.Connection, journal)}
	return &productionDatabase{inventoryConfig: config.Inventory, inventoryEnvironment: config.Environment, lifecycleJournal: journal, pipeline: pipeline, deletion: deletion, check: session.CheckEffectAuthority}, nil
}
func (d *productionDatabase) Start(ctx context.Context, session globalWorkerSession) error {
	inventory, err := startProductionDatabaseInventory(ctx, d.inventoryConfig, d.inventoryEnvironment, d.lifecycleJournal)
	if err != nil {
		return err
	}
	d.inventory = inventory
	service, err := databaseadmission.StartAuthority(ctx, session.Connection, d.pipeline)
	if err != nil {
		return errors.Join(err, d.inventory.Close())
	}
	d.service = service
	d.lifecycleService, err = databaseadmission.StartLifecycleAuthority(ctx, session.Connection, d.lifecycleJournal)
	if err != nil {
		return errors.Join(err, d.inventory.Close(), d.service.Close())
	}
	d.deletionService, err = databaseadmission.StartDeletionAuthority(ctx, session.Connection, d.deletion)
	if err != nil {
		return errors.Join(err, d.inventory.Close(), d.service.Close(), d.lifecycleService.Close())
	}
	return nil
}
func (d *productionDatabase) Close() error {
	if d == nil {
		return nil
	}
	var errs []error
	if d.inventory != nil {
		errs = append(errs, d.inventory.Close())
	}
	if d.lifecycleService != nil {
		errs = append(errs, d.lifecycleService.Close())
	}
	if d.service != nil {
		errs = append(errs, d.service.Close())
	}
	if d.deletionService != nil {
		errs = append(errs, d.deletionService.Close())
	}
	return errors.Join(errs...)
}
func validateDatabaseProposal(ctx context.Context, journal databaseadmission.Journal, host, operation string, proposal *pb.PlacementStageRequest) error {
	records, err := journal.List(ctx)
	if err != nil {
		return err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(proposal)
	if err != nil {
		return err
	}
	for _, record := range records {
		if databaseadmission.PlacementOperationID(record.Request) != operation {
			continue
		}
		for _, target := range record.PlacementTargets {
			if target.ServerIdentity == host && bytes.Equal(target.Proposal, encoded) {
				return nil
			}
		}
	}
	return errors.New("runtime database: placement differs from accepted immutable plan")
}

func (config productionDatabaseConfig) plan(ctx context.Context, r databaseadmission.Record, journal databaseadmission.Journal, placements placementpublisher.Journal) (databaseadmission.Plan, error) {
	if r.Request.Environment != config.Environment {
		return databaseadmission.Plan{}, databaseadmission.ErrInvalid
	}
	records, err := journal.List(ctx)
	if err != nil {
		return databaseadmission.Plan{}, err
	}
	declarations, err := databasePlacementDeclarations(config.Environment, records, r)
	if err != nil {
		return databaseadmission.Plan{}, err
	}
	// A successor proposal must not overtake an unresolved operation on a host.
	for _, prior := range records {
		if prior.State != "placement_pending" && prior.State != "ready" {
			return databaseadmission.Plan{}, errors.New("runtime database: previous database admission is unresolved")
		}
	}
	proposal := &pb.PlacementProposal{Environment: config.Environment, Cluster: config.Cluster, Generation: 1, Epoch: 1}
	targets := []databaseadmission.Target{}
	placementTargets := []databaseadmission.PlacementTarget{}
	selected := map[string]bool{}
	for _, region := range config.Regions {
		for _, host := range []productionDatabaseHost{region.Writer, region.Follower} {
			placementTargets = append(placementTargets, databaseadmission.PlacementTarget{ServerIdentity: host.ServerIdentity, MemberID: host.MemberID, Region: region.Region})
		}
		proposal.Regions = append(proposal.Regions, &pb.PlacementRegionSeats{Region: region.Region, Members: []string{region.Writer.MemberID, region.Follower.MemberID}})
		if !slices.Contains(r.Request.Regions, region.Region) {
			continue
		}
		if selected[region.Region] {
			return databaseadmission.Plan{}, databaseadmission.ErrInvalid
		}
		selected[region.Region] = true
		proposal.Assignments = append(proposal.Assignments, &pb.PlacementDatabaseAssignment{Tenant: r.Request.TenantID, Project: r.Request.ProjectID, Database: r.DatabaseID, Region: region.Region, WriterMember: region.Writer.MemberID, FollowerMember: region.Follower.MemberID})
		for _, host := range []productionDatabaseHost{region.Writer, region.Follower} {
			vault := region.Vault
			vault.Binding = keylease.Binding{Environment: r.Request.Environment, TenantID: r.Request.TenantID, ProjectID: r.Request.ProjectID, DatabaseID: r.DatabaseID, KeyVersion: r.KeyVersion, Region: region.Region, Purpose: "data"}
			targets = append(targets, databaseadmission.Target{ServerIdentity: host.ServerIdentity, MemberID: host.MemberID, Region: region.Region, Provision: vault})
		}
	}
	if len(selected) != len(r.Request.Regions) {
		return databaseadmission.Plan{}, databaseadmission.ErrInvalid
	}
	// Each target journal is authoritative for its local CAS revision. Merge all
	// admitted prior assignments so a new database cannot erase an existing one.
	revisions := map[string]uint64{}
	for _, target := range placementTargets {
		prior, err := placements.Load(ctx, target.ServerIdentity)
		if errors.Is(err, placementpublisher.ErrIntentMissing) {
			continue
		}
		if err != nil {
			return databaseadmission.Plan{}, err
		}
		receipt := new(pb.PlacementProposalResponse)
		previous := new(pb.PlacementStageRequest)
		if len(prior.Receipt) == 0 || proto.Unmarshal(prior.Receipt, receipt) != nil || proto.Unmarshal(prior.Request, previous) != nil || tbep.ValidatePlacementReceipt(receipt, previous.Proposal) != nil {
			return databaseadmission.Plan{}, errors.New("runtime database: previous placement remains unresolved")
		}
		if previous.Proposal.Environment != config.Environment || previous.Proposal.Cluster != config.Cluster {
			return databaseadmission.Plan{}, databaseadmission.ErrConflict
		}
		if previous.Proposal.Generation == ^uint64(0) || previous.Proposal.Epoch == ^uint64(0) {
			return databaseadmission.Plan{}, databaseadmission.ErrInvalid
		}
		revisions[target.ServerIdentity] = receipt.Revision
		proposal.Generation = max(proposal.Generation, previous.Proposal.Generation+1)
		proposal.Epoch = max(proposal.Epoch, previous.Proposal.Epoch+1)
		for _, seats := range previous.Proposal.Regions {
			i := slices.IndexFunc(proposal.Regions, func(v *pb.PlacementRegionSeats) bool { return v.Region == seats.Region })
			if i < 0 {
				return databaseadmission.Plan{}, databaseadmission.ErrConflict
			} else if !slices.Equal(slices.Sorted(slices.Values(proposal.Regions[i].Members)), slices.Sorted(slices.Values(seats.Members))) {
				return databaseadmission.Plan{}, databaseadmission.ErrConflict
			}
		}
		for _, assignment := range previous.Proposal.Assignments {
			i := slices.IndexFunc(proposal.Assignments, func(v *pb.PlacementDatabaseAssignment) bool {
				return v.Database == assignment.Database && v.Region == assignment.Region
			})
			if i < 0 {
				proposal.Assignments = append(proposal.Assignments, proto.CloneOf(assignment))
			} else if !proto.Equal(proposal.Assignments[i], assignment) {
				return databaseadmission.Plan{}, databaseadmission.ErrConflict
			}
		}
	}
	if err := validateDatabaseDeclarationsAgainstProposal(declarations, proposal); err != nil {
		return databaseadmission.Plan{}, err
	}
	canonical, err := tbep.CanonicalPlacement(proposal)
	if err != nil {
		return databaseadmission.Plan{}, fmt.Errorf("runtime database plan: %w", err)
	}
	for i := range targets {
		targets[i].Proposal, err = (proto.MarshalOptions{Deterministic: true}).Marshal(&pb.PlacementStageRequest{ExpectedRevision: revisions[targets[i].ServerIdentity], Proposal: canonical, Declarations: declarations})
		if err != nil {
			return databaseadmission.Plan{}, err
		}
	}
	for i := range placementTargets {
		placementTargets[i].Proposal, err = (proto.MarshalOptions{Deterministic: true}).Marshal(&pb.PlacementStageRequest{ExpectedRevision: revisions[placementTargets[i].ServerIdentity], Proposal: canonical, Declarations: declarations})
		if err != nil {
			return databaseadmission.Plan{}, err
		}
	}
	return databaseadmission.Plan{Members: targets, Placements: placementTargets}, nil
}

// databasePlacementDeclarations carries the complete authenticated database
// scope into every placement CAS request. Declarations are control metadata;
// they do not add storage targets or member assignments.
func databasePlacementDeclarations(environment string, records []databaseadmission.Record, current databaseadmission.Record) ([]*pb.PlacementDatabaseDeclaration, error) {
	type scope struct {
		tenant, project, database string
		regions                   []string
	}
	declarations := map[string]scope{}
	databaseOwners := map[string]string{}
	add := func(record databaseadmission.Record) error {
		if record.Request.Environment != environment || databaseadmission.ValidateRequest(record.Request) != nil || record.DatabaseID == "" {
			return databaseadmission.ErrInvalid
		}
		regions := slices.Clone(record.Request.Regions)
		slices.Sort(regions)
		for i := 1; i < len(regions); i++ {
			if regions[i] == regions[i-1] {
				return databaseadmission.ErrInvalid
			}
		}
		key := record.Request.TenantID + "\x00" + record.Request.ProjectID + "\x00" + record.DatabaseID
		owner := record.Request.TenantID + "\x00" + record.Request.ProjectID
		if prior, ok := databaseOwners[record.DatabaseID]; ok && prior != owner {
			return databaseadmission.ErrConflict
		}
		databaseOwners[record.DatabaseID] = owner
		candidate := scope{tenant: record.Request.TenantID, project: record.Request.ProjectID, database: record.DatabaseID, regions: regions}
		if prior, ok := declarations[key]; ok && (!slices.Equal(prior.regions, candidate.regions) || prior.tenant != candidate.tenant || prior.project != candidate.project || prior.database != candidate.database) {
			return databaseadmission.ErrConflict
		}
		declarations[key] = candidate
		return nil
	}
	for _, record := range records {
		if err := add(record); err != nil {
			return nil, err
		}
	}
	if err := add(current); err != nil {
		return nil, err
	}
	ordered := make([]scope, 0, len(declarations))
	for _, declaration := range declarations {
		ordered = append(ordered, declaration)
	}
	slices.SortFunc(ordered, func(a, b scope) int {
		return cmp.Or(cmp.Compare(a.tenant, b.tenant), cmp.Compare(a.project, b.project), cmp.Compare(a.database, b.database))
	})
	out := make([]*pb.PlacementDatabaseDeclaration, 0, len(ordered))
	for _, declaration := range ordered {
		out = append(out, &pb.PlacementDatabaseDeclaration{Tenant: declaration.tenant, Project: declaration.project, Database: declaration.database, SelectedRegions: declaration.regions})
	}
	return out, nil
}

func validateDatabaseDeclarationsAgainstProposal(declarations []*pb.PlacementDatabaseDeclaration, proposal *pb.PlacementProposal) error {
	declared := make(map[string][]string, len(declarations))
	for _, declaration := range declarations {
		if declaration == nil || declaration.Tenant == "" || declaration.Project == "" || declaration.Database == "" || len(declaration.SelectedRegions) == 0 {
			return databaseadmission.ErrInvalid
		}
		key := declaration.Tenant + "\x00" + declaration.Project + "\x00" + declaration.Database
		if _, exists := declared[key]; exists {
			return databaseadmission.ErrConflict
		}
		regions := slices.Clone(declaration.SelectedRegions)
		slices.Sort(regions)
		for i := 1; i < len(regions); i++ {
			if regions[i] == regions[i-1] {
				return databaseadmission.ErrInvalid
			}
		}
		declared[key] = regions
	}
	assigned := make(map[string][]string)
	for _, assignment := range proposal.GetAssignments() {
		if assignment == nil || assignment.Tenant == "" || assignment.Project == "" || assignment.Database == "" || assignment.Region == "" {
			return databaseadmission.ErrInvalid
		}
		key := assignment.Tenant + "\x00" + assignment.Project + "\x00" + assignment.Database
		assigned[key] = append(assigned[key], assignment.Region)
	}
	if len(declared) != len(assigned) {
		return databaseadmission.ErrConflict
	}
	for key, regions := range assigned {
		slices.Sort(regions)
		if !slices.Equal(declared[key], regions) {
			return databaseadmission.ErrConflict
		}
	}
	return nil
}

// Unreachable hosts retain their durable intent and retry. Authority loss and
// corrupt immutable records stop the session instead of repeatedly dispatching.
func (d *productionDatabase) Reconcile(ctx context.Context) error {
	err := errors.Join(d.pipeline.Reconcile(ctx), d.deletion.Resume(ctx))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if authorityErr := d.check(ctx); authorityErr != nil {
			return authorityErr
		}
		if errors.Is(err, databaseadmission.ErrInvalid) {
			return err
		}
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	d.mu.Lock()
	changed := message != d.failure
	d.failure = message
	d.mu.Unlock()
	if changed && err != nil {
		slog.ErrorContext(ctx, "database admission remains unresolved", "error", err)
	}
	return nil
}
