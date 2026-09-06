package databaseadmission

import (
	"context"
	"crypto/rand"
	"errors"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/oklog/ulid"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type Config struct {
	BranchRestore *BranchRestoreConfig
	Journal       Journal
	CatalogPath   string
	// Authorize checks verified organization admission and the caller's project.
	Authorize      func(context.Context, Request) error
	CheckAuthority func(context.Context) error
	Plan           func(context.Context, Record) (Plan, error)
	Install        func(context.Context, Record, Target, []keylease.Entry) error
	// AcceptPlacement returns the exact producer receipt after the fenced
	// remote stage. The receipt is persisted before progress advances.
	AcceptPlacement func(context.Context, string, string, *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error)
	// ActivatePlacement delivers a separately authorized accepted-membership
	// proof. Success does not establish RF2 or caught-up serving readiness.
	ActivatePlacement func(context.Context, Record) error
	Readiness         *ReadinessConfig
}
type Pipeline struct {
	config Config
	mu     sync.Mutex
}

func New(config Config) (*Pipeline, error) {
	if config.Journal == nil || config.CatalogPath == "" || config.Authorize == nil || config.CheckAuthority == nil || config.Plan == nil || config.Install == nil || config.AcceptPlacement == nil || config.ActivatePlacement == nil {
		return nil, ErrInvalid
	}
	if config.Readiness != nil && (config.Readiness.Collect == nil || len(config.Readiness.Keys) == 0) {
		return nil, ErrInvalid
	}
	if config.Readiness != nil {
		if err := validateReadinessKeys(config.Readiness.Keys); err != nil {
			return nil, err
		}
	}
	if config.BranchRestore != nil && (config.BranchRestore.Capture == nil || config.BranchRestore.Restore == nil || len(config.BranchRestore.Keys) == 0) {
		return nil, ErrInvalid
	}
	return &Pipeline{config: config}, nil
}
func (p *Pipeline) Accept(ctx context.Context, request Request) (Record, error) {
	if ValidateRequest(request) != nil {
		return Record{}, ErrInvalid
	}
	if err := p.config.Authorize(ctx, request); err != nil {
		return Record{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.config.CheckAuthority(ctx); err != nil {
		return Record{}, err
	}
	key := ScopeKey(request)
	existing, found, err := p.config.Journal.Load(ctx, key)
	if err != nil {
		return Record{}, err
	}
	if found {
		if !reflect.DeepEqual(existing.Request, request) {
			return Record{}, ErrConflict
		}
		return existing, nil
	}
	if request.ParentDatabaseID != "" {
		if p.config.BranchRestore == nil {
			return Record{}, ErrInvalid
		}
		if err := p.validateParent(ctx, request); err != nil {
			return Record{}, err
		}
	}
	id, err := ulid.New(ulid.Timestamp(time.Now()), rand.Reader)
	if err != nil {
		return Record{}, err
	}
	version, err := ulid.New(ulid.Timestamp(time.Now()), rand.Reader)
	if err != nil {
		return Record{}, err
	}
	record := Record{Request: request, DatabaseID: id.String(), KeyVersion: version.String(), State: "accepted", CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	plan, err := p.config.Plan(ctx, record)
	record.Targets, record.PlacementTargets = plan.Members, plan.Placements
	if err != nil {
		return Record{}, err
	}
	if ValidateRecord(record) != nil {
		return Record{}, ErrInvalid
	}
	record.Revision, err = p.config.Journal.Save(ctx, key, 0, record)
	if err != nil {
		return Record{}, err
	}
	return record, nil
}
func (p *Pipeline) Status(ctx context.Context, request Request) (Record, error) {
	if ValidateRequest(request) != nil {
		return Record{}, ErrInvalid
	}
	if err := p.config.Authorize(ctx, request); err != nil {
		return Record{}, err
	}
	record, found, err := p.config.Journal.Load(ctx, ScopeKey(request))
	if err != nil {
		return Record{}, err
	}
	if !found || !reflect.DeepEqual(record.Request, request) {
		return Record{}, ErrConflict
	}
	return record, nil
}

// LookupOperation uses only the authenticated scope and opaque operation ID.
// Authorization still evaluates the original immutable request before any
// database metadata is returned to a poller.
func (p *Pipeline) LookupOperation(ctx context.Context, scope Request) (Record, error) {
	if validateLookup(scope) != nil {
		return Record{}, ErrInvalid
	}
	records, err := p.config.Journal.List(ctx)
	if err != nil {
		return Record{}, err
	}
	for _, record := range records {
		r := record.Request
		if r.Environment != scope.Environment || r.TenantID != scope.TenantID || r.ProjectID != scope.ProjectID || r.OperationID != scope.OperationID {
			continue
		}
		if err := p.config.Authorize(ctx, r); err != nil {
			return Record{}, err
		}
		return record, nil
	}
	return Record{}, ErrConflict
}

func validateLookup(scope Request) error {
	if scope.Name != "" || len(scope.Regions) != 0 || scope.Residency != "" || scope.ParentDatabaseID != "" {
		return ErrInvalid
	}
	probe := scope
	probe.Name = "lookup"
	probe.Regions = []string{"GRU"}
	return ValidateRequest(probe)
}
func (p *Pipeline) save(ctx context.Context, r *Record) error {
	revision, err := p.config.Journal.Save(ctx, ScopeKey(r.Request), r.Revision, *r)
	if err == nil {
		r.Revision = revision
	}
	return err
}

// Reconcile resumes every accepted operation, including responses lost after
// any external effect. All effect adapters must persist immutable retry IDs.
func (p *Pipeline) Reconcile(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.config.CheckAuthority(ctx); err != nil {
		return err
	}
	records, err := p.config.Journal.List(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, record := range records {
		if err := p.reconcile(ctx, record); err != nil {
			failures = append(failures, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return errors.Join(failures...)
}
func (p *Pipeline) reconcile(ctx context.Context, r Record) error {
	if ValidateRecord(r) != nil {
		return ErrInvalid
	}
	if r.State == "ready" {
		return nil
	}
	if r.State == "placement_pending" {
		if err := p.config.CheckAuthority(ctx); err != nil {
			return err
		}
		if err := p.restoreBranch(ctx, &r); err != nil {
			return err
		}
		return p.activateAndObserve(ctx, r)
	}
	if err := p.provisionKeys(ctx, &r); err != nil {
		return err
	}
	for i, target := range r.Targets {
		if target.Installed {
			continue
		}
		if err := p.config.CheckAuthority(ctx); err != nil {
			return err
		}
		entries := []keylease.Entry{}
		for _, entry := range r.Wrapped {
			if entry.Binding.Region == target.Region {
				entries = append(entries, entry)
			}
		}
		if len(entries) != len(databaseKeyPurposes) {
			return ErrInvalid
		}
		if err := p.config.Install(ctx, r, target, entries); err != nil {
			return err
		}
		r.Targets[i].Installed = true
		if err := p.save(ctx, &r); err != nil {
			return err
		}
	}
	if r.State != "members_admitted" {
		r.State = "members_admitted"
		if err := p.save(ctx, &r); err != nil {
			return err
		}
	}
	for i, target := range r.PlacementTargets {
		if target.Proposed {
			continue
		}
		if err := p.config.CheckAuthority(ctx); err != nil {
			return err
		}
		request := new(pb.PlacementStageRequest)
		if proto.Unmarshal(target.Proposal, request) != nil {
			return ErrInvalid
		}
		receipt, err := p.config.AcceptPlacement(ctx, target.ServerIdentity, PlacementOperationID(r.Request), request)
		if err != nil {
			return err
		}
		if receipt == nil || receipt.Revision == 0 {
			return ErrInvalid
		}
		r.PlacementTargets[i].Proposed = true
		encoded, marshalErr := proto.Marshal(receipt)
		if marshalErr != nil {
			return marshalErr
		}
		r.PlacementTargets[i].Receipt = encoded
		r.PlacementTargets[i].Revision = receipt.Revision
		if err := p.save(ctx, &r); err != nil {
			return err
		}
	}
	if !slices.ContainsFunc(r.PlacementTargets, func(t PlacementTarget) bool { return !t.Proposed }) {
		r.State = "placement_pending"
		if err := p.save(ctx, &r); err != nil {
			return err
		}
		if err := p.config.CheckAuthority(ctx); err != nil {
			return err
		}
		if err := p.restoreBranch(ctx, &r); err != nil {
			return err
		}
		return p.activateAndObserve(ctx, r)
	}
	return nil
}

func (p *Pipeline) activateAndObserve(ctx context.Context, r Record) error {
	if err := p.config.ActivatePlacement(ctx, r); err != nil {
		return err
	}
	// The original install registered a closed encrypted scope so Stage could
	// validate it. Replay after accepted membership lets the engine publish that
	// same scope under the now-authorized role, without inventing a writer grant.
	for _, target := range r.Targets {
		if err := p.config.CheckAuthority(ctx); err != nil {
			return err
		}
		entries := []keylease.Entry{}
		for _, entry := range r.Wrapped {
			if entry.Binding.Region == target.Region {
				entries = append(entries, entry)
			}
		}
		if len(entries) != len(databaseKeyPurposes) {
			return ErrInvalid
		}
		if err := p.config.Install(ctx, r, target, entries); err != nil {
			return err
		}
	}
	return p.establishReadiness(ctx, r)
}

// validateParent prevents a derived database from escaping its source scope or
// changing the immutable placement and residency selected at source creation.
func (p *Pipeline) validateParent(ctx context.Context, request Request) error {
	records, err := p.config.Journal.List(ctx)
	if err != nil {
		return err
	}
	for _, parent := range records {
		if parent.DatabaseID != request.ParentDatabaseID {
			continue
		}
		source := parent.Request
		if source.Environment != request.Environment || source.TenantID != request.TenantID || source.ProjectID != request.ProjectID {
			return ErrForbidden
		}
		if parent.State != "ready" || !slices.Equal(source.Regions, request.Regions) || source.Residency != request.Residency {
			return ErrConflict
		}
		return nil
	}
	return ErrForbidden
}
