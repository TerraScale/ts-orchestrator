package databaseadmission

import (
	"context"
	"encoding/json/v2"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

type DeleteRequest struct {
	Environment string `json:"environment"`
	TenantID    string `json:"tenant_id"`
	ProjectID   string `json:"project_id"`
	DatabaseID  string `json:"database_id"`
	OperationID string `json:"operation_id"`
}
type DeletionStop struct {
	databaselifecycle.Identity
	OperationID string    `json:"operation_id"`
	Region      string    `json:"region"`
	Cutoff      time.Time `json:"cutoff"`
	RetainUntil time.Time `json:"retain_until,omitzero"`
}
type DeletionReceipt struct {
	DeletionStop
	AccessRevoked bool `json:"access_revoked"`
	UsageStopped  bool `json:"usage_stopped"`
}
type DeletionClaimReceipt struct {
	SchemaVersion     uint8     `json:"schemaVersion"`
	Environment       string    `json:"environment"`
	TenantID          string    `json:"tenant_id"`
	ProjectID         string    `json:"project_id"`
	DatabaseID        string    `json:"database_id"`
	OperationID       string    `json:"operation_id"`
	PolicyRevision    string    `json:"policy_revision"`
	PolicyFingerprint string    `json:"policy_fingerprint"`
	GraceCondition    string    `json:"grace_condition"`
	Deadline          time.Time `json:"deadline"`
	AcceptedAt        time.Time `json:"accepted_at"`
	AuthorityEpoch    string    `json:"authority_epoch"`
}
type DeletionPreparation struct {
	databaselifecycle.Identity
	OperationID     string    `json:"operation_id"`
	Region          string    `json:"region"`
	Prepared        bool      `json:"prepared"`
	LastAccountedAt time.Time `json:"last_accounted_at"`
}
type DeletionEdgeReceipt struct {
	Request       DeleteRequest `json:"request"`
	Cutoff        time.Time     `json:"cutoff"`
	AccessRevoked bool          `json:"access_revoked"`
}
type DeletionEdgeRevoker interface {
	RevokeDeletion(context.Context, Deletion) (DeletionEdgeReceipt, error)
}
type DeletionTarget struct {
	Preparation *DeletionPreparation `json:"preparation,omitempty"`
	Stop        DeletionStop         `json:"stop"`
	Receipt     *DeletionReceipt     `json:"receipt,omitempty"`
}
type Deletion struct {
	RequestedAt time.Time             `json:"requested_at"`
	EdgeReceipt *DeletionEdgeReceipt  `json:"edge_receipt,omitempty"`
	Request     DeleteRequest         `json:"request"`
	Cutoff      time.Time             `json:"cutoff"`
	State       string                `json:"state"`
	Targets     []DeletionTarget      `json:"targets"`
	Claim       *DeletionClaimReceipt `json:"claim,omitempty"`
}
type DeletionJournal interface {
	BeginDeletion(context.Context, DeleteRequest, time.Time, time.Time) (Deletion, error)
	RecordDeletionPreparation(context.Context, DeleteRequest, DeletionPreparation, time.Time) (Deletion, error)
	RecordDeletionEdge(context.Context, DeleteRequest, DeletionEdgeReceipt) (Deletion, error)
	RecordDeletionStop(context.Context, DeleteRequest, DeletionReceipt) (Deletion, error)
	ListDeletions(context.Context) ([]Deletion, error)
}

// AuthorizeDeletion must verify the caller's organization/project membership and
// current deletion policy/protection before any durable deletion is accepted.
type DeletionPolicyDecision struct {
	RetainUntil time.Time
	Claim       *DeletionClaimReceipt
}
type DeletionPolicy interface {
	AuthorizeDeletion(context.Context, DeleteRequest) (DeletionPolicyDecision, error)
}
type DeletionClaimJournal interface {
	BeginDeletionWithClaim(context.Context, DeleteRequest, time.Time, time.Time, DeletionClaimReceipt) (Deletion, error)
}

// StopDeletion must authenticate regional evidence and cover every serving host,
// reader and usage producer before returning a receipt.
type DeletionStopper interface {
	PrepareDeletion(context.Context, DeletionStop) (DeletionPreparation, error)
	StopDeletion(context.Context, DeletionStop) (DeletionReceipt, error)
}
type DeletionWorkflow struct {
	Journal DeletionJournal
	Policy  DeletionPolicy
	Stopper DeletionStopper
	Edge    DeletionEdgeRevoker
}

func (w *DeletionWorkflow) Begin(ctx context.Context, r DeleteRequest) (Deletion, error) {
	if w == nil || w.Journal == nil || w.Policy == nil || w.Stopper == nil || !validDeleteRequest(r) {
		return Deletion{}, ErrInvalid
	}
	decision, err := w.Policy.AuthorizeDeletion(ctx, r)
	if err != nil {
		return Deletion{}, err
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	var d Deletion
	if decision.Claim != nil {
		journal, ok := w.Journal.(DeletionClaimJournal)
		if !ok || decision.Claim.OperationID != r.OperationID || decision.Claim.Environment != r.Environment || decision.Claim.TenantID != r.TenantID || decision.Claim.ProjectID != r.ProjectID || decision.Claim.DatabaseID != r.DatabaseID {
			return Deletion{}, ErrConflict
		}
		d, err = journal.BeginDeletionWithClaim(ctx, r, at, decision.RetainUntil, *decision.Claim)
	} else {
		d, err = w.Journal.BeginDeletion(ctx, r, at, decision.RetainUntil)
	}
	if err != nil {
		return Deletion{}, err
	}
	return w.advance(ctx, d)
}
func (w *DeletionWorkflow) Resume(ctx context.Context) error {
	if w == nil || w.Journal == nil || w.Stopper == nil {
		return ErrInvalid
	}
	records, err := w.Journal.ListDeletions(ctx)
	if err != nil {
		return err
	}
	for _, d := range records {
		if d.State != "cleanup_pending" {
			if _, err = w.advance(ctx, d); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w *DeletionWorkflow) advance(ctx context.Context, d Deletion) (Deletion, error) {
	if d.State == "preparing" {
		for _, t := range d.Targets {
			if t.Preparation != nil {
				continue
			}
			receipt, err := w.Stopper.PrepareDeletion(ctx, t.Stop)
			if err != nil {
				return d, err
			}
			d, err = w.Journal.RecordDeletionPreparation(ctx, d.Request, receipt, time.Now().UTC().Truncate(time.Millisecond))
			if err != nil {
				return d, err
			}
		}
	}
	for _, t := range d.Targets {
		if t.Receipt != nil {
			continue
		}
		receipt, err := w.Stopper.StopDeletion(ctx, t.Stop)
		if err != nil {
			return d, err
		}
		d, err = w.Journal.RecordDeletionStop(ctx, d.Request, receipt)
		if err != nil {
			return d, err
		}
	}
	if d.State == "edge_pending" {
		if w.Edge == nil {
			return d, ErrJournalUnavailable
		}
		receipt, err := w.Edge.RevokeDeletion(ctx, d)
		if err != nil {
			return d, err
		}
		return w.Journal.RecordDeletionEdge(ctx, d.Request, receipt)
	}
	return d, nil
}
func validDeleteRequest(r DeleteRequest) bool {
	if !environmentName.MatchString(r.Environment) || !canonicalID.MatchString(r.TenantID) || !canonicalID.MatchString(r.ProjectID) || !canonicalID.MatchString(r.DatabaseID) || len(r.OperationID) == 0 || len(r.OperationID) > 128 {
		return false
	}
	for _, c := range r.OperationID {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func deletionKey(r DeleteRequest) string {
	b, _ := json.Marshal([]string{r.Environment, r.TenantID, r.ProjectID, r.OperationID})
	return string(b)
}
func validStopReceipt(s DeletionStop, r DeletionReceipt) bool {
	return s.Identity == r.Identity && s.OperationID == r.OperationID && s.Region == r.Region && s.Cutoff.Equal(r.Cutoff) && s.RetainUntil.Equal(r.RetainUntil) && r.AccessRevoked && r.UsageStopped
}
func validateDeletions(s journalState) error {
	for key, d := range s.Deletions {
		if key != deletionKey(d.Request) || !validDeleteRequest(d.Request) || d.RequestedAt.IsZero() || (d.Cutoff.IsZero() != (d.State == "preparing")) || len(d.Targets) == 0 || !slices.Contains([]string{"preparing", "stopping", "edge_pending", "cleanup_pending"}, d.State) {
			return ErrInvalid
		}
		all := true
		allPrepared := true
		seen := map[string]bool{}
		for _, t := range d.Targets {
			v := t.Stop
			k := v.DatabaseID + "/" + v.Region
			if seen[k] || v.Environment != d.Request.Environment || v.OrganizationID != d.Request.TenantID || v.ProjectID != d.Request.ProjectID || v.OperationID != d.Request.OperationID || !v.Cutoff.Equal(d.Cutoff) || !canonicalID.MatchString(v.DatabaseID) || !slices.Contains([]string{"GRU", "SFO", "FRA"}, v.Region) {
				return ErrInvalid
			}
			seen[k] = true
			if t.Preparation == nil {
				allPrepared = false
			} else if !validPreparation(v, *t.Preparation) {
				return ErrInvalid
			}
			if t.Receipt == nil {
				all = false
			} else if !validStopReceipt(v, *t.Receipt) {
				return ErrInvalid
			}
		}
		if all != (d.State == "edge_pending" || d.State == "cleanup_pending") || allPrepared != (d.State != "preparing") || (d.EdgeReceipt != nil) != (d.State == "cleanup_pending") || (d.EdgeReceipt != nil && !validEdgeReceipt(d, *d.EdgeReceipt)) {
			return ErrInvalid
		}
	}
	return nil
}
func beginDeletion(s *journalState, r DeleteRequest, at time.Time, retainUntil time.Time) (Deletion, error) {
	if !validDeleteRequest(r) || at.IsZero() || (!retainUntil.IsZero() && retainUntil.Before(at)) {
		return Deletion{}, ErrInvalid
	}
	key := deletionKey(r)
	if old, ok := s.Deletions[key]; ok {
		if old.Request != r {
			return Deletion{}, ErrConflict
		}
		return old, nil
	}
	for _, closed := range s.Lifecycle.Closed {
		if closed.OrganizationID == r.TenantID && at.Before(closed.End) {
			return Deletion{}, databaselifecycle.ErrClosed
		}
	}
	for _, old := range s.Deletions {
		if old.Request.Environment == r.Environment && old.Request.TenantID == r.TenantID {
			for _, t := range old.Targets {
				if t.Stop.DatabaseID == r.DatabaseID {
					return Deletion{}, ErrConflict
				}
			}
		}
	}
	id := databaselifecycle.Identity{Environment: r.Environment, OrganizationID: r.TenantID, ProjectID: r.ProjectID, DatabaseID: r.DatabaseID}
	root, ok := s.Lifecycle.Resources[databaselifecycle.Key(id)]
	if !ok || root.ProjectID != r.ProjectID || !root.DeletedAt.IsZero() {
		return Deletion{}, ErrConflict
	}
	d := Deletion{Request: r, RequestedAt: at.UTC(), State: "preparing"}
	ids := map[string]bool{r.DatabaseID: true}
	for changed := true; changed; {
		changed = false
		for _, v := range s.Lifecycle.Resources {
			if v.Environment == r.Environment && v.OrganizationID == r.TenantID && v.ProjectID == r.ProjectID && ids[v.ParentDatabaseID] && !ids[v.DatabaseID] && v.DeletedAt.IsZero() {
				ids[v.DatabaseID] = true
				changed = true
			}
		}
	}
	for _, old := range s.Deletions {
		if old.Request.Environment == r.Environment && old.Request.TenantID == r.TenantID {
			for _, target := range old.Targets {
				if ids[target.Stop.DatabaseID] {
					return Deletion{}, ErrConflict
				}
			}
		}
	}
	for _, v := range s.Lifecycle.Resources {
		if v.Environment != r.Environment || v.OrganizationID != r.TenantID || !ids[v.DatabaseID] {
			continue
		}
		if v.CreatedAt.After(at) {
			return Deletion{}, ErrConflict
		}
		for _, region := range v.Regions {
			d.Targets = append(d.Targets, DeletionTarget{Stop: DeletionStop{Identity: v.Identity, OperationID: r.OperationID, Region: region, Cutoff: d.Cutoff, RetainUntil: retainUntil.UTC()}})
		}
	}
	slices.SortFunc(d.Targets, func(a, b DeletionTarget) int {
		if a.Stop.DatabaseID < b.Stop.DatabaseID {
			return -1
		}
		if a.Stop.DatabaseID > b.Stop.DatabaseID {
			return 1
		}
		if a.Stop.Region < b.Stop.Region {
			return -1
		}
		if a.Stop.Region > b.Stop.Region {
			return 1
		}
		return 0
	})
	if s.Deletions == nil {
		s.Deletions = map[string]Deletion{}
	}
	s.Deletions[key] = d
	if err := validateReservedCapacity(*s); err != nil {
		return Deletion{}, err
	}
	return d, nil
}
func recordDeletionStop(s *journalState, r DeleteRequest, receipt DeletionReceipt) (Deletion, error) {
	key := deletionKey(r)
	d, ok := s.Deletions[key]
	if !ok || d.Request != r || d.State == "preparing" {
		return Deletion{}, ErrConflict
	}
	if d.State == "cleanup_pending" {
		return d, nil
	}
	found := false
	all := true
	for i, t := range d.Targets {
		if validStopReceipt(t.Stop, receipt) {
			d.Targets[i].Receipt = new(receipt)
			found = true
		}
		if d.Targets[i].Receipt == nil {
			all = false
		}
	}
	if !found {
		return Deletion{}, ErrInvalid
	}
	if all {
		if err := finalizeDeletion(s, d); err != nil {
			return Deletion{}, err
		}
		d.State = "edge_pending"
	}
	s.Deletions[key] = d
	if err := validateReservedCapacity(*s); err != nil {
		return Deletion{}, err
	}
	return d, nil
}
func (j *NATSJournal) BeginDeletion(ctx context.Context, r DeleteRequest, at time.Time, retainUntil time.Time) (d Deletion, err error) {
	if j == nil || j.journal == nil {
		return d, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, true, func(s *journalState) error { var e error; d, e = beginDeletion(s, r, at, retainUntil); return e })
	return
}
func (j *NATSJournal) BeginDeletionWithClaim(ctx context.Context, r DeleteRequest, at time.Time, retainUntil time.Time, claim DeletionClaimReceipt) (d Deletion, err error) {
	if j == nil || j.journal == nil {
		return d, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, true, func(s *journalState) error {
		var e error
		d, e = beginDeletion(s, r, at, retainUntil)
		if e != nil {
			return e
		}
		if d.Claim != nil && *d.Claim != claim {
			return ErrConflict
		}
		d.Claim = &claim
		s.Deletions[deletionKey(r)] = d
		return nil
	})
	return
}
func (j *NATSJournal) RecordDeletionStop(ctx context.Context, r DeleteRequest, v DeletionReceipt) (d Deletion, err error) {
	if j == nil || j.journal == nil {
		return d, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, true, func(s *journalState) error { var e error; d, e = recordDeletionStop(s, r, v); return e })
	return
}
func (j *NATSJournal) ListDeletions(ctx context.Context) (out []Deletion, err error) {
	if j == nil || j.journal == nil {
		return nil, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, false, func(s *journalState) error {
		for _, d := range s.Deletions {
			out = append(out, d)
		}
		return nil
	})
	return
}
func (j *MemoryJournal) BeginDeletion(ctx context.Context, r DeleteRequest, at time.Time, retainUntil time.Time) (d Deletion, err error) {
	err = j.lifecycleTransact(ctx, func(s *journalState) error { var e error; d, e = beginDeletion(s, r, at, retainUntil); return e })
	return
}
func (j *MemoryJournal) BeginDeletionWithClaim(ctx context.Context, r DeleteRequest, at time.Time, retainUntil time.Time, claim DeletionClaimReceipt) (d Deletion, err error) {
	err = j.lifecycleTransact(ctx, func(s *journalState) error {
		var e error
		d, e = beginDeletion(s, r, at, retainUntil)
		if e != nil {
			return e
		}
		if d.Claim != nil && *d.Claim != claim {
			return ErrConflict
		}
		d.Claim = &claim
		s.Deletions[deletionKey(r)] = d
		return nil
	})
	return
}
func (j *MemoryJournal) RecordDeletionStop(ctx context.Context, r DeleteRequest, v DeletionReceipt) (d Deletion, err error) {
	err = j.lifecycleTransact(ctx, func(s *journalState) error { var e error; d, e = recordDeletionStop(s, r, v); return e })
	return
}
func (j *MemoryJournal) ListDeletions(ctx context.Context) (out []Deletion, err error) {
	s, err := j.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range s.Deletions {
		out = append(out, d)
	}
	return
}

func finalizeDeletion(s *journalState, d Deletion) error {
	for _, t := range d.Targets {
		v := s.Lifecycle.Resources[databaselifecycle.Key(t.Stop.Identity)]
		if v.DeletedAt.IsZero() {
			if err := databaselifecycle.Apply(&s.Lifecycle, databaselifecycle.Event{Identity: v.Identity, OperationID: "delete-" + d.Request.OperationID + "-" + v.DatabaseID, Kind: "delete", At: d.Cutoff, RetainUntil: t.Stop.RetainUntil}); err != nil {
				return err
			}
		}
	}
	for _, t := range d.Targets {
		v := s.Lifecycle.Resources[databaselifecycle.Key(t.Stop.Identity)]
		changed := false
		v.Streams = slices.Clone(v.Streams)
		for i, stream := range v.Streams {
			if stream.Region == t.Stop.Region && stream.StoppedAt.IsZero() {
				if !stream.StartedAt.Before(d.Cutoff) {
					return ErrConflict
				}
				v.Streams[i].StoppedAt = d.Cutoff
				changed = true
			}
		}
		if changed {
			if err := databaselifecycle.Apply(&s.Lifecycle, databaselifecycle.Event{Identity: v.Identity, OperationID: "stop-" + d.Request.OperationID + "-" + v.DatabaseID + "-" + t.Stop.Region, Kind: "streams", At: d.Cutoff, Streams: v.Streams}); err != nil {
				return err
			}
		}
	}
	return nil
}
func deletionBlocksEvent(s *journalState, e databaselifecycle.Event) bool {
	for _, d := range s.Deletions {
		for _, t := range d.Targets {
			if t.Stop.Environment == e.Environment && t.Stop.OrganizationID == e.OrganizationID && (t.Stop.DatabaseID == e.DatabaseID || t.Stop.DatabaseID == e.ParentDatabaseID) {
				return true
			}
		}
	}
	return false
}
func deletionBlocksFreeze(s *journalState, org string, end time.Time) bool {
	for _, d := range s.Deletions {
		if d.Request.TenantID == org && (d.State == "preparing" || d.State == "stopping") && d.RequestedAt.Before(end) {
			return true
		}
	}
	return false
}

func reserveDeletionCapacity(s *journalState) {
	out := make(map[string]Deletion, len(s.Deletions))
	for key, d := range s.Deletions {
		d.Targets = slices.Clone(d.Targets)
		d.EdgeReceipt = &DeletionEdgeReceipt{Request: d.Request, Cutoff: d.Cutoff, AccessRevoked: true}
		for i, t := range d.Targets {
			if t.Preparation == nil {
				d.Targets[i].Preparation = &DeletionPreparation{Identity: t.Stop.Identity, OperationID: t.Stop.OperationID, Region: t.Stop.Region, Prepared: true, LastAccountedAt: d.RequestedAt}
			}
			if t.Receipt == nil {
				d.Targets[i].Receipt = &DeletionReceipt{DeletionStop: t.Stop, AccessRevoked: true, UsageStopped: true}
			}
		}
		d.State = "cleanup_pending"
		out[key] = d
	}
	s.Deletions = out
}

func validPreparation(stop DeletionStop, r DeletionPreparation) bool {
	return stop.Identity == r.Identity && stop.OperationID == r.OperationID && stop.Region == r.Region && r.Prepared && !r.LastAccountedAt.IsZero() && r.LastAccountedAt.Nanosecond()%int(time.Millisecond) == 0
}
func validEdgeReceipt(d Deletion, r DeletionEdgeReceipt) bool {
	return r.Request == d.Request && r.Cutoff.Equal(d.Cutoff) && r.AccessRevoked
}
func recordDeletionPreparation(s *journalState, r DeleteRequest, p DeletionPreparation, now time.Time) (Deletion, error) {
	key := deletionKey(r)
	d, ok := s.Deletions[key]
	if !ok || d.Request != r {
		return Deletion{}, ErrConflict
	}
	if d.State != "preparing" {
		for _, t := range d.Targets {
			if validPreparation(t.Stop, p) && t.Preparation != nil && t.Preparation.LastAccountedAt.Equal(p.LastAccountedAt) {
				return d, nil
			}
		}
		return Deletion{}, ErrConflict
	}
	found := false
	all := true
	cutoff := maxTime(now.UTC().Truncate(time.Millisecond), d.RequestedAt)
	d.Targets = slices.Clone(d.Targets)
	for i, t := range d.Targets {
		if validPreparation(t.Stop, p) {
			if t.Preparation != nil && !t.Preparation.LastAccountedAt.Equal(p.LastAccountedAt) {
				return Deletion{}, ErrConflict
			}
			d.Targets[i].Preparation = new(p)
			found = true
		}
		if d.Targets[i].Preparation == nil {
			all = false
		} else {
			cutoff = maxTime(cutoff, d.Targets[i].Preparation.LastAccountedAt)
		}
	}
	if !found {
		return Deletion{}, ErrInvalid
	}
	if all {
		for _, closed := range s.Lifecycle.Closed {
			if closed.OrganizationID == r.TenantID && cutoff.Before(closed.End) {
				return Deletion{}, databaselifecycle.ErrClosed
			}
		}
		d.Cutoff = cutoff
		d.State = "stopping"
		for i := range d.Targets {
			d.Targets[i].Stop.Cutoff = cutoff
			if !d.Targets[i].Stop.RetainUntil.IsZero() && d.Targets[i].Stop.RetainUntil.Before(cutoff) {
				return Deletion{}, ErrConflict
			}
		}
	}
	s.Deletions[key] = d
	if err := validateReservedCapacity(*s); err != nil {
		return Deletion{}, err
	}
	return d, nil
}
func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}
func recordDeletionEdge(s *journalState, r DeleteRequest, receipt DeletionEdgeReceipt) (Deletion, error) {
	key := deletionKey(r)
	d, ok := s.Deletions[key]
	if !ok || d.Request != r || !validEdgeReceipt(d, receipt) || (d.State != "edge_pending" && d.State != "cleanup_pending") {
		return Deletion{}, ErrConflict
	}
	d.EdgeReceipt = new(receipt)
	d.State = "cleanup_pending"
	s.Deletions[key] = d
	if err := validateReservedCapacity(*s); err != nil {
		return Deletion{}, err
	}
	return d, nil
}
func (j *NATSJournal) RecordDeletionPreparation(ctx context.Context, r DeleteRequest, p DeletionPreparation, now time.Time) (d Deletion, err error) {
	if j == nil || j.journal == nil {
		return d, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, true, func(s *journalState) error { var e error; d, e = recordDeletionPreparation(s, r, p, now); return e })
	return
}
func (j *MemoryJournal) RecordDeletionPreparation(ctx context.Context, r DeleteRequest, p DeletionPreparation, now time.Time) (d Deletion, err error) {
	err = j.lifecycleTransact(ctx, func(s *journalState) error { var e error; d, e = recordDeletionPreparation(s, r, p, now); return e })
	return
}
func (j *NATSJournal) RecordDeletionEdge(ctx context.Context, r DeleteRequest, p DeletionEdgeReceipt) (d Deletion, err error) {
	if j == nil || j.journal == nil {
		return d, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, true, func(s *journalState) error { var e error; d, e = recordDeletionEdge(s, r, p); return e })
	return
}
func (j *MemoryJournal) RecordDeletionEdge(ctx context.Context, r DeleteRequest, p DeletionEdgeReceipt) (d Deletion, err error) {
	err = j.lifecycleTransact(ctx, func(s *journalState) error { var e error; d, e = recordDeletionEdge(s, r, p); return e })
	return
}
