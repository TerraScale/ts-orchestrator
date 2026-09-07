// Package reaper implements the infrastructure half of the Free-tier reaper
// (D-70, D-76).  It deliberately has no OCI, TerraBase, CDN, or mail
// implementation: those boundaries are injected and can therefore be tested
// without touching customer data.
//
// A catalog is authoritative for the current plan and last-request time. A
// catalog implementation must only return databases owned by TerraScale. The
// executor operations are idempotent for their supplied operation key. The
// reaper persists that key before invoking an operation and persists its
// completion afterwards, so a process crash or cancellation retries the same
// operation rather than inventing a new destructive mutation.
package reaper

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultPauseAfter and DefaultDeleteAfter are the D-76 idle thresholds.
	DefaultPauseAfter  = 30 * 24 * time.Hour
	DefaultDeleteAfter = 90 * 24 * time.Hour
	// The second lifecycle notice is sent at idle day 60. The final notice is
	// sent at the deletion threshold (day 90 by default), immediately before
	// destructive work starts.
	DefaultFirstReminder  = 60 * 24 * time.Hour
	DefaultSecondReminder = 90 * 24 * time.Hour
	DefaultPageSize       = 100
)

var (
	ErrPaidDatabase      = errors.New("reaper: paid database is not eligible")
	ErrExemptDatabase    = errors.New("reaper: database is exempt")
	ErrNotFound          = errors.New("reaper: database state not found")
	ErrDeleted           = errors.New("reaper: database has been deleted")
	ErrDeletionStarted   = errors.New("reaper: deletion has started")
	ErrInvalidDatabase   = errors.New("reaper: invalid database")
	ErrInvalidCursor     = errors.New("reaper: catalog cursor did not advance")
	ErrMissingDependency = errors.New("reaper: required dependency is missing")
)

// Plan is the billing plan observed from the control plane.
type Plan string

const (
	PlanFree Plan = "free"
	PlanPaid Plan = "paid"
)

// Phase is the durable reaper lifecycle. Deleting is entered only after the
// pause and both reminder notices have completed.
type Phase string

const (
	PhaseActive   Phase = "active"
	PhasePaused   Phase = "paused"
	PhaseDeleting Phase = "deleting"
	PhaseDeleted  Phase = "deleted"
)

// Exemption is a product/admin exemption. Until is optional (zero means no
// expiry). An active exemption always wins over age, including at deletion.
type Exemption struct {
	Active bool      `json:"active"`
	Reason string    `json:"reason,omitempty"`
	Until  time.Time `json:"until,omitempty"`
}

func (e Exemption) activeAt(now time.Time) bool {
	return e.Active && (e.Until.IsZero() || now.Before(e.Until))
}

// Database is the current catalog observation. LastRequest must be the last
// successful customer request, not an orchestrator heartbeat. A zero value is
// unknown and is handled fail-closed (it is never reaped).
type Database struct {
	ID                      string     `json:"id"`
	OrganizationID          string     `json:"organizationId,omitempty"`
	ProjectID               string     `json:"projectId,omitempty"`
	OwnerEmail              string     `json:"ownerEmail"`
	Plan                    Plan       `json:"plan"`
	LastRequest             time.Time  `json:"lastRequest"`
	Exemption               Exemption  `json:"exemption"`
	OwnershipProof          string     `json:"ownershipProof,omitempty"`
	PolicyRevision          string     `json:"policyRevision,omitempty"`
	SelectedGraceCondition  string     `json:"selectedGraceCondition,omitempty"`
	BillingGraceDeadline    *time.Time `json:"billingGraceDeadline,omitempty"`
	BillingDeletionEligible bool       `json:"billingDeletionEligible,omitempty"`
}

// Page is one deterministic catalog page. NextCursor is empty at the end.
type Page struct {
	Databases  []Database
	NextCursor string
}

// Catalog lists authoritative current observations. Implementations should
// use a stable ordering while a cursor is active.
type Catalog interface {
	List(ctx context.Context, cursor string, limit int) (Page, error)
}

// Executor is the infrastructure seam. Every method must be idempotent for
// the supplied operation key. EnsureSnapshot must leave the retained
// TerraBase native backup snapshot available before CloseDatabase is allowed to complete.
type Executor interface {
	EnsureSnapshot(ctx context.Context, databaseID, operationKey string) error
	CloseDatabase(ctx context.Context, databaseID, operationKey string) error
	StopNativeBackup(ctx context.Context, databaseID, operationKey string) error
	Reactivate(ctx context.Context, databaseID, operationKey string) error
	PurgeCDN(ctx context.Context, databaseID, operationKey string) error
	DestroyDEK(ctx context.Context, databaseID, operationKey string) error
	ObserveDEKDestruction(ctx context.Context, databaseID, operationKey string) (bool, error)
	DeleteOwnedData(ctx context.Context, databaseID, operationKey string) error
}

// DeletionAdmission atomically claims an automatic billing deletion and
// persists the native admission journal before destructive effects begin.
type DeletionAdmission interface {
	AdmitDeletion(context.Context, Database, string) error
}

// Email is intentionally plain metadata; no database data is included.
type Email struct {
	To           string
	Template     string
	DatabaseID   string
	OperationKey string
}

type Mailer interface {
	Send(ctx context.Context, email Email) error
}

// AuditEvent is safe to publish to an audit stream. It contains no owner
// email, credentials, DEKs, snapshots, or customer data.
type AuditEvent struct {
	ID           string    `json:"id"`
	DatabaseID   string    `json:"databaseId"`
	Action       string    `json:"action"`
	Outcome      string    `json:"outcome"`
	OperationKey string    `json:"operationKey"`
	At           time.Time `json:"at"`
	Error        string    `json:"error,omitempty"`
}

type AuditSink interface {
	Record(ctx context.Context, event AuditEvent) error
}

// Clock permits deterministic scans and tests.
type Clock interface{ Now() time.Time }

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Operation is durable bookkeeping for one idempotent side effect.
type Operation struct {
	Status      string    `json:"status"`
	Attempts    uint32    `json:"attempts"`
	StartedAt   time.Time `json:"startedAt,omitempty"`
	CompletedAt time.Time `json:"completedAt,omitempty"`
	LastError   string    `json:"lastError,omitempty"`
}

const (
	operationStarted = "started"
	operationFailed  = "failed"
	operationDone    = "done"
)

// Entry is the durable reaper state for a database.
type Entry struct {
	DatabaseID string `json:"databaseId"`
	Plan       Plan   `json:"plan"`
	Phase      Phase  `json:"phase"`
	// Cycle increments after a reactivation. Side-effect operation keys include
	// the cycle so a later pause cannot be mistaken for an old completed pause.
	Cycle          uint64               `json:"cycle,omitempty"`
	LastRequest    time.Time            `json:"lastRequest"`
	PausedAt       time.Time            `json:"pausedAt,omitempty"`
	FirstNoticeAt  time.Time            `json:"firstNoticeAt,omitempty"`
	SecondNoticeAt time.Time            `json:"secondNoticeAt,omitempty"`
	DeletedAt      time.Time            `json:"deletedAt,omitempty"`
	BillingGrace   bool                 `json:"billingGrace,omitempty"`
	Operations     map[string]Operation `json:"operations,omitempty"`
	Audits         map[string]bool      `json:"audits,omitempty"`
}

// State is the complete metadata checkpoint. Cursor is committed only after
// every database in its page has reconciled successfully.
type State struct {
	Version uint64           `json:"version"`
	Cursor  string           `json:"cursor,omitempty"`
	Entries map[string]Entry `json:"entries,omitempty"`
}

type StateStore interface {
	Load(ctx context.Context) (State, error)
	Save(ctx context.Context, state State) error
}

// Config wires all external effects. Zero durations select D-76 defaults.
type Config struct {
	Catalog     Catalog
	Executor    Executor
	Admission   DeletionAdmission
	Mailer      Mailer
	Audit       AuditSink
	Store       StateStore
	Clock       Clock
	PageSize    int
	PauseAfter  time.Duration
	DeleteAfter time.Duration
	ReminderAt  []time.Duration
}

// Result reports one scan. Counts are observations of decisions, not billing
// metrics. A failed scan returns its result along with an error.
type Result struct {
	Processed   int
	Paused      int
	Notices     int
	Reactivated int
	Deleted     int
	Skipped     int
	Cursor      string
}

type Reconciler struct {
	catalog                 Catalog
	executor                Executor
	admission               DeletionAdmission
	mailer                  Mailer
	audit                   AuditSink
	store                   StateStore
	clock                   Clock
	pageSize                int
	pauseAfter, deleteAfter time.Duration
	reminderAt              []time.Duration
	mu                      sync.Mutex
}

func NewReconciler(config Config) (*Reconciler, error) {
	if isNil(config.Catalog) || isNil(config.Executor) || isNil(config.Admission) || isNil(config.Mailer) || isNil(config.Audit) || isNil(config.Store) {
		return nil, ErrMissingDependency
	}
	if config.Clock != nil && isNil(config.Clock) {
		return nil, ErrMissingDependency
	}
	clock := config.Clock
	if clock == nil {
		clock = systemClock{}
	}
	pageSize := config.PageSize
	if pageSize == 0 {
		pageSize = DefaultPageSize
	}
	if pageSize < 1 {
		return nil, errors.New("reaper: page size must be positive")
	}
	pauseAfter := config.PauseAfter
	if pauseAfter == 0 {
		pauseAfter = DefaultPauseAfter
	}
	deleteAfter := config.DeleteAfter
	if deleteAfter == 0 {
		deleteAfter = DefaultDeleteAfter
	}
	reminders := append([]time.Duration(nil), config.ReminderAt...)
	if len(reminders) == 0 {
		first, final := DefaultFirstReminder, DefaultSecondReminder
		// Short test/operational windows should remain usable without requiring
		// callers to duplicate the policy. Keep the normal 60/90-day values when
		// they fit; otherwise place the second notice halfway through the window
		// and the final notice at deletion.
		if first <= pauseAfter || first >= deleteAfter {
			first = pauseAfter + (deleteAfter-pauseAfter)/2
		}
		if final < first || final > deleteAfter {
			final = deleteAfter
		}
		reminders = []time.Duration{first, final}
	} else if len(reminders) == 1 {
		// A single configured reminder means day 60 plus the final notice at
		// deletion time.
		reminders = append(reminders, deleteAfter)
	}
	if pauseAfter <= 0 || deleteAfter <= pauseAfter || (len(reminders) != 1 && len(reminders) != 2) || reminders[0] <= pauseAfter || reminders[0] >= deleteAfter || (len(reminders) == 2 && (reminders[1] < reminders[0] || reminders[1] > deleteAfter)) {
		return nil, errors.New("reaper: invalid pause, reminder, or deletion thresholds")
	}
	return &Reconciler{catalog: config.Catalog, executor: config.Executor, admission: config.Admission, mailer: config.Mailer, audit: config.Audit, store: config.Store, clock: clock, pageSize: pageSize, pauseAfter: pauseAfter, deleteAfter: deleteAfter, reminderAt: reminders}, nil
}

// Run scans all catalog pages. A page cursor is not advanced if any database
// fails; completed operations in that page are safe to retry by key.
func (r *Reconciler) Run(ctx context.Context) (Result, error) {
	if r == nil || isNil(r.catalog) {
		return Result{}, ErrMissingDependency
	}
	if ctx == nil {
		return Result{}, errors.New("reaper: context is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	state, err := r.load(ctx)
	if err != nil {
		return Result{}, redactError(err)
	}
	var result Result
	for {
		if err := ctx.Err(); err != nil {
			result.Cursor = state.Cursor
			return result, err
		}
		page, err := r.catalog.List(ctx, state.Cursor, r.pageSize)
		if err != nil {
			result.Cursor = state.Cursor
			return result, redactError(err)
		}
		if page.NextCursor != "" && page.NextCursor == state.Cursor {
			result.Cursor = state.Cursor
			return result, ErrInvalidCursor
		}
		seenPage := make(map[string]struct{}, len(page.Databases))
		for _, database := range page.Databases {
			if _, duplicate := seenPage[database.ID]; duplicate {
				result.Cursor = state.Cursor
				return result, fmt.Errorf("%w: duplicate database in catalog page", ErrInvalidDatabase)
			}
			seenPage[database.ID] = struct{}{}
		}
		sort.Slice(page.Databases, func(i, j int) bool { return page.Databases[i].ID < page.Databases[j].ID })
		for _, database := range page.Databases {
			result.Processed++
			outcome, err := r.reconcileLocked(ctx, &state, database)
			if err != nil {
				result.Cursor = state.Cursor
				return result, err
			}
			switch outcome {
			case "paused":
				result.Paused++
			case "notice":
				result.Notices++
			case "reactivated":
				result.Reactivated++
			case "deleted":
				result.Deleted++
			case "skipped":
				result.Skipped++
			}
		}
		state.Cursor = page.NextCursor
		if err := r.save(ctx, &state); err != nil {
			result.Cursor = state.Cursor
			return result, redactError(err)
		}
		result.Cursor = state.Cursor
		if state.Cursor == "" {
			return result, nil
		}
	}
}

// Reconcile applies one catalog observation without changing the scan cursor.
// It is useful to wire an immediate control-plane change notification while
// the periodic Run loop remains the recovery mechanism.
func (r *Reconciler) Reconcile(ctx context.Context, database Database) error {
	if r == nil || isNil(r.catalog) {
		return ErrMissingDependency
	}
	if ctx == nil {
		return errors.New("reaper: context is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := r.load(ctx)
	if err != nil {
		return redactError(err)
	}
	_, err = r.reconcileLocked(ctx, &state, database)
	if err != nil {
		return redactError(err)
	}
	return redactError(r.save(ctx, &state))
}

func (r *Reconciler) load(ctx context.Context) (State, error) {
	state, err := r.store.Load(ctx)
	if err != nil {
		return State{}, redactError(err)
	}
	if state.Entries == nil {
		state.Entries = make(map[string]Entry)
	}
	return state, nil
}

func (r *Reconciler) save(ctx context.Context, state *State) error {
	state.Version++
	return redactError(r.store.Save(ctx, *state))
}

func (r *Reconciler) reconcileLocked(ctx context.Context, state *State, database Database) (string, error) {
	if err := validateDatabase(database); err != nil {
		return "", err
	}
	now := r.clock.Now().UTC()
	entry, exists := state.Entries[database.ID]
	if !exists {
		entry = Entry{DatabaseID: database.ID, Plan: database.Plan, Phase: PhaseActive, LastRequest: database.LastRequest, Operations: make(map[string]Operation), Audits: make(map[string]bool)}
	} else {
		if entry.Operations == nil {
			entry.Operations = make(map[string]Operation)
		}
		if entry.Audits == nil {
			entry.Audits = make(map[string]bool)
		}
		// Keep the newest observation. Catalog pages can be retried or arrive out
		// of order; an older page must never make an idle database look idle again.
		if database.LastRequest.After(entry.LastRequest) {
			entry.LastRequest = database.LastRequest
		}
		entry.Plan = database.Plan
	}
	state.Entries[database.ID] = entry
	if entry.BillingGrace && entry.Phase == PhaseDeleting && billingIrreversibleFence(entry) {
		confirmed, err := r.billingDestructionConfirmed(ctx, entry, database.ID)
		if err != nil {
			return "", err
		}
		if !confirmed {
			due := database.BillingDeletionEligible && database.BillingGraceDeadline != nil && !now.Before(*database.BillingGraceDeadline)
			if due {
				if err := r.deleteLocked(ctx, state, database, now); err != nil {
					return "", err
				}
				return "deleted", nil
			}
			if err := r.cancelBillingDeletionLocked(ctx, state, database, now); err != nil {
				return "", err
			}
			return "reactivated", nil
		}
		if err := r.deleteLocked(ctx, state, database, now); err != nil {
			return "", err
		}
		return "deleted", nil
	}
	if entry.BillingGrace && entry.Phase == PhaseDeleting && database.BillingDeletionEligible && database.BillingGraceDeadline != nil && !now.Before(*database.BillingGraceDeadline) {
		if err := r.deleteLocked(ctx, state, database, now); err != nil {
			return "", err
		}
		return "deleted", nil
	}
	if entry.BillingGrace && (database.BillingGraceDeadline == nil || now.Before(*database.BillingGraceDeadline)) && (entry.Phase == PhasePaused || entry.Phase == PhaseDeleting) && !billingIrreversibleFence(entry) {
		if err := r.cancelBillingDeletionLocked(ctx, state, database, now); err != nil {
			return "", err
		}
		return "reactivated", nil
	}
	if database.BillingGraceDeadline == nil && entry.BillingGrace && entry.Phase == PhasePaused {
		if err := r.reactivateLocked(ctx, state, database.ID, entry.LastRequest); err != nil {
			return "", err
		}
		return "reactivated", nil
	}
	if database.BillingGraceDeadline != nil {
		if !database.BillingDeletionEligible || now.Before(*database.BillingGraceDeadline) {
			return "skipped", r.auditOnce(ctx, state, database.ID, "eligibility", "billing-covered", "eligibility/"+database.ID+"/billing-covered", now, "")
		}
		if entry.Phase == PhaseActive {
			entry.BillingGrace = true
			state.Entries[database.ID] = entry
			if err := r.pauseLocked(ctx, state, database, now); err != nil {
				return "", err
			}
			return "paused", nil
		}
		if entry.Phase == PhasePaused {
			if err := r.deleteLocked(ctx, state, database, now); err != nil {
				return "", err
			}
			return "deleted", nil
		}
		return "skipped", nil
	}
	if database.Plan != PlanFree {
		return "skipped", r.auditOnce(ctx, state, database.ID, "eligibility", "paid", "eligibility/"+database.ID+"/paid", now, "")
	}
	if database.Exemption.activeAt(now) {
		return "skipped", r.auditOnce(ctx, state, database.ID, "eligibility", "exempt", "eligibility/"+database.ID+"/exempt", now, "")
	}
	if entry.LastRequest.IsZero() {
		return "skipped", r.auditOnce(ctx, state, database.ID, "eligibility", "unknown-last-request", "eligibility/"+database.ID+"/unknown-request", now, "")
	}
	if entry.Phase == PhaseDeleted {
		return "skipped", r.auditOnce(ctx, state, database.ID, "delete", "completed", "delete/complete/"+database.ID, now, "")
	}
	if entry.Phase == PhaseDeleting && database.LastRequest.After(entry.PausedAt) {
		// A request racing with destructive work must fail closed. The data
		// plane should reject such a request once deletion is fenced; retaining
		// this guard protects us if an observation arrives out of order.
		key := "delete/request-after-fence/" + database.ID
		if auditErr := r.auditOnce(context.WithoutCancel(ctx), state, database.ID, "delete", "blocked-request", key, now, "request observed after deletion fence"); auditErr != nil {
			return "", errors.Join(ErrDeletionStarted, auditErr)
		}
		return "", ErrDeletionStarted
	}
	if entry.Phase == PhasePaused && database.LastRequest.After(entry.PausedAt) {
		if err := r.reactivateLocked(ctx, state, database.ID, database.LastRequest); err != nil {
			return "", err
		}
		return "reactivated", nil
	}
	idle := now.Sub(entry.LastRequest)
	if idle < r.pauseAfter {
		return "skipped", r.auditOnce(ctx, state, database.ID, "eligibility", "active", fmt.Sprintf("eligibility/%s/active", database.ID), now, "")
	}
	if entry.Phase == PhaseActive {
		if err := r.pauseLocked(ctx, state, database, now); err != nil {
			return "", err
		}
		return "paused", nil
	}
	if entry.Phase != PhasePaused && entry.Phase != PhaseDeleting {
		return "skipped", nil
	}
	if entry.Phase == PhasePaused {
		pauseEmailKey := r.operationName(state.Entries[database.ID], "notice/pause/"+database.ID)
		if entry.Operations[pauseEmailKey].Status != operationDone {
			if err := r.emailLocked(ctx, state, database, pauseEmailKey, "free-tier-paused", now); err != nil {
				return "", err
			}
			return "notice", nil
		}
	}
	// The second lifecycle email is sent once at the configured reminder
	// threshold (day 60 by default). A delayed scan still sends it before any
	// destructive work is considered.
	if entry.FirstNoticeAt.IsZero() && idle >= r.reminderAt[0] {
		key := r.operationName(state.Entries[database.ID], "notice/second/"+database.ID)
		if err := r.emailLocked(ctx, state, database, key, "free-tier-reminder-1", now); err != nil {
			return "", err
		}
		entry = state.Entries[database.ID]
		entry.FirstNoticeAt = now
		state.Entries[database.ID] = entry
		if err := r.save(ctx, state); err != nil {
			return "", err
		}
		return "notice", nil
	}
	// Permit an explicitly earlier final-notice threshold while retaining the
	// day-90 deletion gate. This is useful for operators that want additional
	// notice time, and keeps delayed scans deterministic.
	if entry.SecondNoticeAt.IsZero() && idle >= r.reminderAt[1] && idle < r.deleteAfter {
		key := r.operationName(state.Entries[database.ID], "notice/final/"+database.ID)
		if err := r.emailLocked(ctx, state, database, key, "free-tier-final", now); err != nil {
			return "", err
		}
		entry = state.Entries[database.ID]
		entry.SecondNoticeAt = now
		state.Entries[database.ID] = entry
		if err := r.save(ctx, state); err != nil {
			return "", err
		}
		return "notice", nil
	}
	if idle < r.deleteAfter || entry.FirstNoticeAt.IsZero() {
		return "skipped", nil
	}
	if entry.Phase != PhasePaused && entry.Phase != PhaseDeleting {
		return "skipped", nil
	}
	if err := r.deleteLocked(ctx, state, database, now); err != nil {
		return "", err
	}
	return "deleted", nil
}

func validateDatabase(database Database) error {
	if !validDatabaseID(database.ID) || database.Plan == "" {
		return ErrInvalidDatabase
	}
	if database.Plan != PlanFree && database.Plan != PlanPaid {
		return ErrInvalidDatabase
	}
	return nil
}

func validDatabaseID(id string) bool {
	if strings.TrimSpace(id) != id || id == "" || len(id) > 255 {
		return false
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f || strings.ContainsRune("/\\", r) {
			return false
		}
	}
	return true
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func (r *Reconciler) pauseLocked(ctx context.Context, state *State, database Database, now time.Time) error {
	entry := state.Entries[database.ID]
	for _, operation := range []struct {
		name string
		run  func(context.Context, string) error
	}{
		{r.operationName(entry, "pause/snapshot"), func(ctx context.Context, key string) error { return r.executor.EnsureSnapshot(ctx, database.ID, key) }},
		{r.operationName(entry, "pause/close"), func(ctx context.Context, key string) error { return r.executor.CloseDatabase(ctx, database.ID, key) }},
		{r.operationName(entry, "pause/native-backup"), func(ctx context.Context, key string) error { return r.executor.StopNativeBackup(ctx, database.ID, key) }},
	} {
		if err := r.operationLocked(ctx, state, database.ID, operation.name, operation.run, now); err != nil {
			return err
		}
	}
	entry = state.Entries[database.ID]
	entry.Phase, entry.PausedAt = PhasePaused, now
	state.Entries[database.ID] = entry
	if err := r.save(ctx, state); err != nil {
		return redactError(err)
	}
	return r.emailLocked(ctx, state, database, r.operationName(entry, "notice/pause/"+database.ID), "free-tier-paused", now)
}

func (r *Reconciler) deleteLocked(ctx context.Context, state *State, database Database, now time.Time) error {
	entry := state.Entries[database.ID]
	if r.admission == nil {
		return ErrMissingDependency
	}
	if err := r.admission.AdmitDeletion(ctx, database, r.operationName(entry, "automatic-delete")); err != nil {
		return err
	}
	entry.Phase = PhaseDeleting
	state.Entries[database.ID] = entry
	if err := r.save(ctx, state); err != nil {
		return err
	}
	// The final notice is part of the deletion transaction: it must be durably
	// acknowledged before a DEK can be destroyed. If delivery or its audit
	// checkpoint fails, the phase remains deleting and this exact operation key
	// is retried on the next scan.
	if entry.SecondNoticeAt.IsZero() {
		key := r.operationName(entry, "notice/final/"+database.ID)
		if err := r.emailLocked(ctx, state, database, key, "free-tier-final", now); err != nil {
			return err
		}
		entry = state.Entries[database.ID]
		entry.SecondNoticeAt = now
		state.Entries[database.ID] = entry
		if err := r.save(ctx, state); err != nil {
			return err
		}
	}
	// Purging first ensures an edge copy cannot outlive the DEK destruction.
	for _, operation := range []struct {
		name string
		run  func(context.Context, string) error
	}{
		{"delete/cdn-purge", func(ctx context.Context, key string) error { return r.executor.PurgeCDN(ctx, database.ID, key) }},
		{r.operationName(entry, "delete/crypto-shred"), func(ctx context.Context, key string) error { return r.executor.DestroyDEK(ctx, database.ID, key) }},
		{r.operationName(entry, "delete/data"), func(ctx context.Context, key string) error { return r.executor.DeleteOwnedData(ctx, database.ID, key) }},
	} {
		if err := r.operationLocked(ctx, state, database.ID, operation.name, operation.run, now); err != nil {
			return err
		}
	}
	entry = state.Entries[database.ID]
	entry.Phase, entry.DeletedAt = PhaseDeleted, now
	state.Entries[database.ID] = entry
	if err := r.save(ctx, state); err != nil {
		return err
	}
	return r.auditOnce(ctx, state, database.ID, "delete", "completed", "delete/complete/"+database.ID, now, "")
}

func (r *Reconciler) operationLocked(ctx context.Context, state *State, databaseID, name string, run func(context.Context, string) error, now time.Time) error {
	entry := state.Entries[databaseID]
	op := entry.Operations[name]
	if op.Status == operationDone {
		return nil
	}
	op.Status, op.Attempts, op.StartedAt, op.LastError = operationStarted, op.Attempts+1, now, ""
	entry.Operations[name] = op
	state.Entries[databaseID] = entry
	if err := r.save(ctx, state); err != nil {
		return redactError(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := run(ctx, name+"/"+databaseID); err != nil {
		op = state.Entries[databaseID].Operations[name]
		op.Status, op.LastError = operationFailed, safeError(err)
		entry = state.Entries[databaseID]
		entry.Operations[name] = op
		state.Entries[databaseID] = entry
		_ = r.save(context.WithoutCancel(ctx), state)
		auditErr := r.auditOnce(context.WithoutCancel(ctx), state, databaseID, name, "failed", name+"/failed/"+databaseID, now, safeError(err))
		if auditErr != nil {
			return redactError(errors.Join(err, auditErr))
		}
		return redactError(err)
	}
	op = state.Entries[databaseID].Operations[name]
	op.Status, op.CompletedAt, op.LastError = operationDone, r.clock.Now().UTC(), ""
	entry = state.Entries[databaseID]
	entry.Operations[name] = op
	state.Entries[databaseID] = entry
	if err := r.save(ctx, state); err != nil {
		return redactError(err)
	}
	return r.auditOnce(ctx, state, databaseID, name, "completed", name+"/completed/"+databaseID, now, "")
}

// operationName returns the durable name for a side effect in this lifecycle
// cycle. Keeping cycle zero unsuffixed preserves the original on-disk format;
// subsequent pauses use a new provider id after a reactivation.
func (r *Reconciler) operationName(entry Entry, base string) string {
	if entry.Cycle == 0 {
		return base
	}
	return fmt.Sprintf("%s/cycle-%d", base, entry.Cycle)
}

func (r *Reconciler) emailLocked(ctx context.Context, state *State, database Database, key, template string, now time.Time) error {
	if err := r.operationLocked(ctx, state, database.ID, key, func(ctx context.Context, opKey string) error {
		if strings.TrimSpace(database.OwnerEmail) == "" {
			return errors.New("owner email is missing")
		}
		return r.mailer.Send(ctx, Email{To: database.OwnerEmail, Template: template, DatabaseID: database.ID, OperationKey: opKey})
	}, now); err != nil {
		return err
	}
	return r.auditOnce(ctx, state, database.ID, "email", "sent", key, now, "")
}

func (r *Reconciler) auditOnce(ctx context.Context, state *State, databaseID, action, outcome, key string, now time.Time, eventError string) error {
	entry := state.Entries[databaseID]
	if entry.Audits == nil {
		entry.Audits = make(map[string]bool)
	}
	if entry.Audits[key] {
		return nil
	}
	if err := r.audit.Record(ctx, AuditEvent{ID: key, DatabaseID: databaseID, Action: action, Outcome: outcome, OperationKey: key, At: now, Error: eventError}); err != nil {
		return redactError(err)
	}
	entry.Audits[key] = true
	state.Entries[databaseID] = entry
	return r.save(ctx, state)
}

func (r *Reconciler) reactivateLocked(ctx context.Context, state *State, databaseID string, requestAt time.Time) error {
	entry := state.Entries[databaseID]
	if entry.Phase == PhaseDeleted {
		return ErrDeleted
	}
	if entry.Phase == PhaseDeleting {
		return ErrDeletionStarted
	}
	if entry.Phase == PhaseActive {
		return nil
	}
	key := fmt.Sprintf("reactivate/%s/%d", databaseID, requestAt.UnixNano())
	if err := r.operationLocked(ctx, state, databaseID, key, func(ctx context.Context, opKey string) error { return r.executor.Reactivate(ctx, databaseID, opKey) }, requestAt.UTC()); err != nil {
		return err
	}
	entry = state.Entries[databaseID]
	entry.Cycle++
	entry.Phase, entry.PausedAt, entry.FirstNoticeAt, entry.SecondNoticeAt, entry.BillingGrace = PhaseActive, time.Time{}, time.Time{}, time.Time{}, false
	entry.LastRequest = requestAt.UTC()
	state.Entries[databaseID] = entry
	if err := r.save(ctx, state); err != nil {
		return err
	}
	return r.auditOnce(ctx, state, databaseID, "reactivate", "completed", key, requestAt.UTC(), "")
}

func billingIrreversibleFence(entry Entry) bool {
	for _, base := range []string{"delete/crypto-shred", "delete/data"} {
		if entry.Operations[fmt.Sprintf("%s/cycle-%d", base, entry.Cycle)].Status != "" {
			return true
		}
		if entry.Cycle == 0 && entry.Operations[base].Status != "" {
			return true
		}
	}
	return false
}

func (r *Reconciler) billingDestructionConfirmed(ctx context.Context, entry Entry, databaseID string) (bool, error) {
	key := r.operationName(entry, "delete/crypto-shred")
	status := entry.Operations[key].Status
	if status == operationDone {
		return true, nil
	}
	if status != "" {
		return r.executor.ObserveDEKDestruction(ctx, databaseID, key+"/"+databaseID)
	}
	return true, nil
}

func (r *Reconciler) cancelBillingDeletionLocked(ctx context.Context, state *State, database Database, now time.Time) error {
	entry := state.Entries[database.ID]
	entry.Phase = PhasePaused
	state.Entries[database.ID] = entry
	if err := r.reactivateLocked(ctx, state, database.ID, entry.LastRequest); err != nil {
		return err
	}
	return r.auditOnce(ctx, state, database.ID, "billing-deletion", "cancelled", "billing-deletion/cancelled/"+database.ID, now, "")
}

// Reactivate performs the one-request reactivation operation for a paused
// database. A later catalog observation also invokes this method internally.
func (r *Reconciler) Reactivate(ctx context.Context, databaseID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, err := r.load(ctx)
	if err != nil {
		return err
	}
	entry, ok := state.Entries[databaseID]
	if !ok {
		return ErrNotFound
	}
	if entry.Phase == PhaseDeleted {
		return ErrDeleted
	}
	if entry.Phase == PhaseDeleting {
		return ErrDeletionStarted
	}
	return r.reactivateLocked(ctx, &state, databaseID, r.clock.Now().UTC())
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	// Provider errors can accidentally contain URLs, tokens, or response
	// bodies. Keep the durable journal/audit record useful for classification
	// without copying untrusted error text into a long-lived control store.
	return fmt.Sprintf("%T", err)
}

// redactedError preserves errors.Is for callers while keeping provider
// response bodies, URLs, and credentials out of command output. Durable
// state/audit already use safeError; this also protects the synchronous hook.
type redactedError struct{ cause error }

func (e redactedError) Error() string { return "reaper: infrastructure operation failed" }
func (e redactedError) Unwrap() error { return e.cause }

func redactError(err error) error {
	if err == nil || err == context.Canceled || err == context.DeadlineExceeded {
		return err
	}
	return redactedError{cause: err}
}
