package reaper

import (
	"context"
	"reflect"
	"time"
)

// DatabaseAdapter is the production boundary for the database and backup
// control plane. It must only return TerraScale-owned databases from List and
// every mutating method must be idempotent for operationKey.
//
// VerifySnapshotPlacement is deliberately separate from EnsureSnapshot. A
// production implementation must verify the immutable placement lock before
// making the retained snapshot visible, and must enforce that same lock while
// creating it. The reaper never chooses a backup Region itself.
// Snapshot, close, backup-stop and reactivation operations belong to TerraBase
// and must use its admitted TBEP lifecycle contract. StopNativeBackup stops the
// selected database's native backup stream; it must not stop shared engine
// workers, supervise an external process, or delete the retained snapshot.
type DatabaseAdapter interface {
	Catalog
	EnsureSnapshot(ctx context.Context, databaseID, operationKey string) error
	VerifySnapshotPlacement(ctx context.Context, databaseID string) error
	CloseDatabase(ctx context.Context, databaseID, operationKey string) error
	StopNativeBackup(ctx context.Context, databaseID, operationKey string) error
	Reactivate(ctx context.Context, databaseID, operationKey string) error
	PurgeCDN(ctx context.Context, databaseID, operationKey string) error
	DeleteOwnedData(ctx context.Context, databaseID, operationKey string) error
}

// KeyAdapter owns the final destruction of a database DEK. It is required in
// production even though the generic Executor seam has a DestroyDEK method;
// keeping it explicit prevents a database adapter from silently becoming a
// key-management implementation.
type KeyAdapter interface {
	DestroyDEK(ctx context.Context, databaseID, operationKey string) error
	ObserveDEKDestruction(ctx context.Context, databaseID, operationKey string) (bool, error)
}

// MailAdapter is the production email delivery boundary. Templates contain
// metadata only; implementations must not infer a successful send from a
// queued-but-unacknowledged request.
type MailAdapter interface {
	Send(ctx context.Context, email Email) error
}

// ProductionConfig contains every authority needed by the D-76 production
// reaper. Missing adapters fail closed before a reconciler is returned.
type ProductionConfig struct {
	Database             DatabaseAdapter
	Key                  KeyAdapter
	Admission            DeletionAdmission
	Mail                 MailAdapter
	Store                *NATSStateStoreConfig
	Audit                AuditSink
	Clock                Clock
	PageSize             int
	CheckEffectAuthority func(context.Context) error
}

// productionExecutor keeps key destruction in the explicit key adapter while
// forwarding the remaining infrastructure operations to the database
// adapter. Snapshot placement is checked before snapshot creation and the
// adapter contract requires the check to remain true for the operation.
type productionExecutor struct {
	database DatabaseAdapter
	key      KeyAdapter
	check    func(context.Context) error
}

func (e productionExecutor) EnsureSnapshot(ctx context.Context, databaseID, operationKey string) error {
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return err
	}
	if err := e.database.VerifySnapshotPlacement(ctx, databaseID); err != nil {
		return err
	}
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return err
	}
	return e.database.EnsureSnapshot(ctx, databaseID, operationKey)
}

func (e productionExecutor) CloseDatabase(ctx context.Context, databaseID, operationKey string) error {
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return err
	}
	return e.database.CloseDatabase(ctx, databaseID, operationKey)
}

func (e productionExecutor) StopNativeBackup(ctx context.Context, databaseID, operationKey string) error {
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return err
	}
	return e.database.StopNativeBackup(ctx, databaseID, operationKey)
}

func (e productionExecutor) Reactivate(ctx context.Context, databaseID, operationKey string) error {
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return err
	}
	return e.database.Reactivate(ctx, databaseID, operationKey)
}

func (e productionExecutor) PurgeCDN(ctx context.Context, databaseID, operationKey string) error {
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return err
	}
	return e.database.PurgeCDN(ctx, databaseID, operationKey)
}

func (e productionExecutor) DestroyDEK(ctx context.Context, databaseID, operationKey string) error {
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return err
	}
	return e.key.DestroyDEK(ctx, databaseID, operationKey)
}

func (e productionExecutor) ObserveDEKDestruction(ctx context.Context, databaseID, operationKey string) (bool, error) {
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return false, err
	}
	return e.key.ObserveDEKDestruction(ctx, databaseID, operationKey)
}

func (e productionExecutor) DeleteOwnedData(ctx context.Context, databaseID, operationKey string) error {
	if err := checkReaperEffect(ctx, e.check); err != nil {
		return err
	}
	return e.database.DeleteOwnedData(ctx, databaseID, operationKey)
}

func missingProductionDependency(value any) bool {
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

// NewProductionReconciler wires the D-76 production policy: Free databases
// only, a 30-day pause, notices at days 30/60/90, and destruction at day 90
// only after the earlier notices have been durably acknowledged. The generic
// lifecycle engine owns all operation keys, cursor commits, audit checkpoints,
// retries, and request races.
func NewProductionReconciler(config ProductionConfig) (*Reconciler, error) {
	if missingProductionDependency(config.Database) || missingProductionDependency(config.Key) ||
		missingProductionDependency(config.Mail) || missingProductionDependency(config.Store) ||
		missingProductionDependency(config.Audit) || missingProductionDependency(config.Admission) || config.CheckEffectAuthority == nil {
		return nil, ErrMissingDependency
	}
	store, err := NewNATSStateStore(*config.Store)
	if err != nil {
		return nil, err
	}
	return NewReconciler(Config{
		Catalog:     config.Database,
		Executor:    productionExecutor{database: config.Database, key: config.Key, check: config.CheckEffectAuthority},
		Admission:   config.Admission,
		Mailer:      guardedReaperMail{config.Mail, config.CheckEffectAuthority},
		Audit:       guardedReaperAudit{config.Audit, config.CheckEffectAuthority},
		Store:       store,
		Clock:       config.Clock,
		PageSize:    config.PageSize,
		PauseAfter:  DefaultPauseAfter,
		DeleteAfter: DefaultDeleteAfter,
		ReminderAt:  []time.Duration{DefaultFirstReminder, DefaultSecondReminder},
	})
}

// NewProduction is a concise alias retained for callers that treat the
// production composition root as the package's primary constructor.
func NewProduction(config ProductionConfig) (*Reconciler, error) {
	return NewProductionReconciler(config)
}

// ParentWiringHook is the narrow hook a parent control-plane runtime can use
// for periodic scans and immediate catalog notifications. Both paths share
// the same durable reconciler and therefore the same idempotency keys.
type ParentWiringHook struct {
	Run        func(context.Context) (Result, error)
	Reconcile  func(context.Context, Database) error
	Reactivate func(context.Context, string) error
}

// ProductionWiring is the parent-facing lifecycle handle. It intentionally
// exposes no adapter internals or customer data.
type ProductionWiring struct {
	reconciler *Reconciler
}

// NewProductionWiring composes a production reaper and returns the hook that
// a parent orchestrator loop can register. The constructor performs no
// provider, mail, key, or database calls.
func NewProductionWiring(config ProductionConfig) (*ProductionWiring, error) {
	reconciler, err := NewProductionReconciler(config)
	if err != nil {
		return nil, err
	}
	return &ProductionWiring{reconciler: reconciler}, nil
}

// NewProductionHook is a convenience constructor for parents that only need
// callbacks and do not need to retain the wiring handle itself.
func NewProductionHook(config ProductionConfig) (ParentWiringHook, error) {
	wiring, err := NewProductionWiring(config)
	if err != nil {
		return ParentWiringHook{}, err
	}
	return wiring.ParentHook(), nil
}

// ParentHook returns the periodic/immediate wiring callbacks.
func (w *ProductionWiring) ParentHook() ParentWiringHook {
	if w == nil || w.reconciler == nil {
		return ParentWiringHook{}
	}
	return ParentWiringHook{
		Run:        w.reconciler.Run,
		Reconcile:  w.reconciler.Reconcile,
		Reactivate: w.reconciler.Reactivate,
	}
}

// Reconciler returns the shared lifecycle engine for a parent that needs to
// retain a concrete handle. It returns nil for an empty wiring value.
func (w *ProductionWiring) Reconciler() *Reconciler {
	if w == nil {
		return nil
	}
	return w.reconciler
}

// Compile-time checks keep accidental adapter drift visible at this boundary.
var (
	_ Catalog  = (DatabaseAdapter)(nil)
	_ Executor = productionExecutor{}
	_ Mailer   = (MailAdapter)(nil)
)

// Admission is checked for every call, including failure audits whose caller
// deliberately detached cancellation. Provider implementations must repeat the
// authority check at each transport retry and mutation boundary. This callback
// cannot revoke requests already admitted by an external service.
func checkReaperEffect(ctx context.Context, check func(context.Context) error) error {
	if ctx == nil || check == nil {
		return ErrStateFenced
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return check(ctx)
}

type guardedReaperMail struct {
	mail  MailAdapter
	check func(context.Context) error
}

func (g guardedReaperMail) Send(ctx context.Context, email Email) error {
	if err := checkReaperEffect(ctx, g.check); err != nil {
		return err
	}
	return g.mail.Send(ctx, email)
}

type guardedReaperAudit struct {
	audit AuditSink
	check func(context.Context) error
}

func (g guardedReaperAudit) Record(ctx context.Context, event AuditEvent) error {
	if err := checkReaperEffect(ctx, g.check); err != nil {
		return err
	}
	return g.audit.Record(ctx, event)
}
