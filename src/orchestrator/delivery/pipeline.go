package delivery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const MaximumDeliveryPlanBytes = 8 << 20

const (
	// DeliveryClaimLease is deliberately finite. A process that disappears
	// after claiming a plan must not leave the plan pending forever.
	DeliveryClaimLease        = 15 * time.Second
	maximumDeliveryClaimLease = 5 * time.Minute
)

var (
	ErrDeliveryFenced   = errors.New("delivery authority changed")
	ErrDeliveryConflict = errors.New("delivery plan identity changed")
	ErrDeliveryClaimed  = errors.New("delivery plan is claimed by another runtime")
)

// DeliveryHandoff is the only deployment boundary owned by this package. The
// implementation decides how a plan is reconciled; delivery never talks to a
// cluster, provider, or deployment system directly.
type DeliveryHandoff interface {
	Handoff(context.Context, *DeliveryPlan) error
}

// Handoff is retained as a short spelling for callers that use the original
// delivery vocabulary.
type Handoff = DeliveryHandoff

// DeliveryReconciler is an alternate narrow boundary for controllers that
// call the operation reconciliation rather than a handoff.
type DeliveryReconciler interface {
	Reconcile(context.Context, *DeliveryPlan) error
}

type DeliveryHandoffFunc func(context.Context, *DeliveryPlan) error

func (f DeliveryHandoffFunc) Handoff(ctx context.Context, p *DeliveryPlan) error {
	if f == nil {
		return errors.New("delivery handoff is missing")
	}
	return f(ctx, p)
}

type reconcilerHandoff struct{ reconciler DeliveryReconciler }

func (h reconcilerHandoff) Handoff(ctx context.Context, p *DeliveryPlan) error {
	if h.reconciler == nil {
		return errors.New("delivery reconciler is missing")
	}
	return h.reconciler.Reconcile(ctx, p)
}

type SourceDescriptor struct {
	Repository    string
	Commit        string
	Blob          string
	ContentSHA256 string
	Dependencies  []string
}

type ArchiveDescriptor struct {
	Repository    string
	Commit        string
	Tree          string
	ContentSHA256 string
	Size          int
}

type ReconciliationIntent struct {
	Action         string
	Repository     string
	Commit         string
	Tree           string
	Idempotency    string
	ArchiveSHA256  string
	AuthorityEpoch int64
}

type DeliveryPlan struct {
	SchemaVersion  int
	Idempotency    string
	Digest         string
	Trigger        TriggerPlan
	Job            JobRequest
	Snapshot       SourceSnapshot
	Descriptors    []SourceDescriptor
	Archives       []SourceArchive
	ArchiveRecords []ArchiveDescriptor
	Intent         ReconciliationIntent
}

type DeliveryDisposition uint8

const (
	DeliveryUnspecified DeliveryDisposition = iota
	DeliveryRecorded
	DeliveryDuplicate
	DeliveryHeld
	DeliveryFenced
	DeliveryClaimed
)

type DeliveryReceipt struct {
	Disposition DeliveryDisposition
	Digest      string
}

type DeliveryProcessor struct {
	Graph      *RepositorySourceGraph
	Ledger     Ledger
	Handoff    DeliveryHandoff
	Authority  func() AuthoritySnapshot
	claimID    string
	claimLease time.Duration
	now        func() time.Time
	mu         sync.Mutex
}

func NewDeliveryProcessor(graph *RepositorySourceGraph, ledger Ledger, handoff DeliveryHandoff, authority func() AuthoritySnapshot) *DeliveryProcessor {
	if authority == nil {
		authority = func() AuthoritySnapshot { return AuthoritySnapshot{Ready: true, Leader: true, Epoch: 1} }
	}
	return &DeliveryProcessor{Graph: graph, Ledger: ledger, Handoff: handoff, Authority: authority, claimID: newDeliveryClaimID(), claimLease: DeliveryClaimLease, now: time.Now}
}

func NewDeliveryProcessorWithReconciler(graph *RepositorySourceGraph, ledger Ledger, reconciler DeliveryReconciler, authority func() AuthoritySnapshot) *DeliveryProcessor {
	var handoff DeliveryHandoff
	if reconciler != nil {
		handoff = reconcilerHandoff{reconciler: reconciler}
	}
	return NewDeliveryProcessor(graph, ledger, handoff, authority)
}

// Process consumes one already authenticated webhook. It is safe to retry the
// same event after a handoff or process failure. The durable record and its
// fenced lease claim are written before the external call and committed with a
// compare-and-swap afterwards.
func (p *DeliveryProcessor) Process(ctx context.Context, event *WebhookEnvelope) (DeliveryReceipt, error) {
	return p.process(ctx, event, nil)
}

// ProcessSnapshot is used by the polling fallback after it has fetched and
// fenced a graph snapshot. It avoids a second metadata read for that cycle.
func (p *DeliveryProcessor) ProcessSnapshot(ctx context.Context, event *WebhookEnvelope, snapshot SourceSnapshot) (DeliveryReceipt, error) {
	return p.process(ctx, event, &snapshot)
}

func (p *DeliveryProcessor) Publish(ctx context.Context, event *WebhookEnvelope) error {
	_, err := p.Process(ctx, event)
	return err
}

func (p *DeliveryProcessor) process(ctx context.Context, event *WebhookEnvelope, supplied *SourceSnapshot) (DeliveryReceipt, error) {
	if ctx == nil {
		return DeliveryReceipt{}, errors.New("delivery context is required")
	}
	if err := ctx.Err(); err != nil {
		return DeliveryReceipt{}, err
	}
	if p == nil || p.Ledger == nil || p.Authority == nil || event == nil {
		return DeliveryReceipt{}, errors.New("delivery processor dependencies are missing")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.claimID == "" {
		p.claimID = newDeliveryClaimID()
	}
	if p.claimLease <= 0 {
		p.claimLease = DeliveryClaimLease
	}
	if p.now == nil {
		p.now = time.Now
	}
	if !ValidRepository(event.Repository) || event.PayloadSHA256 == "" || event.DeliveryID == "" {
		return DeliveryReceipt{}, errors.New("delivery event identity is incomplete")
	}
	key := "plan." + hash(event.DedupeKey())
	if existing, err := p.Ledger.Get(ctx, key); err != nil {
		return DeliveryReceipt{}, err
	} else if existing != nil {
		doc, err := decodeDeliveryJournal(existing.Value)
		if err != nil {
			return DeliveryReceipt{}, err
		}
		if !doc.matches(event) {
			return DeliveryReceipt{}, ErrDeliveryConflict
		}
		if doc.State == "accepted" {
			return DeliveryReceipt{Disposition: DeliveryDuplicate, Digest: doc.Digest}, nil
		}
	}

	trigger := PlanTrigger(event)
	if trigger == nil {
		return DeliveryReceipt{}, errors.New("delivery trigger plan is missing")
	}
	authority := p.Authority()
	if trigger.Disposition == TriggerDispatch && (!authority.Ready || !authority.Leader || authority.Epoch <= 0) {
		return DeliveryReceipt{}, ErrDeliveryFenced
	}

	plan := DeliveryPlan{SchemaVersion: 1, Idempotency: event.DedupeKey(), Trigger: *cloneTrigger(trigger)}
	if trigger.Disposition == TriggerDispatch {
		if p.Graph == nil || p.Handoff == nil {
			return DeliveryReceipt{}, errors.New("dispatch requires source graph and handoff")
		}
		if event.SourceRepository != event.Repository {
			return DeliveryReceipt{}, errors.New("dispatch source repository is outside graph root")
		}
		var snapshot SourceSnapshot
		var err error
		if supplied != nil {
			snapshot = cloneSnapshot(*supplied)
		} else {
			branch, exactRoot, ok := deliveryBranch(event)
			if !ok {
				return DeliveryReceipt{}, errors.New("dispatch reference is not supported")
			}
			snapshot, err = p.Graph.Snapshot(ctx, event, branch, exactRoot)
			if err != nil {
				return DeliveryReceipt{}, err
			}
		}
		if err := validateSnapshot(p.Graph, event, snapshot); err != nil {
			return DeliveryReceipt{}, err
		}
		plan.Snapshot = snapshot
		plan.Descriptors = descriptors(snapshot)
		root, ok := sourceForRepository(snapshot.Sources, p.Graph.Root)
		if !ok {
			return DeliveryReceipt{}, errors.New("source graph snapshot omits root")
		}
		job, err := trigger.CreateJob(ResolvedJobRevision{Repository: root.Repository, Commit: root.Commit, Tree: root.Tree, SignatureVerified: root.SignatureVerified}, 1, 1, 1)
		if err != nil {
			return DeliveryReceipt{}, err
		}
		plan.Job = job
		archive, err := p.Graph.ReadArchive(ctx, root)
		if err != nil {
			return DeliveryReceipt{}, err
		}
		if err := validateArchive(root, archive); err != nil {
			return DeliveryReceipt{}, err
		}
		plan.Archives = []SourceArchive{cloneArchive(archive)}
		plan.ArchiveRecords = []ArchiveDescriptor{{Repository: archive.Revision.Repository, Commit: archive.Revision.Commit, Tree: archive.Revision.Tree, ContentSHA256: archive.ContentSHA256, Size: len(archive.Content)}}
		plan.Intent = ReconciliationIntent{Action: deliveryAction(trigger.JobKind), Repository: root.Repository, Commit: root.Commit, Tree: root.Tree, Idempotency: plan.Idempotency, ArchiveSHA256: archive.ContentSHA256, AuthorityEpoch: authority.Epoch}
	} else {
		plan.Intent = ReconciliationIntent{Action: "hold", Repository: event.Repository, Commit: event.Revision, Idempotency: plan.Idempotency, AuthorityEpoch: authority.Epoch}
	}
	plan.Digest = digestPlan(plan)
	if len(plan.Digest) == 0 {
		return DeliveryReceipt{}, errors.New("delivery plan digest is missing")
	}

	doc := deliveryJournalDocument{SchemaVersion: 1, State: "pending", Envelope: *event, Digest: plan.Digest, AuthorityEpoch: authority.Epoch, Job: plan.Job, Sources: append([]ResolvedRevision(nil), plan.Snapshot.Sources...), Descriptors: append([]SourceDescriptor(nil), plan.Descriptors...), Archives: append([]ArchiveDescriptor(nil), plan.ArchiveRecords...), Intent: plan.Intent}
	reservation, err := p.reserve(ctx, key, doc)
	if err != nil {
		return DeliveryReceipt{}, err
	}
	if reservation.State == "accepted" {
		return DeliveryReceipt{Disposition: DeliveryDuplicate, Digest: reservation.Digest}, nil
	}
	if trigger.Disposition == TriggerDispatch {
		claim, err := p.claim(ctx, key, doc, authority)
		if err != nil {
			disposition := DeliveryUnspecified
			if errors.Is(err, ErrDeliveryFenced) {
				disposition = DeliveryFenced
			}
			return DeliveryReceipt{Disposition: disposition, Digest: plan.Digest}, err
		}
		if !claim.Claimed {
			if claim.Reservation.State == "accepted" {
				return DeliveryReceipt{Disposition: DeliveryDuplicate, Digest: claim.Reservation.Digest}, nil
			}
			return DeliveryReceipt{Disposition: DeliveryClaimed, Digest: plan.Digest}, ErrDeliveryClaimed
		}
		reservation = claim.Reservation
		doc.ClaimOwner = reservation.ClaimOwner
		doc.ClaimEpoch = reservation.ClaimEpoch
		doc.ClaimedAt = reservation.ClaimedAt
		doc.ClaimExpiresAt = reservation.ClaimExpiresAt
		if err := ensureAuthority(p.Authority, authority); err != nil {
			_ = p.releaseClaim(ctx, key, reservation)
			return DeliveryReceipt{}, err
		}
		handoffErr := p.invokeHandoff(ctx, key, reservation, authority, &plan)
		if handoffErr != nil {
			// A known failed handoff can be retried immediately. The release is
			// itself fenced by the claim owner and ledger revision, so it cannot
			// clear a successor's claim after a restart or lease expiry.
			_ = p.releaseClaim(ctx, key, reservation)
			return DeliveryReceipt{}, handoffErr
		}
		if err := ensureAuthority(p.Authority, authority); err != nil {
			return DeliveryReceipt{}, err
		}
	}
	if err := p.accept(ctx, key, reservation, doc, plan.Digest); err != nil {
		return DeliveryReceipt{}, err
	}
	if trigger.Disposition == TriggerDispatch {
		return DeliveryReceipt{Disposition: DeliveryRecorded, Digest: plan.Digest}, nil
	}
	return DeliveryReceipt{Disposition: DeliveryHeld, Digest: plan.Digest}, nil
}

type deliveryJournalDocument struct {
	SchemaVersion  int                  `json:"schemaVersion"`
	State          string               `json:"state"`
	Envelope       WebhookEnvelope      `json:"envelope"`
	Digest         string               `json:"digest"`
	AuthorityEpoch int64                `json:"authorityEpoch"`
	Job            JobRequest           `json:"job,omitempty"`
	Sources        []ResolvedRevision   `json:"sources,omitempty"`
	Descriptors    []SourceDescriptor   `json:"descriptors,omitempty"`
	Archives       []ArchiveDescriptor  `json:"archives,omitempty"`
	Intent         ReconciliationIntent `json:"intent"`
	ClaimOwner     string               `json:"claimOwner,omitempty"`
	ClaimEpoch     int64                `json:"claimEpoch,omitempty"`
	ClaimedAt      int64                `json:"claimedAt,omitempty"`
	ClaimExpiresAt int64                `json:"claimExpiresAt,omitempty"`
}

func (d deliveryJournalDocument) matches(e *WebhookEnvelope) bool {
	return d.SchemaVersion == 1 && d.Envelope.DeliveryID == e.DeliveryID && d.Envelope.Kind == e.Kind && d.Envelope.Action == e.Action && d.Envelope.Repository == e.Repository && d.Envelope.SourceRepository == e.SourceRepository && d.Envelope.BaseRevision == e.BaseRevision && d.Envelope.Revision == e.Revision && d.Envelope.SourceRef == e.SourceRef && d.Envelope.TargetRef == e.TargetRef && d.Envelope.PullRequestNumber == e.PullRequestNumber && d.Envelope.IsDeletion == e.IsDeletion && d.Envelope.PayloadSHA256 == e.PayloadSHA256 && d.Envelope.DedupeKey() == e.DedupeKey()
}

func decodeDeliveryJournal(b []byte) (deliveryJournalDocument, error) {
	var d deliveryJournalDocument
	if err := json.Unmarshal(b, &d); err != nil {
		return d, fmt.Errorf("invalid delivery journal: %w", err)
	}
	if d.SchemaVersion != 1 || d.State != "pending" && d.State != "accepted" || !ValidRepository(d.Envelope.Repository) || d.Digest != "" && len(d.Digest) != 64 || d.AuthorityEpoch <= 0 || !validDeliveryClaim(d) {
		return d, errors.New("invalid delivery journal identity")
	}
	return d, nil
}

type deliveryReservation struct {
	Revision       uint64
	State          string
	Digest         string
	ClaimOwner     string
	ClaimEpoch     int64
	ClaimedAt      int64
	ClaimExpiresAt int64
}

type deliveryClaimResult struct {
	Reservation deliveryReservation
	Claimed     bool
}

func newDeliveryClaimID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	// A random owner is preferred, but a startup must still fail closed into
	// a distinct lease owner if the system random source is unavailable.
	return hash(fmt.Sprintf("delivery-claim-%d", time.Now().UnixNano()))
}

func (p *DeliveryProcessor) deliveryClaimLease() time.Duration {
	if p == nil || p.claimLease <= 0 || p.claimLease > maximumDeliveryClaimLease {
		return DeliveryClaimLease
	}
	return p.claimLease
}

func (p *DeliveryProcessor) deliveryNow() time.Time {
	if p == nil || p.now == nil {
		return time.Now()
	}
	return p.now()
}

func validDeliveryClaim(d deliveryJournalDocument) bool {
	empty := d.ClaimOwner == "" && d.ClaimEpoch == 0 && d.ClaimedAt == 0 && d.ClaimExpiresAt == 0
	if empty {
		return true
	}
	return d.ClaimOwner != "" && d.ClaimEpoch > 0 && d.ClaimedAt >= 0 && d.ClaimExpiresAt > d.ClaimedAt && d.ClaimExpiresAt-d.ClaimedAt <= maximumDeliveryClaimLease.Nanoseconds()
}

func (d deliveryJournalDocument) claimIsStale(epoch int64, now int64) bool {
	return d.ClaimOwner == "" || d.ClaimEpoch < epoch || d.ClaimExpiresAt <= now
}

func (p *DeliveryProcessor) claim(ctx context.Context, key string, wanted deliveryJournalDocument, authority AuthoritySnapshot) (deliveryClaimResult, error) {
	if authority.Epoch <= 0 || p.claimID == "" {
		return deliveryClaimResult{}, ErrDeliveryFenced
	}
	lease := p.deliveryClaimLease()
	for i := 0; i < 8; i++ {
		cur, err := p.Ledger.Get(ctx, key)
		if err != nil {
			return deliveryClaimResult{}, err
		}
		if cur == nil {
			return deliveryClaimResult{}, ErrDeliveryConflict
		}
		doc, err := decodeDeliveryJournal(cur.Value)
		if err != nil {
			return deliveryClaimResult{}, err
		}
		if !doc.matches(&wanted.Envelope) || doc.Digest != wanted.Digest {
			return deliveryClaimResult{}, ErrDeliveryConflict
		}
		if doc.State == "accepted" {
			return deliveryClaimResult{Reservation: deliveryReservation{Revision: cur.Revision, State: doc.State, Digest: doc.Digest}, Claimed: false}, nil
		}
		now := p.deliveryNow().UnixNano()
		if doc.ClaimOwner != "" && doc.ClaimedAt > now+maximumDeliveryClaimLease.Nanoseconds() {
			return deliveryClaimResult{}, ErrDeliveryFenced
		}
		if doc.ClaimOwner != "" && doc.ClaimEpoch > authority.Epoch {
			return deliveryClaimResult{}, ErrDeliveryFenced
		}
		if !doc.claimIsStale(authority.Epoch, now) {
			if doc.ClaimOwner == p.claimID && doc.ClaimEpoch == authority.Epoch {
				return deliveryClaimResult{Reservation: deliveryReservation{Revision: cur.Revision, State: doc.State, Digest: doc.Digest, ClaimOwner: doc.ClaimOwner, ClaimEpoch: doc.ClaimEpoch, ClaimedAt: doc.ClaimedAt, ClaimExpiresAt: doc.ClaimExpiresAt}, Claimed: true}, nil
			}
			return deliveryClaimResult{Reservation: deliveryReservation{Revision: cur.Revision, State: doc.State, Digest: doc.Digest}, Claimed: false}, nil
		}
		doc.ClaimOwner = p.claimID
		doc.ClaimEpoch = authority.Epoch
		doc.ClaimedAt = now
		doc.ClaimExpiresAt = time.Unix(0, now).Add(lease).UnixNano()
		b, err := json.Marshal(doc)
		if err != nil {
			return deliveryClaimResult{}, err
		}
		if len(b) > MaximumDeliveryPlanBytes {
			return deliveryClaimResult{}, errors.New("delivery journal record exceeds bound")
		}
		updated, err := p.Ledger.Update(ctx, key, b, cur.Revision)
		if err == nil {
			return deliveryClaimResult{Reservation: deliveryReservation{Revision: updated.Revision, State: doc.State, Digest: doc.Digest, ClaimOwner: doc.ClaimOwner, ClaimEpoch: doc.ClaimEpoch, ClaimedAt: doc.ClaimedAt, ClaimExpiresAt: doc.ClaimExpiresAt}, Claimed: true}, nil
		}
		if !errors.Is(err, ErrLedgerConflict) {
			return deliveryClaimResult{}, err
		}
	}
	return deliveryClaimResult{}, errors.New("delivery claim conflicts exceeded")
}

func (p *DeliveryProcessor) renewClaim(ctx context.Context, key string, claim deliveryReservation, authority AuthoritySnapshot) (deliveryReservation, error) {
	cur, err := p.Ledger.Get(ctx, key)
	if err != nil {
		return deliveryReservation{}, err
	}
	if cur == nil {
		return deliveryReservation{}, ErrDeliveryClaimed
	}
	doc, err := decodeDeliveryJournal(cur.Value)
	if err != nil {
		return deliveryReservation{}, err
	}
	if doc.State == "accepted" || doc.ClaimOwner != claim.ClaimOwner || doc.ClaimEpoch != claim.ClaimEpoch || doc.ClaimEpoch != authority.Epoch {
		return deliveryReservation{}, ErrDeliveryClaimed
	}
	now := p.deliveryNow().UnixNano()
	if doc.ClaimExpiresAt <= now {
		return deliveryReservation{}, ErrDeliveryClaimed
	}
	doc.ClaimExpiresAt = time.Unix(0, now).Add(p.deliveryClaimLease()).UnixNano()
	b, err := json.Marshal(doc)
	if err != nil {
		return deliveryReservation{}, err
	}
	updated, err := p.Ledger.Update(ctx, key, b, cur.Revision)
	if err != nil {
		if errors.Is(err, ErrLedgerConflict) {
			return deliveryReservation{}, ErrDeliveryClaimed
		}
		return deliveryReservation{}, err
	}
	claim.Revision = updated.Revision
	claim.ClaimExpiresAt = doc.ClaimExpiresAt
	return claim, nil
}

func (p *DeliveryProcessor) invokeHandoff(ctx context.Context, key string, claim deliveryReservation, authority AuthoritySnapshot, plan *DeliveryPlan) error {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	lost := make(chan error, 1)
	stop := make(chan struct{})
	var heartbeat sync.WaitGroup
	heartbeat.Add(1)
	go func() {
		defer heartbeat.Done()
		interval := p.deliveryClaimLease() / 3
		if interval <= 0 {
			interval = time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-callCtx.Done():
				return
			case <-ticker.C:
				if err := ensureAuthority(p.Authority, authority); err != nil {
					select {
					case lost <- err:
					default:
					}
					cancel()
					return
				}
				var err error
				claim, err = p.renewClaim(callCtx, key, claim, authority)
				if err != nil {
					select {
					case lost <- err:
					default:
					}
					cancel()
					return
				}
			}
		}
	}()
	err := p.Handoff.Handoff(callCtx, plan)
	close(stop)
	heartbeat.Wait()
	select {
	case lostErr := <-lost:
		if err == nil || errors.Is(err, context.Canceled) {
			return lostErr
		}
	default:
	}
	return err
}

func (p *DeliveryProcessor) releaseClaim(ctx context.Context, key string, claim deliveryReservation) error {
	for i := 0; i < 8; i++ {
		cur, err := p.Ledger.Get(ctx, key)
		if err != nil {
			return err
		}
		if cur == nil {
			return nil
		}
		doc, err := decodeDeliveryJournal(cur.Value)
		if err != nil {
			return err
		}
		if doc.State == "accepted" || doc.ClaimOwner != claim.ClaimOwner || doc.ClaimEpoch != claim.ClaimEpoch {
			return nil
		}
		doc.ClaimOwner, doc.ClaimEpoch, doc.ClaimedAt, doc.ClaimExpiresAt = "", 0, 0, 0
		b, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		if _, err = p.Ledger.Update(ctx, key, b, cur.Revision); err == nil {
			return nil
		} else if !errors.Is(err, ErrLedgerConflict) {
			return err
		}
	}
	return errors.New("delivery claim release conflicts exceeded")
}

func (p *DeliveryProcessor) reserve(ctx context.Context, key string, wanted deliveryJournalDocument) (deliveryReservation, error) {
	b, err := json.Marshal(wanted)
	if err != nil {
		return deliveryReservation{}, err
	}
	if len(b) > MaximumDeliveryPlanBytes {
		return deliveryReservation{}, errors.New("delivery journal record exceeds bound")
	}
	for i := 0; i < 8; i++ {
		cur, err := p.Ledger.Get(ctx, key)
		if err != nil {
			return deliveryReservation{}, err
		}
		if cur == nil {
			created, err := p.Ledger.Create(ctx, key, b)
			if err == nil {
				return deliveryReservation{Revision: created.Revision, State: wanted.State, Digest: wanted.Digest}, nil
			}
			if errors.Is(err, ErrLedgerConflict) {
				continue
			}
			return deliveryReservation{}, err
		}
		doc, err := decodeDeliveryJournal(cur.Value)
		if err != nil {
			return deliveryReservation{}, err
		}
		if !doc.matches(&wanted.Envelope) {
			return deliveryReservation{}, ErrDeliveryConflict
		}
		if doc.State == "accepted" {
			return deliveryReservation{Revision: cur.Revision, State: doc.State, Digest: doc.Digest}, nil
		}
		if doc.Digest != "" && doc.Digest != wanted.Digest {
			return deliveryReservation{}, ErrDeliveryConflict
		}
		if doc.AuthorityEpoch == wanted.AuthorityEpoch && doc.Digest == wanted.Digest {
			return deliveryReservation{Revision: cur.Revision, State: doc.State, Digest: doc.Digest}, nil
		}
		updated, err := p.Ledger.Update(ctx, key, b, cur.Revision)
		if err == nil {
			return deliveryReservation{Revision: updated.Revision, State: wanted.State, Digest: wanted.Digest}, nil
		}
		if !errors.Is(err, ErrLedgerConflict) {
			return deliveryReservation{}, err
		}
	}
	return deliveryReservation{}, errors.New("delivery journal conflicts exceeded")
}

func (p *DeliveryProcessor) accept(ctx context.Context, key string, r deliveryReservation, pending deliveryJournalDocument, digest string) error {
	pending.State = "accepted"
	pending.Digest = digest
	pending.ClaimOwner = r.ClaimOwner
	pending.ClaimEpoch = r.ClaimEpoch
	pending.ClaimedAt = r.ClaimedAt
	pending.ClaimExpiresAt = r.ClaimExpiresAt
	b, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	if len(b) > MaximumDeliveryPlanBytes {
		return errors.New("delivery journal record exceeds bound")
	}
	for i := 0; i < 8; i++ {
		if _, err := p.Ledger.Update(ctx, key, b, r.Revision); err == nil {
			return nil
		} else if !errors.Is(err, ErrLedgerConflict) {
			return err
		}
		cur, getErr := p.Ledger.Get(ctx, key)
		if getErr != nil {
			return getErr
		}
		if cur == nil {
			return ErrDeliveryConflict
		}
		doc, decodeErr := decodeDeliveryJournal(cur.Value)
		if decodeErr != nil {
			return decodeErr
		}
		if !doc.matches(&pending.Envelope) || doc.Digest != digest {
			return ErrDeliveryConflict
		}
		if doc.State == "accepted" {
			return nil
		}
		if r.ClaimOwner != "" && (doc.ClaimOwner != r.ClaimOwner || doc.ClaimEpoch != r.ClaimEpoch) {
			return ErrDeliveryClaimed
		}
		r.Revision = cur.Revision
		r.ClaimedAt = doc.ClaimedAt
		r.ClaimExpiresAt = doc.ClaimExpiresAt
	}
	return errors.New("delivery journal commit conflicts exceeded")
}

func ensureAuthority(authority func() AuthoritySnapshot, expected AuthoritySnapshot) error {
	if authority == nil {
		return ErrDeliveryFenced
	}
	actual := authority()
	if !actual.Ready || !actual.Leader || actual.Epoch != expected.Epoch {
		return ErrDeliveryFenced
	}
	return nil
}

func deliveryBranch(e *WebhookEnvelope) (string, bool, bool) {
	if e.Kind == WebhookPush && e.SourceRef == "refs/heads/develop" && !e.IsDeletion {
		return "develop", true, true
	}
	if e.Kind == WebhookPullRequest && (e.TargetRef == "develop" || e.TargetRef == "main") {
		return e.TargetRef, false, true
	}
	return "", false, false
}

func deliveryAction(kind JobKind) string {
	if kind == JobTrustedBuild {
		return "trusted-build"
	}
	return "product-validation"
}

func validateSnapshot(graph *RepositorySourceGraph, event *WebhookEnvelope, snapshot SourceSnapshot) error {
	if graph == nil || len(snapshot.Sources) == 0 || len(snapshot.Sources) != len(graph.Sources) || len(snapshot.Files) != len(graph.Sources) {
		return errors.New("source graph snapshot is incomplete")
	}
	seen := map[string]struct{}{}
	for _, observation := range snapshot.Observations {
		if !observation.Protected || observation.Branch != "develop" && observation.Branch != "main" || !ValidRepository(observation.Revision.Repository) || graph.Sources[observation.Revision.Repository] == nil || !objectID(observation.Revision.Commit) || allZero(observation.Revision.Commit) || !objectID(observation.Revision.Tree) || allZero(observation.Revision.Tree) {
			return errors.New("source graph observation is unsafe")
		}
	}
	for i, rev := range snapshot.Sources {
		if !ValidRepository(rev.Repository) || graph.Sources[rev.Repository] == nil || !objectID(rev.Commit) || allZero(rev.Commit) || !objectID(rev.Tree) || allZero(rev.Tree) {
			return errors.New("source graph revision is invalid")
		}
		if _, ok := seen[rev.Repository]; ok {
			return errors.New("source graph revision is duplicated")
		}
		seen[rev.Repository] = struct{}{}
		file := snapshot.Files[i]
		if file.Repository != rev.Repository || !strings.EqualFold(file.Commit, rev.Commit) || file.Path != CIDescriptorPath || !objectID(file.Blob) || allZero(file.Blob) || len(file.Content) > MaximumSourceFileBytes || file.ContentSHA256 != contentDigest(file.Content) {
			return errors.New("source descriptor metadata is invalid")
		}
		repository, deps, err := parseDescriptor(file.Content)
		if err != nil || repository != rev.Repository {
			return errors.New("source descriptor identity is invalid")
		}
		for _, dep := range deps {
			if graph.Sources[dep] == nil || dep == rev.Repository {
				return errors.New("source descriptor dependency is outside graph")
			}
		}
	}
	root, ok := sourceForRepository(snapshot.Sources, graph.Root)
	if !ok || event.Repository != graph.Root {
		return errors.New("source graph root is missing")
	}
	if (event.Kind == WebhookPush || event.Kind == WebhookPullRequest) && !strings.EqualFold(root.Commit, event.Revision) {
		return errors.New("source graph root does not match event")
	}
	return nil
}

func descriptors(snapshot SourceSnapshot) []SourceDescriptor {
	out := make([]SourceDescriptor, 0, len(snapshot.Files))
	for _, f := range snapshot.Files {
		_, deps, _ := parseDescriptor(f.Content)
		out = append(out, SourceDescriptor{Repository: f.Repository, Commit: f.Commit, Blob: f.Blob, ContentSHA256: f.ContentSHA256, Dependencies: append([]string(nil), deps...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repository < out[j].Repository })
	return out
}

func sourceForRepository(revisions []ResolvedRevision, repository string) (ResolvedRevision, bool) {
	for _, rev := range revisions {
		if rev.Repository == repository {
			return rev, true
		}
	}
	return ResolvedRevision{}, false
}

func validateArchive(revision ResolvedRevision, archive SourceArchive) error {
	if archive.Revision.Repository != revision.Repository || !strings.EqualFold(archive.Revision.Commit, revision.Commit) || !strings.EqualFold(archive.Revision.Tree, revision.Tree) || len(archive.Content) == 0 || len(archive.Content) > MaximumSourceArchiveBytes || archive.ContentSHA256 != contentDigest(archive.Content) {
		return errors.New("source archive metadata is invalid")
	}
	return nil
}

func contentDigest(content []byte) string {
	d := sha256.Sum256(content)
	return hex.EncodeToString(d[:])
}

func digestPlan(plan DeliveryPlan) string {
	type digestInput struct {
		SchemaVersion int
		Idempotency   string
		Trigger       TriggerPlan
		Sources       []ResolvedRevision
		Job           JobRequest
		Files         []SourceDescriptor
		Archives      []ArchiveDescriptor
		Intent        ReconciliationIntent
	}
	trigger := *cloneTrigger(&plan.Trigger)
	intent := plan.Intent
	// The authority epoch fences the external mutation, but does not change
	// the event's deterministic plan identity. A pending plan can therefore be
	// resumed safely by the next leader.
	intent.AuthorityEpoch = 0
	input := digestInput{SchemaVersion: plan.SchemaVersion, Idempotency: plan.Idempotency, Trigger: trigger, Sources: append([]ResolvedRevision(nil), plan.Snapshot.Sources...), Job: plan.Job, Files: append([]SourceDescriptor(nil), plan.Descriptors...), Archives: append([]ArchiveDescriptor(nil), plan.ArchiveRecords...), Intent: intent}
	b, err := json.Marshal(input)
	if err != nil || len(b) > MaximumDeliveryPlanBytes {
		return ""
	}
	return contentDigest(b)
}

func cloneTrigger(in *TriggerPlan) *TriggerPlan {
	if in == nil {
		return nil
	}
	out := *in
	if in.Envelope != nil {
		e := *in.Envelope
		out.Envelope = &e
	}
	out.Capabilities = append([]RunnerCapability(nil), in.Capabilities...)
	return &out
}

func cloneSnapshot(in SourceSnapshot) SourceSnapshot {
	out := SourceSnapshot{Sources: append([]ResolvedRevision(nil), in.Sources...), Observations: append([]BranchObservation(nil), in.Observations...)}
	for _, f := range in.Files {
		f.Content = append([]byte(nil), f.Content...)
		out.Files = append(out.Files, f)
	}
	return out
}

func cloneArchive(in SourceArchive) SourceArchive {
	in.Content = append([]byte(nil), in.Content...)
	return in
}
