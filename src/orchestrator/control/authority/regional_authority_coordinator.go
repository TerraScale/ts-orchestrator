package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

type RegionalAuthoritySnapshot struct {
	State          string
	IsLeader       bool
	Epoch          int64
	KvRevision     int64
	LeaseExpiresAt *time.Time
	ObservedAt     time.Time
	Error          *string
}

func (s RegionalAuthoritySnapshot) Ready() bool {
	if s.State != "leader" && s.State != "follower" {
		return false
	}

	if s.Error != nil {
		return false
	}

	if s.ObservedAt.Before(time.Now().UTC().Add(-30 * time.Second)) {
		return false
	}

	return s.LeaseExpiresAt != nil && s.LeaseExpiresAt.After(time.Now().UTC())
}

// Equal compares the snapshot field by field.
func (s RegionalAuthoritySnapshot) Equal(other RegionalAuthoritySnapshot) bool {
	return s.State == other.State &&
		s.IsLeader == other.IsLeader &&
		s.Epoch == other.Epoch &&
		s.KvRevision == other.KvRevision &&
		optionalTimeEqual(s.LeaseExpiresAt, other.LeaseExpiresAt) &&
		s.ObservedAt.Equal(other.ObservedAt) &&
		optionalStringEqual(s.Error, other.Error)
}

func optionalTimeEqual(first, second *time.Time) bool {
	if first == nil || second == nil {
		return first == second
	}

	return first.Equal(*second)
}

func optionalStringEqual(first, second *string) bool {
	if first == nil || second == nil {
		return first == second
	}

	return *first == *second
}

// RegionalAuthorityLeaseDocument is the KV lease record. JSON tags serialize
// PascalCase names.
type RegionalAuthorityLeaseDocument struct {
	SchemaVersion        int       `json:"SchemaVersion"`
	AuthorityId          string    `json:"AuthorityId"`
	Epoch                int64     `json:"Epoch"`
	CandidateId          string    `json:"CandidateId"`
	LeaseId              string    `json:"LeaseId"`
	IssuedAt             time.Time `json:"IssuedAt"`
	DurationMilliseconds int64     `json:"DurationMilliseconds"`
}

func RegionalAuthorityLeaseDocumentFrom(
	authorityId string,
	epoch int64,
	lease AuthorityLease,
) RegionalAuthorityLeaseDocument {
	return RegionalAuthorityLeaseDocument{
		SchemaVersion:        1,
		AuthorityId:          authorityId,
		Epoch:                epoch,
		CandidateId:          lease.CandidateId,
		LeaseId:              lease.LeaseId,
		IssuedAt:             lease.ServerIssuedAt,
		DurationMilliseconds: lease.Duration.Milliseconds(),
	}
}

func (d RegionalAuthorityLeaseDocument) ToLease() (AuthorityLease, error) {
	if err := d.Validate(); err != nil {
		return AuthorityLease{}, err
	}

	return AuthorityLease{
		CandidateId:    d.CandidateId,
		LeaseId:        d.LeaseId,
		ServerIssuedAt: d.IssuedAt,
		Duration:       time.Duration(d.DurationMilliseconds) * time.Millisecond,
	}, nil
}

func (d RegionalAuthorityLeaseDocument) Validate() error {
	if d.SchemaVersion != 1 || d.AuthorityId == "" || d.Epoch <= 0 ||
		d.CandidateId == "" || d.LeaseId == "" ||
		d.DurationMilliseconds < 1 || d.DurationMilliseconds > 60000 ||
		d.IssuedAt.IsZero() || d.IssuedAt.After(time.Now().UTC().Add(time.Minute)) {
		return errors.New("The regional authority lease document is invalid.")
	}

	return nil
}

// RegionalAuthorityCoordinator is the KV-backed authority lease loop that
// publishes the RegionalAuthoritySnapshot.
type RegionalAuthorityCoordinator struct {
	leaseDuration time.Duration
	tickInterval  time.Duration

	store                     jetstream.KeyValue
	authorityId               string
	candidateId               string
	leaseKey                  string
	tolerateTransientFailures bool

	stateMu           sync.Mutex
	journalState      *AuthorityState
	confirmedLeaseAge time.Time
	snapshot          RegionalAuthoritySnapshot

	stoppingCtx context.Context
	stopping    context.CancelFunc
	loopDone    chan struct{}
	disposeOnce sync.Once
}

var regionalAuthoritySnapshotInitial = RegionalAuthoritySnapshot{
	State:      "follower",
	IsLeader:   false,
	Epoch:      0,
	KvRevision: 0,
	ObservedAt: time.Time{},
	Error:      func() *string { value := "authority-not-observed"; return &value }(),
}

// RegionalAuthorityCoordinatorStartAsync starts the regional authority lease
// loop for one cell's controller.
func RegionalAuthorityCoordinatorStartAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	cell string,
	instance string,
) (*RegionalAuthorityCoordinator, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if store == nil {
		return nil, errors.New("(Parameter 'store')")
	}
	if !shared.MessagingCellTokenIsValid(cell) || !shared.MessagingCellTokenIsValid(instance) {
		return nil, errors.New("The regional authority identity is invalid.")
	}
	coordinator := newRegionalAuthorityCoordinator(
		store, cell+"-regional", cell+"-controller-"+instance, "authority.regional", false)

	if err := coordinator.tick(ctx); err != nil {
		return nil, err
	}

	coordinator.startLoop()
	return coordinator, nil
}

// RegionalAuthorityCoordinatorStartGlobalAsync starts the global authority
// lease loop.
func RegionalAuthorityCoordinatorStartGlobalAsync(
	ctx context.Context,
	store jetstream.KeyValue,
	cell string,
	instance string,
) (*RegionalAuthorityCoordinator, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if store == nil {
		return nil, errors.New("(Parameter 'store')")
	}
	if !messaging.GlobalNatsTopologyIsCellToken(cell) {
		return nil, errors.New("The global authority candidate cell is invalid. (Parameter 'cell')")
	}
	if !shared.MessagingCellTokenIsValid(instance) {
		return nil, errors.New("The global authority candidate instance is invalid. (Parameter 'instance')")
	}

	coordinator := newRegionalAuthorityCoordinator(
		store, "global", "global-controller-"+cell+"-"+instance, "authority.global", true)

	if err := coordinator.tick(ctx); err != nil {
		return nil, err
	}

	coordinator.startLoop()
	return coordinator, nil
}

func newRegionalAuthorityCoordinator(
	store jetstream.KeyValue,
	authorityId string,
	candidateId string,
	leaseKey string,
	tolerateTransientFailures bool,
) *RegionalAuthorityCoordinator {
	stoppingCtx, stopping := context.WithCancel(context.Background())
	return &RegionalAuthorityCoordinator{
		leaseDuration:             15 * time.Second,
		tickInterval:              3 * time.Second,
		store:                     store,
		authorityId:               authorityId,
		candidateId:               candidateId,
		leaseKey:                  leaseKey,
		tolerateTransientFailures: tolerateTransientFailures,
		journalState:              AuthorityStateEmpty,
		snapshot:                  regionalAuthoritySnapshotInitial,
		stoppingCtx:               stoppingCtx,
		stopping:                  stopping,
		loopDone:                  make(chan struct{}),
	}
}

func (c *RegionalAuthorityCoordinator) startLoop() {
	go func() {
		defer close(c.loopDone)

		ticker := time.NewTicker(c.tickInterval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stoppingCtx.Done():
				return
			case <-ticker.C:
			}

			if err := c.tick(c.stoppingCtx); err != nil &&
				c.tolerateTransientFailures && shared.IsNatsTransientError(err) {
				c.stateMu.Lock()
				confirmed := AuthorityObservation{
					AuthorityId:   c.authorityId,
					ObservationId: "global-nats-unavailable",
				}
				if c.journalState.Confirmed != nil {
					confirmed = *c.journalState.Confirmed
				}

				c.journalState = AuthorityStateEmpty
				c.confirmedLeaseAge = time.Time{}
				c.stateMu.Unlock()
				// Snapshot publication takes stateMu itself. Keep it outside the
				// state transition lock to avoid a self-deadlock on transient NATS
				// failures.
				c.publish("unavailable", false, confirmed, "global-nats-unavailable", time.Now().UTC())
			}
		}
	}()
}

func (c *RegionalAuthorityCoordinator) Snapshot() RegionalAuthoritySnapshot {
	if c == nil {
		return RegionalAuthoritySnapshot{}
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	return c.snapshot
}

func (c *RegionalAuthorityCoordinator) Completion() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.loopDone
}

// Dispose stops the lease loop.
func (c *RegionalAuthorityCoordinator) Dispose() {
	if c == nil {
		return
	}
	c.disposeOnce.Do(func() {
		if c.stopping != nil {
			c.stopping()
		}
		if c.loopDone != nil {
			<-c.loopDone
		}
		c.stoppingCtx = nil
	})
}

func (c *RegionalAuthorityCoordinator) tick(ctx context.Context) error {
	if ctx == nil {
		return errors.New("(Parameter 'ctx')")
	}
	if c == nil || c.store == nil {
		return errors.New("(Parameter 'coordinator')")
	}
	state := c.currentState()

	if state.Status == AuthorityStatusLeader && state.Confirmed != nil {
		return c.renew(ctx, *state.Confirmed)
	}

	if state.Status == AuthorityStatusFenced {
		return errors.New("The regional authority candidate is fenced and must restart.")
	}

	observed, err := c.read(ctx)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if observed.Lease != nil && observed.Lease.ServerIssuedAt.Add(observed.Lease.Duration).After(now) {
		c.publishSnapshot("follower", false, observed, nil, now)
		return nil
	}

	requestId := "acquire-" + shared.RandomNatsNonce()
	health := regionalAuthorityHealth(now, time.Duration(0))
	baseline := observed
	acquisition, err := AuthorityEngine.DecideFromState(c.currentState(), NewAcquireAuthority(
		c.authorityId,
		c.candidateId,
		requestId,
		"lease-"+shared.RandomNatsNonce(),
		&baseline,
		&health,
		c.leaseDuration))
	if err != nil {
		return err
	}

	c.apply(acquisition)

	intent, hasIntent := singleCompareAndSetLeaseIntent(acquisition.Intents)
	if !hasIntent {
		c.publishDecision(acquisition, observed, now)
		return nil
	}

	return c.executeSet(ctx, *intent)
}

func (c *RegionalAuthorityCoordinator) renew(ctx context.Context, current AuthorityObservation) error {
	now := time.Now().UTC()
	requestId := "renew-" + shared.RandomNatsNonce()
	c.stateMu.Lock()
	elapsed := time.Duration(0)
	if !c.confirmedLeaseAge.IsZero() {
		elapsed = time.Since(c.confirmedLeaseAge)
	}

	state := c.currentStateLocked()
	c.stateMu.Unlock()

	renewalHealth := regionalAuthorityHealth(now, elapsed)
	renewalCurrent := current
	renewal, err := AuthorityEngine.DecideFromState(state, NewRenewAuthority(
		c.authorityId,
		c.candidateId,
		requestId,
		&renewalCurrent,
		&renewalHealth,
		c.leaseDuration))
	if err != nil {
		return err
	}

	c.apply(renewal)

	intent, hasIntent := singleCompareAndSetLeaseIntent(renewal.Intents)
	if !hasIntent {
		c.publishDecision(renewal, current, now)
		return nil
	}

	return c.executeSet(ctx, *intent)
}

func (c *RegionalAuthorityCoordinator) executeSet(ctx context.Context, intent CompareAndSetLeaseIntent) error {
	document := RegionalAuthorityLeaseDocumentFrom(c.authorityId, intent.ProposedEpoch, intent.ProposedLease)
	value, err := json.Marshal(document)
	if err != nil {
		return err
	}

	var revision uint64
	if intent.ExpectedRevision == 0 {
		revision, err = c.store.Create(ctx, c.leaseKey, value)
	} else {
		revision, err = c.store.Update(ctx, c.leaseKey, value, uint64(intent.ExpectedRevision))
	}

	if err != nil &&
		(errors.Is(err, jetstream.ErrKeyExists) ||
			errors.Is(err, jetstream.ErrKeyRevisionMismatch) ||
			errors.Is(err, jetstream.ErrKeyNotFound)) {
		// A simultaneous create loser may surface as KeyNotFound while the
		// client resolves the failed create response. It is still a normal CAS
		// conflict: re-read the authoritative key and enter the follower path.
		observed, readErr := c.read(ctx)
		if readErr != nil {
			return readErr
		}

		conflictHealth := regionalAuthorityHealth(time.Now().UTC(), time.Duration(0))
		conflictObservation := observed
		result, err := AuthorityEngine.DecideFromState(c.currentState(), NewObserveAuthorityCas(
			c.authorityId,
			c.candidateId,
			intent.RequestId,
			AuthorityCasOutcomeConflict,
			&conflictObservation,
			&conflictHealth))
		if err != nil {
			return err
		}

		c.apply(result)
		// Losing a CAS is the normal follower path. It denies mutation
		// authority but does not make the read-serving controller unhealthy.
		c.publishSnapshot("follower", false, observed, nil, time.Now().UTC())
		return nil
	}

	if err != nil {
		return err
	}

	observed := AuthorityObservation{
		AuthorityId:   c.authorityId,
		KvRevision:    int64(revision),
		Epoch:         intent.ProposedEpoch,
		ObservationId: fmt.Sprintf("kv-%d", revision),
		Lease:         &intent.ProposedLease,
	}

	successHealth := regionalAuthorityHealth(time.Now().UTC(), time.Duration(0))
	successObservation := observed
	result, err := AuthorityEngine.DecideFromState(c.currentState(), NewObserveAuthorityCas(
		c.authorityId,
		c.candidateId,
		intent.RequestId,
		AuthorityCasOutcomeSucceeded,
		&successObservation,
		&successHealth))
	if err != nil {
		return err
	}

	c.apply(result)
	if result.State.Status == AuthorityStatusLeader {
		c.stateMu.Lock()
		c.confirmedLeaseAge = time.Now()
		c.stateMu.Unlock()
	}

	c.publishDecision(result, observed, time.Now().UTC())
	return nil
}

func (c *RegionalAuthorityCoordinator) read(ctx context.Context) (AuthorityObservation, error) {
	entry, err := c.store.Get(ctx, c.leaseKey)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
			return AuthorityObservation{
				AuthorityId:   c.authorityId,
				KvRevision:    0,
				Epoch:         0,
				ObservationId: "kv-absent",
			}, nil
		}

		return AuthorityObservation{}, err
	}

	var document RegionalAuthorityLeaseDocument
	if err := json.Unmarshal(entry.Value(), &document); err != nil {
		return AuthorityObservation{}, errors.New("The regional authority lease is empty.")
	}

	if err := document.Validate(); err != nil {
		return AuthorityObservation{}, err
	}

	if document.AuthorityId != c.authorityId {
		return AuthorityObservation{}, errors.New("The regional authority lease belongs to another cell.")
	}

	lease, err := document.ToLease()
	if err != nil {
		return AuthorityObservation{}, err
	}

	return AuthorityObservation{
		AuthorityId:   c.authorityId,
		KvRevision:    int64(entry.Revision()),
		Epoch:         document.Epoch,
		ObservationId: fmt.Sprintf("kv-%d", entry.Revision()),
		Lease:         &lease,
	}, nil
}

// RegionalAuthorityCoordinatorHealth builds the AuthorityHealth input the
// coordinator feeds the decision engine.
func RegionalAuthorityCoordinatorHealth(now time.Time, confirmedLeaseAge time.Duration) AuthorityHealth {
	return regionalAuthorityHealth(now, confirmedLeaseAge)
}

func regionalAuthorityHealth(now time.Time, confirmedLeaseAge time.Duration) AuthorityHealth {
	return AuthorityHealth{
		ServerTime:       now,
		MonotonicElapsed: confirmedLeaseAge,
		PartitionCertain: true,
		ClockCertain:     true,
	}
}

func (c *RegionalAuthorityCoordinator) currentState() *AuthorityState {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.currentStateLocked()
}

// currentStateLocked returns the current state while stateMu is held by the
// caller. AuthorityState values are immutable after a decision is applied, so
// returning the pointer is safe for the decision engine's read-only use.
func (c *RegionalAuthorityCoordinator) currentStateLocked() *AuthorityState {
	if c.journalState == nil {
		return AuthorityStateEmpty
	}

	return c.journalState
}

func (c *RegionalAuthorityCoordinator) apply(decision *AuthorityDecision) {
	if decision != nil && len(decision.EventsToAppend) != 0 {
		c.stateMu.Lock()
		c.journalState = decision.State
		c.stateMu.Unlock()
	}
}

func (c *RegionalAuthorityCoordinator) publishDecision(
	decision *AuthorityDecision,
	observed AuthorityObservation,
	now time.Time,
) {
	state := AuthorityStateEmpty
	if decision != nil && decision.State != nil {
		state = decision.State
	}
	var errText *string
	if len(decision.Errors) > 0 {
		text := decision.Errors[0].Code.String()
		errText = &text
	}

	statusText := "follower"
	switch state.Status {
	case AuthorityStatusLeader:
		statusText = "leader"
	case AuthorityStatusFenced:
		statusText = "fenced"
	case AuthorityStatusReadOnlyHeld:
		statusText = "held"
	}

	isLeader := state.Status == AuthorityStatusLeader && decision.MutationPermit != nil
	if state.Confirmed != nil {
		c.publishSnapshot(statusText, isLeader, *state.Confirmed, errText, now)
	} else {
		c.publishSnapshot(statusText, isLeader, observed, errText, now)
	}
}

// publishSnapshot updates the externally visible snapshot under its own lock.
// Callers must not hold stateMu.
func (c *RegionalAuthorityCoordinator) publishSnapshot(
	state string,
	isLeader bool,
	observed AuthorityObservation,
	errText *string,
	now time.Time,
) {
	var expiresAt *time.Time
	if observed.Lease != nil {
		expiry := observed.Lease.ServerIssuedAt.Add(observed.Lease.Duration)
		expiresAt = &expiry
	}

	c.stateMu.Lock()
	c.snapshot = RegionalAuthoritySnapshot{
		State:          state,
		IsLeader:       isLeader,
		Epoch:          observed.Epoch,
		KvRevision:     observed.KvRevision,
		LeaseExpiresAt: expiresAt,
		ObservedAt:     now,
		Error:          errText,
	}
	c.stateMu.Unlock()
}

func (c *RegionalAuthorityCoordinator) publish(
	state string,
	isLeader bool,
	observed AuthorityObservation,
	errText string,
	now time.Time,
) {
	var errPointer *string
	if errText != "" {
		errPointer = &errText
	}

	c.publishSnapshot(state, isLeader, observed, errPointer, now)
}

func singleCompareAndSetLeaseIntent(intents []AuthorityIntent) (*CompareAndSetLeaseIntent, bool) {
	if len(intents) != 1 {
		return nil, false
	}

	intent, ok := intents[0].(*CompareAndSetLeaseIntent)
	return intent, ok
}

// RegionalAuthorityCoordinatorForSnapshot returns a coordinator primed with
// one state snapshot and no lease machinery; read-only hosts and tests use it
// to present a known authority state.
func RegionalAuthorityCoordinatorForSnapshot(snapshot RegionalAuthoritySnapshot) *RegionalAuthorityCoordinator {
	return &RegionalAuthorityCoordinator{snapshot: snapshot}
}
