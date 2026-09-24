package authority

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var natsToken = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

const authorityDiagnosticQueueSize = 64

type authorityDiagnostic struct {
	logger  *slog.Logger
	level   slog.Level
	message string
	attrs   []any
	dropped *atomic.Uint64
	barrier chan struct{}
}

var authorityDiagnosticQueue = make(chan authorityDiagnostic, authorityDiagnosticQueueSize)

func init() {
	go runAuthorityDiagnostics()
}

func runAuthorityDiagnostics() {
	for event := range authorityDiagnosticQueue {
		if event.barrier != nil {
			close(event.barrier)
			continue
		}
		if event.logger == nil {
			continue
		}
		if event.dropped != nil {
			if dropped := event.dropped.Swap(0); dropped > 0 {
				event.attrs = append(event.attrs, "dropped_diagnostics", dropped)
			}
		}
		event.logger.Log(context.Background(), event.level, event.message, event.attrs...)
	}
}

func flushAuthorityDiagnostics(ctx context.Context) error {
	barrier := make(chan struct{})
	select {
	case authorityDiagnosticQueue <- authorityDiagnostic{barrier: barrier}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-barrier:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func enqueueAuthorityDiagnostic(queue chan authorityDiagnostic, dropped *atomic.Uint64, event authorityDiagnostic) bool {
	event.dropped = dropped
	select {
	case queue <- event:
		return true
	default:
		if dropped != nil {
			dropped.Add(1)
		}
		return false
	}
}

// Runtime manages the lease for one scope and owns the shared ordered control
// stream. Term changes and host mutations are serialized by the same stream
// sequence, so an old epoch cannot commit a host record after a newer term.
type Runtime struct {
	js          jetstream.JetStream
	publisher   jetstream.Publisher
	stream      jetstream.Stream
	readStream  jetstream.Stream
	config      Config
	leaseSub    string
	ownerID     string
	logger      *slog.Logger
	diagnostics chan authorityDiagnostic

	mu                     sync.Mutex
	readMu                 sync.Mutex
	stateMu                sync.Mutex
	diagMu                 sync.Mutex
	diagTimes              map[string]time.Time
	snapshot               atomic.Pointer[Snapshot]
	lastDiagnosticSnapshot *Snapshot
	droppedDiagnostics     atomic.Uint64
	cancel                 context.CancelFunc
	done                   chan struct{}
	once                   sync.Once
}

type leaseRecord struct {
	Version       int    `json:"version"`
	Scope         string `json:"scope"`
	CandidateID   string `json:"candidate_id"`
	OwnerID       string `json:"owner_id"`
	Epoch         uint64 `json:"epoch"`
	LeaseDuration int64  `json:"lease_duration_ns"`
	TransitionID  string `json:"transition_id"`
	Released      bool   `json:"released"`
}

// Start creates or validates the durable R3 control log, observes or acquires
// the current lease, and starts periodic renewal. A valid follower is returned
// successfully with Ready=true and Leader=false.
func Start(ctx context.Context, js jetstream.JetStream, config Config) (*Runtime, error) {
	if js == nil {
		return nil, errors.New("JetStream is required")
	}
	config = config.withDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	stream, err := openControlStream(ctx, js, config.Replicas)
	if err != nil {
		return nil, fmt.Errorf("open authority control log: %w", err)
	}
	readStream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		return nil, fmt.Errorf("open authority read handle: %w", err)
	}
	readInfo, err := readStream.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect authority read handle: %w", err)
	}
	if err := verifyControlStreamConfig(readInfo.Config, config.Replicas); err != nil {
		return nil, fmt.Errorf("validate authority read handle: %w", err)
	}
	loopCtx, cancel := context.WithCancel(ctx)
	runtime := &Runtime{
		js:          js,
		publisher:   js,
		stream:      stream,
		readStream:  readStream,
		config:      config,
		leaseSub:    fmt.Sprintf("%s.%s.lease", controlSubjectRoot, config.Scope),
		ownerID:     uuid.New().String(),
		logger:      logger,
		diagnostics: authorityDiagnosticQueue,
		diagTimes:   make(map[string]time.Time),
		cancel:      cancel,
		done:        make(chan struct{}),
	}
	runtime.publishSnapshot(Snapshot{Scope: config.Scope, CandidateID: config.CandidateID, OwnerID: runtime.ownerID, Reason: "not-observed"})
	runtime.logSnapshotTransition()
	var observeErr error
	for range 8 {
		observeErr = runtime.reconcileWithRetry(loopCtx)
		runtime.logSnapshotTransition()
		if !errors.Is(observeErr, ErrConflict) {
			break
		}
		select {
		case <-loopCtx.Done():
			observeErr = loopCtx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if observeErr != nil {
		cancel()
		close(runtime.done)
		return nil, fmt.Errorf("observe authority lease: %w", observeErr)
	}
	go runtime.run(loopCtx)
	return runtime, nil
}

func (c Config) validate() error {
	if !natsToken.MatchString(c.Scope) {
		return errors.New("authority scope must be a lowercase NATS token")
	}
	if !natsToken.MatchString(c.CandidateID) {
		return errors.New("authority candidate ID must be a lowercase NATS token")
	}
	if c.LeaseDuration == 0 {
		c.LeaseDuration = defaultLeaseDuration
	}
	if c.RenewInterval == 0 {
		c.RenewInterval = defaultRenewInterval
	}
	if c.Replicas == 0 {
		c.Replicas = defaultReplicas
	}
	if c.LeaseDuration < time.Second || c.LeaseDuration > 5*time.Minute {
		return errors.New("authority lease duration must be between one second and five minutes")
	}
	if c.RenewInterval < 10*time.Millisecond || c.RenewInterval >= c.LeaseDuration/2 {
		return errors.New("authority renew interval must be positive and less than half the lease duration")
	}
	if c.Replicas != 1 && c.Replicas != 3 && c.Replicas != 5 {
		return errors.New("authority replicas must be 1, 3, or 5")
	}
	return nil
}

func (r *Runtime) run(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.config.RenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := r.reconcileWithRetry(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				r.recordFailure(err)
				if !errors.Is(err, ErrConflict) {
					r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Reason: "control-log-unavailable"})
				}
			}
			r.logSnapshotTransition()
		}
	}
}

func (r *Runtime) reconcileWithRetry(ctx context.Context) error {
	var lastErr error
	for range 8 {
		err := r.reconcile(ctx)
		if !errors.Is(err, ErrConflict) {
			return err
		}
		lastErr = err
	}
	if lastErr != nil {
		return lastErr
	}
	return ErrConflict
}

func (r *Runtime) reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, err := r.stream.Info(ctx)
	if err != nil {
		return stageFailure("stream_info", err)
	}
	if err := verifyControlStreamConfig(info.Config, r.config.Replicas); err != nil {
		return stageFailure("stream_config", err)
	}
	entry, err := r.stream.GetLastMsgForSubject(ctx, r.leaseSub)
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return r.acquire(ctx, info.State.LastSeq, 0, 1)
	}
	if err != nil {
		return stageFailure("lease_msg_get", err)
	}
	if entry.Sequence > info.State.LastSeq {
		return stageFailure("lease_sequence_check", ErrConflict)
	}
	lease, err := decodeLease(entry.Data)
	if err != nil || lease.Scope != r.config.Scope || lease.Epoch == 0 {
		r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Revision: entry.Sequence, ObservedAt: time.Now(), Reason: "lease-corrupt"})
		return nil
	}
	expiresAt := entry.Time.Add(time.Duration(lease.LeaseDuration))
	now := time.Now()
	current := r.Current()
	if !lease.Released && now.Before(expiresAt) {
		if lease.CandidateID != r.config.CandidateID || lease.OwnerID != r.ownerID {
			r.publishSnapshot(Snapshot{
				Scope: r.config.Scope, CandidateID: lease.CandidateID, OwnerID: lease.OwnerID, Ready: true,
				Epoch: lease.Epoch, Revision: entry.Sequence, ExpiresAt: expiresAt,
				ObservedAt: now, Reason: "follower",
			})
			return nil
		}
		if current.Epoch != lease.Epoch || !current.Leader {
			return r.appendLease(ctx, info.State.LastSeq, entry.Sequence, lease.Epoch, false)
		}
		return r.appendLease(ctx, info.State.LastSeq, entry.Sequence, lease.Epoch, false)
	}
	if lease.CandidateID == r.config.CandidateID && lease.OwnerID == r.ownerID && current.Leader && current.Epoch == lease.Epoch {
		r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Revision: entry.Sequence, ObservedAt: now, Reason: "lease-expired"})
	}
	return r.acquire(ctx, info.State.LastSeq, entry.Sequence, lease.Epoch+1)
}

func (r *Runtime) acquire(ctx context.Context, lastSequence, leaseSequence, epoch uint64) error {
	return r.appendLease(ctx, lastSequence, leaseSequence, epoch, false)
}

func (r *Runtime) appendLease(ctx context.Context, lastSequence, leaseSequence, epoch uint64, released bool) error {
	if epoch == 0 {
		return ErrFenced
	}
	lease := leaseRecord{
		Version: 1, Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID,
		Epoch: epoch, LeaseDuration: int64(r.config.LeaseDuration), TransitionID: uuid.New().String(), Released: released,
	}
	data, err := jsonMarshal(lease)
	if err != nil {
		return stageFailure("lease_encode", err)
	}
	msg := controlMessage(r.leaseSub, "lease", lease.TransitionID, data)
	ack, err := r.publisher.PublishMsg(ctx, msg,
		jetstream.WithExpectLastSequence(lastSequence),
		jetstream.WithExpectLastSequenceForSubject(leaseSequence, r.leaseSub),
	)
	if err != nil {
		if isSequenceConflict(err) {
			return stageFailure("lease_publish", ErrConflict)
		}
		return stageFailure("lease_publish", r.resolveLeaseAppend(ctx, lease, err))
	}
	stored, err := r.stream.GetLastMsgForSubject(ctx, r.leaseSub)
	if err != nil {
		return stageFailure("lease_confirm_get", r.resolveLeaseAppend(ctx, lease, err))
	}
	if stored.Sequence != ack.Sequence {
		return stageFailure("lease_confirm_sequence", ErrConflict)
	}
	confirmed, err := decodeLease(stored.Data)
	if err != nil || confirmed.Scope != r.config.Scope || confirmed.CandidateID != r.config.CandidateID || confirmed.OwnerID != r.ownerID || confirmed.Epoch != epoch || confirmed.TransitionID != lease.TransitionID || confirmed.Released != released {
		return stageFailure("lease_confirm_record", ErrFenced)
	}
	if released {
		r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Epoch: epoch, Revision: ack.Sequence, ObservedAt: time.Now(), Reason: "released"})
		return nil
	}
	now := time.Now()
	expiresAt := stored.Time.Add(time.Duration(confirmed.LeaseDuration))
	if !now.Before(expiresAt) {
		return stageFailure("lease_confirm_expiry", ErrFenced)
	}
	r.publishSnapshot(Snapshot{
		Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Leader: true, Ready: true,
		Epoch: epoch, Revision: ack.Sequence, ExpiresAt: expiresAt, ObservedAt: now, Reason: "leader",
	})
	return nil
}

func (r *Runtime) resolveLeaseAppend(ctx context.Context, attempted leaseRecord, original error) error {
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	entry, err := r.stream.GetLastMsgForSubject(probeCtx, r.leaseSub)
	if err == nil {
		lease, decodeErr := decodeLease(entry.Data)
		if decodeErr == nil && lease.TransitionID == attempted.TransitionID && lease.Scope == attempted.Scope &&
			lease.CandidateID == attempted.CandidateID && lease.OwnerID == attempted.OwnerID &&
			lease.Epoch == attempted.Epoch && lease.Released == attempted.Released {
			now := time.Now()
			if attempted.Released {
				r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Epoch: attempted.Epoch, Revision: entry.Sequence, ObservedAt: now, Reason: "released"})
				return nil
			}
			expiresAt := entry.Time.Add(time.Duration(lease.LeaseDuration))
			if now.Before(expiresAt) {
				r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Leader: true, Ready: true, Epoch: lease.Epoch, Revision: entry.Sequence, ExpiresAt: expiresAt, ObservedAt: now, Reason: "leader"})
				return nil
			}
			return ErrFenced
		}
		if decodeErr == nil && (lease.Epoch > attempted.Epoch || lease.OwnerID != attempted.OwnerID) {
			return ErrFenced
		}
	}
	return stageFailure("lease_outcome_probe", fmt.Errorf("%w: %w", ErrOutcomeUnknown, original))
}

// Current returns the most recently confirmed local authority observation.
func (r *Runtime) Current() Snapshot {
	if r == nil {
		return Snapshot{Reason: "unavailable"}
	}
	if snapshot := r.snapshot.Load(); snapshot != nil {
		return *snapshot
	}
	return Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Reason: "not-observed"}
}

func (r *Runtime) publishSnapshot(snapshot Snapshot) {
	r.snapshot.Store(&snapshot)
}

func (r *Runtime) logSnapshotTransition() {
	if r == nil || r.logger == nil {
		return
	}
	r.stateMu.Lock()
	current := r.Current()
	previous := r.lastDiagnosticSnapshot
	if previous != nil && sameDiagnosticState(*previous, current) {
		r.stateMu.Unlock()
		return
	}
	r.lastDiagnosticSnapshot = &current
	var previousReady, previousLeader bool
	var previousEpoch uint64
	var previousReason string
	if previous != nil {
		previousReady = previous.Ready
		previousLeader = previous.Leader
		previousEpoch = previous.Epoch
		previousReason = previous.Reason
	}
	r.stateMu.Unlock()
	r.emitDiagnostic(slog.LevelInfo, "authority state transition",
		"scope", current.Scope,
		"from_ready", previousReady,
		"from_leader", previousLeader,
		"from_epoch", previousEpoch,
		"from_reason", previousReason,
		"ready", current.Ready,
		"leader", current.Leader,
		"epoch", current.Epoch,
		"reason", current.Reason,
	)
}

func (r *Runtime) emitDiagnostic(level slog.Level, message string, attrs ...any) {
	if r == nil || r.logger == nil {
		return
	}
	queue := r.diagnostics
	if queue == nil {
		queue = authorityDiagnosticQueue
	}
	enqueueAuthorityDiagnostic(queue, &r.droppedDiagnostics, authorityDiagnostic{
		logger: r.logger, level: level, message: message, attrs: attrs,
	})
}

func sameDiagnosticState(left, right Snapshot) bool {
	return left.Ready == right.Ready && left.Leader == right.Leader && left.Epoch == right.Epoch && left.Reason == right.Reason
}

type authorityStageFailure struct {
	stage string
	err   error
}

func (e *authorityStageFailure) Error() string { return e.stage + ": " + e.err.Error() }
func (e *authorityStageFailure) Unwrap() error { return e.err }

func stageFailure(stage string, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*authorityStageFailure](err); ok {
		return err
	}
	return &authorityStageFailure{stage: stage, err: err}
}

func (r *Runtime) recordFailure(err error) {
	if r == nil || err == nil || r.logger == nil {
		return
	}
	staged, ok := errors.AsType[*authorityStageFailure](err)
	if !ok {
		staged = &authorityStageFailure{stage: "reconcile", err: err}
	}
	errorClass := authorityErrorClass(err)
	causeClass := authorityCauseClass(err)
	var apiCode jetstream.ErrorCode
	if apiErr, ok := errors.AsType[*jetstream.APIError](err); ok {
		apiCode = apiErr.ErrorCode
	}
	now := time.Now()
	key := fmt.Sprintf("%s/%s/%s/%d", staged.stage, errorClass, causeClass, apiCode)
	r.diagMu.Lock()
	if previous, ok := r.diagTimes[key]; ok && now.Sub(previous) < 15*time.Second {
		r.diagMu.Unlock()
		return
	}
	if len(r.diagTimes) >= 64 {
		clear(r.diagTimes)
	}
	r.diagTimes[key] = now
	r.diagMu.Unlock()
	r.emitDiagnostic(slog.LevelWarn, "authority operation failed",
		"scope", r.config.Scope,
		"stage", staged.stage,
		"error_class", errorClass,
		"cause_class", causeClass,
		"jetstream_error_code", uint16(apiCode),
	)
}

func authorityCauseClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, nats.ErrNoResponders):
		return "no_responders"
	default:
		if _, ok := errors.AsType[*jetstream.APIError](err); ok {
			return "jetstream_api"
		}
		return "other"
	}
}

func authorityErrorClass(err error) string {
	switch {
	case errors.Is(err, ErrConflict):
		return "cas_conflict"
	case errors.Is(err, ErrFenced):
		return "fenced"
	case errors.Is(err, ErrOutcomeUnknown):
		return "outcome_unknown"
	case errors.Is(err, ErrLeaseCorrupt):
		return "lease_corrupt"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, nats.ErrNoResponders):
		return "no_responders"
	default:
		if _, ok := errors.AsType[*jetstream.APIError](err); ok {
			return "jetstream_api"
		}
		return "transport_or_internal"
	}
}

// Guard forces a quorum-acknowledged lease renewal immediately before a
// mutation. The lease append shares the control-log sequence with host writes,
// so a new-term barrier and any following write have a single durable order.
func (r *Runtime) Guard(ctx context.Context, expectedEpoch uint64) error {
	if r == nil {
		return ErrNotLeader
	}
	r.mu.Lock()
	current := r.Current()
	if !current.CanMutate() || current.CandidateID != r.config.CandidateID || current.OwnerID != r.ownerID {
		wasLocalLeader := current.Leader && current.CandidateID == r.config.CandidateID && current.OwnerID == r.ownerID
		r.mu.Unlock()
		r.logSnapshotTransition()
		if wasLocalLeader {
			r.recordFailure(stageFailure("guard_precondition", ErrNotLeader))
		}
		return ErrNotLeader
	}
	if expectedEpoch == 0 || current.Epoch != expectedEpoch {
		r.mu.Unlock()
		return ErrFenced
	}
	var lastErr error
	for range 8 {
		err := r.guardLocked(ctx, expectedEpoch)
		if !errors.Is(err, ErrConflict) {
			r.mu.Unlock()
			r.logSnapshotTransition()
			if err != nil {
				r.recordFailure(err)
			}
			return err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = stageFailure("guard_retry", ErrConflict)
	}
	r.mu.Unlock()
	r.logSnapshotTransition()
	r.recordFailure(lastErr)
	return lastErr
}

func (r *Runtime) guardLocked(ctx context.Context, expectedEpoch uint64) error {
	info, err := r.stream.Info(ctx)
	if err != nil {
		r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Reason: "control-log-unavailable"})
		return stageFailure("guard_stream_info", err)
	}
	if err := verifyControlStreamConfig(info.Config, r.config.Replicas); err != nil {
		r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Reason: "control-log-incompatible"})
		return stageFailure("guard_stream_config", err)
	}
	entry, err := r.stream.GetLastMsgForSubject(ctx, r.leaseSub)
	if err != nil {
		r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Reason: "lease-unreadable"})
		return stageFailure("guard_lease_msg_get", err)
	}
	if entry.Sequence > info.State.LastSeq {
		return stageFailure("guard_sequence_check", ErrConflict)
	}
	lease, err := decodeLease(entry.Data)
	if err != nil {
		r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, OwnerID: r.ownerID, Reason: "lease-corrupt"})
		return stageFailure("guard_lease_decode", ErrLeaseCorrupt)
	}
	if lease.CandidateID != r.config.CandidateID || lease.OwnerID != r.ownerID || lease.Epoch != expectedEpoch || lease.Released || !time.Now().Before(entry.Time.Add(time.Duration(lease.LeaseDuration))) {
		r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: lease.CandidateID, OwnerID: lease.OwnerID, Epoch: lease.Epoch, Revision: entry.Sequence, ObservedAt: time.Now(), Reason: "lease-fenced"})
		return stageFailure("guard_lease_check", ErrFenced)
	}
	return r.appendLease(ctx, info.State.LastSeq, entry.Sequence, expectedEpoch, false)
}

// Close stops renewal and, when possible, appends a release barrier. If NATS
// is unavailable the durable lease simply expires and the next candidate
// advances the epoch.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	r.once.Do(func() {
		r.cancel()
		<-r.done
		current := r.Current()
		if current.CanMutate() && current.CandidateID == r.config.CandidateID && current.OwnerID == r.ownerID {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			r.mu.Lock()
			defer r.mu.Unlock()
			info, err := r.stream.Info(ctx)
			if err == nil && verifyControlStreamConfig(info.Config, r.config.Replicas) == nil {
				entry, getErr := r.stream.GetLastMsgForSubject(ctx, r.leaseSub)
				if getErr == nil {
					lease, decodeErr := decodeLease(entry.Data)
					if decodeErr == nil && lease.CandidateID == r.config.CandidateID && lease.OwnerID == r.ownerID && lease.Epoch == current.Epoch && !lease.Released {
						closeErr = r.appendLease(ctx, info.State.LastSeq, entry.Sequence, current.Epoch, true)
					}
				}
			}
		}
	})
	r.logSnapshotTransition()
	return closeErr
}

func (c Config) withDefaults() Config {
	if c.LeaseDuration == 0 {
		c.LeaseDuration = defaultLeaseDuration
	}
	if c.RenewInterval == 0 {
		c.RenewInterval = defaultRenewInterval
	}
	if c.Replicas == 0 {
		c.Replicas = defaultReplicas
	}
	return c
}

// Observe reads the current lease without creating a lease, publishing a
// heartbeat, or claiming leadership. The returned Leader bit is always false;
// callers may use the epoch to sign work but cannot mistake an observation for
// a local mutation grant.
func Observe(ctx context.Context, js jetstream.JetStream, scope string) (Snapshot, error) {
	if js == nil {
		return Snapshot{}, errors.New("JetStream is required")
	}
	if !natsToken.MatchString(scope) {
		return Snapshot{}, errors.New("authority scope must be a lowercase NATS token")
	}
	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		return Snapshot{}, err
	}
	subject := fmt.Sprintf("%s.%s.lease", controlSubjectRoot, scope)
	for range 8 {
		info, err := stream.Info(ctx)
		if err != nil {
			return Snapshot{}, err
		}
		if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
			return Snapshot{}, err
		}
		entry, err := stream.GetLastMsgForSubject(ctx, subject)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return Snapshot{Scope: scope, Ready: true, ObservedAt: time.Now(), Reason: "no-lease"}, nil
		}
		if err != nil {
			return Snapshot{}, err
		}
		if entry.Sequence > info.State.LastSeq {
			continue
		}
		lease, err := decodeLease(entry.Data)
		if err != nil || lease.Scope != scope {
			return Snapshot{Scope: scope, Revision: entry.Sequence, ObservedAt: time.Now(), Reason: "lease-corrupt"}, ErrLeaseCorrupt
		}
		expiresAt := entry.Time.Add(time.Duration(lease.LeaseDuration))
		now := time.Now()
		snapshot := Snapshot{
			Scope: scope, CandidateID: lease.CandidateID, OwnerID: lease.OwnerID, Ready: true, Epoch: lease.Epoch,
			Revision: entry.Sequence, ExpiresAt: expiresAt, ObservedAt: now, Reason: "observed",
		}
		if lease.Released || !now.Before(expiresAt) {
			snapshot.Ready = false
			snapshot.Reason = "lease-inactive"
		}
		return snapshot, nil
	}
	return Snapshot{}, ErrConflict
}
