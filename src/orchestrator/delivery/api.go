package delivery

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HTTP paths of the delivery API. ts-deploy POSTs a DeliveryRequest to
// OperationsPath; receipts are polled at OperationPath with the operation ID.
const (
	OperationsPath   = "/delivery/v1/operations"
	operationsPrefix = OperationsPath + "/"
	recoverySuffix   = "/recover"
)

// Roller executes one verified delivery against the estate: the canary-to-
// rolling rollout for host services, edge promotion for Workers and
// Snippets. It returns the terminal receipt facts; the API validates and
// publishes them, never inventing one.
type Roller interface {
	Roll(ctx context.Context, request *Request, artifact *ReleaseArtifact) (RolloutResult, error)
}

// FencedRoller is the side-effecting rollout contract. Implementations must
// pass the fence to each host/edge provider and invoke the checker immediately
// before every mutation. Roller remains source-compatible for old test-only
// adapters; NewServer refuses to wire one into an authoritative server.
type FencedRoller interface {
	RollFenced(context.Context, *Request, *ReleaseArtifact, OperationFence, FenceChecker) (RolloutResult, error)
}

// RolloutRollbacker is an optional recovery surface for a Roller. A Roller
// that can mutate hosts should retain its touched-host progress and expose
// rollback here; the API invokes it when Roll returns an error or panics.
// Rollers without this surface are recorded as rollback_failed because an
// interrupted rollout cannot safely claim that rollback was unnecessary.
type RolloutRollbacker interface {
	Rollback(context.Context, *Request, *ReleaseArtifact) (*Rollback, error)
}

type FencedRollbacker interface {
	RollbackFenced(context.Context, *Request, *ReleaseArtifact, OperationFence, FenceChecker) (*Rollback, error)
}

// RolloutResult is the terminal outcome of one rollout.
type RolloutResult struct {
	Status    string
	Checks    []*HealthCheck
	Converged bool
	Rollback  *Rollback
	Error     *Error
}

// ServerConfig is the fully explicit delivery API configuration. Every
// dependency is required; none is defaulted.
type ServerConfig struct {
	// OwnerID identifies this process for durable operation fencing. Empty uses
	// a process-unique ID; production may provide a stable instance identity.
	OwnerID string
	// LeaseTTL bounds how long another process must wait before safe recovery.
	LeaseTTL time.Duration
	// Token returns the delivery bearer token (the O-3 Forgejo Actions
	// secret). Required: an unauthenticated delivery API is refused.
	Token func() (string, error)
	// Fetcher retrieves release artifacts. Required.
	Fetcher ArtifactFetcher
	// Trust returns the active release-signing trust set; a function so the
	// 24-hour rotation swaps are visible without restart. Required.
	Trust func() *TrustSet
	// Mirror mirrors artifacts into every Region's bucket (D-71). Required.
	Mirror *ArtifactMirror
	// Rollout executes verified deliveries. Required.
	Rollout Roller
	// Journal records operations and receipts. Required.
	Journal *Journal
	// Now overrides the clock for tests.
	Now func() time.Time
}

// Server is the signed delivery API of D-67: it authenticates ts-deploy's
// request, verifies the artifact signature and sha256, mirrors the artifact
// into every Region's release bucket, drives the rollout, and publishes the
// terminal receipt ts-deploy can poll. It is safe for concurrent use.
type Server struct {
	config   ServerConfig
	inFlight sync.Map // operation ID -> struct{}
}

var serverOwnerSequence atomic.Uint64

// NewServer validates the configuration and composes the API.
func NewServer(config ServerConfig) (*Server, error) {
	if strings.TrimSpace(config.OwnerID) == "" {
		sequence := serverOwnerSequence.Add(1)
		config.OwnerID = "delivery-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(sequence, 10)
	}
	if config.LeaseTTL <= 0 {
		config.LeaseTTL = defaultOperationLeaseTTL
	}
	if config.LeaseTTL < minimumOperationLeaseTTL {
		return nil, fmt.Errorf("delivery: operation lease TTL must be at least %s", minimumOperationLeaseTTL)
	}
	if config.Token == nil {
		return nil, errors.New("delivery: server requires a delivery token source")
	}
	if config.Fetcher == nil {
		return nil, errors.New("delivery: server requires an artifact fetcher")
	}
	if config.Trust == nil {
		return nil, errors.New("delivery: server requires a release trust source")
	}
	if config.Mirror == nil {
		return nil, errors.New("delivery: server requires an artifact mirror")
	}
	if config.Mirror.Store == nil {
		return nil, errors.New("delivery: server requires a configured artifact mirror store")
	}
	if _, ok := config.Mirror.Store.(FencedRegionObjectStore); !ok {
		return nil, errors.New("delivery: server requires a fenced artifact mirror store")
	}
	if config.Rollout == nil {
		return nil, errors.New("delivery: server requires a rollout")
	}
	if _, ok := config.Rollout.(FencedRoller); !ok {
		return nil, errors.New("delivery: server requires a fenced rollout")
	}
	if config.Journal == nil {
		return nil, errors.New("delivery: server requires a journal")
	}
	return &Server{config: config}, nil
}

// Handler serves the delivery API: POST one DeliveryRequest, GET one receipt
// by operation ID, GET the operation summary list.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(OperationsPath, s.serveOperations)
	mux.HandleFunc(operationsPrefix, s.serveOperation)
	return mux
}

func (s *Server) serveOperations(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		s.handleSubmit(writer, request)
	case http.MethodGet:
		if err := s.authorize(request); err != nil {
			s.writeError(writer, http.StatusUnauthorized, "delivery_unauthorized", "The delivery token is missing or invalid.", "Send the orchestrator delivery token as a bearer token.")
			return
		}
		operations, err := s.config.Journal.SnapshotWithError()
		if err != nil {
			s.writeError(writer, http.StatusInternalServerError, "delivery_internal", "The delivery journal is unavailable.", "Restore journal health and retry the same operation ID.")
			return
		}
		s.writeJSON(writer, http.StatusOK, operationSummaries(operations))
	default:
		s.writeMethodNotAllowed(writer)
	}
}

func (s *Server) serveOperation(writer http.ResponseWriter, request *http.Request) {
	path := strings.TrimPrefix(request.URL.Path, operationsPrefix)
	isRecovery := strings.HasSuffix(path, recoverySuffix)
	if isRecovery {
		if request.Method != http.MethodPost {
			s.writeMethodNotAllowed(writer)
			return
		}
		if err := s.authorize(request); err != nil {
			s.writeError(writer, http.StatusUnauthorized, "delivery_unauthorized", "The delivery token is missing or invalid.", "Send the orchestrator delivery token as a bearer token.")
			return
		}
		operationID := strings.TrimSuffix(path, recoverySuffix)
		if operationID == "" || strings.Contains(operationID, "/") {
			s.writeError(writer, http.StatusNotFound, "operation_not_found", "The operation does not exist.", "Poll the operation ID returned by the delivery request.")
			return
		}
		if _, running := s.inFlight.Load(operationID); running {
			s.writeError(writer, http.StatusConflict, "operation_in_progress", "The operation is still running.", "Wait for the terminal receipt or retry recovery after the owner lease expires.")
			return
		}
		receipt, err := s.config.Journal.RecoverUnknown(operationID)
		if err != nil {
			if errors.Is(err, ErrOperationLeaseActive) {
				s.writeError(writer, http.StatusConflict, "operation_in_progress", "The operation is still running.", "Wait for the terminal receipt or retry recovery after the owner lease expires.")
				return
			}
			if errors.Is(err, ErrStoreNotFound) {
				s.writeError(writer, http.StatusNotFound, "operation_not_found", "The operation does not exist.", "Poll the operation ID returned by the delivery request.")
				return
			}
			s.writeError(writer, http.StatusInternalServerError, "delivery_internal", "The delivery journal is unavailable.", "Restore journal health and retry the recovery request.")
			return
		}
		s.writeJSON(writer, http.StatusOK, receipt)
		return
	}
	if request.Method != http.MethodGet {
		s.writeMethodNotAllowed(writer)
		return
	}
	if err := s.authorize(request); err != nil {
		s.writeError(writer, http.StatusUnauthorized, "delivery_unauthorized", "The delivery token is missing or invalid.", "Send the orchestrator delivery token as a bearer token.")
		return
	}
	operationID := path
	if operationID == "" || strings.Contains(operationID, "/") {
		s.writeError(writer, http.StatusNotFound, "operation_not_found", "The operation does not exist.", "Poll the operation ID returned by the delivery request.")
		return
	}
	operation, ok, err := s.config.Journal.GetWithError(operationID)
	if err != nil {
		s.writeError(writer, http.StatusInternalServerError, "delivery_internal", "The delivery journal is unavailable.", "Restore journal health and retry the same operation ID.")
		return
	}
	if !ok {
		s.writeError(writer, http.StatusNotFound, "operation_not_found", "The operation does not exist.", "Poll the operation ID returned by the delivery request.")
		return
	}
	if operation.State != OperationDone || operation.Receipt == nil {
		// The version-1 contract has no in-flight receipt status, so an
		// operation that has not finished answers not-found until its
		// terminal receipt exists.
		s.writeError(writer, http.StatusNotFound, "operation_in_progress", "The operation has not finished.", "Poll again; the terminal receipt appears when the rollout finishes.")
		return
	}
	s.writeJSON(writer, http.StatusOK, operation.Receipt)
}

func (s *Server) handleSubmit(writer http.ResponseWriter, request *http.Request) {
	if err := s.authorize(request); err != nil {
		s.writeError(writer, http.StatusUnauthorized, "delivery_unauthorized", "The delivery token is missing or invalid.", "Send the orchestrator delivery token as a bearer token.")
		return
	}
	body := http.MaxBytesReader(writer, request.Body, MaxDocumentBytes)
	payload, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeError(writer, http.StatusRequestEntityTooLarge, "request_too_large", "The delivery request exceeds the 1 MiB limit.", "Write a bounded request document and retry.")
			return
		}
		s.writeError(writer, http.StatusBadRequest, "delivery_request_invalid", "The delivery request body could not be read.", "Retry with a bounded UTF-8 JSON document.")
		return
	}
	parsed, err := ParseRequest(string(payload))
	if err != nil {
		s.writeValidationError(writer, err)
		return
	}
	if err := ValidateRequest(parsed); err != nil {
		s.writeValidationError(writer, err)
		return
	}
	// The shared contract admits source-only deliveries; the orchestrator's
	// delivery API does not: every accepted candidate is an exact, signed
	// artifact (D-67), so the artifact identity is required here.
	if parsed.Artifact == nil {
		s.writeError(writer, http.StatusBadRequest, "artifact_required", "The orchestrator delivers exact artifacts only.", "Include artifact.digest, artifact.manifestDigest, artifact.kind, and artifact.architecture.")
		return
	}
	receipt, err := s.Submit(request.Context(), parsed)
	if err != nil {
		var inProgress *inProgressError
		if errors.As(err, &inProgress) {
			s.writeError(writer, http.StatusConflict, "operation_in_progress", "The operation is already running.", "Poll the receipt endpoint until the terminal receipt appears.")
			return
		}
		var conflict *conflictError
		if errors.As(err, &conflict) {
			s.writeError(writer, http.StatusConflict, "operation_conflict", "The operation ID was reused with a different request.", "Retry with a fresh operation ID.")
			return
		}
		s.writeError(writer, http.StatusInternalServerError, "delivery_internal", "The delivery could not be processed.", "Retry the same operation ID after the transient failure is resolved.")
		return
	}
	s.writeJSON(writer, http.StatusOK, receipt)
}

// ErrInProgress marks an operation already running; ErrConflict an operation
// ID reused with a different request.
type inProgressError struct{ operationID string }

func (e *inProgressError) Error() string {
	return "delivery: operation " + e.operationID + " is already running"
}

type conflictError struct{ operationID string }

func (e *conflictError) Error() string { return "delivery: operation " + e.operationID + " conflicts" }

var errRolloutPanicked = errors.New("delivery: rollout panicked")

const rolloutRecoveryTimeout = 30 * time.Second

// Submit runs one delivery end to end: idempotent admission, artifact
// verification, all-Region mirroring, rollout, and the terminal receipt.
// The terminal receipt always validates against the request before it is
// returned or stored.
func (s *Server) Submit(ctx context.Context, request *Request) (*Receipt, error) {
	if request == nil {
		return nil, errors.New("delivery: request is required")
	}
	// Own an immutable snapshot for the entire operation. Callers often reuse
	// and mutate a request object while polling; allowing that alias into the
	// fetch/rollout path would change the CAS digest mid-flight and strand the
	// durable operation.
	request = cloneRequest(request)
	if request == nil {
		return nil, errors.New("delivery: request could not be copied")
	}
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	if request.Artifact == nil {
		return nil, errors.New("delivery: exact artifact identity is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lease := OperationLease{OwnerID: s.config.OwnerID, TTL: s.config.LeaseTTL}
	operation, exists, err := s.config.Journal.Begin(request, lease)
	if err != nil {
		if errors.Is(err, ErrOperationConflict) {
			return nil, &conflictError{operationID: request.OperationID}
		}
		return nil, fmt.Errorf("delivery: journal admission failed: %w", err)
	}
	if exists {
		if operation.State == OperationDone && operation.Receipt != nil {
			return operation.Receipt, nil
		}
		taken, takeoverErr := s.config.Journal.Takeover(request.OperationID, operation.RequestDigest, lease)
		if takeoverErr != nil {
			// A running record is a durable ownership fence until its lease
			// expires. No second process may race provider mutations.
			return nil, &inProgressError{operationID: request.OperationID}
		}
		operation = taken
	}
	if _, loaded := s.inFlight.LoadOrStore(request.OperationID, struct{}{}); loaded {
		return nil, &inProgressError{operationID: request.OperationID}
	}
	defer s.inFlight.Delete(request.OperationID)

	operationContext, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go s.renewOperationLease(operationContext, request, operation, heartbeatDone, cancel)
	receipt, err := s.deliver(operationContext, request, operation)
	cancel()
	<-heartbeatDone
	if err != nil {
		return nil, err
	}
	if err := ValidateReceipt(receipt, request); err != nil {
		// A malformed rollout result must not strand the admitted operation in
		// running. Persist a fixed, redacted failure instead of exposing the
		// validator detail (which may contain implementation-specific text).
		receipt, err = buildReceipt(request, rolloutFailureResult("rollout_result_invalid", nil), true)
		if err != nil {
			return nil, fmt.Errorf("delivery: produced an invalid receipt for %s: %w", request.OperationID, err)
		}
		if err := ValidateReceipt(receipt, request); err != nil {
			return nil, fmt.Errorf("delivery: produced an invalid failure receipt for %s: %w", request.OperationID, err)
		}
	}
	if err := s.config.Journal.Finish(request.OperationID, operation.RequestDigest, receipt, leaseFor(operation, s.config)); err != nil {
		return nil, err
	}
	return receipt, nil
}

func leaseFor(operation *Operation, config ServerConfig) OperationLease {
	return OperationLease{OwnerID: config.OwnerID, TTL: config.LeaseTTL, Generation: operation.Generation}
}

func (s *Server) renewOperationLease(ctx context.Context, request *Request, operation *Operation, done chan<- struct{}, cancel context.CancelFunc) {
	defer close(done)
	interval := operationLeaseRenewInterval(s.config.LeaseTTL)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lease := leaseFor(operation, s.config)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.config.Journal.Renew(request.OperationID, operation.RequestDigest, lease, operation.Generation); err != nil {
				cancel()
				return
			}
		}
	}
}

func operationLeaseRenewInterval(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = defaultOperationLeaseTTL
	}
	interval := ttl / 3
	if interval <= 0 || interval >= ttl {
		interval = ttl / 2
	}
	if interval <= 0 {
		interval = time.Nanosecond
	}
	return interval
}

// deliver is the verify → mirror → roll pipeline. Every failure produces a
// terminal receipt (never a half-ack): verification and mirroring failures
// mean the deploy never started; rollout errors, cancellation, and panics are
// converted to a fixed failed result so the operation can be finished.
func (s *Server) deliver(ctx context.Context, request *Request, operation *Operation) (receipt *Receipt, err error) {
	verified := false
	defer func() {
		if recovered := recover(); recovered != nil {
			// Provider and trust adapters are outside this package's authority
			// boundary. A panic must still leave a terminal, redacted receipt in
			// the durable journal rather than strand the accepted operation.
			receipt, err = buildReceipt(request, rolloutFailureResult("delivery_panicked", nil), verified)
		}
	}()
	failed := func(code, message, remediation string) (*Receipt, error) {
		return buildReceipt(request, RolloutResult{
			Status: StatusFailed,
			Checks: []*HealthCheck{{Name: "verify", Status: "failed"}},
			Error:  &Error{Code: ptr(code), Message: ptr(message), Remediation: ptr(remediation)},
		}, false)
	}

	// Verification and mirroring establish the candidate needed for a
	// terminal rollout receipt. If cancellation happened before this pipeline
	// began, use a detached context for those read-only/preparation steps and
	// preserve the original context for rollout, where it becomes the explicit
	// rollout_cancelled result.
	preflightContext := ctx
	if ctx.Err() != nil {
		preflightContext = context.Background()
	}
	artifact, err := verifyArtifact(preflightContext, s.config.Fetcher, s.config.Trust(), request)
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return failed("rollout_cancelled", "The delivery was cancelled before rollout started.", "Retry with a fresh operation ID after the target is ready.")
		}
		return failed("artifact_unverified", "The release artifact could not be fetched or verified.", "Confirm the release is published with a valid detached signature, then retry the same operation ID.")
	}
	verified = true
	fence := fenceFor(operation)
	if err := s.config.Mirror.MirrorAllFenced(preflightContext, artifact, fence, s.config.Journal.VerifyFence); err != nil {
		// D-71: the artifact mirrors into every Region before rollout starts;
		// a partial mirror means the deploy never started, so nothing is
		// stranded mid-way.
		if ctx != nil && ctx.Err() != nil {
			return failed("rollout_cancelled", "The delivery was cancelled before rollout started.", "Retry with a fresh operation ID after the target is ready.")
		}
		return failed("mirror_incomplete", "The artifact could not be mirrored into every Region.", "Retry the same operation ID after the Region object stores are reachable.")
	}
	result, err := rollSafely(ctx, s.config.Rollout, request, artifact, fence, s.config.Journal.VerifyFence)
	if err != nil {
		return buildReceipt(request, rolloutFailureResult(rolloutFailureCode(ctx, err), s.recoverOwnedRollout(ctx, request, artifact, operation)), true)
	}
	return buildReceipt(request, result, true)
}

// recoverOwnedRollout fences rollback itself. A lease can expire while a
// provider call is blocked; in that case a different process may have taken
// over the generation and the stale owner must not issue compensating writes.
// Renewing immediately before rollback also keeps the lease alive while the
// heartbeat goroutine remains active during the bounded recovery call.
func (s *Server) recoverOwnedRollout(ctx context.Context, request *Request, artifact *ReleaseArtifact, operation *Operation) *Rollback {
	if operation == nil || s.config.Journal == nil {
		return nil
	}
	lease := leaseFor(operation, s.config)
	if err := s.config.Journal.Renew(request.OperationID, operation.RequestDigest, lease, operation.Generation); err != nil {
		return nil
	}
	if fenced, ok := s.config.Rollout.(FencedRollbacker); ok {
		return recoverFencedRollout(ctx, fenced, request, artifact, fenceFor(operation), s.config.Journal.VerifyFence)
	}
	return recoverRollout(ctx, s.config.Rollout, request, artifact)
}

func fenceFor(operation *Operation) OperationFence {
	if operation == nil {
		return OperationFence{}
	}
	return OperationFence{OperationID: operation.OperationID, RequestDigest: operation.RequestDigest, OwnerID: operation.OwnerID, Generation: operation.Generation}
}

func rollSafely(ctx context.Context, roller Roller, request *Request, artifact *ReleaseArtifact, fence OperationFence, check FenceChecker) (result RolloutResult, err error) {
	defer func() {
		if recover() != nil {
			result = RolloutResult{}
			err = errRolloutPanicked
		}
	}()
	if fenced, ok := roller.(FencedRoller); ok {
		return fenced.RollFenced(ctx, request, artifact, fence, check)
	}
	return RolloutResult{}, ErrOperationLeaseActive
}

func recoverFencedRollout(ctx context.Context, roller FencedRollbacker, request *Request, artifact *ReleaseArtifact, fence OperationFence, check FenceChecker) (rollback *Rollback) {
	defer func() {
		if recover() != nil {
			rollback = nil
		}
	}()
	rollback, err := roller.RollbackFenced(ctx, request, artifact, fence, check)
	if err != nil {
		return nil
	}
	return rollback
}

func rolloutFailureCode(ctx context.Context, err error) string {
	if errors.Is(err, errRolloutPanicked) {
		return "rollout_panicked"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || (ctx != nil && ctx.Err() != nil) {
		return "rollout_cancelled"
	}
	return "rollout_failed"
}

func recoverRollout(ctx context.Context, roller Roller, request *Request, artifact *ReleaseArtifact) *Rollback {
	// A terminal failure must say recovery was attempted. When a Roller does
	// not expose a rollback operation, the orchestrator cannot claim recovery
	// was unnecessary: the outcome is explicitly failed/unknown and remains
	// visible to operators for remediation.
	rollback := &Rollback{Attempted: true, Status: RollbackFailed}
	if _, ok := roller.(RolloutRollbacker); !ok {
		if _, ok := roller.(interface {
			Rollback(context.Context, *Request, *ReleaseArtifact) (Rollback, error)
		}); !ok {
			if _, ok := roller.(interface {
				Rollback(context.Context, *Request, *ReleaseArtifact) error
			}); !ok {
				return rollback
			}
		}
	}
	rollback.Attempted = true
	recoveryContext := context.Background()
	if ctx != nil {
		// Rollback must not inherit a cancellation that interrupted the forward
		// rollout; the API still imposes a finite recovery bound below.
		recoveryContext = context.WithoutCancel(ctx)
	}
	recoveryContext, cancel := context.WithTimeout(recoveryContext, rolloutRecoveryTimeout)
	defer cancel()
	var recovered *Rollback
	var recoveryErr error
	func() {
		defer func() {
			if recover() != nil {
				recovered = nil
				recoveryErr = errRolloutPanicked
			}
		}()
		switch recovery := roller.(type) {
		case RolloutRollbacker:
			recovered, recoveryErr = recovery.Rollback(recoveryContext, request, artifact)
		case interface {
			Rollback(context.Context, *Request, *ReleaseArtifact) (Rollback, error)
		}:
			var value Rollback
			value, recoveryErr = recovery.Rollback(recoveryContext, request, artifact)
			recovered = &value
		case interface {
			Rollback(context.Context, *Request, *ReleaseArtifact) error
		}:
			recoveryErr = recovery.Rollback(recoveryContext, request, artifact)
			if recoveryErr == nil {
				recovered = &Rollback{Status: RollbackSucceeded}
			}
		}
	}()
	if recoveryErr != nil || recovered == nil {
		return rollback
	}
	copy := *recovered
	copy.Attempted = true
	if copy.Status != RollbackSucceeded {
		copy.Status = RollbackFailed
	}
	return &copy
}

func rolloutFailureResult(code string, rollback *Rollback) RolloutResult {
	if rollback == nil {
		// This helper is used for interrupted/unknown rollouts, including
		// panic recovery. Such a terminal failure must explicitly record that
		// recovery was attempted; not having a rollback adapter is itself a
		// failed recovery outcome, never "not required".
		rollback = &Rollback{Attempted: true, Status: RollbackFailed}
	}
	message := "The rollout did not reach a terminal outcome."
	remediation := "Retry with a fresh operation ID after reviewing the rollout logs."
	if code == "rollout_cancelled" {
		message = "The rollout was cancelled before it reached a terminal outcome."
		remediation = "Retry with a fresh operation ID after the target is ready."
	}
	if code == "rollout_panicked" {
		message = "The rollout terminated unexpectedly."
	}
	if rollback.Status == RollbackFailed {
		remediation = "Inspect the recorded rollback status, then retry with a fresh operation ID."
	}
	return RolloutResult{
		Status:    StatusFailed,
		Checks:    []*HealthCheck{{Name: "rollout", Status: "failed"}},
		Converged: false,
		Rollback:  rollback,
		Error:     &Error{Code: ptr(code), Message: ptr(message), Remediation: ptr(remediation)},
	}
}

// buildReceipt assembles the terminal receipt of one delivery. verified is
// the artifact provenance outcome; the rollout result carries the rest.
func buildReceipt(request *Request, result RolloutResult, verified bool) (*Receipt, error) {
	if result.Rollback == nil {
		result.Rollback = &Rollback{Status: RollbackNotRequired}
	}
	if result.Checks == nil {
		result.Checks = []*HealthCheck{}
	}
	status := result.Status
	if status == "" {
		status = StatusFailed
	}
	var artifactDigest, manifestDigest *string
	if request.Artifact != nil {
		artifactDigest = ptr(request.Artifact.Digest)
		manifestDigest = ptr(request.Artifact.ManifestDigest)
	}
	return &Receipt{
		SchemaVersion:          ContractVersion,
		OperationID:            request.OperationID,
		Status:                 status,
		Source:                 request.Source,
		ArtifactDigest:         artifactDigest,
		Target:                 request.Target,
		Provenance:             &Provenance{Verified: verified, ConfigurationRevision: request.ConfigurationRevision, MigrationRevision: request.MigrationRevision},
		Health:                 &Health{Checks: result.Checks, Converged: result.Converged},
		Rollback:               result.Rollback,
		AuditID:                "op-" + request.OperationID,
		Error:                  result.Error,
		ArtifactManifestDigest: manifestDigest,
	}, nil
}

func (s *Server) authorize(request *http.Request) error {
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return errors.New("delivery: missing bearer token")
	}
	presented := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	expected, err := s.config.Token()
	if err != nil || expected == "" {
		return errors.New("delivery: delivery token is not configured")
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) != 1 {
		return errors.New("delivery: bearer token mismatch")
	}
	return nil
}

func (s *Server) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(Serialize(value)))
}

func (s *Server) writeError(writer http.ResponseWriter, status int, code, message, remediation string) {
	s.writeJSON(writer, status, &Error{Code: ptr(code), Message: ptr(message), Remediation: ptr(remediation)})
}

func (s *Server) writeValidationError(writer http.ResponseWriter, err error) {
	if code, ok := AsValidationError(err); ok {
		s.writeError(writer, http.StatusBadRequest, code.Code, code.Message, code.Remediation)
		return
	}
	s.writeError(writer, http.StatusBadRequest, "delivery_request_invalid", "The delivery document is not valid version-1 JSON.", "Check the field names and value types against the delivery contract.")
}

func (s *Server) writeMethodNotAllowed(writer http.ResponseWriter) {
	s.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "The delivery API accepts POST of requests and GET of receipts.", "Retry with POST or GET.")
}

// OperationSummary is one row of the operation list the rollout status
// command renders.
type OperationSummary struct {
	OperationID string   `json:"operationId"`
	Service     string   `json:"service"`
	State       string   `json:"state"`
	Status      string   `json:"status,omitempty"`
	StartedAt   string   `json:"startedAt"`
	FinishedAt  string   `json:"finishedAt,omitempty"`
	Regions     []string `json:"regions,omitempty"`
}

func operationSummaries(operations []Operation) []OperationSummary {
	summaries := make([]OperationSummary, 0, len(operations))
	for _, operation := range operations {
		summary := OperationSummary{
			OperationID: operation.OperationID,
			State:       operation.State,
			StartedAt:   operation.StartedAt.UTC().Format(time.RFC3339),
		}
		if operation.Request != nil && operation.Request.Target != nil {
			summary.Service = operation.Request.Target.Service
			summary.Regions = operation.Request.Target.Regions
		}
		if operation.Receipt != nil {
			summary.Status = operation.Receipt.Status
		}
		if !operation.FinishedAt.IsZero() {
			summary.FinishedAt = operation.FinishedAt.UTC().Format(time.RFC3339)
		}
		summaries = append(summaries, summary)
	}
	return summaries
}
