package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// ConfigDigestOf binds executable arguments and environment to an intent.
// Callers should resolve secrets on the host; durable desired state is readable
// by the regional control-plane identity.
func ConfigDigestOf(args []string, env map[string]string) string {
	if args == nil {
		args = []string{}
	}
	if env == nil {
		env = map[string]string{}
	}
	b, _ := json.Marshal(struct {
		Args []string          `json:"args"`
		Env  map[string]string `json:"env"`
	}{args, env})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Run processes durable intents until ctx is canceled. A message is acknowledged
// only after its acceptance or rejection has a durable record. Transient errors
// remain unacknowledged and are retried without a finite delivery cap.
func (s *Service) Run(ctx context.Context) error {
	if s == nil || s.consumer == nil || s.config.Verifier == nil || s.config.Authorize == nil || s.config.Fencer == nil || s.config.Planner == nil || s.config.Writer == nil {
		return errors.New("delivery consumer ports are not configured")
	}
	var diagnostics deliveryRetryDiagnostics
	for ctx.Err() == nil {
		if !s.config.Fencer.Current().CanMutate() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		batch, err := s.consumer.Fetch(1, jetstream.FetchContext(fetchCtx))
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if retry, waitErr := retryDeliveryTransport(ctx, err); retry {
				if waitErr != nil {
					return waitErr
				}
				continue
			}
			return fmt.Errorf("fetch delivery intent: %w", err)
		}
		for msg := range batch.Messages() {
			if !s.config.Fencer.Current().CanMutate() {
				_ = msg.NakWithDelay(250 * time.Millisecond)
				continue
			}
			terminal, processErr := s.process(ctx, msg.Data())
			if terminal {
				if err := msg.Ack(); err != nil {
					cancel()
					if ctx.Err() != nil {
						return ctx.Err()
					}
					// The result is durable; leave the message unacknowledged for
					// redelivery if its acknowledgement was lost during failover.
					if retry, waitErr := retryDeliveryTransport(ctx, err); retry {
						if waitErr != nil {
							return waitErr
						}
						break
					}
					return fmt.Errorf("ack delivery intent: %w", err)
				}
				recordAcknowledged()
			} else {
				intentsDeferred.Inc()
				if processErr != nil {
					diagnostics.report(slog.Default(), processErr)
				}
				delay := 250 * time.Millisecond
				if !errors.Is(processErr, authority.ErrNotLeader) {
					delay = 2 * time.Second
					if metadata, err := msg.Metadata(); err == nil {
						for range min(int(metadata.NumDelivered)-1, 5) {
							delay *= 2
						}
					}
				}
				_ = msg.NakWithDelay(delay)
				if processErr != nil && ctx.Err() != nil {
					cancel()
					return ctx.Err()
				}
			}
		}
		fetchErr := batch.Error()
		cancel()
		if fetchErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if retry, waitErr := retryDeliveryTransport(ctx, fetchErr); retry {
				if waitErr != nil {
					return waitErr
				}
				continue
			}
			return fmt.Errorf("fetch delivery batch: %w", fetchErr)
		}
	}
	return ctx.Err()
}

// Retry diagnostics are deliberately bounded and contain no operation identity,
// signed wire, placement payload, or raw error text. Run owns this limiter, so
// it needs no lock and cannot delay authority lease renewal.
const deliveryRetryLogInterval = 10 * time.Second

type deliveryStageError struct {
	stage string
	cause error
}

func (e deliveryStageError) Error() string { return "delivery " + e.stage + " failed" }
func (e deliveryStageError) Unwrap() error { return e.cause }

func stageDeliveryError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return deliveryStageError{stage: stage, cause: err}
}

type deliveryRetryDiagnostics struct {
	next       time.Time
	suppressed uint64
}

func (d *deliveryRetryDiagnostics) report(logger *slog.Logger, err error) {
	now := time.Now()
	if now.Before(d.next) {
		d.suppressed++
		return
	}
	stage := "unknown"
	if staged, ok := errors.AsType[deliveryStageError](err); ok {
		stage = staged.stage
	}
	causeClass, apiCode := deliveryFailureClass(err)
	fields := []any{"stage", stage, "cause_class", causeClass, "suppressed", d.suppressed}
	if apiCode != 0 {
		fields = append(fields, "jetstream_api_code", apiCode)
	}
	logger.Warn("delivery intent processing deferred", fields...)
	d.next = now.Add(deliveryRetryLogInterval)
	d.suppressed = 0
}

func deliveryFailureClass(err error) (string, uint16) {
	switch {
	case errors.Is(err, placement.ErrInsufficientCapacity):
		return "insufficient_capacity", 0
	case errors.Is(err, placement.ErrInvalidWorkload):
		return "invalid_workload", 0
	case errors.Is(err, authority.ErrFenced):
		return "authority_fenced", 0
	case errors.Is(err, authority.ErrNotLeader):
		return "not_leader", 0
	case errors.Is(err, host.ErrDesiredConflict):
		return "desired_conflict", 0
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return "timeout", 0
	case errors.Is(err, context.Canceled):
		return "canceled", 0
	case errors.Is(err, nats.ErrDisconnected), errors.Is(err, nats.ErrNoServers):
		return "disconnected", 0
	case errors.Is(err, nats.ErrNoResponders):
		return "no_responders", 0
	}
	if apiErr, ok := errors.AsType[*jetstream.APIError](err); ok {
		return "jetstream_api", uint16(apiErr.Code)
	}
	// ListHosts reports these retryable snapshot races as ordinary errors today.
	// Match only its known phrases; never include their free text in a log.
	message := err.Error()
	if staged, ok := errors.AsType[deliveryStageError](err); ok {
		message = staged.cause.Error()
	}
	if strings.Contains(message, "changed during host status read") {
		return "host_snapshot_changed", 0
	}
	if strings.Contains(message, "unverified host status cannot drive placement") {
		return "host_status_unverified", 0
	}
	return "other", 0
}

// A pull request or acknowledgement may fail when its serving peer shuts down
// or JetStream moves consumer leadership. The durable consumer remains bound
// by stream and name; the next Fetch uses the surviving connection.
func retryDeliveryTransport(ctx context.Context, err error) (bool, error) {
	if errors.Is(err, jetstream.ErrJetStreamNotEnabled) || errors.Is(err, jetstream.ErrJetStreamNotEnabledForAccount) ||
		errors.Is(err, jetstream.ErrInvalidOption) || errors.Is(err, jetstream.ErrConsumerDeleted) ||
		errors.Is(err, jetstream.ErrConsumerDoesNotExist) || errors.Is(err, nats.ErrPermissionViolation) ||
		errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrAuthExpired) ||
		errors.Is(err, nats.ErrAuthRevoked) || errors.Is(err, nats.ErrAccountAuthExpired) {
		return false, nil
	}
	quiet := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, jetstream.ErrNoMessages)
	transient := quiet || errors.Is(err, jetstream.ErrServerShutdown) ||
		errors.Is(err, jetstream.ErrConsumerLeadershipChanged) ||
		errors.Is(err, jetstream.ErrNoHeartbeat) ||
		errors.Is(err, nats.ErrDisconnected) || errors.Is(err, nats.ErrNoServers) ||
		errors.Is(err, nats.ErrNoResponders) || errors.Is(err, nats.ErrTimeout)
	if !transient {
		if apiErr, ok := errors.AsType[*jetstream.APIError](err); ok {
			transient = apiErr.Code >= 500
		}
	}
	if !transient {
		return false, nil
	}
	if !quiet {
		transportRetries.Inc()
		slog.Warn("delivery intent transport temporarily unavailable; retrying",
			observability.ComponentKey, "delivery", "error", err)
	}
	select {
	case <-ctx.Done():
		return true, ctx.Err()
	case <-time.After(250 * time.Millisecond):
		return true, nil
	}
}

func (s *Service) process(ctx context.Context, wire []byte) (terminal bool, processErr error) {
	defer func() {
		if processErr != nil {
			if _, ok := errors.AsType[deliveryStageError](processErr); !ok {
				processErr = stageDeliveryError("receipt", processErr)
			}
		}
	}()
	if len(wire) == 0 || len(wire) > MaxIntentBytes+8192 {
		return s.reject(ctx, wire, "signed intent exceeds size bound")
	}
	intent, actor, err := s.verifiedIntent(ctx, wire)
	if errors.Is(err, ErrUnauthorized) {
		return s.reject(ctx, wire, "unauthorized delivery actor")
	}
	if errors.Is(err, ErrInvalid) {
		return s.reject(ctx, wire, "invalid operator signature or intent")
	}
	if err != nil {
		return false, stageDeliveryError("verified_intent", err)
	}
	fingerprint, err := intent.fingerprint()
	if err != nil {
		return false, stageDeliveryError("decode", err)
	}
	key := operationKey(intent.OperationID)
	entry, err := s.getOperation(ctx, key)
	if err == nil {
		var existing operation
		if err := json.Unmarshal(entry.Value(), &existing); err != nil {
			return false, stageDeliveryError("operation_lookup", err)
		}
		if existing.Intent.OperationID != intent.OperationID || existing.Fingerprint != fingerprint || existing.Actor != actor {
			return s.reject(ctx, wire, "operation ID already binds a different request")
		}
		if existing.Receipt != nil {
			return true, nil
		}
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return false, stageDeliveryError("operation_lookup", err)
	}
	entryErr := err
	admission, err := s.readAdmission(ctx, intent.ArtifactDigest, intent.Cell, intent.Role, intent.Environment)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		if entry != nil {
			return false, stageDeliveryError("admission_read", err)
		}
		return s.rejectIntent(ctx, wire, intent, actor, "artifact is not admitted")
	}
	if err != nil {
		return false, stageDeliveryError("admission_read", err)
	}
	if admission.ManifestDigest != intent.ManifestDigest || admission.Source != intent.Source || admission.Cell != intent.Cell || admission.Role != intent.Role || admission.Environment != intent.Environment {
		if entry != nil {
			return false, stageDeliveryError("admission_read", ErrConflict)
		}
		return s.rejectIntent(ctx, wire, intent, actor, "artifact source or manifest does not match admission")
	}
	if err := s.verifyArtifact(ctx, admission); err != nil {
		return false, stageDeliveryError("artifact_verify", err)
	}
	var op operation
	var revision uint64
	if errors.Is(entryErr, jetstream.ErrKeyNotFound) {
		if err := s.config.Fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
			if errors.Is(err, authority.ErrFenced) {
				return s.rejectIntent(ctx, wire, intent, actor, "authority epoch was fenced before acceptance")
			}
			return false, stageDeliveryError("initial_guard", err)
		}
		plan, planErr := s.config.Planner.Plan(ctx, intent)
		if planErr != nil {
			return false, stageDeliveryError("planner", planErr)
		}
		if err := validatePlan(intent, plan); err != nil {
			return s.rejectIntent(ctx, wire, intent, actor, "invalid desired placement plan")
		}
		op = operation{Intent: intent, Fingerprint: fingerprint, Actor: actor, Plan: plan}
		b, marshalErr := json.Marshal(op)
		if marshalErr != nil {
			return false, stageDeliveryError("operation_create", marshalErr)
		}
		revision, err = s.operations.Create(ctx, key, b)
		if err != nil && !errors.Is(err, jetstream.ErrKeyExists) {
			return false, stageDeliveryError("operation_create", err)
		}
		if errors.Is(err, jetstream.ErrKeyExists) {
			entry, err = s.getOperation(ctx, key)
		} else {
			err = nil
		}
	}
	if err != nil {
		return false, stageDeliveryError("operation_create", err)
	}
	if entry != nil {
		if err := json.Unmarshal(entry.Value(), &op); err != nil {
			return false, stageDeliveryError("operation_lookup", err)
		}
		revision = entry.Revision()
	}
	if op.Intent.OperationID != intent.OperationID || op.Fingerprint != fingerprint || op.Actor != actor {
		return s.reject(ctx, wire, "operation ID already binds a different request")
	}
	if op.Receipt != nil {
		return true, nil
	}
	if err := validatePlan(intent, op.Plan); err != nil {
		return false, stageDeliveryError("validate_plan", err)
	}
	for _, desired := range op.Plan {
		if err := s.config.Fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
			if errors.Is(err, authority.ErrFenced) {
				return s.hold(ctx, key, op, revision, "authority epoch fenced; reconcile with a new intent")
			}
			return false, stageDeliveryError("apply_guard", err)
		}
		if _, err := s.config.Writer.ApplyDesired(ctx, desired); err != nil {
			if errors.Is(err, authority.ErrFenced) {
				return s.hold(ctx, key, op, revision, "authority epoch fenced; reconcile with a new intent")
			}
			if errors.Is(err, host.ErrDesiredConflict) {
				return s.hold(ctx, key, op, revision, "desired target conflicts with committed host state; reconcile with a new intent")
			}
			return false, stageDeliveryError("apply_desired", err)
		}
	}
	if err := s.config.Fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
		if errors.Is(err, authority.ErrFenced) {
			return s.hold(ctx, key, op, revision, "authority epoch fenced; reconcile with a new intent")
		}
		return false, stageDeliveryError("receipt_guard", err)
	}
	op.Receipt = &Receipt{OperationID: intent.OperationID, Fingerprint: fingerprint, Status: "accepted", ArtifactDigest: intent.ArtifactDigest, ManifestDigest: intent.ManifestDigest, Cell: intent.Cell, Role: intent.Role, Environment: intent.Environment, Generation: intent.Generation, AuthorityEpoch: intent.AuthorityEpoch}
	b, err := json.Marshal(op)
	if err != nil {
		return false, stageDeliveryError("receipt", err)
	}
	if _, err = s.operations.Update(ctx, key, b, revision); err != nil {
		if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
			current, statusErr := s.Status(ctx, intent.OperationID)
			if statusErr == nil && current.Fingerprint == fingerprint && current.Status == "accepted" {
				return true, nil
			}
		}
		return false, stageDeliveryError("receipt", err)
	}
	return true, nil
}

func (s *Service) hold(ctx context.Context, key string, op operation, revision uint64, reason string) (bool, error) {
	i := op.Intent
	op.Receipt = &Receipt{OperationID: i.OperationID, Fingerprint: op.Fingerprint, Status: "held", Error: reason, ArtifactDigest: i.ArtifactDigest, ManifestDigest: i.ManifestDigest, Cell: i.Cell, Role: i.Role, Environment: i.Environment, Generation: i.Generation, AuthorityEpoch: i.AuthorityEpoch}
	b, err := json.Marshal(op)
	if err != nil {
		return false, err
	}
	if _, err := s.operations.Update(ctx, key, b, revision); err == nil {
		return true, nil
	}
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		current, statusErr := s.Status(ctx, i.OperationID)
		if statusErr == nil && current.Fingerprint == op.Fingerprint && (current.Status == "held" || current.Status == "accepted") {
			return true, nil
		}
	}
	return false, fmt.Errorf("record fenced delivery: %w", err)
}

func validatePlan(intent Intent, plan []host.Desired) error {
	seen := make(map[string]struct{}, len(plan))
	active := 0
	for _, d := range plan {
		if d.Cell != intent.Cell || d.Role != intent.Role || d.Environment != intent.Environment || d.Generation != intent.Generation || d.AuthorityEpoch != intent.AuthorityEpoch || !nameRE.MatchString(d.Node) {
			return ErrInvalid
		}
		if _, ok := seen[d.Node]; ok {
			return ErrInvalid
		}
		seen[d.Node] = struct{}{}
		if d.Withdrawn {
			if d.Digest != "" || len(d.Args) != 0 || len(d.Env) != 0 {
				return ErrInvalid
			}
			continue
		}
		if d.Digest != intent.ArtifactDigest || ConfigDigestOf(d.Args, d.Env) != intent.ConfigDigest {
			return ErrInvalid
		}
		active++
	}
	if active != intent.DesiredReplicas || !slices.IsSortedFunc(plan, func(a, b host.Desired) int {
		if a.Node < b.Node {
			return -1
		}
		if a.Node > b.Node {
			return 1
		}
		return 0
	}) {
		return ErrInvalid
	}
	return nil
}

// verifiedIntent persists the one-time signature and authorization decision
// before any desired effect. A redelivery after the envelope's time window can
// resume the exact same bytes from this durable verified-wire record.
func (s *Service) verifiedIntent(ctx context.Context, wire []byte) (Intent, string, error) {
	sum := sha256.Sum256(wire)
	key := "w_" + hex.EncodeToString(sum[:])
	e, err := s.getOperation(ctx, key)
	if err == nil {
		var cached struct {
			Intent Intent `json:"intent"`
			Actor  string `json:"actor"`
		}
		if err := json.Unmarshal(e.Value(), &cached); err != nil {
			return Intent{}, "", err
		}
		if err := cached.Intent.Validate(); err != nil || cached.Intent.Cell != s.config.Cell || cached.Actor == "" {
			return Intent{}, "", ErrInvalid
		}
		return cached.Intent, cached.Actor, nil
	}
	if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return Intent{}, "", err
	}
	verified, err := s.config.Verifier.Verify(ctx, wire)
	if err != nil || verified.Actor == "" {
		return Intent{}, "", ErrInvalid
	}
	intent, err := DecodeIntent(verified.Payload)
	if err != nil || intent.Cell != s.config.Cell {
		return Intent{}, "", ErrInvalid
	}
	if err := s.config.Authorize(ctx, verified.Actor, intent); err != nil {
		return Intent{}, "", err
	}
	b, err := json.Marshal(struct {
		Intent Intent `json:"intent"`
		Actor  string `json:"actor"`
	}{intent, verified.Actor})
	if err != nil {
		return Intent{}, "", err
	}
	if _, err := s.operations.Create(ctx, key, b); err != nil && !errors.Is(err, jetstream.ErrKeyExists) {
		return Intent{}, "", fmt.Errorf("cache verified delivery intent: %w", err)
	}
	return intent, verified.Actor, nil
}

func (s *Service) reject(ctx context.Context, wire []byte, reason string) (bool, error) {
	sum := sha256.Sum256(wire)
	key := "r_" + hex.EncodeToString(sum[:])
	b, err := json.Marshal(Receipt{Fingerprint: hex.EncodeToString(sum[:]), Status: "rejected", Error: reason})
	if err != nil {
		return false, err
	}
	if _, err := s.operations.Create(ctx, key, b); err != nil && !errors.Is(err, jetstream.ErrKeyExists) {
		return false, fmt.Errorf("record rejected delivery: %w", err)
	}
	return true, nil
}

func (s *Service) rejectIntent(ctx context.Context, wire []byte, intent Intent, actor, reason string) (bool, error) {
	fingerprint, err := intent.fingerprint()
	if err != nil {
		return false, err
	}
	receipt := &Receipt{OperationID: intent.OperationID, Fingerprint: fingerprint, Status: "rejected", Error: reason, ArtifactDigest: intent.ArtifactDigest, ManifestDigest: intent.ManifestDigest, Cell: intent.Cell, Role: intent.Role, Environment: intent.Environment, Generation: intent.Generation, AuthorityEpoch: intent.AuthorityEpoch}
	op := operation{Intent: intent, Fingerprint: fingerprint, Actor: actor, Receipt: receipt}
	b, err := json.Marshal(op)
	if err != nil {
		return false, err
	}
	key := operationKey(intent.OperationID)
	if _, err := s.operations.Create(ctx, key, b); err == nil {
		return true, nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		return false, fmt.Errorf("record rejected intent: %w", err)
	}
	e, err := s.getOperation(ctx, key)
	if err != nil {
		return false, err
	}
	var existing operation
	if err := json.Unmarshal(e.Value(), &existing); err != nil {
		return false, err
	}
	if existing.Fingerprint == fingerprint && existing.Actor == actor && existing.Receipt != nil {
		return true, nil
	}
	return s.reject(ctx, wire, "operation ID already binds a different request")
}
