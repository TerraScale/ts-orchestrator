package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	operatorBindRecoveryTimeout     = 15 * time.Second
	operatorBindAttemptTimeout      = 5 * time.Second
	operatorAdmissionAttemptTimeout = 10 * time.Second
	operatorSubmitSetupTimeout      = 10 * time.Second
	operatorRetryInitialBackoff     = 100 * time.Millisecond
	operatorRetryMaxBackoff         = 800 * time.Millisecond
)

func operatorService(ctx context.Context, cfg Config, runtime *natscell.Runtime, signed bool) (*delivery.Service, error) {
	settings := delivery.Config{Conn: runtime.Conn(), JS: runtime.JetStream(), Cell: cfg.NATS.Cell}
	if signed {
		policy, err := buildSignerPolicy(cfg)
		if err != nil {
			return nil, err
		}
		codec, err := policy.withOperator(cfg.Operator)
		if err != nil {
			return nil, err
		}
		settings.Signer = codec
		settings.ArtifactSigner = codec
		settings.ArtifactVerifier = codec
		settings.AuthorizeArtifact = policy.authorizeArtifact
	}
	return delivery.ConnectClient(ctx, settings)
}

func retryableOperatorBackendError(err error, attemptTimedOut bool) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return attemptTimedOut
	}
	if errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrDisconnected) || errors.Is(err, nats.ErrNoServers) ||
		errors.Is(err, jetstream.ErrNoStreamResponse) {
		return true
	}
	if api, ok := errors.AsType[*jetstream.APIError](err); ok {
		return api.Code == 503 && api.ErrorCode == 10008
	}
	if api, ok := errors.AsType[*nats.APIError](err); ok {
		return api.Code == 503 && api.ErrorCode == 10008
	}
	return false
}

func waitOperatorRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func retryOperatorMetadata[T any](ctx context.Context, call func(context.Context) (T, error)) (T, error) {
	var zero T
	backoff := operatorRetryInitialBackoff
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		attemptCtx, stop := context.WithTimeout(ctx, operatorBindAttemptTimeout)
		value, err := call(attemptCtx)
		attemptTimedOut := errors.Is(attemptCtx.Err(), context.DeadlineExceeded)
		stop()
		if err == nil {
			return value, nil
		}
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		if !retryableOperatorBackendError(err, attemptTimedOut) {
			return zero, err
		}
		if err := waitOperatorRetry(ctx, backoff); err != nil {
			return zero, err
		}
		backoff = min(backoff*2, operatorRetryMaxBackoff)
	}
}

func observeOperatorAuthority(ctx context.Context, observe func(context.Context) (authority.Snapshot, error)) (uint64, error) {
	snapshot, err := retryOperatorMetadata(ctx, observe)
	if err != nil {
		return 0, fmt.Errorf("observe regional authority: %w", err)
	}
	if !snapshot.Ready || snapshot.Reason != "observed" || snapshot.Epoch == 0 || !time.Now().Before(snapshot.ExpiresAt) {
		return 0, errors.New("regional authority lease is not current")
	}
	return snapshot.Epoch, nil
}

// submitIntent fills an intent's defaults, signs and submits it, and returns
// the submitted intent with its fingerprint. The fingerprint is set once
// Submit was called, even when it failed: only then may the intent have been
// published.
func submitIntent(ctx context.Context, cfg Config, runtime *natscell.Runtime, intent delivery.Intent) (delivery.Intent, string, error) {
	if intent.SchemaVersion == 0 {
		intent.SchemaVersion = delivery.SchemaVersion
	}
	if intent.Cell == "" {
		intent.Cell = cfg.NATS.Cell
	}
	if intent.Cell != cfg.NATS.Cell {
		return intent, "", errors.New("delivery intent belongs to another cell")
	}
	if intent.OperationID == "" {
		intent.OperationID = entityid.New()
	}
	// Both setup calls are read-only. Keep their total recovery within ten
	// seconds, and never replay Submit after an ambiguous intent publish.
	setupCtx, stopSetup := context.WithTimeout(ctx, operatorSubmitSetupTimeout)
	defer stopSetup()
	if intent.AuthorityEpoch == 0 {
		epoch, err := observeOperatorAuthority(setupCtx, func(attemptCtx context.Context) (authority.Snapshot, error) {
			return authority.Observe(attemptCtx, runtime.JetStream(), cfg.NATS.Cell)
		})
		if err != nil {
			return intent, "", err
		}
		intent.AuthorityEpoch = epoch
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return intent, "", err
	}
	service, err := retryOperatorMetadata(setupCtx, func(attemptCtx context.Context) (*delivery.Service, error) {
		return operatorService(attemptCtx, cfg, runtime, true)
	})
	if err != nil {
		return intent, "", fmt.Errorf("bind delivery client: %w", err)
	}
	if err := service.Submit(ctx, intent); err != nil {
		return intent, fingerprint, fmt.Errorf("submit operation %s fingerprint %s: %w", intent.OperationID, fingerprint, err)
	}
	return intent, fingerprint, nil
}
