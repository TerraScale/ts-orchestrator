package ociresource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
	"uuid"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// Operation binds retries to one durable desired-resource convergence. A
// successful API response is not completion: observation must confirm the spec.
type Operation struct {
	ID           string    `json:"id"`
	Epoch        uint64    `json:"epoch"`
	StartedAt    time.Time `json:"startedAt"`
	AppliedAt    time.Time `json:"appliedAt,omitzero"`
	CompletedAt  time.Time `json:"completedAt,omitzero"`
	WorkRequests []string  `json:"workRequests,omitempty"`
	Failure      string    `json:"failure,omitempty"`
}

func (o Operation) validate() error {
	if _, err := uuid.Parse(o.ID); err != nil || o.Epoch == 0 || o.StartedAt.IsZero() ||
		!o.CompletedAt.IsZero() && o.CompletedAt.Before(o.StartedAt) {
		return errors.New("OCI resource operation identity, epoch, or timestamps are invalid")
	}
	if len(o.WorkRequests) > 512 || len(o.Failure) > 4096 || !o.CompletedAt.IsZero() && len(o.WorkRequests) != 0 {
		return errors.New("OCI operation work requests exceed their bound or remain unfinished")
	}
	for _, id := range o.WorkRequests {
		if id == "" || len(id) > 1024 {
			return errors.New("OCI operation work request ID is invalid")
		}
	}
	return nil
}

type operationContextKey struct{}

type operationContext struct {
	id     string
	record func(context.Context, string) error
}

// WithOperation carries an already persisted operation ID to OCI SDK calls.
// It confers no authority; callers still fence every mutation separately.
func WithOperation(ctx context.Context, operationID string) context.Context {
	if existing, ok := ctx.Value(operationContextKey{}).(operationContext); ok && existing.id == operationID {
		return ctx
	}
	return context.WithValue(ctx, operationContextKey{}, operationContext{id: operationID})
}

// RecordWorkRequest checkpoints an accepted asynchronous OCI mutation before
// waiting for it, so the next leader can finish observing it before new writes.
func RecordWorkRequest(ctx context.Context, id string) error {
	operation, _ := ctx.Value(operationContextKey{}).(operationContext)
	if operation.record == nil {
		return nil
	}
	return operation.record(ctx, id)
}

// RetryToken derives a stable OCI token for one request within an operation.
// Step must bind the request's target and payload, so different requests never
// share a token. Direct SDK consumers without an operation retain fresh tokens.
func RetryToken(ctx context.Context, step string) string {
	operation, _ := ctx.Value(operationContextKey{}).(operationContext)
	if operation.id == "" {
		return common.RetryToken()
	}
	sum := sha256.Sum256([]byte(operation.id + "\x00" + step))
	return hex.EncodeToString(sum[:])
}
