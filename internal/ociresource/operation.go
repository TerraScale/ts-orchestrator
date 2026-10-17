package ociresource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// Operation binds retries to one durable desired-resource convergence. A
// successful API response is not completion: observation must confirm the spec.
type Operation struct {
	ID           string           `json:"id"`
	Epoch        uint64           `json:"epoch"`
	StartedAt    time.Time        `json:"startedAt"`
	AppliedAt    time.Time        `json:"appliedAt,omitzero"`
	CompletedAt  time.Time        `json:"completedAt,omitzero"`
	WorkRequests []string         `json:"workRequests,omitempty"`
	Failure      string           `json:"failure,omitempty"`
	Requests     []RequestAttempt `json:"requests,omitempty"`
}

// RequestAttempt retains the exact mutation bytes and retry identity before
// dispatch. Authentication headers never enter this protected journal.
type RequestAttempt struct {
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	Body       []byte    `json:"body,omitempty"`
	IfMatch    string    `json:"ifMatch,omitempty"`
	RetryToken string    `json:"retryToken,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
	Deadline   time.Time `json:"deadline"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	Sent       bool      `json:"sent"`
	Status     int       `json:"status,omitzero"`
}

func (a RequestAttempt) sameRequest(b RequestAttempt) bool {
	return a.Method == b.Method && a.URL == b.URL && bytes.Equal(a.Body, b.Body) && a.IfMatch == b.IfMatch && a.RetryToken == b.RetryToken
}

// Uncertain requires observation or the exact original request before any
// different mutation may begin in this convergence.
func (a RequestAttempt) Uncertain() bool {
	return a.FinishedAt.IsZero() || a.Sent && (a.Status == 0 || a.Status >= 500 || a.Status == http.StatusRequestTimeout)
}

func requestAttempt(request *http.Request, now time.Time) (RequestAttempt, error) {
	deadline, ok := request.Context().Deadline()
	if !ok || !now.Before(deadline) || request.URL == nil || request.URL.User != nil {
		return RequestAttempt{}, errors.New("OCI mutation requires its original bounded request deadline and target")
	}
	attempt := RequestAttempt{Method: request.Method, URL: request.URL.String(), IfMatch: request.Header.Get("If-Match"),
		RetryToken: request.Header.Get("opc-retry-token"), StartedAt: now.UTC(), Deadline: deadline.UTC()}
	if request.Body != nil && request.Body != http.NoBody {
		if request.GetBody == nil {
			return RequestAttempt{}, errors.New("OCI mutation cannot checkpoint its exact request body")
		}
		body, err := request.GetBody()
		if err != nil {
			return RequestAttempt{}, err
		}
		defer body.Close()
		attempt.Body, err = io.ReadAll(io.LimitReader(body, maxRecordBytes+1))
		if err != nil || len(attempt.Body) > maxRecordBytes {
			return RequestAttempt{}, errors.Join(errors.New("OCI mutation request exceeds its byte bound"), err)
		}
	}
	return attempt, nil
}

func beginRequest(operation Operation, attempt RequestAttempt, now time.Time) (Operation, int, error) {
	operation.Requests = slices.Clone(operation.Requests)
	for _, previous := range operation.Requests {
		if previous.Uncertain() && !previous.sameRequest(attempt) {
			return Operation{}, 0, errors.New("uncertain original OCI request differs from retry bytes or token")
		}
	}
	for i, previous := range operation.Requests {
		if previous.sameRequest(attempt) {
			if !now.Before(previous.Deadline) {
				return Operation{}, 0, errors.New("original OCI request deadline expired; outcome needs observation")
			}
			// A retry retains the first deadline and exact bytes. A missing
			// outcome after this checkpoint remains uncertain on restart.
			previous.FinishedAt, previous.Status, previous.Sent = time.Time{}, 0, false
			operation.Requests[i] = previous
			return operation, i, nil
		}
	}
	if len(operation.Requests) >= 128 {
		return Operation{}, 0, errors.New("OCI operation request journal exceeds its bound")
	}
	operation.Requests = append(operation.Requests, attempt)
	return operation, len(operation.Requests) - 1, nil
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
	if len(o.Requests) > 128 {
		return errors.New("OCI operation request journal exceeds its bound")
	}
	for _, request := range o.Requests {
		if request.Method == "" || request.URL == "" || len(request.URL) > 4096 || len(request.Body) > maxRecordBytes ||
			len(request.IfMatch) > 1024 || len(request.RetryToken) > 256 || request.StartedAt.Before(o.StartedAt) ||
			!request.Deadline.After(request.StartedAt) || !request.FinishedAt.IsZero() && request.FinishedAt.Before(request.StartedAt) ||
			request.Status < 0 || request.Status > 599 || request.Status != 0 && (!request.Sent || request.FinishedAt.IsZero()) {
			return errors.New("OCI operation request has invalid original bytes, deadline or outcome")
		}
	}
	return nil
}

func checkpointRequest(ctx context.Context, request *http.Request, desired *Desired, store Store, epoch uint64, now func() time.Time) (func(*http.Response, error, bool) error, error) {
	if desired.Operation == nil {
		return nil, errors.New("OCI wire request has no durable operation")
	}
	attempt, err := requestAttempt(request, now())
	if err != nil {
		return nil, err
	}
	operation, index, err := beginRequest(*desired.Operation, attempt, now())
	if err != nil {
		return nil, err
	}
	retained, cancel := context.WithDeadline(request.Context(), operation.Requests[index].Deadline)
	*request = *request.WithContext(retained)
	ctx = retained
	desired.Operation = &operation
	*desired, err = store.SaveOperation(ctx, *desired, epoch, now(), false)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := ociclient.LimitAdmission(request.Context(), desired.Operation.Requests[index].Deadline); err != nil {
		cancel()
		return nil, err
	}
	return func(response *http.Response, _ error, sent bool) error {
		if response == nil || response.Body == nil {
			defer cancel()
		} else {
			// OCI decodes the response after dispatch returns. Keep its bounded
			// context live until that body closes rather than canceling early.
			response.Body = retainedRequestBody{ReadCloser: response.Body, cancel: cancel}
		}
		operation := *desired.Operation
		operation.Requests = slices.Clone(operation.Requests)
		attempt := operation.Requests[index]
		attempt.FinishedAt, attempt.Sent = now(), sent
		if response != nil && sent {
			attempt.Status = response.StatusCode
		}
		operation.Requests[index] = attempt
		desired.Operation = &operation
		updated, err := store.SaveOperation(ctx, *desired, epoch, now(), false)
		if err != nil {
			return fmt.Errorf("persist original OCI request outcome: %w", err)
		}
		*desired = updated
		return nil
	}, nil
}

type retainedRequestBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b retainedRequestBody) Close() error { defer b.cancel(); return b.ReadCloser.Close() }

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
