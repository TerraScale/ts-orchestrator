package oci

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const (
	PoolWirePoint  = "point"
	PoolWireGrowth = "growth"
)

// PoolWireAttempt is consistency evidence, not independently authenticated origin.
// Every SDK retry receives its own immutable begin and outcome records.
type PoolWireAttempt struct {
	OperationID   string    `json:"operationId"`
	Kind          string    `json:"kind"`
	AttemptID     string    `json:"attemptId"`
	RequestSHA256 string    `json:"requestSha256"`
	StartedAt     time.Time `json:"startedAt"`
}

// PoolWireOutcome never classifies earlier attempts. Missing outcomes and
// transport failures remain unknown even when a later attempt returns 412.
type PoolWireOutcome struct {
	OperationID    string `json:"operationId"`
	Kind           string `json:"kind"`
	AttemptID      string `json:"attemptId"`
	StatusCode     int    `json:"statusCode"`
	OpcRequestID   string `json:"opcRequestId,omitempty"`
	TransportError bool   `json:"transportError,omitzero"`
	NotSent        bool   `json:"notSent,omitzero"`
}

type PoolWireRecord struct {
	Attempt PoolWireAttempt
	Outcome *PoolWireOutcome
}

// ListPoolWireAttempts retains each earlier unknown beside later outcomes.
// These local records never independently authorize a successor or adoption.
func (journal *KVJournal) ListPoolWireAttempts(ctx context.Context, operationID, kind string) ([]PoolWireRecord, error) {
	if _, _, err := journal.poolWireRequest(ctx, operationID, kind); err != nil {
		return nil, err
	}
	keys, err := journal.kv.Keys(ctx)
	if errors.Is(err, jetstream.ErrNoKeysFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(keys) > 10_000 {
		return nil, errors.New("pool wire inventory exceeds safety bound")
	}
	var records []PoolWireRecord
	for _, key := range keys {
		entry, err := journal.read(ctx, key)
		if err != nil {
			return nil, err
		}
		attempt := entry.PoolWireAttempt
		if entry.Kind != "pool-wire-attempt" || attempt.OperationID != operationID || attempt.Kind != kind {
			continue
		}
		if key != poolWireKey(operationID, kind, attempt.AttemptID, "begin") {
			return nil, errors.New("pool wire begin has an invalid key")
		}
		verified, found, err := journal.GetPoolWireAttempt(ctx, operationID, kind, attempt.AttemptID)
		if err != nil || !found {
			return nil, errors.Join(err, errors.New("pool wire begin disappeared"))
		}
		record := PoolWireRecord{Attempt: verified}
		outcome, found, err := journal.GetPoolWireOutcome(ctx, operationID, kind, attempt.AttemptID)
		if err != nil {
			return nil, err
		}
		if found {
			record.Outcome = new(outcome)
		}
		records = append(records, record)
	}
	return records, nil
}

func (journal *KVJournal) poolWireRequest(ctx context.Context, operationID, kind string) (string, time.Time, error) {
	switch kind {
	case PoolCreateConfiguration, PoolCreatePool:
		request, found, err := journal.GetPoolCreateRequest(ctx, operationID, kind)
		if err != nil || !found {
			return "", time.Time{}, errors.Join(err, errors.New("wire attempt lacks original create request"))
		}
		return request.RequestSHA256, request.StartedAt, nil
	case PoolWirePoint:
		request, found, err := journal.GetPoolPointRequest(ctx, operationID)
		if err != nil || !found {
			return "", time.Time{}, errors.Join(err, errors.New("wire attempt lacks original point request"))
		}
		return request.Request.RequestSHA256, request.Request.StartedAt, nil
	case PoolWireGrowth:
		request, found, err := journal.GetCapacityRequest(ctx, operationID)
		if err != nil || !found {
			return "", time.Time{}, errors.Join(err, errors.New("wire attempt lacks original growth request"))
		}
		return request.RequestSHA256, request.StartedAt, nil
	default:
		return "", time.Time{}, errors.New("unknown pool wire operation")
	}
}

func poolWireKey(operationID, kind, attemptID, record string) string {
	return entityid.Derive("oci-pool-wire", operationID, kind, attemptID, record)
}

func (journal *KVJournal) RecordPoolWireAttempt(ctx context.Context, attempt PoolWireAttempt) error {
	digest, originalStarted, err := journal.poolWireRequest(ctx, attempt.OperationID, attempt.Kind)
	if err != nil {
		return err
	}
	if !entityid.Valid(attempt.AttemptID) || attempt.RequestSHA256 != digest || attempt.StartedAt.IsZero() ||
		attempt.StartedAt.Location() != time.UTC || attempt.StartedAt.Before(originalStarted) ||
		attempt.StartedAt.Sub(originalStarted) >= 23*time.Hour {
		return errors.New("wire attempt differs from original request or its original retry window")
	}
	return journal.writePoolEntry(ctx, poolWireKey(attempt.OperationID, attempt.Kind, attempt.AttemptID, "begin"), journalEntry{
		SchemaVersion: journalSchema, Kind: "pool-wire-attempt", PoolWireAttempt: attempt})
}

func (journal *KVJournal) GetPoolWireAttempt(ctx context.Context, operationID, kind, attemptID string) (PoolWireAttempt, bool, error) {
	if journal == nil || !entityid.Valid(operationID) || !entityid.Valid(attemptID) {
		return PoolWireAttempt{}, false, errors.New("wire lookup requires exact operation and attempt")
	}
	entry, err := journal.read(ctx, poolWireKey(operationID, kind, attemptID, "begin"))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return PoolWireAttempt{}, false, nil
	}
	if err != nil {
		return PoolWireAttempt{}, false, err
	}
	attempt := entry.PoolWireAttempt
	digest, started, requestErr := journal.poolWireRequest(ctx, operationID, kind)
	if requestErr != nil || entry.Kind != "pool-wire-attempt" || attempt.OperationID != operationID || attempt.Kind != kind ||
		attempt.AttemptID != attemptID || attempt.RequestSHA256 != digest || attempt.StartedAt.IsZero() || attempt.StartedAt.Location() != time.UTC ||
		attempt.StartedAt.Before(started) || attempt.StartedAt.Sub(started) >= 23*time.Hour {
		return PoolWireAttempt{}, false, errors.Join(requestErr, errors.New("pool wire attempt is corrupt"))
	}
	return attempt, true, nil
}

func validPoolWireOutcome(outcome PoolWireOutcome) bool {
	return (outcome.StatusCode == 0 && outcome.TransportError || !outcome.NotSent && outcome.StatusCode >= 100 && outcome.StatusCode <= 599) &&
		len(outcome.OpcRequestID) <= 1024 && !strings.ContainsAny(outcome.OpcRequestID, "\r\n")
}

func (journal *KVJournal) RecordPoolWireOutcome(ctx context.Context, outcome PoolWireOutcome) error {
	if _, found, err := journal.GetPoolWireAttempt(ctx, outcome.OperationID, outcome.Kind, outcome.AttemptID); err != nil || !found {
		return errors.Join(err, errors.New("wire outcome requires its exact durable begin"))
	}
	if !validPoolWireOutcome(outcome) {
		return errors.New("wire outcome lacks an exact HTTP or transport outcome")
	}
	return journal.writePoolEntry(ctx, poolWireKey(outcome.OperationID, outcome.Kind, outcome.AttemptID, "outcome"), journalEntry{
		SchemaVersion: journalSchema, Kind: "pool-wire-outcome", PoolWireOutcome: outcome})
}

func (journal *KVJournal) GetPoolWireOutcome(ctx context.Context, operationID, kind, attemptID string) (PoolWireOutcome, bool, error) {
	if _, found, err := journal.GetPoolWireAttempt(ctx, operationID, kind, attemptID); err != nil || !found {
		return PoolWireOutcome{}, false, err
	}
	entry, err := journal.read(ctx, poolWireKey(operationID, kind, attemptID, "outcome"))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return PoolWireOutcome{}, false, nil
	}
	if err != nil {
		return PoolWireOutcome{}, false, err
	}
	outcome := entry.PoolWireOutcome
	if entry.Kind != "pool-wire-outcome" || outcome.OperationID != operationID || outcome.Kind != kind || outcome.AttemptID != attemptID || !validPoolWireOutcome(outcome) {
		return PoolWireOutcome{}, false, errors.New("pool wire outcome is corrupt")
	}
	return outcome, true, nil
}
