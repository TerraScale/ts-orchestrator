package delivery

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
)

func (s *Service) processContainer(ctx context.Context, wire []byte, intent Intent, actor, fingerprint string, entry *operationValue) (bool, error) {
	if s.config.ContainerApply == nil {
		if entry != nil {
			return false, stageDeliveryError("container_apply", errors.New("container admission is unavailable"))
		}
		return s.rejectIntent(ctx, wire, intent, actor, "container admission is unavailable")
	}
	key := operationKey(intent.OperationID)
	if entry == nil {
		if err := s.config.Fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
			if errors.Is(err, authority.ErrFenced) {
				return s.rejectIntent(ctx, wire, intent, actor, "authority epoch was fenced before acceptance")
			}
			return false, stageDeliveryError("container_guard", err)
		}
	}
	op := operation{Intent: intent.Clone(), Fingerprint: fingerprint, Actor: actor}
	var revision uint64
	if entry == nil {
		data, err := json.Marshal(op)
		if err != nil {
			return false, err
		}
		revision, err = s.operations.Create(ctx, key, data)
		if errors.Is(err, jetstream.ErrKeyExists) {
			entry, err = s.getOperation(ctx, key)
		}
		if err != nil {
			return false, stageDeliveryError("operation_create", err)
		}
	}
	if entry != nil {
		if err := json.Unmarshal(entry.Value(), &op); err != nil {
			return false, err
		}
		revision = entry.Revision()
	}
	if op.Intent.OperationID != intent.OperationID || op.Fingerprint != fingerprint || op.Actor != actor {
		return s.reject(ctx, wire, "operation ID already binds a different request")
	}
	if op.Receipt != nil {
		return true, nil
	}
	// The CAS above retains the authenticated proof before SwarmKit can create
	// tasks; registry resolution reads that same operation while apply is pending.
	if err := s.config.Fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
		if errors.Is(err, authority.ErrFenced) {
			return s.hold(ctx, key, op, revision, "authority epoch fenced; reconcile with a new intent")
		}
		return false, stageDeliveryError("container_guard", err)
	}
	if err := s.config.ContainerApply(ctx, op.Intent.Clone()); err != nil {
		if errors.Is(err, ErrInvalid) || errors.Is(err, ErrUnauthorized) {
			return s.hold(ctx, key, op, revision, "container admission refused; reconcile with a new intent")
		}
		if errors.Is(err, authority.ErrFenced) {
			return s.hold(ctx, key, op, revision, "authority epoch fenced; reconcile with a new intent")
		}
		return false, stageDeliveryError("container_apply", err)
	}
	if err := s.config.Fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
		return false, stageDeliveryError("receipt_guard", err)
	}
	op.Receipt = &Receipt{OperationID: intent.OperationID, Fingerprint: fingerprint, Status: "accepted", Cell: intent.Cell, Role: intent.Role, Environment: intent.Environment, Generation: intent.Generation, AuthorityEpoch: intent.AuthorityEpoch}
	data, err := json.Marshal(op)
	if err != nil {
		return false, err
	}
	if _, err := s.operations.Update(ctx, key, data, revision); err != nil {
		if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
			receipt, readErr := s.StatusFor(ctx, intent)
			if readErr == nil && receipt.Status == "accepted" {
				return true, nil
			}
		}
		return false, err
	}
	recordIntentDecision(ctx, intent, decisionlog.KindDeliveryApplied, decisionlog.StatusSucceeded, intent.DesiredReplicas, "signed OCI release admitted by SwarmKit with application readiness")
	return true, nil
}

// ContainerIntent returns the exact authenticated proof retained before runtime
// mutation. The manager must independently bind its actual service/task to this
// operation and verify the release and registry authority before pulling.
func (s *Service) ContainerIntent(ctx context.Context, operationID string) (Intent, error) {
	if s == nil || s.config.Authorize == nil {
		return Intent{}, ErrInvalid
	}
	op, err := s.containerIntentRecord(ctx, operationID)
	if err != nil {
		return Intent{}, err
	}
	if err := s.config.Authorize(ctx, op.Actor, op.Intent.Clone()); err != nil {
		return Intent{}, err
	}
	return op.Intent.Clone(), nil
}

// RetainedContainerIntent reads public provenance from an exact protected record.
// It does not prove original actor admission, execution, or existence before root
// retirement. Consumers must verify the signed bundle and actual prior writer
// independently; this read grants no current execution authority.
func (s *Service) RetainedContainerIntent(ctx context.Context, operationID string) (Intent, error) {
	op, err := s.containerIntentRecord(ctx, operationID)
	if err != nil {
		return Intent{}, err
	}
	return op.Intent.Clone(), nil
}

func (s *Service) containerIntentRecord(ctx context.Context, operationID string) (operation, error) {
	if s == nil || !entityid.Valid(operationID) {
		return operation{}, ErrInvalid
	}
	entry, err := s.getOperation(ctx, operationKey(operationID))
	if err != nil {
		return operation{}, err
	}
	var op operation
	if err := json.Unmarshal(entry.Value(), &op); err != nil {
		return operation{}, err
	}
	fingerprint, err := op.Intent.Fingerprint()
	if err != nil || op.Intent.Container == nil || op.Intent.OperationID != operationID || fingerprint != op.Fingerprint || op.Actor == "" || op.Intent.Cell != s.config.Cell {
		return operation{}, ErrConflict
	}
	if op.Receipt != nil && op.Receipt.Status != "accepted" {
		return operation{}, fmt.Errorf("%w: container operation is %s", ErrUnauthorized, op.Receipt.Status)
	}
	return op, nil
}
