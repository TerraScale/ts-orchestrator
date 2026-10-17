package delivery

import (
	"context"
	"encoding/json/v2"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// NativeCanaryIntent reads only a genuinely accepted native operation.
func (s *Service) NativeCanaryIntent(ctx context.Context, operationID string) (Intent, error) {
	if s == nil || !entityid.Valid(operationID) || s.config.Authorize == nil {
		return Intent{}, ErrInvalid
	}
	entry, err := s.getOperation(ctx, operationKey(operationID))
	if err != nil {
		return Intent{}, err
	}
	var op operation
	if err := json.Unmarshal(entry.Value(), &op, json.RejectUnknownMembers(true)); err != nil {
		return Intent{}, err
	}
	fingerprint, err := op.Intent.Fingerprint()
	if err != nil || op.Intent.Container != nil || op.Intent.OperationID != operationID || fingerprint != op.Fingerprint || op.Actor == "" ||
		op.Intent.Cell != s.config.Cell || op.Receipt == nil || op.Receipt.Status != "accepted" {
		return Intent{}, ErrUnauthorized
	}
	if err := s.config.Authorize(ctx, op.Actor, op.Intent.Clone()); err != nil {
		return Intent{}, err
	}
	return op.Intent.Clone(), nil
}
