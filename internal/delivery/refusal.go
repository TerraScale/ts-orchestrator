package delivery

import (
	"context"
	"encoding/json/v2"
)

// RefuseIntent records a controller-authorized pre-submission refusal.
// The current leader may settle an old epoch; existing claimed plans remain untouched.
func (s *Service) RefuseIntent(ctx context.Context, intent Intent, actor string, authorityEpoch uint64, reason string) error {
	if s == nil || s.operations == nil || s.config.Authorize == nil || s.config.Fencer == nil {
		return ErrInvalid
	}
	if actor == "" || reason == "" || len(reason) > 1024 || intent.Cell != s.config.Cell {
		return ErrInvalid
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	if err := s.config.Authorize(ctx, actor, intent); err != nil {
		return err
	}
	if err := s.config.Fencer.Guard(ctx, authorityEpoch); err != nil {
		return err
	}
	wire, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	terminal, err := s.recordIntentReceipt(ctx, wire, intent, actor, "rejected", reason)
	if err != nil {
		return err
	}
	if !terminal {
		return ErrConflict
	}
	entry, err := s.getOperation(ctx, operationKey(intent.OperationID))
	if err != nil {
		return err
	}
	var stored operation
	if err := json.Unmarshal(entry.Value(), &stored); err != nil {
		return err
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	if stored.Fingerprint != fingerprint || stored.Actor != actor || stored.Receipt == nil || stored.Receipt.Status != "rejected" {
		return ErrConflict
	}
	return nil
}
