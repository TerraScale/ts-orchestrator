package foundationbinding

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
)

// VerifiedCapacityLedger is protected root history, not a declaration that
// every resource or charge is covered. Only the authenticated SDK reader mints it.
type VerifiedCapacityLedger struct {
	bindings VerifiedBindings
	ledger   capacityledger.Ledger
}

// CapacityLedger rereads the current grant and protected FoundationRecord.
// Regional KV entries, tags and caller-provided records never enter this path.
func (v VerifiedBindings) CapacityLedger(ctx context.Context) (VerifiedCapacityLedger, error) {
	if v.factory == nil {
		return VerifiedCapacityLedger{}, errors.New("capacity history lacks authenticated foundation bindings")
	}
	authority := v.authority
	authority.Keys = nil
	current, err := Verify(ctx, v.factory, authority, v.wire)
	if err != nil {
		return VerifiedCapacityLedger{}, err
	}
	if current.capacityLedger == nil {
		return VerifiedCapacityLedger{}, errors.New("protected root capacity ledger is absent")
	}
	for _, host := range current.capacityLedger.Hosts {
		r := host.Receipt
		if r.TenancyID != current.authority.TenancyID || r.Quote.Cell != current.authority.Cell || r.Quote.Currency != current.capacityCurrency || r.GrantGeneration > current.authority.Generation ||
			r.GrantGeneration == current.authority.Generation && r.GrantSHA256 != current.authority.GrantSHA256 ||
			!slices.Contains(current.capacityCompartments, r.Quote.CompartmentID) {
			return VerifiedCapacityLedger{}, errors.New("protected financial history differs from its authenticated foundation scope")
		}
	}
	return VerifiedCapacityLedger{bindings: current, ledger: current.capacityLedger.Clone()}, nil
}

func (v VerifiedCapacityLedger) Cell() string                  { return v.bindings.authority.Cell }
func (v VerifiedCapacityLedger) TenancyID() string             { return v.bindings.authority.TenancyID }
func (v VerifiedCapacityLedger) Currency() string              { return v.bindings.capacityCurrency }
func (v VerifiedCapacityLedger) GrantSHA256() string           { return v.bindings.authority.GrantSHA256 }
func (v VerifiedCapacityLedger) Generation() uint64            { return v.bindings.authority.Generation }
func (v VerifiedCapacityLedger) ExpiresAt() time.Time          { return v.bindings.expires }
func (v VerifiedCapacityLedger) Ledger() capacityledger.Ledger { return v.ledger.Clone() }

func (v VerifiedCapacityLedger) ValidAt(now time.Time) bool {
	return v.bindings.factory != nil && !v.bindings.observedAt.After(now) && now.Sub(v.bindings.observedAt) <= 2*time.Minute && now.Before(v.ExpiresAt())
}

// Revalidate rejects any changed ledger; a new root effect needs a new snapshot.
func (v VerifiedCapacityLedger) Revalidate(ctx context.Context) error {
	if !v.ValidAt(time.Now()) {
		return errors.New("protected capacity history is absent or stale")
	}
	current, err := v.bindings.CapacityLedger(ctx)
	if err != nil {
		return err
	}
	left, leftErr := json.Marshal(v.ledger, json.Deterministic(true))
	right, rightErr := json.Marshal(current.ledger, json.Deterministic(true))
	if leftErr != nil || rightErr != nil || string(left) != string(right) {
		return errors.New("protected capacity history changed after accounting")
	}
	return nil
}
