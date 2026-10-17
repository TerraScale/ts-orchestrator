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

type capacityChild struct {
	OperationID       string    `json:"operationId"`
	RecipeSHA256      string    `json:"recipeSha256"`
	InstanceID        string    `json:"instanceId"`
	BootVolumeID      string    `json:"bootVolumeId"`
	BornAt            time.Time `json:"bornAt"`
	InstanceRetiredAt time.Time `json:"instanceRetiredAt"`
	BootRetiredAt     time.Time `json:"bootRetiredAt"`
	Launch            struct {
		RequestSHA256  string    `json:"requestSha256"`
		FirstAttemptAt time.Time `json:"firstAttemptAt"`
	} `json:"launch"`
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
	children := map[string]capacityChild{}
	if len(current.capacityChildren) != 0 && string(current.capacityChildren) != "null" {
		if err := json.Unmarshal(current.capacityChildren, &children); err != nil {
			return VerifiedCapacityLedger{}, errors.New("protected child provenance has invalid schema")
		}
	}
	for _, host := range current.capacityLedger.Hosts {
		r := host.Receipt
		if r.TenancyID != current.authority.TenancyID || r.Quote.Cell != current.authority.Cell || r.Quote.Currency != current.capacityCurrency || r.GrantGeneration > current.authority.Generation ||
			r.GrantGeneration == current.authority.Generation && r.GrantSHA256 != current.authority.GrantSHA256 ||
			!slices.Contains(current.capacityCompartments, r.Quote.CompartmentID) {
			return VerifiedCapacityLedger{}, errors.New("protected financial history differs from its authenticated foundation scope")
		}
		if host.RequestSHA256 != "" {
			child, ok := children[r.OperationID]
			if !ok || child.OperationID != r.OperationID || child.RecipeSHA256 != r.RecipeSHA256 ||
				child.Launch.RequestSHA256 != host.RequestSHA256 || !child.Launch.FirstAttemptAt.Equal(host.StartedAt) {
				return VerifiedCapacityLedger{}, errors.New("protected liability differs from the exact original launch provenance")
			}
			if !host.BornAt.IsZero() && (child.InstanceID != host.InstanceID || child.BootVolumeID != host.BootVolumeID || !child.BornAt.Equal(host.BornAt)) ||
				!host.InstanceRetiredAt.IsZero() && !host.InstanceRetiredAt.Equal(child.InstanceRetiredAt) ||
				!host.BootRetiredAt.IsZero() && !host.BootRetiredAt.Equal(child.BootRetiredAt) {
				return VerifiedCapacityLedger{}, errors.New("protected liability differs from its positive child, boot or terminal result")
			}
		}
	}
	return VerifiedCapacityLedger{bindings: current, ledger: current.capacityLedger.Clone()}, nil
}

func (v VerifiedCapacityLedger) Cell() string                  { return v.bindings.authority.Cell }
func (v VerifiedCapacityLedger) TenancyID() string             { return v.bindings.authority.TenancyID }
func (v VerifiedCapacityLedger) Currency() string              { return v.bindings.capacityCurrency }
func (v VerifiedCapacityLedger) GrantSHA256() string           { return v.bindings.authority.GrantSHA256 }
func (v VerifiedCapacityLedger) Generation() uint64            { return v.bindings.authority.Generation }
func (v VerifiedCapacityLedger) Ledger() capacityledger.Ledger { return v.ledger.Clone() }

func (v VerifiedCapacityLedger) ExpiresAt() time.Time {
	freshUntil := v.bindings.observedAt.Add(2 * time.Minute)
	if v.bindings.expires.Before(freshUntil) {
		return v.bindings.expires
	}
	return freshUntil
}

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
