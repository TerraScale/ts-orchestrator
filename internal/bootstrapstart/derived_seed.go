package bootstrapstart

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// DerivedSeedRecords preserves the original reservation before any ledger write
// and the completion before publishing the observed founder result.
type DerivedSeedRecords struct {
	Reservation ExternalSeedReservationRecords `json:"reservation"`
	Completion  ExternalSeedCompletionRecords  `json:"completion"`
}

// DerivedSeedJournal loads existing records when proposed is nil. A proposal
// must be durably checkpointed before returning the winning bytes.
type DerivedSeedJournal func(context.Context, *DerivedSeedRecords) (DerivedSeedRecords, error)

// EnsureDerivedSeed uses the original ledger transaction for an independently
// observed source founder. No root signing key or replacement store is used.
func EnsureDerivedSeed(ctx context.Context, roots trust.Keyring, anchor bootstrap.VerifiedBootstrapAnchor, authority bootstrap.DerivedStartupAuthority, founder VerifiedSourceFounder, ledgerPrivate ed25519.PrivateKey, journal DerivedSeedJournal) (bootstrap.SlotState, error) {
	manifest := authority.Manifest()
	if journal == nil || !founder.IsVerified() || !authority.IsVerified() || authority.AnchorDigest() != anchor.Digest() || founder.GrantDigest() != digest(authority.GrantWire()) || founder.TemplateDigest() != authority.TemplateDigest() || founder.SeedSlot() != manifest.SeedSlot || manifest.Slot != manifest.SeedSlot || authority.VerifyLedgerKey(ledgerPrivatePublic(ledgerPrivate)) != nil {
		return bootstrap.SlotState{}, ErrSourceFounder
	}
	factory, guarded, err := founder.GuardedFactory(ctx)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	ctx = guarded
	observed, err := founder.ObserveCurrent(ctx)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	if observed.BootstrapCreateKey == "" {
		return bootstrap.SlotState{}, ErrExternalSeedObservation
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	ledger, err := authority.OpenLedgerWithClient(ctx, roots, &objects)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	scope := bootstrap.BootstrapScope{DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Slot: manifest.SeedSlot}
	checkpoint, err := journal(ctx, nil)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	state, err := ledger.ReadSlot(ctx, scope)
	if errors.Is(err, bootstrap.ErrRecordMissing) {
		if len(checkpoint.Reservation.IntentWire) == 0 {
			records, buildErr := BuildExternalSeedReservation(ExternalSeedReservationRequest{Identity: BakedIdentity{DeploymentID: manifest.DeploymentID, Cell: manifest.Cell, Environment: manifest.Environment}, Anchor: anchor, Manifest: authority, ReviewedPlanSHA256: authority.TemplateDigest(), CreateIdentity: observed.BootstrapCreateKey, LedgerPrivate: ledgerPrivate, Now: time.Now().UTC(), ExpiresAt: authority.ExpiresAt()})
			if buildErr != nil {
				return bootstrap.SlotState{}, buildErr
			}
			checkpoint.Reservation = records
			checkpoint, err = journal(ctx, &checkpoint)
			if err != nil {
				return bootstrap.SlotState{}, err
			}
		}
		state, err = ledger.ReserveSlot(ctx, scope, checkpoint.Reservation.IntentWire, checkpoint.Reservation.InitialHeadWire)
	}
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	expectedIP, err := founder.template.SlotPrivateIP(manifest.SeedSlot)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	if _, err := VerifyExternalSeedObservation(anchor, authority, state, observed, expectedIP); err != nil {
		return bootstrap.SlotState{}, err
	}
	if state.Head.ResultDigest != "" && state.Result != nil {
		if state.Result.InstanceOCID != founder.InstanceID() {
			return bootstrap.SlotState{}, ErrExternalSeedObservation
		}
		return state, nil
	}
	facts, err := VerifyExternalSeedObservation(anchor, authority, state, observed, expectedIP)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	records := checkpoint.Completion
	if len(records.ResultWire) == 0 {
		observed, err = founder.ObserveCurrent(ctx)
		if err != nil {
			return bootstrap.SlotState{}, err
		}
		now := time.Now().UTC()
		var reuse []byte
		if state.SeedReceiptRecord != nil {
			reuse = state.SeedReceiptRecord.Bytes
		}
		records, err = BuildExternalSeedCompletion(ExternalSeedCompletionRequest{Identity: BakedIdentity{DeploymentID: manifest.DeploymentID, Cell: manifest.Cell, Environment: manifest.Environment}, Anchor: anchor, Manifest: authority, Roots: roots, State: state, Observation: observed, ObservedAt: now, ExpectedPrivateIP: expectedIP, LedgerPrivate: ledgerPrivate, ReuseReceiptWire: reuse, Now: now, ExpiresAt: authority.ExpiresAt()})
		if err != nil {
			return bootstrap.SlotState{}, err
		}
		checkpoint.Completion = records
		checkpoint, err = journal(ctx, &checkpoint)
		if err != nil {
			return bootstrap.SlotState{}, err
		}
		records = checkpoint.Completion
	}
	// A checkpoint can repair a committed result indefinitely. It cannot
	// authorize the first write of an observation past its freshness bound.
	_, _, stored, err := ledger.ExternalSeedProgress(ctx, scope, authority.Wire(), records.ReceiptWire, records.ResultWire)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	if !stored {
		envelope, err := trust.DecodeEnvelope(records.ResultWire)
		if err != nil {
			return bootstrap.SlotState{}, err
		}
		if err := authority.VerifyLedgerEnvelope(envelope, trust.Scope{Domain: "bootstrap-result", DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Environment: manifest.Environment, Role: "controller", Slot: manifest.Slot}, time.Now()); err != nil {
			return bootstrap.SlotState{}, err
		}
		var result bootstrap.Result
		if err := json.Unmarshal(envelope.Payload, &result); err != nil || result.ObservedAt.IsZero() || time.Since(result.ObservedAt) > bootstrap.ExternalSeedObservationMaxAge || result.ObservedAt.After(time.Now().UTC().Add(bootstrap.ManifestClockSkew)) {
			return bootstrap.SlotState{}, ErrExternalSeedObservation
		}
	}
	if err := founder.VerifyCurrent(ctx); err != nil {
		return bootstrap.SlotState{}, err
	}
	if err := authority.VerifyCurrent(ctx, time.Now()); err != nil {
		return bootstrap.SlotState{}, err
	}
	return ledger.RecordExternalSeed(ctx, scope, authority.Wire(), records.ReceiptWire, facts, records.ResultWire, records.CompletedHeadWire)
}

func ledgerPrivatePublic(key ed25519.PrivateKey) ed25519.PublicKey {
	if len(key) != ed25519.PrivateKeySize {
		return nil
	}
	return key.Public().(ed25519.PublicKey)
}
