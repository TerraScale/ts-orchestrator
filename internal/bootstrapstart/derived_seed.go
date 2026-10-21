package bootstrapstart

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// DerivedSeedJournal loads an existing completion when proposed is nil. A
// proposal must be durably checkpointed before returning the winning bytes.
type DerivedSeedJournal func(context.Context, *ExternalSeedCompletionRecords) (ExternalSeedCompletionRecords, error)

// EnsureDerivedSeed uses the original ledger transaction for an independently
// observed source founder. No root signing key or replacement store is used.
func EnsureDerivedSeed(ctx context.Context, roots trust.Keyring, anchor bootstrap.VerifiedBootstrapAnchor, authority bootstrap.DerivedStartupAuthority, founder VerifiedSourceFounder, ledgerPrivate ed25519.PrivateKey, journal DerivedSeedJournal) (bootstrap.SlotState, error) {
	manifest := authority.Manifest()
	if _, err := authority.Template().OriginalLaunch(); err == nil {
		return bootstrap.SlotState{}, ErrOriginalStartup
	}
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
	expectedIP, err := founder.template.SlotPrivateIP(manifest.SeedSlot)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	return ensureObservedSeed(ctx, roots, anchor, authority, factory, observed, observed.BootstrapCreateKey, expectedIP, founder.InstanceID(), founder.ObserveCurrent, founder.VerifyCurrent, ledgerPrivate, journal)
}

// Both callers authenticate their distinct provenance and physical host before
// entering the shared immutable reserve/receipt/result transaction.
func ensureObservedSeed(ctx context.Context, roots trust.Keyring, anchor bootstrap.VerifiedBootstrapAnchor,
	authority bootstrap.DerivedStartupAuthority, factory *ociclient.Factory, observed InstanceObservation,
	createKey, expectedIP, instanceID string, observe func(context.Context) (InstanceObservation, error),
	verifyCurrent func(context.Context) error, ledgerPrivate ed25519.PrivateKey, journal DerivedSeedJournal,
) (bootstrap.SlotState, error) {
	manifest := authority.Manifest()
	storageFactory := factory
	if _, err := authority.OriginalLaunch(); err == nil {
		var err error
		storageFactory, err = originalHomeFactory(authority, factory)
		if err != nil {
			return bootstrap.SlotState{}, err
		}
	}
	objects, err := storageFactory.ObjectStorage()
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	ledger, err := authority.OpenLedgerWithClient(ctx, roots, &objects)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	scope := bootstrap.BootstrapScope{DeploymentID: manifest.DeploymentID, Cell: string(manifest.Cell), Slot: manifest.SeedSlot}
	state, err := ledger.ReadSlot(ctx, scope)
	if errors.Is(err, bootstrap.ErrRecordMissing) {
		records, buildErr := BuildExternalSeedReservation(ExternalSeedReservationRequest{Identity: BakedIdentity{DeploymentID: manifest.DeploymentID, Cell: manifest.Cell, Environment: manifest.Environment}, Anchor: anchor, Manifest: authority, ReviewedPlanSHA256: authority.TemplateDigest(), CreateIdentity: createKey, LedgerPrivate: ledgerPrivate, Now: authority.IssuedAt(), ExpiresAt: authority.ExpiresAt()})
		if buildErr != nil {
			return bootstrap.SlotState{}, buildErr
		}
		state, err = ledger.ReserveSlot(ctx, scope, records.IntentWire, records.InitialHeadWire)
	}
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	if _, err := VerifyExternalSeedObservation(anchor, authority, state, observed, expectedIP); err != nil {
		return bootstrap.SlotState{}, err
	}
	if state.Head.ResultDigest != "" && state.Result != nil {
		if state.Result.InstanceOCID != instanceID {
			return bootstrap.SlotState{}, ErrExternalSeedObservation
		}
		return state, nil
	}
	facts, err := VerifyExternalSeedObservation(anchor, authority, state, observed, expectedIP)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	records, err := journal(ctx, nil)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	if len(records.ResultWire) == 0 {
		observed, err = observe(ctx)
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
		records, err = journal(ctx, &records)
		if err != nil {
			return bootstrap.SlotState{}, err
		}
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
	if err := verifyCurrent(ctx); err != nil {
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
