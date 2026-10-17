package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ProvisionFoundationBundle consumes the signed preparation stage. A lock
// prelude reports pending; only the strict final bundle provisions the footprint.
func ProvisionFoundationBundle(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, bundle RetainedFoundation) error {
	if len(bundle.LedgerProtectionWire) != 0 {
		purpose, err := verifyRootOperationLedgerLockPrelude(ctx, bundle, genesis)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithDeadline(ctx, purpose.DispatchDeadline)
		defer cancel()
		roots := trust.Keyring{}
		for id, key := range genesis {
			roots[id] = bytes.Clone(key)
		}
		operation := verifiedRootOperationLedgerLockPrelude{purpose: purpose, original: ctx, expires: purpose.DispatchDeadline,
			bundle: bundle.clone(), genesis: roots}
		observed, err := applyRootOperationLedgerLockPrelude(ctx, factory, operation)
		if err != nil {
			return err
		}
		return fmt.Errorf("%w until %s", ErrFoundationLedgerProtectionPending, observed.LockedAt.Format(time.RFC3339))
	}
	if err := VerifyFoundationProvisionBundle(ctx, genesis, bundle); err != nil {
		return err
	}
	authority, resolver, err := newOperatorHomeIAMAuthority(ctx, factory, genesis, bundle)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, authority.operator.deadline)
	defer cancel()
	reader := resolver.Footprint.(*SignedFootprint)
	footprint, err := reader.AuthorizedRegions(ctx)
	if err != nil {
		return err
	}
	controller := &FoundationController{Footprint: reader, Authority: authority, Store: resolver.Store, Foundations: SDKFoundations{Factory: authority.factory}, initialGRUAuxiliary: authority.operator.buckets}
	// Sequential initial provisioning also uses the shared home IAM lease.
	// The protected regional record supplies its fencing epoch, never a CLI knob.
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		var intent *FoundationIntent
		for index := range footprint.Regions {
			if footprint.Regions[index].Plan["cell"] == cell {
				intent = &footprint.Regions[index]
			}
		}
		if intent == nil {
			return errors.New("initial provisioning requires the complete signed regional footprint")
		}
		current, _, err := resolver.Store.Load(ctx, cell)
		if err != nil && !errors.Is(err, ErrFoundationMissing) {
			return err
		}
		epoch := max(uint64(1), current.Epoch)
		if _, err := controller.reconcile(ctx, epoch, footprint, *intent); err != nil {
			return fmt.Errorf("provision signed %s foundation: %w", cell, err)
		}
	}
	// Original allocation verifies the protected current grant before launch;
	// the discovery anchor remains unpublished until every writer is ready.
	if err := authority.publishFoundationPrerequisites(ctx); err != nil {
		return fmt.Errorf("publish signed foundation prerequisites: %w", err)
	}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		original, err := launchFoundationWriter(ctx, authority, resolver, bundle, cell)
		if err != nil {
			return fmt.Errorf("launch signed original %s writer: %w", cell, err)
		}
		if err := installFoundationWriter(ctx, authority, resolver, bundle, cell, original); err != nil {
			return fmt.Errorf("install original %s writer policy: %w", cell, err)
		}
		if err := installOCIRAuthority(ctx, authority, resolver, bundle, cell, original); err != nil {
			return fmt.Errorf("install original %s OCIR authority: %w", cell, err)
		}
	}
	purpose, err := resolver.NetBirdJournalPurposeForOperation(ctx, ctx)
	if err != nil {
		return fmt.Errorf("verify signed NetBird journal purpose: %w", err)
	}
	if err := authority.ReconcileNetBirdJournalUnderlay(ctx, resolver, purpose); err != nil {
		return fmt.Errorf("reconcile signed NetBird private journal underlay: %w", err)
	}
	guarded, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	if err := authority.Guard(guarded, 0); err != nil {
		return err
	}
	return PublishFoundationBundle(guarded, authority.factory, genesis, bundle)
}

// VerifyFoundationProvisionBundle rejects invalid authority before a CLI opens
// operator credentials. It never constructs a provider or sends an OCI request.
func VerifyFoundationProvisionBundle(ctx context.Context, genesis trust.Keyring, bundle RetainedFoundation) error {
	if ctx == nil || len(genesis) == 0 {
		return errors.New("foundation provisioning requires context and independent roots")
	}
	if _, err := verifyRetainedFoundation(ctx, bundle, genesis); err != nil {
		return err
	}
	envelope, err := trust.DecodeEnvelope(bundle.GrantWire)
	if err != nil {
		return err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	return ValidatePreparedFoundation(grant)
}

// Verification of the prelude-only stage cannot validate a final grant.
func verifyFoundationCreateInput(ctx context.Context, genesis trust.Keyring, bundle RetainedFoundation) error {
	if len(bundle.LedgerProtectionWire) != 0 {
		_, err := verifyRootOperationLedgerLockPrelude(ctx, bundle, genesis)
		return err
	}
	return VerifyFoundationProvisionBundle(ctx, genesis, bundle)
}
