package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ProvisionFoundationBundle is the explicit paid provisioning path. Every
// resource comes from the same offline-approved bundle; discovery is last.
func ProvisionFoundationBundle(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, bundle RetainedFoundation) error {
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
	controller := &FoundationController{Footprint: reader, Authority: authority, Store: resolver.Store, Foundations: SDKFoundations{Factory: authority.factory}}
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
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		original, err := launchFoundationWriter(ctx, authority, resolver, bundle, cell)
		if err != nil {
			return fmt.Errorf("launch signed original %s writer: %w", cell, err)
		}
		if err := installFoundationWriter(ctx, authority, resolver, bundle, cell, original); err != nil {
			return fmt.Errorf("install original %s writer policy: %w", cell, err)
		}
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
