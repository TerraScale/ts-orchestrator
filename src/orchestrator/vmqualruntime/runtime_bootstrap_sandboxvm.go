//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"encoding/json"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

// Initial activation uses its separately seeded finite grant. This path never
// supplies a regional lease and never authorizes ordinary delivery mutations.
func (factory *firecrackerFactory) activateGuest(ctx context.Context, host string) error {
	vm, err := factory.activeDeliveryVM(host)
	if err != nil {
		return err
	}
	bootstrap, _, err := factory.services.Bootstrap(vm.guest)
	if err != nil {
		return err
	}
	if bootstrap.InitialGrant == nil {
		return errors.New("vmqual: seeded initial grant is missing")
	}
	material := vmqualbootstrap.Material{PublicKeyPEM: bootstrap.InitialGrant.PublicKeyPEM, SignedGrant: bootstrap.InitialGrant.SignedGrant}
	if err := vmqualbootstrap.Activate(ctx, host, material, factory.nodeStatus, factory.requestBootstrapStep); err != nil {
		return err
	}
	return nil
}

func (factory *firecrackerFactory) requestBootstrapStep(ctx context.Context, host, subject string, command json.RawMessage, reply any) error {
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok || services == nil {
		return errors.New("vmqual: initial grant services unavailable")
	}
	services.mu.Lock()
	issuer := services.bootstrapIssuer
	closed := services.closed
	services.mu.Unlock()
	if closed || issuer == nil {
		return errors.New("vmqual: initial grant issuer unavailable")
	}
	payload, err := issuer.Sign(host, subject, command)
	if err != nil {
		return err
	}
	return factory.requestTSNodePayload(ctx, host, subject, payload, reply)
}
