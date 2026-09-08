//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"encoding/json"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

func (factory *firecrackerFactory) prepareGuestAdmission(ctx context.Context, guest vmqual.Guest) error {
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok || services == nil || guest.Region == "GRU" {
		return nil
	}
	return services.prepareCandidate(ctx, guest)
}

// guestReady is called only after the provider's real ready transition. The
// reserved expansion network is not evidence that its guests are admitted.
func (factory *firecrackerFactory) guestReady(ctx context.Context, host string) error {
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok || services == nil {
		return nil
	}
	if _, err := factory.activeDeliveryVM(host); err != nil {
		return err
	}
	services.mu.Lock()
	if services.closed {
		services.mu.Unlock()
		return errors.New("vmqual: qualification services are closed")
	}
	declared := false
	for _, region := range services.plan.Regions {
		for _, guest := range region.Guests {
			if guest.ID == host {
				if region.Code == vmqual.FourthRegion {
					services.mu.Unlock()
					return nil
				}
				declared = true
			}
		}
	}
	if !declared {
		services.mu.Unlock()
		return errors.New("vmqual: ready guest is outside the declared launch estate")
	}
	if services.controlReady == nil {
		services.controlReady = make(map[string]bool)
	}
	services.controlReady[host] = true
	ready := true
	for _, region := range services.plan.Regions {
		if region.Code == vmqual.FourthRegion {
			continue
		}
		for _, guest := range region.Guests {
			ready = ready && services.controlReady[guest.ID]
		}
	}
	source := services.controlSource
	services.mu.Unlock()
	if !ready || source == nil {
		return nil
	}
	services.controlConfigure.Do(func() {
		services.controlConfigureErr = factory.ConfigureQualificationControlRuntimeFromSource(ctx, source)
	})
	return services.controlConfigureErr
}

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
	defer bootstrap.ControllerRun.Clear()
	defer bootstrap.OrdinaryAuthority.Clear()
	defer bootstrap.Engine.Clear()
	if bootstrap.Candidate != nil {
		defer bootstrap.Candidate.Clear()
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
