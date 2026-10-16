package oci

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// FleetObserver verifies existing hosts without exposing fleet mutations.
type FleetObserver interface {
	Observe(context.Context) ([]Instance, error)
	SelectiveObserver
}

type fleetObserver struct{ reader *fleet }

func NewFleetObserver(config RegionConfig, intent RegionIntent, factory *ociclient.Factory, reader JournalReader, imageVerifier ImageQualificationVerifier) (FleetObserver, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	region, err := config.Region.OCIRegion()
	if err != nil || factory == nil || factory.Region() != region || reader.journal == nil || imageVerifier == nil {
		return nil, errors.New("fleet observation requires the exact regional OCI factory, durable journal reader and verified image source")
	}
	config.FaultDomains = slices.Clone(config.FaultDomains)
	config.NetworkSecurityGroupIDs = slices.Clone(config.NetworkSecurityGroupIDs)
	provider, err := sdkProviderFrom(factory, config, nil)
	if err != nil {
		return nil, err
	}
	// Registration always verifies current storage and network, even if its
	// caller inherited the periodic placement sweep's cache context.
	provider.verified = nil
	return &fleetObserver{reader: &fleet{
		config: config, provider: fleetObservationProvider{volumeObservationProvider{Provider: provider}},
		journal: volumeObservationJournal{reader.journal}, imageVerifier: imageVerifier, now: time.Now,
	}}, nil
}

func (o *fleetObserver) Observe(ctx context.Context) ([]Instance, error) {
	return o.reader.Observe(ctx)
}

func (o *fleetObserver) ObserveSelected(ctx context.Context, selectInstance func(id, node string) bool) ([]Instance, error) {
	return o.reader.ObserveSelected(ctx, selectInstance)
}

type fleetObservationProvider struct{ volumeObservationProvider }

func (p fleetObservationProvider) ListInstances(ctx context.Context, compartment string) ([]CloudInstance, error) {
	return p.Provider.ListInstances(ociclient.RequestContext(ctx), compartment)
}
