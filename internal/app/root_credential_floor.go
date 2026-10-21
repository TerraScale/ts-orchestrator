//go:build linux

package app

import (
	"context"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

func (producer *rootMaterialAdmission) credentialFloor(ctx context.Context, call rootoci.Call, cfg Config,
	config containerMaterialConfig,
) (func(context.Context, host.Registration) (uint64, error), error) {
	managed, err := loadManagedControllerConfig(cfg)
	if err != nil || managed == nil || config.Specs.ociRegion == nil || !reflect.DeepEqual(managed.region, *config.Specs.ociRegion) {
		return nil, containermaterial.ErrPending
	}
	material, err := acceptedMaterialConfigFromMarker(config.Accepted, cfg.NATS.Cell, managed.region)
	if err != nil {
		return nil, err
	}
	region, err := material.repository.Region.OCIRegion()
	if err != nil {
		return nil, err
	}
	rootKV, err := config.JS.KeyValue(ctx, rootChainBucket)
	if err != nil {
		return nil, err
	}
	root, err := rootKV.Get(ctx, rootChainKey)
	if err != nil || root == nil || root.Operation() != jetstream.KeyValuePut {
		return nil, containermaterial.ErrPending
	}
	chain, err := trust.DecodeRootChain(root.Value())
	if err != nil {
		return nil, err
	}
	roots, err := trust.VerifyRootChain(config.Specs.roots.genesis, config.Specs.roots.identity, chain)
	if err != nil || roots.Head != config.Specs.roots.reply("").Head {
		return nil, containermaterial.ErrPending
	}
	spec, err := config.Specs.kv.Get(ctx, cellSpecKey)
	if err != nil || spec == nil || spec.Operation() != jetstream.KeyValuePut || spec.Revision() != config.Specs.revision {
		return nil, containermaterial.ErrPending
	}
	original := config.credentialContext
	deadline, ok := original.Deadline()
	if !ok || original.Done() == nil || original.Err() != nil {
		return nil, containermaterial.ErrPending
	}
	if !config.releaseDeadline.IsZero() {
		deadline = earlier(deadline, config.releaseDeadline)
	}
	sourceGuard := func(ctx context.Context) error {
		if ctx.Err() != nil || original.Err() != nil || !time.Now().Before(deadline) || call.Guard(ctx) != nil ||
			config.credentialSource.Guard(ctx) != nil || rootTrustChainCurrent(ctx, config.JS, root) != nil ||
			controllerHostSpecCurrent(ctx, config.JS, config.Specs, spec, roots.Head) != nil {
			return containermaterial.ErrPending
		}
		current, err := loadManagedControllerConfig(cfg)
		if err != nil || !reflect.DeepEqual(current, managed) || config.credentialSource.Guard(ctx) != nil ||
			call.Guard(ctx) != nil || ctx.Err() != nil || original.Err() != nil || !time.Now().Before(deadline) {
			return containermaterial.ErrPending
		}
		return nil
	}
	if err := sourceGuard(ctx); err != nil {
		return nil, err
	}
	return func(ctx context.Context, registration host.Registration) (uint64, error) {
		if ctx == nil || registration.ManagedPlacement == nil || registration.Cell != cfg.NATS.Cell {
			return 0, containermaterial.ErrPending
		}
		ctx, cancel := context.WithDeadline(ctx, deadline)
		stop := context.AfterFunc(original, cancel)
		defer cancel()
		defer stop()
		guard := func(ctx context.Context) error {
			if sourceGuard(ctx) != nil || host.GuardCredentialFloorSession(ctx) != nil || sourceGuard(ctx) != nil {
				return containermaterial.ErrPending
			}
			return nil
		}
		if guard(ctx) != nil {
			return 0, containermaterial.ErrPending
		}
		factory, err := producer.factory.ForRegion(region)
		if err != nil {
			return 0, err
		}
		client, err := factory.ObjectStorage()
		if err != nil {
			return 0, err
		}
		floor, err := managedmaterial.NewCredentialFloorReader(material.repository, &client, config.Mutations, config.ResponsePublic, material.subnetCIDR)
		if err != nil {
			return 0, err
		}
		ctx = ociclient.WithRequestGuard(ctx, guard)
		generation, err := floor.Current(ctx, registration.ManagedPlacement.DatabaseID, registration.ManagedPlacement.PartitionID)
		if err != nil || guard(ctx) != nil {
			return 0, containermaterial.ErrPending
		}
		return generation, nil
	}, nil
}
