//go:build linux

package app

import (
	"context"
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/rootbackup"
	"github.com/TerraScale/ts-orchestrator/internal/rootfoundation"
	"github.com/TerraScale/ts-orchestrator/internal/rootnetbird"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociread"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
)

// The listener and later source binding share these exact backend instances.
type managedRootBackends struct {
	service    *rootoci.Service
	foundation *rootfoundation.Backend
	readers    *rootociread.Backend
	containers *rootrelease.Backend
	channels   *rootReleaseChannels
	capacity   *rootPoolBackend
	netbird    *rootnetbird.Backend
}

func newManagedRootBackends(ctx context.Context, cfg Config, local automaticFoundation, ownhost *managedRuntimeHost) (*managedRootBackends, error) {
	if os.Geteuid() != 0 || ctx == nil || local.factory == nil || ownhost == nil {
		return nil, rootoci.ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ownhost.mu.RLock()
	founder, accepted := ownhost.reader, ownhost.accepted.Clone()
	ownhost.mu.RUnlock()
	if founder == nil || accepted.Validate() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	readers, err := rootociread.New(local.factory)
	if err != nil {
		return nil, fmt.Errorf("construct root OCI readers: %w", err)
	}
	foundation, err := rootfoundation.NewController(ctx, founder, accepted)
	if err != nil {
		return nil, fmt.Errorf("construct root foundation authority: %w", err)
	}
	foundations, err := newRootOCIResources(cfg, foundation)
	if err != nil {
		return nil, fmt.Errorf("construct root foundation and resource backend: %w", err)
	}
	homeIAM, err := foundation.GuardedHomeIAM(ctx)
	if err != nil {
		return nil, fmt.Errorf("retain original root home IAM authority: %w", err)
	}
	capacity, err := newRootCapacityBackend(ctx, local.factory, local.foundations, homeIAM)
	if err != nil {
		return nil, fmt.Errorf("construct root capacity backend: %w", err)
	}
	netbird, err := rootnetbird.New(local.factory)
	if err != nil {
		return nil, fmt.Errorf("construct root NetBird backend: %w", err)
	}
	containers, err := rootrelease.New(local.factory)
	if err != nil {
		return nil, fmt.Errorf("construct root container release backend: %w", err)
	}
	channels, err := newRootReleaseChannels(ctx, cfg, local.factory, containers, founder, accepted)
	if err != nil {
		return nil, fmt.Errorf("construct root release channels: %w", err)
	}
	workloads, err := newRootWorkloadCredentials(ownhost, local.factory)
	if err != nil {
		return nil, fmt.Errorf("construct root workload credentials: %w", err)
	}
	backups, err := rootbackup.New(local.factory, founder, accepted)
	if err != nil {
		return nil, fmt.Errorf("construct root volume backup backend: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	service, err := rootoci.NewService(rootoci.Backends{
		Readers: readers, Foundations: foundations, Credentials: rootsecret.Service{},
		Capacity: capacity, NetBird: netbird, Releases: channels,
		Volumes: readers, Workloads: workloads, Backups: backups, ContainerMaterial: containers,
	})
	if err != nil {
		return nil, fmt.Errorf("construct complete root OCI service: %w", err)
	}
	return &managedRootBackends{service: service, foundation: foundation, readers: readers, containers: containers,
		channels: channels, capacity: capacity, netbird: netbird}, nil
}
