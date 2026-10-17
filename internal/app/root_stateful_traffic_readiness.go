//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionleader"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (b *rootOCIResources) rootStatefulTrafficReadiness(ctx context.Context, controller *containerMaterialController, snapshot rootResourceSnapshot, relay *host.Agent, guard func(context.Context) error) (*swarmruntime.RootTaskReadiness, error) {
	if b == nil || b.traffic == nil || controller == nil || controller.config.ReadLease == nil || controller.config.Evidence == nil || relay == nil || guard == nil {
		return nil, rootoci.ErrUnauthorized
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	config := controller.config
	members, err := placement.OpenMemberPinReader(ctx, config.JS, b.cfg.NATS.Cell, b.cfg.NATS.Replicas)
	if err != nil {
		return nil, err
	}
	journal, err := oci.OpenJournalReader(ctx, config.JS, b.cfg.NATS.Replicas)
	if err != nil {
		return nil, err
	}
	volumes, err := oci.NewVolumeMountObserverWithReader(b.traffic.factory, snapshot.managed.region, snapshot.managed.intent, journal)
	if err != nil {
		return nil, err
	}
	identity := config.Specs.identity
	claim := func(ctx context.Context, operationID string, read func(context.Context, string) (delivery.Intent, error), current bool) (delivery.Intent, error) {
		if err := guard(ctx); err != nil {
			return delivery.Intent{}, err
		}
		intent, err := read(ctx, operationID)
		if err != nil {
			return delivery.Intent{}, err
		}
		if intent.OperationID != operationID || intent.Role != terrabase.Role || intent.Cell != b.cfg.NATS.Cell || intent.Environment != identity.Environment || intent.Container == nil || current && intent.AuthorityEpoch != config.ReadLease.Epoch() {
			return delivery.Intent{}, rootoci.ErrUnauthorized
		}
		return intent, guard(ctx)
	}
	evidence := func(read func(context.Context, string) (delivery.Intent, error), current bool) executionleader.EvidenceReader {
		return func(ctx context.Context, operationID, digest string) (io.ReadCloser, error) {
			if _, err := claim(ctx, operationID, read, current); err != nil {
				return nil, err
			}
			body, err := config.Evidence(ctx, terrabase.Role, digest)
			if err != nil {
				return nil, err
			}
			if err := guard(ctx); err != nil {
				body.Close()
				return nil, err
			}
			return body, nil
		}
	}
	allocations := func(read func(context.Context, string) (delivery.Intent, error), current bool) executionleader.AllocationResolver {
		return func(ctx context.Context, operationID string, bundle release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
			intent, err := claim(ctx, operationID, read, current)
			if err != nil {
				return release.SequenceLocation{}, err
			}
			if target.Cell != strings.ToUpper(b.cfg.NATS.Cell) || target.Environment != identity.Environment || target.Role != terrabase.Role {
				return release.SequenceLocation{}, rootoci.ErrUnauthorized
			}
			if err := rootTrafficBundleMatches(*intent.Container, bundle); err != nil {
				return release.SequenceLocation{}, err
			}
			location, err := currentContainerAllocations(ctx, b.traffic.factory, bundle, roots, target)
			if err != nil {
				return release.SequenceLocation{}, err
			}
			return location, guard(ctx)
		}
	}
	producer, err := executionleader.NewReadOnlyVerifier(executionleader.ReadOnlyVerifierConfig{
		Client: config.Client, Authority: config.Mutations, Lease: config.ReadLease, Members: members, Delivery: config.Delivery, Volumes: volumes,
		Roots: config.Specs.roots.current(), HistoricalRoots: config.Specs.roots.historical(), Cell: b.cfg.NATS.Cell, Environment: identity.Environment,
		Evidence: evidence(config.Delivery.ContainerIntent, true), RetainedEvidence: evidence(config.Delivery.RetainedContainerIntent, false),
		Allocations: allocations(config.Delivery.ContainerIntent, true), RetainedAllocations: allocations(config.Delivery.RetainedContainerIntent, false),
	})
	if err != nil {
		return nil, err
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	return swarmruntime.NewRootTaskReadiness(config.Client, config.Mutations, config.ReadLease, producer, config.Registrations, relay)
}

func rootTrafficBundleMatches(signed, requested release.ContainerBundle) error {
	before, err := json.Marshal(signed, json.Deterministic(true))
	if err != nil {
		return err
	}
	after, err := json.Marshal(requested, json.Deterministic(true))
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return rootoci.ErrUnauthorized
	}
	return nil
}
