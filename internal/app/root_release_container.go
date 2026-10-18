package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (b *rootReleaseChannels) ContainerRelease(ctx context.Context, call rootoci.Call, request rootoci.ContainerReleaseRequest) (rootoci.ContainerReleaseObservation, error) {
	ctx, cancel, o, err := b.beginChannel(ctx, call, rootoci.OperationContainerRelease)
	defer cancel()
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	if !request.Valid() {
		return rootoci.ContainerReleaseObservation{}, rootoci.ErrUnauthorized
	}
	if _, ok := o.registry.profiles()[request.Role]; !ok {
		return rootoci.ContainerReleaseObservation{}, rootoci.ErrUnauthorized
	}
	location, err := o.location(ctx)
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	bundle, found, err := releasechannel.ReadContainerBundle(ctx, location, request.Role, request.Architecture)
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	result := rootoci.ContainerReleaseObservation{Found: found, ExpiresAt: o.deadline}
	if !found {
		return result, o.guard(ctx)
	}
	target := release.ContainerTarget{Cell: o.source.Identity().Cell, Environment: o.source.Identity().Environment, Role: request.Role, Architecture: request.Architecture}
	roots := o.registry.roots.current()
	var genesisResolver region.FoundationResolver
	if len(bundle.Migration) == 0 {
		genesisResolver, err = region.NewFoundationDiscovery(b.factory, o.source.Anchor(), roots)
		if err != nil {
			return rootoci.ContainerReleaseObservation{}, err
		}
		target.Genesis, result.OriginalProof, err = genesisResolver.WorkloadGenesis(ctx, target.Cell, target.Role, target.Environment)
		if err != nil {
			return rootoci.ContainerReleaseObservation{}, err
		}
	}
	historical, err := release.VerifyContainerHistorical(bundle, roots, target)
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	// Capture original proof expiries before allocation or evidence network waits.
	for _, wire := range [][]byte{bundle.Claim, bundle.Delegation, historical.Claim().Production.Qualification, historical.Claim().Production.Delegation} {
		if len(wire) == 0 {
			continue
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return rootoci.ContainerReleaseObservation{}, err
		}
		o.capDeadline(envelope.ExpiresAt)
	}
	if err := o.guard(ctx); err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	allocations, err := currentContainerAllocations(ctx, b.factory, bundle, roots, target)
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	verified, err := release.VerifyContainerCurrent(ctx, bundle, roots, target, time.Now().UTC(), o.deadline.Add(-time.Nanosecond), func(ctx context.Context, digest string) (io.ReadCloser, error) {
		return releasechannel.ReadContainerEvidence(ctx, location, request.Role, digest)
	}, allocations)
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	manager, err := b.sources.Node.ControlClient(ctx)
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	identity := o.source.Identity()
	floor, floorFound, err := swarmruntime.ReadServiceReleaseFloor(ctx, manager, swarmruntime.ServiceIntent{
		ID:   entityid.Derive("platform-service", request.Role, identity.Environment, identity.OCIRegion),
		Role: request.Role, Region: identity.OCIRegion, Environment: identity.Environment, Architecture: request.Architecture,
	}, verified, roots)
	if err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	result.Floor = &rootoci.ContainerReleaseFloor{Found: floorFound, OperationID: floor.OperationID, Generation: floor.Generation,
		ReleaseSequence: floor.ReleaseSequence, ReleaseIdentity: floor.ReleaseIdentity, IntentSHA256: floor.IntentSHA256}
	// A channel replacement during verification must be observed on the next read.
	current, stillFound, err := releasechannel.ReadContainerBundle(ctx, location, request.Role, request.Architecture)
	if err != nil || !stillFound {
		return rootoci.ContainerReleaseObservation{}, errors.Join(rootrelease.ErrPending, err)
	}
	digest, err := release.ContainerBundleSHA256(current)
	if err != nil || digest != verified.BundleSHA256() {
		return rootoci.ContainerReleaseObservation{}, errors.Join(rootrelease.ErrPending, err)
	}
	if err := o.guard(ctx); err != nil {
		return rootoci.ContainerReleaseObservation{}, err
	}
	if target.Genesis.IsVerified() {
		currentGenesis, originalProof, err := genesisResolver.WorkloadGenesis(ctx, target.Cell, target.Role, target.Environment)
		if err != nil || currentGenesis.Fingerprint() != target.Genesis.Fingerprint() || !bytes.Equal(originalProof, result.OriginalProof) {
			return rootoci.ContainerReleaseObservation{}, errors.Join(rootrelease.ErrPending, err)
		}
		if err := o.guard(ctx); err != nil {
			return rootoci.ContainerReleaseObservation{}, err
		}
	}
	result.Bundle, result.BundleSHA256, result.Fingerprint, result.ExpiresAt = bundle, verified.BundleSHA256(), verified.Fingerprint(), o.deadline
	if !result.Valid(request, time.Now()) {
		return rootoci.ContainerReleaseObservation{}, rootoci.ErrUnauthorized
	}
	return result, nil
}
