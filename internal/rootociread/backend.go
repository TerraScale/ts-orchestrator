// Package rootociread implements finite OCI observations inside the root process.
package rootociread

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var ErrPending = errors.New("root OCI observation dependency is pending")

type Backend struct {
	factory *ociclient.Factory
	mu      sync.RWMutex
	journal oci.JournalReader
	images  oci.ImageQualificationVerifier
}

var _ rootoci.Reader = (*Backend)(nil)

func New(factory *ociclient.Factory) (*Backend, error) {
	if os.Geteuid() != 0 || factory == nil || !catalog.IsOCIRegion(factory.Region()) {
		return nil, errors.New("root OCI observations require the root process and its regional principal")
	}
	return &Backend{factory: factory}, nil
}

// BindFleet attaches root-owned read dependencies after the regional broker opens.
// Its journal handle cannot create buckets or change durable ownership.
func (b *Backend) BindFleet(journal oci.JournalReader, images oci.ImageQualificationVerifier) error {
	if os.Geteuid() != 0 || b == nil || images == nil {
		return ErrPending
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.journal, b.images = journal, images
	return nil
}

type scope struct {
	cell, grant string
	footprint   *region.SignedFootprint
}

func (b *Backend) current(ctx context.Context, call rootoci.Call) (scope, error) {
	if b == nil || b.factory == nil || os.Geteuid() != 0 {
		return scope{}, ErrPending
	}
	if err := call.Guard(ctx); err != nil {
		return scope{}, err
	}
	entry, ok := catalog.CellForOCIRegion(b.factory.Region())
	if !ok || call.Expected().Cell != "" && !strings.EqualFold(call.Expected().Cell, entry.Cell) {
		return scope{}, errors.New("root OCI read cell differs from the installed principal")
	}
	resolver, err := region.DiscoverCurrentFoundation(ctx, b.factory)
	if err != nil {
		return scope{}, err
	}
	footprint, ok := resolver.Footprint.(*region.SignedFootprint)
	if !ok {
		return scope{}, errors.New("root OCI read lacks current signed foundation authority")
	}
	approved, err := footprint.AuthorizedRegions(ctx)
	if err != nil {
		return scope{}, err
	}
	if !slices.ContainsFunc(approved.Regions, func(intent region.FoundationIntent) bool {
		return intent.Plan["cell"] == entry.Cell && intent.Plan["region"] == entry.OCIRegion
	}) {
		return scope{}, errors.New("root OCI read region is outside the current signed footprint")
	}
	grant, err := footprint.CurrentGrantDigest(ctx)
	if err != nil {
		return scope{}, err
	}
	if expected := call.Expected().GrantSHA256; expected != "" && expected != grant {
		return scope{}, errors.New("root OCI read grant expectation is stale")
	}
	return scope{cell: entry.Cell, grant: grant, footprint: footprint}, nil
}

func (b *Backend) begin(ctx context.Context, call rootoci.Call, operation rootoci.Operation) (context.Context, context.CancelFunc, scope, error) {
	deadline := time.Now().Add(90 * time.Second)
	if original := call.Deadline(); !original.IsZero() && original.Before(deadline) {
		deadline = original
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	ctx = ociclient.WithRequestGuard(ctx, call.Guard)
	if actual := call.Operation(); actual != "" && actual != operation {
		return ctx, cancel, scope{}, rootoci.ErrUnauthorized
	}
	scope, err := b.current(ctx, call)
	return ctx, cancel, scope, err
}

func (b *Backend) finish(ctx context.Context, call rootoci.Call, before scope) error {
	after, err := b.current(ctx, call)
	if err != nil {
		return err
	}
	if before.cell != after.cell || before.grant != after.grant {
		return errors.New("root OCI observation authority changed during the read")
	}
	return call.Guard(ctx)
}

func (b *Backend) Inventory(ctx context.Context, call rootoci.Call) (rootoci.InventoryObservation, error) {
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationInventory)
	defer cancel()
	if err != nil {
		return rootoci.InventoryObservation{}, err
	}
	proof, err := scope.footprint.InfrastructureSpend(ctx)
	if err != nil {
		return rootoci.InventoryObservation{}, err
	}
	if !proof.IsVerified() || proof.GrantDigest() != scope.grant {
		return rootoci.InventoryObservation{}, errors.New("root OCI inventory scope changed")
	}
	reader, err := capacityinventory.New(b.factory)
	if err != nil {
		return rootoci.InventoryObservation{}, err
	}
	observed, err := reader.ReadOwned(ctx, proof.Footprint())
	if err != nil {
		return rootoci.InventoryObservation{}, err
	}
	if err := b.finish(ctx, call, scope); err != nil {
		return rootoci.InventoryObservation{}, err
	}
	return rootoci.InventoryObservation{ScopeSHA256: observed.ScopeSHA256, Currency: observed.Currency,
		ObservedAt: observed.ObservedAt, ExpiresAt: observed.ExpiresAt, MonthlyCents: observed.MonthlyCents,
		Resources: observed.Resources, CoveredCompartments: observed.CoveredCompartments, Pending: observed.Pending}, nil
}

func (b *Backend) ObserveLocalInstance(ctx context.Context, call rootoci.Call) (bootstrapstart.InstanceObservation, error) {
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationObserveLocalInstance)
	defer cancel()
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	id, err := bootstrapstart.NewIMDSClient().FetchInstanceID(ctx)
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	parts := strings.Split(id, ".")
	if len(parts) != 5 || parts[3] != b.factory.Region() {
		return bootstrapstart.InstanceObservation{}, bootstrapstart.ErrInstanceObservation
	}
	observer, err := bootstrapstart.NewOCIInstanceObserverWithFactory(oci.Region(scope.cell), b.factory)
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	observed, err := observer.ObserveInstance(ctx, id)
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	if err := b.finish(ctx, call, scope); err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	return observed, nil
}

func (b *Backend) ObserveFleet(ctx context.Context, call rootoci.Call) ([]oci.Instance, error) {
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationObserveFleet)
	defer cancel()
	if err != nil {
		return nil, err
	}
	_, intent, config, err := bootstrapstart.LoadAcceptedOCIConfig()
	if err != nil || string(config.Region) != scope.cell {
		return nil, errors.Join(ErrPending, err)
	}
	b.mu.RLock()
	journal, images := b.journal, b.images
	b.mu.RUnlock()
	observer, err := oci.NewFleetObserver(config, intent, b.factory, journal, images)
	if err != nil {
		return nil, err
	}
	observed, err := observer.Observe(ctx)
	if err != nil {
		return nil, err
	}
	if err := b.finish(ctx, call, scope); err != nil {
		return nil, err
	}
	return observed, nil
}

func (b *Backend) Costs(ctx context.Context, call rootoci.Call) (ocicost.Report, error) {
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationCosts)
	defer cancel()
	if err != nil {
		return ocicost.Report{}, err
	}
	usage, err := ocicost.Connect(ctx, b.factory, strings.ToLower(scope.cell), b.factory.Region())
	if err != nil {
		return ocicost.Report{}, err
	}
	observed, err := usage.Read(ctx, time.Now().UTC())
	if err != nil {
		return ocicost.Report{}, err
	}
	if err := b.finish(ctx, call, scope); err != nil {
		return ocicost.Report{}, err
	}
	return observed, nil
}

func (b *Backend) ReleaseChannel(ctx context.Context, call rootoci.Call) (rootoci.ChannelObservation, error) {
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationReleaseChannel)
	defer cancel()
	if err != nil {
		return rootoci.ChannelObservation{}, err
	}
	bucket, err := releasechannel.BucketName(strings.ToLower(scope.cell))
	if err != nil {
		return rootoci.ChannelObservation{}, err
	}
	client, err := b.factory.ObjectStorage()
	if err != nil {
		return rootoci.ChannelObservation{}, err
	}
	namespace, err := client.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{})
	if err != nil || namespace.Value == nil || *namespace.Value == "" {
		return rootoci.ChannelObservation{}, errors.Join(ErrPending, err)
	}
	channel, found, err := releasechannel.ReadChannel(ctx, releasechannel.Location{Client: client, Namespace: *namespace.Value, Bucket: bucket})
	if err != nil {
		return rootoci.ChannelObservation{}, err
	}
	if err := b.finish(ctx, call, scope); err != nil {
		return rootoci.ChannelObservation{}, err
	}
	return rootoci.ChannelObservation{Found: found, Channel: channel}, nil
}
