package hostadmission

import (
	"context"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/usageapi"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

var _ rootoci.Reader = StartupReader{}

func (r StartupReader) begin(ctx context.Context, call rootoci.Call, operation rootoci.Operation) (context.Context, context.CancelFunc, error) {
	cancel := func() {}
	if call.Operation() != "" && call.Operation() != operation || call.Guard(ctx) != nil || r.Guard(ctx) != nil {
		return ctx, cancel, ErrAdmission
	}
	expected := call.Expected()
	if expected.Cell != "" && expected.Cell != r.Candidate().Cell || expected.GrantSHA256 != "" || expected.OperationID != "" || expected.Epoch != 0 {
		return ctx, cancel, ErrAdmission
	}
	ctx, cancel = context.WithDeadline(ctx, minTime(r.ExpiresAt(), call.Deadline()))
	guard := func(ctx context.Context) error {
		if call.Guard(ctx) != nil {
			return ErrAdmission
		}
		return r.state.localGuard(ctx)
	}
	return ociclient.WithRequestGuard(ociclient.WithAuthority(ctx, guard), guard), cancel, nil
}

func (r StartupReader) finish(ctx context.Context, call rootoci.Call) error {
	if call.Guard(ctx) != nil || r.Guard(ctx) != nil {
		return ErrAdmission
	}
	return nil
}

func (r StartupReader) Inventory(ctx context.Context, call rootoci.Call) (rootoci.InventoryObservation, error) {
	ctx, cancel, err := r.begin(ctx, call, rootoci.OperationInventory)
	defer cancel()
	if err != nil {
		return rootoci.InventoryObservation{}, err
	}
	a := r.state.verified.approval
	reader, err := capacityinventory.New(r.state.factory)
	if err != nil {
		return rootoci.InventoryObservation{}, err
	}
	scope := capacityinventory.Scope{TenancyID: a.Tenancy, SHA256: r.BindingSHA256(), Currency: "USD", ExpiresAt: r.ExpiresAt(),
		Regions: []capacityinventory.RegionScope{{Cell: a.Candidate.Cell, OCIRegion: a.OCIRegion, CompartmentIDs: []string{a.Compartment}}}}
	observed, err := reader.Read(ctx, scope)
	if err != nil {
		return rootoci.InventoryObservation{}, err
	}
	if err := r.finish(ctx, call); err != nil {
		return rootoci.InventoryObservation{}, err
	}
	return rootoci.InventoryObservation{ScopeSHA256: observed.ScopeSHA256, Currency: observed.Currency, ObservedAt: observed.ObservedAt,
		ExpiresAt: observed.ExpiresAt, MonthlyCents: observed.MonthlyCents, Resources: observed.Resources, CoveredCompartments: observed.CoveredCompartments, Pending: observed.Pending}, nil
}

func (r StartupReader) ObserveLocalInstance(ctx context.Context, call rootoci.Call) (bootstrapstart.InstanceObservation, error) {
	ctx, cancel, err := r.begin(ctx, call, rootoci.OperationObserveLocalInstance)
	defer cancel()
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	observed, err := r.state.observeCurrent(ctx)
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	if err := r.finish(ctx, call); err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	return observed, nil
}

func (r StartupReader) ObserveFleet(ctx context.Context, call rootoci.Call) ([]oci.Instance, error) {
	ctx, cancel, err := r.begin(ctx, call, rootoci.OperationObserveFleet)
	defer cancel()
	if err != nil {
		return nil, err
	}
	observed := make([]oci.Instance, 0, 4)
	for _, h := range r.state.verified.binding.Hosts {
		if err := call.Guard(ctx); err != nil {
			return nil, err
		}
		host, err := r.state.observer.ObserveInstance(ctx, h.InstanceID)
		if err != nil || r.state.matchHost(ctx, host, h) != nil {
			return nil, ErrAdmission
		}
		observed = append(observed, oci.Instance{ID: host.InstanceOCID, Region: oci.Region(r.Candidate().Cell), PrivateIP: host.PrimaryPrivateIP,
			FaultDomain: host.FaultDomain, Shape: host.Shape, ImageID: host.ImageOCID, ETag: host.ETag, State: host.LifecycleState})
	}
	if err := r.finish(ctx, call); err != nil {
		return nil, err
	}
	return observed, nil
}

// compartmentUsage narrows the existing regional collector at every SDK query.
type compartmentUsage struct {
	api         ocicost.UsageAPI
	compartment string
}

func (u compartmentUsage) RequestSummarizedUsages(ctx context.Context, request usageapi.RequestSummarizedUsagesRequest) (usageapi.RequestSummarizedUsagesResponse, error) {
	filters := []usageapi.Filter{{Operator: usageapi.FilterOperatorAnd, Dimensions: []usageapi.Dimension{{Key: new("compartmentId"), Value: new(u.compartment)}}}}
	if request.Filter != nil {
		filters = append(filters, *request.Filter)
	}
	request.Filter = &usageapi.Filter{Operator: usageapi.FilterOperatorAnd, Filters: filters}
	return u.api.RequestSummarizedUsages(ctx, request)
}

func (r StartupReader) Costs(ctx context.Context, call rootoci.Call) (ocicost.Report, error) {
	ctx, cancel, err := r.begin(ctx, call, rootoci.OperationCosts)
	defer cancel()
	if err != nil {
		return ocicost.Report{}, err
	}
	a := r.state.verified.approval
	// The independently approved IAM region is already the tenancy's home region.
	factory, err := r.state.factory.ForRegion(a.IAMRegion)
	if err != nil {
		return ocicost.Report{}, err
	}
	client, err := factory.Usage()
	if err != nil {
		return ocicost.Report{}, err
	}
	usage := ocicost.Usage{Cell: strings.ToLower(a.Candidate.Cell), OCIRegion: a.OCIRegion, TenancyID: a.Tenancy, API: compartmentUsage{api: client, compartment: a.Compartment}}
	observed, err := usage.Read(ctx, time.Now().UTC())
	if err != nil {
		return ocicost.Report{}, err
	}
	if err := r.finish(ctx, call); err != nil {
		return ocicost.Report{}, err
	}
	return observed, nil
}

func (r StartupReader) ObserveImage(ctx context.Context, call rootoci.Call, request rootoci.ImageRequest) (rootoci.ImageObservation, error) {
	ctx, cancel, err := r.begin(ctx, call, rootoci.OperationObserveImage)
	defer cancel()
	if err != nil || request.ImageID != r.ImageID() {
		return rootoci.ImageObservation{}, ErrAdmission
	}
	observed, err := r.state.observeImage(ctx)
	if err != nil {
		return rootoci.ImageObservation{}, err
	}
	if err := r.finish(ctx, call); err != nil {
		return rootoci.ImageObservation{}, err
	}
	a := r.state.verified.approval
	var shape string
	for _, h := range a.Hosts {
		if h.Name == r.state.verified.host.Name {
			shape = h.Shape
		}
	}
	return rootoci.ImageObservation{ImageID: r.ImageID(), CompartmentID: a.Compartment, State: string(observed.LifecycleState), Shape: shape, Architecture: a.Candidate.Architecture}, nil
}

func (r StartupReader) ReleaseChannel(ctx context.Context, call rootoci.Call) (rootoci.ChannelObservation, error) {
	ctx, cancel, err := r.begin(ctx, call, rootoci.OperationReleaseChannel)
	defer cancel()
	if err != nil {
		return rootoci.ChannelObservation{}, err
	}
	a := r.state.verified.approval
	objects, err := r.state.factory.ObjectStorage()
	if err != nil {
		return rootoci.ChannelObservation{}, err
	}
	channel, found, err := releasechannel.ReadChannel(ctx, releasechannel.Location{Client: objects, Namespace: a.Namespace, Bucket: a.Bucket})
	if err != nil {
		return rootoci.ChannelObservation{}, err
	}
	if found {
		if _, err := channel.Verify(r.state.roots, a.Candidate.Cell, a.Candidate.Environment, time.Now()); err != nil {
			return rootoci.ChannelObservation{}, err
		}
	}
	if err := r.finish(ctx, call); err != nil {
		return rootoci.ChannelObservation{}, err
	}
	return rootoci.ChannelObservation{Found: found, Channel: channel}, nil
}
