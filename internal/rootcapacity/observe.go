package rootcapacity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func (c *Controller) ObservePoolChild(ctx context.Context, call rootoci.Call, request rootoci.PoolChildObservation) (rootoci.PoolChildView, error) {
	if c == nil || c.store == nil || call.Guard(ctx) != nil || !validInstanceID(request.InstanceID) ||
		call.Operation() != "" && call.Operation() != rootoci.OperationObservePoolChild {
		return rootoci.PoolChildView{}, rootoci.ErrUnauthorized
	}
	readCtx := ociclient.RequestContext(ociclient.WithRequestGuard(ociclient.CheckpointContext(ctx), call.Guard))
	record, _, err := c.store.Load(readCtx, request.Cell)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	var selected region.PoolChildRecord
	for _, child := range record.PoolChildren {
		if child.InstanceID == request.InstanceID {
			if selected.OperationID != "" {
				return rootoci.PoolChildView{}, errors.New("instance has conflicting original protected births")
			}
			selected = child
		}
	}
	if selected.OperationID == "" || selected.Stage != region.PoolChildReady ||
		request.OperationID != "" && request.OperationID != selected.OperationID || request.RecipeSHA256 != "" && request.RecipeSHA256 != selected.RecipeSHA256 ||
		request.PoolID != "" && request.PoolID != selected.PoolID || request.ConfigurationID != "" && request.ConfigurationID != selected.ConfigurationID {
		return rootoci.PoolChildView{}, rootoci.ErrPoolChildUnverified
	}
	a, close, err := c.open(ctx, call, request.Cell, selected.OperationID, call.Expected().Epoch)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	if request.GrantSHA256 != "" && request.GrantSHA256 != a.record.GrantSHA256 || request.Generation != 0 && request.Generation != a.record.Generation {
		close()
		return rootoci.PoolChildView{}, rootoci.ErrPoolChildUnverified
	}
	current := a.record.PoolChildren[selected.OperationID]
	if current.InstanceID != selected.InstanceID || current.Stage != region.PoolChildReady {
		close()
		return rootoci.PoolChildView{}, rootoci.ErrPoolChildUnverified
	}
	a, close, err = c.resolveChild(ctx, call, rootoci.PoolChildExpectation{Cell: request.Cell, OperationID: current.OperationID, ReservationID: current.OperationID,
		RecipeSHA256: current.RecipeSHA256, PublicCAPEM: current.PublicCAPEM, AvailabilityDomains: current.AvailabilityDomains,
		PoolID: current.PoolID, ConfigurationID: current.ConfigurationID, GrantSHA256: a.record.GrantSHA256, Generation: a.record.Generation, Epoch: a.original.Epoch}, a, close)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	defer close()
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	return a.childView(ctx, management, current)
}

func (a *attempt) childView(ctx context.Context, management core.ComputeManagementClient, child region.PoolChildRecord) (rootoci.PoolChildView, error) {
	if child.Stage != region.PoolChildReady || child.Launch == nil || child.Attach == nil || child.Launch.AcceptedAt.IsZero() ||
		child.Attach.AcceptedAt.IsZero() || child.Attach.WorkCompletedAt.IsZero() {
		return rootoci.PoolChildView{}, rootoci.ErrPoolChildUnverified
	}
	facts, err := a.readReadyChild(ctx, management, child)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	latest, _, err := a.store.Load(a.readContext(ctx), a.record.Cell)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	previousSHA, err := digestValue(child)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	latestSHA, err := digestValue(latest.PoolChildren[child.OperationID])
	if err != nil || latestSHA != previousSHA {
		return rootoci.PoolChildView{}, errors.Join(err, rootoci.ErrPoolChildUnverified)
	}
	profile := a.worker.Profile()
	profileSHA, err := digestValue(profile.Profile())
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	birthSHA, err := digestValue(struct {
		OperationID, PoolID, ConfigurationID, InstanceID, BootID, RequestSHA256 string
		BornAt                                                                  time.Time
	}{child.OperationID, child.PoolID, child.ConfigurationID, child.InstanceID, child.BootVolumeID, child.Launch.RequestSHA256, child.BornAt})
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	attachSHA, err := digestValue(child.Attach)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	now := time.Now().UTC()
	expires := a.deadline
	if a.worker.ExpiresAt().Before(expires) {
		expires = a.worker.ExpiresAt()
	}
	if err := a.guard(ctx); err != nil || !time.Now().Before(expires) {
		return rootoci.PoolChildView{}, errors.Join(err, rootoci.ErrPoolChildUnverified)
	}
	descriptorSHA := sha256.Sum256([]byte(child.Descriptor))
	return rootoci.PoolChildView{Cell: a.record.Cell, Stage: "attached", OperationID: child.OperationID, ReservationID: child.OperationID,
		InstanceID: child.InstanceID, PoolID: child.PoolID, ConfigurationID: child.ConfigurationID, BootVolumeIDs: []string{child.BootVolumeID},
		RecipeSHA256: child.RecipeSHA256, GrantSHA256: profile.GrantDigest(), ProfileSHA256: profileSHA, SourceSHA256: a.worker.SourceSHA256(),
		SlotID: entityid.Derive("protected-pool-child", a.record.TenancyID, a.record.Cell, child.OperationID), BirthSHA256: birthSHA, AttachSHA256: attachSHA,
		SessionBindingSHA256: a.call.SessionBindingSHA256(), Generation: profile.Generation(), Epoch: a.original.Epoch, Node: child.Node,
		PrivateIP: facts.PrivateIP, CompartmentID: a.receipt.CompartmentID, AvailabilityDomain: child.AvailabilityDomain, FaultDomain: facts.FaultDomain,
		ImageID: facts.Recipe.ImageID, Shape: facts.Recipe.Shape, OCPUs: float32(facts.Recipe.OCPUs), MemoryGB: float32(facts.Recipe.MemoryGB), BootGB: facts.Recipe.BootGB,
		Role: facts.Recipe.Role, Architecture: facts.Recipe.Architecture, Descriptor: child.Descriptor, ObservedAt: now, ExpiresAt: expires, OriginalDeadline: a.deadline,
		Registration: rootoci.PoolChildRegistration{Kind: rootoci.PoolChildRegistrationStatic, Environment: "production", Cell: a.record.Cell, Node: child.Node,
			Role: facts.Recipe.Role, Architecture: facts.Recipe.Architecture, DescriptorSHA256: hex.EncodeToString(descriptorSHA[:])}}, nil
}
