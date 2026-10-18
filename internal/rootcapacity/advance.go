package rootcapacity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// AdvancePoolChild resumes only the retained original launch and attach. Every
// new invocation obtains current authority without replacing original IDs.
func (c *Controller) AdvancePoolChild(ctx context.Context, call rootoci.Call, request rootoci.PoolChildExpectation) (rootoci.PoolChildView, error) {
	if call.Operation() != "" && call.Operation() != rootoci.OperationAdvancePoolChild {
		return rootoci.PoolChildView{}, rootoci.ErrUnauthorized
	}
	a, close, err := c.beginChild(ctx, call, request)
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	defer close()
	if child, exists := a.record.PoolChildren[a.receipt.OperationID]; exists {
		if child.Stage == region.PoolChildReady {
			management, err := a.factory.ComputeManagement()
			if err != nil {
				return rootoci.PoolChildView{}, err
			}
			return a.childView(ctx, management, child)
		}
		switch child.Stage {
		case region.PoolChildDraining, region.PoolChildDetachPrepared, region.PoolChildDetachUnknown, region.PoolChildDetaching,
			region.PoolChildDetached, region.PoolChildTerminating, region.PoolChildRetired:
			return rootoci.PoolChildView{}, errors.New("original child has entered retirement and cannot attach again")
		}
	}
	if err := a.reserveOriginal(ctx); err != nil {
		return rootoci.PoolChildView{}, err
	}
	management, err := a.factory.ComputeManagement()
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	poolID, configurationID, err := a.ensurePool(ctx, management)
	if a.leaseID != "" {
		defer func() {
			_ = a.releasePool(ctx, a.record.PoolChildren[a.receipt.OperationID].Stage == region.PoolChildReady)
		}()
	}
	if err != nil {
		return rootoci.PoolChildView{}, err
	}
	if request.PoolID != "" && request.PoolID != poolID || request.ConfigurationID != "" && request.ConfigurationID != configurationID {
		return rootoci.PoolChildView{}, errors.New("pool request selected identities other than original protected creates")
	}
	child, exists := a.record.PoolChildren[a.receipt.OperationID]
	if !exists {
		child, err = a.prepareChild(ctx, management, poolID, configurationID, request)
		if err != nil {
			return rootoci.PoolChildView{}, err
		}
	}
	if child.PoolID != poolID || child.ConfigurationID != configurationID {
		return rootoci.PoolChildView{}, errors.New("original child cannot move to another pool or configuration")
	}
	if child.Stage == region.PoolChildReserved {
		launch := a.launchRequest(child)
		wire, err := prepareWire(launch, http.MethodPost, "/instanceConfigurations/{instanceConfigurationId}/actions/launch")
		if err != nil {
			return rootoci.PoolChildView{}, err
		}
		child.Launch, child.Stage = wire, region.PoolChildLaunchPrepared
		if err := a.record.CapacityLedger.Prepare(a.receipt.OperationID, wire.RequestSHA256, wire.FirstAttemptAt); err != nil {
			return rootoci.PoolChildView{}, err
		}
		a.record.PoolChildren[a.receipt.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolChildView{}, err
		}
	}
	if child.Stage == region.PoolChildLaunchPrepared || child.Stage == region.PoolChildLaunchUnknown {
		response, err := management.LaunchInstanceConfiguration(a.writeContext(ctx, "launch"), a.launchRequest(child))
		if err != nil {
			return rootoci.PoolChildView{}, err
		}
		if !validInstanceID(value(response.Id)) {
			return rootoci.PoolChildView{}, errors.New("original launch response has no exact positive instance ID")
		}
		child = a.record.PoolChildren[a.receipt.OperationID]
		acceptedWire(child.Launch, response.OpcRequestId, response.OpcWorkRequestId)
		child.InstanceID, child.BornAt, child.Stage = value(response.Id), child.Launch.AcceptedAt, region.PoolChildBorn
		a.record.PoolChildren[a.receipt.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolChildView{}, err
		}
	}
	if child.Stage == region.PoolChildBorn {
		facts, err := a.worker.ObservePoolWorker(a.readContext(ctx), a.factory, child.InstanceID, child.ConfigurationID, child.Descriptor)
		if err != nil {
			return rootoci.PoolChildView{}, err
		}
		if facts.Recipe.AvailabilityDomains[0] != child.AvailabilityDomain || facts.Recipe.SubnetID != child.SubnetID {
			return rootoci.PoolChildView{}, errors.New("original child boot was observed outside original signed placement")
		}
		if child.BootVolumeID == "" {
			child.BootVolumeID, child.BootAttachmentID = facts.BootVolumeID, facts.BootAttachmentID
			if err := a.record.CapacityLedger.BindBirth(a.receipt.OperationID, child.Launch.RequestSHA256, child.InstanceID, child.BootVolumeID, child.BornAt); err != nil {
				return rootoci.PoolChildView{}, err
			}
			a.record.PoolChildren[a.receipt.OperationID] = child
			if err := a.save(ctx); err != nil {
				return rootoci.PoolChildView{}, err
			}
		} else if child.BootVolumeID != facts.BootVolumeID || child.BootAttachmentID != facts.BootAttachmentID {
			return rootoci.PoolChildView{}, errors.New("original child boot identity changed before attach")
		}
		attach := a.attachRequest(child)
		wire, err := prepareWire(attach, http.MethodPost, "/instancePools/{instancePoolId}/instances")
		if err != nil {
			return rootoci.PoolChildView{}, err
		}
		child.Attach, child.Stage = wire, region.PoolChildAttachPrepared
		a.record.PoolChildren[a.receipt.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolChildView{}, err
		}
	}
	if child.Stage == region.PoolChildAttachPrepared || child.Stage == region.PoolChildAttachUnknown {
		response, err := management.AttachInstancePoolInstance(a.writeContext(ctx, "attach"), a.attachRequest(child))
		if err != nil {
			return rootoci.PoolChildView{}, err
		}
		if value(response.Id) != child.InstanceID || value(response.InstancePoolId) != child.PoolID || value(response.InstanceConfigurationId) != child.ConfigurationID ||
			value(response.CompartmentId) != a.receipt.CompartmentID || value(response.AvailabilityDomain) != child.AvailabilityDomain {
			return rootoci.PoolChildView{}, errors.New("attach result differs from exact original born child and pool")
		}
		child = a.record.PoolChildren[a.receipt.OperationID]
		acceptedWire(child.Attach, response.OpcRequestId, response.OpcWorkRequestId)
		child.Stage = region.PoolChildAttached
		a.record.PoolChildren[a.receipt.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolChildView{}, err
		}
	}
	if child.Stage == region.PoolChildAttached {
		completed, err := a.workCompleted(ctx, child.Attach, child.PoolID)
		if err != nil {
			return rootoci.PoolChildView{}, err
		}
		a.record.PoolChildren[a.receipt.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolChildView{}, err
		}
		if !completed {
			return rootoci.PoolChildView{}, fmt.Errorf("%w: original attach work request is running", ErrPending)
		}
		if _, err := a.readReadyChild(ctx, management, child); err != nil {
			return rootoci.PoolChildView{}, err
		}
		pool, err := management.GetInstancePool(a.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(child.PoolID)})
		if err != nil || value(pool.Size) != child.TargetFrom+1 {
			return rootoci.PoolChildView{}, errors.Join(err, errors.New("completed attach differs from original exact pool target"))
		}
		child.ReadyAt, child.Stage = time.Now().UTC(), region.PoolChildReady
		a.record.PoolChildren[a.receipt.OperationID] = child
		if err := a.save(ctx); err != nil {
			return rootoci.PoolChildView{}, err
		}
	}
	if child.Stage != region.PoolChildReady {
		return rootoci.PoolChildView{}, errors.New("original child has entered retirement and cannot attach again")
	}
	return a.childView(ctx, management, child)
}

func (a *attempt) prepareChild(ctx context.Context, management core.ComputeManagementClient, poolID, configurationID string, request rootoci.PoolChildExpectation) (region.PoolChildRecord, error) {
	pool, err := management.GetInstancePool(a.readContext(ctx), core.GetInstancePoolRequest{InstancePoolId: new(poolID)})
	if err != nil {
		return region.PoolChildRecord{}, err
	}
	if err := a.checkPool(pool.InstancePool, poolID); err != nil {
		return region.PoolChildRecord{}, err
	}
	members, err := a.members(ctx, management, poolID)
	if err != nil {
		return region.PoolChildRecord{}, err
	}
	if len(members) != value(pool.Size) || len(members) >= nodescale.MaxPoolNodes {
		return region.PoolChildRecord{}, fmt.Errorf("%w: actual pool target and members are not settled", ErrPending)
	}
	if err := a.knownReadyMembers(members, poolID); err != nil {
		return region.PoolChildRecord{}, err
	}
	used := map[string]bool{}
	live := 0
	for _, child := range a.record.PoolChildren {
		if child.Stage != region.PoolChildRetired {
			used[child.Node] = true
			live++
		}
	}
	if live >= nodescale.MaxPoolNodes {
		return region.PoolChildRecord{}, errors.New("region already retains its maximum protected worker liabilities")
	}
	for _, member := range members {
		used[value(member.DisplayName)] = true
	}
	node := ""
	for i := nodescale.FirstPoolNode; i < nodescale.FirstPoolNode+nodescale.MaxPoolNodes; i++ {
		candidate := fmt.Sprintf("ts-%s-%d", a.recipe.Cell, i)
		if !used[candidate] {
			node = candidate
			break
		}
	}
	if node == "" {
		return region.PoolChildRecord{}, errors.New("region has no free protected worker node identity")
	}
	descriptor, err := hostboot.Static(a.recipe.Cell, a.record.Cell, node).CanonicalBytes()
	if err != nil {
		return region.PoolChildRecord{}, err
	}
	child := region.PoolChildRecord{OperationID: a.receipt.OperationID, RecipeSHA256: a.recipe.SHA256(),
		PublicCAPEM: bytes.Clone(request.PublicCAPEM), AvailabilityDomains: slices.Clone(request.AvailabilityDomains),
		PoolID: poolID, ConfigurationID: configurationID, TargetFrom: value(pool.Size), BirthEpoch: a.original.Epoch, AvailabilityDomain: a.recipe.AvailabilityDomains[len(members)%len(a.recipe.AvailabilityDomains)],
		SubnetID: a.recipe.SubnetID, Stage: region.PoolChildReserved, Node: node, Descriptor: string(descriptor)}
	a.record.PoolChildren[a.receipt.OperationID] = child
	return child, a.save(ctx)
}

func (a *attempt) members(ctx context.Context, management core.ComputeManagementClient, poolID string) ([]core.InstanceSummary, error) {
	var result []core.InstanceSummary
	seen := map[string]bool{}
	seenPages := map[string]bool{}
	var page *string
	for pages := 0; ; pages++ {
		if pages >= 128 {
			return nil, errors.New("pool membership pagination exceeds its finite bound")
		}
		response, err := management.ListInstancePoolInstances(a.readContext(ctx), core.ListInstancePoolInstancesRequest{InstancePoolId: new(poolID), CompartmentId: new(a.record.CapacityPools[poolID].CompartmentID), Page: page})
		if err != nil {
			return nil, err
		}
		for _, member := range response.Items {
			id := value(member.Id)
			if !validInstanceID(id) || seen[id] || len(seen) >= 1024 {
				return nil, errors.New("exact pool membership has duplicate identities or exceeds finite bound")
			}
			seen[id] = true
			if value(member.State) == "TERMINATED" {
				continue
			}
			result = append(result, member)
		}
		if value(response.OpcNextPage) == "" {
			return result, nil
		}
		if seenPages[value(response.OpcNextPage)] {
			return nil, errors.New("pool membership repeated its page token")
		}
		seenPages[value(response.OpcNextPage)] = true
		page = response.OpcNextPage
	}
}

func validInstanceID(id string) bool {
	return len(id) > len("ocid1.instance.") && len(id) <= 512 && bytes.HasPrefix([]byte(id), []byte("ocid1.instance.")) && !bytes.ContainsAny([]byte(id), " \r\n\t")
}

// Membership is descriptive; only protected original births permit new growth.
func (a *attempt) knownReadyMembers(members []core.InstanceSummary, poolID string) error {
	for _, member := range members {
		known := false
		for _, child := range a.record.PoolChildren {
			if child.InstanceID == value(member.Id) && child.PoolID == poolID && child.Stage == region.PoolChildReady &&
				child.ConfigurationID == value(member.InstanceConfigurationId) && child.AvailabilityDomain == value(member.AvailabilityDomain) &&
				value(member.CompartmentId) == a.receipt.CompartmentID && value(member.State) == "RUNNING" {
				known = true
				break
			}
		}
		if !known {
			return errors.New("pool has an unknown or unsettled member requiring independent membership management")
		}
	}
	return nil
}
