package rootcapacity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"maps"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func prepareWire(request common.OCIRequest, method, path string) (*region.PoolWireRecord, error) {
	raw, err := request.HTTPRequest(method, path, nil, nil)
	if err != nil {
		return nil, err
	}
	digest, err := wireSHA256(&raw)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &region.PoolWireRecord{RequestSHA256: digest, RetryToken: raw.Header.Get("opc-retry-token"), IfMatch: raw.Header.Get("if-match"), FirstAttemptAt: now, LastAttemptAt: now}, nil
}

func digestValue(value any) (string, error) {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func retryToken(operation, kind string) *string {
	digest := sha256.Sum256([]byte(operation + ":" + kind))
	return new(hex.EncodeToString(digest[:]))
}

func noRetry() common.RequestMetadata {
	policy := common.NoRetryPolicy()
	return common.RequestMetadata{RetryPolicy: &policy}
}

func (a *attempt) tags(role string) map[string]string {
	return map[string]string{"ts-cell": a.recipe.Cell, "ts-role": role, "ts-pool": nodescale.PoolName(a.recipe.Cell, a.recipe.Capacity),
		"ts-capacity-role": a.recipe.Capacity.Role, "ts-architecture": a.recipe.Capacity.Architecture, "ts-shape": a.recipe.Capacity.Shape,
		"ts-operation-id": a.receipt.OperationID, "ts-recipe-sha256": a.recipe.SHA256()}
}

func (a *attempt) launchDetails() *core.InstanceConfigurationLaunchInstanceDetails {
	return &core.InstanceConfigurationLaunchInstanceDetails{CompartmentId: new(a.receipt.CompartmentID), Shape: new(a.recipe.Capacity.Shape),
		ShapeConfig:       &core.InstanceConfigurationLaunchInstanceShapeConfigDetails{Ocpus: new(a.recipe.OCPUs), MemoryInGBs: new(a.recipe.MemoryGB)},
		SourceDetails:     core.InstanceConfigurationInstanceSourceViaImageDetails{ImageId: new(a.recipe.ImageID), BootVolumeSizeInGBs: new(int64(nodescale.BootVolumeGB))},
		CreateVnicDetails: &core.InstanceConfigurationCreateVnicDetails{AssignPublicIp: new(false), SubnetId: new(a.recipe.SubnetID), NsgIds: a.recipe.NSGIDs},
		Metadata:          maps.Clone(a.recipe.Metadata), InstanceOptions: &core.InstanceConfigurationInstanceOptions{AreLegacyImdsEndpointsDisabled: new(true)},
		LicensingConfigs: []core.LaunchInstanceLicensingConfig{}, FreeformTags: a.tags("node")}
}

func (a *attempt) configurationRequest() core.CreateInstanceConfigurationRequest {
	return core.CreateInstanceConfigurationRequest{CreateInstanceConfiguration: core.CreateInstanceConfigurationDetails{
		CompartmentId: new(a.receipt.CompartmentID), DisplayName: new(nodescale.ConfigurationName(a.recipe) + "-" + a.receipt.OperationID),
		FreeformTags: a.tags("node-config"), InstanceDetails: core.ComputeInstanceDetails{LaunchDetails: a.launchDetails()}},
		OpcRetryToken: retryToken(a.receipt.OperationID, "configuration"), RequestMetadata: noRetry()}
}

func (a *attempt) poolRequest(configurationID string) core.CreateInstancePoolRequest {
	placements := make([]core.CreateInstancePoolPlacementConfigurationDetails, 0, len(a.recipe.AvailabilityDomains))
	for _, ad := range a.recipe.AvailabilityDomains {
		placements = append(placements, core.CreateInstancePoolPlacementConfigurationDetails{AvailabilityDomain: new(ad),
			PrimaryVnicSubnets: &core.InstancePoolPlacementPrimarySubnet{SubnetId: new(a.recipe.SubnetID)}})
	}
	return core.CreateInstancePoolRequest{CreateInstancePoolDetails: core.CreateInstancePoolDetails{CompartmentId: new(a.receipt.CompartmentID),
		InstanceConfigurationId: new(configurationID), DisplayName: new(nodescale.PoolName(a.recipe.Cell, a.recipe.Capacity)),
		Size: new(0), PlacementConfigurations: placements, FreeformTags: a.tags("node-pool")},
		OpcRetryToken: retryToken(a.receipt.OperationID, "pool"), RequestMetadata: noRetry()}
}

func (a *attempt) launchRequest(child region.PoolChildRecord) core.LaunchInstanceConfigurationRequest {
	details := a.launchDetails()
	details.AvailabilityDomain, details.DisplayName = new(child.AvailabilityDomain), new(child.Node)
	details.Metadata[hostboot.MetadataKey] = child.Descriptor
	details.FreeformTags["ts-node"] = child.Node
	return core.LaunchInstanceConfigurationRequest{InstanceConfigurationId: new(child.ConfigurationID),
		InstanceConfiguration: core.ComputeInstanceDetails{LaunchDetails: details},
		OpcRetryToken:         retryToken(a.receipt.OperationID, "launch"), RequestMetadata: noRetry()}
}

func (a *attempt) attachRequest(child region.PoolChildRecord) core.AttachInstancePoolInstanceRequest {
	return core.AttachInstancePoolInstanceRequest{InstancePoolId: new(child.PoolID),
		AttachInstancePoolInstanceDetails: core.AttachInstancePoolInstanceDetails{InstanceId: new(child.InstanceID)},
		OpcRetryToken:                     retryToken(a.receipt.OperationID, "attach"), RequestMetadata: noRetry()}
}

func (a *attempt) detachRequest(poolID, instanceID string) core.DetachInstancePoolInstanceRequest {
	return core.DetachInstancePoolInstanceRequest{InstancePoolId: new(poolID), DetachInstancePoolInstanceDetails: core.DetachInstancePoolInstanceDetails{
		InstanceId: new(instanceID), IsAutoTerminate: new(false), IsDecrementSize: new(true)},
		OpcRetryToken: retryToken(a.operation, "detach"), RequestMetadata: noRetry()}
}

func acceptedWire(wire *region.PoolWireRecord, requestID, workRequestID *string) {
	wire.PendingAttemptID, wire.AcceptedAt = "", time.Now().UTC()
	wire.OpcRequestID, wire.WorkRequestID = value(requestID), value(workRequestID)
}

func value[T any](pointer *T) (zero T) {
	if pointer != nil {
		return *pointer
	}
	return zero
}

// paths use the same tagged SDK representation before and after signing.
const configurationCreatePath = "/instanceConfigurations"
const poolCreatePath = "/instancePools"
