package region

import (
	"context"
	"errors"
	"maps"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// PoolWorkerObservation describes actual SDK state and grants no birth,
// registration or deletion authority. Root separately checks its original IDs.
type PoolWorkerObservation struct {
	Recipe                         WorkerRecipe
	PrivateIP, VNICID, FaultDomain string
	BootVolumeID, BootAttachmentID string
}

func (v VerifiedWorkerRecipe) ObservePoolWorker(ctx context.Context, factory *ociclient.Factory, instanceID, configurationID, descriptorWire string) (PoolWorkerObservation, error) {
	if factory == nil {
		return PoolWorkerObservation{}, errors.New("pool worker observation requires the actual regional SDK")
	}
	if err := v.Revalidate(ctx); err != nil {
		return PoolWorkerObservation{}, err
	}
	descriptor, err := hostboot.ParseHost([]byte(descriptorWire))
	if err != nil || !descriptor.IsStatic() || !strings.EqualFold(descriptor.Region, v.recipe.Cell) {
		return PoolWorkerObservation{}, errors.Join(err, errors.New("pool observation has no exact original static descriptor"))
	}
	candidate, privateIP, vnicID, bootID, err := readWorkerInstance(ctx, factory, instanceID, configurationID, v.recipe.Cell, v.recipe.Role, v.recipe.Architecture)
	if err != nil {
		return PoolWorkerObservation{}, err
	}
	if candidate.Metadata[hostboot.MetadataKey] != descriptorWire {
		return PoolWorkerObservation{}, errors.New("actual worker metadata changed its original protected boot identity")
	}
	delete(candidate.Metadata, hostboot.MetadataKey)
	if err := v.Match(candidate); err != nil {
		return PoolWorkerObservation{}, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return PoolWorkerObservation{}, err
	}
	response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return PoolWorkerObservation{}, err
	}
	metadata := maps.Clone(response.Metadata)
	delete(metadata, hostboot.MetadataKey)
	if workerString(response.Id) != instanceID || workerString(response.InstanceConfigurationId) != configurationID ||
		workerString(response.CompartmentId) != candidate.CompartmentID || workerString(response.AvailabilityDomain) != candidate.AvailabilityDomains[0] ||
		workerString(response.Shape) != candidate.Shape || response.ShapeConfig == nil || response.ShapeConfig.Ocpus == nil || response.ShapeConfig.MemoryInGBs == nil ||
		float64(*response.ShapeConfig.Ocpus) != candidate.OCPUs || float64(*response.ShapeConfig.MemoryInGBs) != candidate.MemoryGB ||
		!maps.Equal(metadata, candidate.Metadata) || response.InstanceOptions == nil || (response.InstanceOptions.AreLegacyImdsEndpointsDisabled == nil || !*response.InstanceOptions.AreLegacyImdsEndpointsDisabled) ||
		len(response.ExtendedMetadata) != 0 || workerString(response.IpxeScript) != "" ||
		response.LifecycleState != core.InstanceLifecycleStateRunning || response.Metadata[hostboot.MetadataKey] != descriptorWire || workerString(response.FaultDomain) == "" {
		return PoolWorkerObservation{}, errors.New("pool worker changed during actual instance observation")
	}
	attachments, err := compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{CompartmentId: new(candidate.CompartmentID),
		AvailabilityDomain: new(candidate.AvailabilityDomains[0]), InstanceId: new(instanceID)})
	if err != nil {
		return PoolWorkerObservation{}, err
	}
	if attachments.OpcNextPage != nil && *attachments.OpcNextPage != "" {
		return PoolWorkerObservation{}, errors.New("exact boot attachment changed during finite child observation")
	}
	attachmentID := ""
	for _, attachment := range attachments.Items {
		if attachment.LifecycleState == core.BootVolumeAttachmentLifecycleStateDetached {
			continue
		}
		if attachmentID != "" || attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached || workerString(attachment.BootVolumeId) != bootID ||
			workerString(attachment.InstanceId) != instanceID || workerString(attachment.Id) == "" ||
			workerString(attachment.CompartmentId) != candidate.CompartmentID || workerString(attachment.AvailabilityDomain) != candidate.AvailabilityDomains[0] {
			return PoolWorkerObservation{}, errors.New("exact original boot attachment differs from fresh worker facts")
		}
		attachmentID = workerString(attachment.Id)
	}
	if attachmentID == "" {
		return PoolWorkerObservation{}, errors.New("pool worker has no exact original boot attachment")
	}
	if err := v.Revalidate(ctx); err != nil {
		return PoolWorkerObservation{}, err
	}
	return PoolWorkerObservation{Recipe: candidate, PrivateIP: privateIP, VNICID: vnicID, FaultDomain: workerString(response.FaultDomain), BootVolumeID: bootID, BootAttachmentID: attachmentID}, nil
}
