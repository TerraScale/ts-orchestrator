package capacityinventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/resourcesearch"
)

// Family lists cover every AD by omitting the optional AD filter. Search is
// retained only to expose additional families which still need cost bounds.
func directResources(ctx context.Context, compute core.ComputeClient, block core.BlockstorageClient, compartment string) ([]resourcesearch.ResourceSummary, error) {
	var resources []resourcesearch.ResourceSummary
	instances, instanceErr := inventoryPages(func(page *string) ([]core.Instance, *string, error) {
		response, err := compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: new(compartment), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	for _, instance := range instances {
		resources = append(resources, resourcesearch.ResourceSummary{Identifier: instance.Id, CompartmentId: instance.CompartmentId, ResourceType: new("Instance"), LifecycleState: new(string(instance.LifecycleState))})
	}
	volumes, volumeErr := inventoryPages(func(page *string) ([]core.Volume, *string, error) {
		response, err := block.ListVolumes(ctx, core.ListVolumesRequest{CompartmentId: new(compartment), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	for _, volume := range volumes {
		resources = append(resources, resourcesearch.ResourceSummary{Identifier: volume.Id, CompartmentId: volume.CompartmentId, ResourceType: new("Volume"), LifecycleState: new(string(volume.LifecycleState))})
	}
	boots, bootErr := inventoryPages(func(page *string) ([]core.BootVolume, *string, error) {
		response, err := block.ListBootVolumes(ctx, core.ListBootVolumesRequest{CompartmentId: new(compartment), Page: page})
		return response.Items, response.OpcNextPage, err
	})
	for _, boot := range boots {
		resources = append(resources, resourcesearch.ResourceSummary{Identifier: boot.Id, CompartmentId: boot.CompartmentId, ResourceType: new("BootVolume"), LifecycleState: new(string(boot.LifecycleState))})
	}
	return resources, errors.Join(instanceErr, volumeErr, bootErr)
}

func inventoryPages[T any](read func(*string) ([]T, *string, error)) ([]T, error) {
	var result []T
	var page *string
	seen := map[string]bool{}
	for range 64 {
		items, next, err := read(page)
		if err != nil {
			return result, err
		}
		result = append(result, items...)
		if len(result) > 10000 {
			return result, errors.New("direct OCI inventory exceeds resource bound")
		}
		if next == nil || *next == "" {
			return result, nil
		}
		if seen[*next] {
			return result, errors.New("direct OCI inventory repeated a pagination token")
		}
		seen[*next] = true
		page = next
	}
	return result, errors.New("direct OCI inventory pagination incomplete")
}

func bootAttribution(ctx context.Context, compute core.ComputeClient, boot core.BootVolume, resource *Resource) error {
	if resource.OperationID != "" && resource.RecipeSHA256 != "" {
		return nil
	}
	if boot.AvailabilityDomain == nil || *boot.AvailabilityDomain == "" || boot.Id == nil || boot.CompartmentId == nil {
		return errors.New("boot attribution requires exact compartment and AD readback")
	}
	attachments, err := inventoryPages(func(page *string) ([]core.BootVolumeAttachment, *string, error) {
		response, err := compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{CompartmentId: boot.CompartmentId, AvailabilityDomain: boot.AvailabilityDomain, BootVolumeId: boot.Id, Page: page})
		return response.Items, response.OpcNextPage, err
	})
	if err != nil {
		return fmt.Errorf("read boot attachment ancestry: %w", err)
	}
	instanceID := ""
	for _, attachment := range attachments {
		if attachment.BootVolumeId == nil || *attachment.BootVolumeId != *boot.Id || attachment.CompartmentId == nil || *attachment.CompartmentId != *boot.CompartmentId || attachment.AvailabilityDomain == nil || *attachment.AvailabilityDomain != *boot.AvailabilityDomain {
			return errors.New("boot attachment ancestry differs from direct volume scope")
		}
		if attachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached {
			continue
		}
		if attachment.InstanceId == nil || *attachment.InstanceId == "" || instanceID != "" && instanceID != *attachment.InstanceId {
			return errors.New("boot attachment ancestry is absent or ambiguous")
		}
		instanceID = *attachment.InstanceId
	}
	if instanceID == "" {
		return errors.New("boot operation membership requires a retained immutable journal binding")
	}
	response, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return err
	}
	if response.Id == nil || *response.Id != instanceID || response.CompartmentId == nil || *response.CompartmentId != *boot.CompartmentId || response.AvailabilityDomain == nil || *response.AvailabilityDomain != *boot.AvailabilityDomain {
		return errors.New("boot ancestor differs from actual instance scope")
	}
	operation, recipe := response.FreeformTags["ts-operation-id"], response.FreeformTags["ts-recipe-sha256"]
	if operation == "" || recipe == "" || resource.OperationID != "" && resource.OperationID != operation || resource.RecipeSHA256 != "" && resource.RecipeSHA256 != recipe {
		return errors.New("boot ancestry lacks unambiguous operation and recipe attribution")
	}
	resource.OperationID, resource.RecipeSHA256 = operation, recipe
	return nil
}

func terminalState(state string) bool { return state == "TERMINATED" || state == "DELETED" }
