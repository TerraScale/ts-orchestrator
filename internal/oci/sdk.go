package oci

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const maxProviderItems = 512

type sdkProvider struct {
	config  RegionConfig
	compute core.ComputeClient
	storage core.BlockstorageClient
	network core.VirtualNetworkClient
}

func newSDKProvider(config RegionConfig) (*sdkProvider, error) {
	ociRegion, err := config.Region.OCIRegion()
	if err != nil {
		return nil, err
	}
	provider, err := auth.InstancePrincipalConfigurationProviderForRegion(common.Region(ociRegion))
	if err != nil {
		return nil, fmt.Errorf("create OCI instance-principal provider: %w", err)
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Compute client: %w", err)
	}
	storage, err := core.NewBlockstorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Block Volume client: %w", err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI network client: %w", err)
	}
	// Pin both service clients to the configured canonical endpoint. RegionConfig
	// validation rejects realm aliases, ports, custom domains, and cross-region URLs.
	compute.Host = strings.TrimSuffix(config.Endpoint, "/")
	storage.Host = strings.TrimSuffix(config.Endpoint, "/")
	network.Host = strings.TrimSuffix(config.Endpoint, "/")
	return &sdkProvider{config: config, compute: compute, storage: storage, network: network}, nil
}

func (provider *sdkProvider) ListInstances(ctx context.Context, compartmentID string) ([]CloudInstance, error) {
	if compartmentID != provider.config.CompartmentID {
		return nil, ErrForeignResource
	}
	var instances []CloudInstance
	var page *string
	for {
		response, err := provider.compute.ListInstances(ctx, core.ListInstancesRequest{
			CompartmentId: new(compartmentID), Page: page, Limit: new(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list OCI instances: %w", err)
		}
		for _, instance := range response.Items {
			instances = append(instances, cloudInstance(instance, ""))
			if len(instances) > maxProviderItems {
				return nil, errors.New("OCI instance list exceeds its safety bound")
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return instances, nil
		}
		page = response.OpcNextPage
	}
}

func (provider *sdkProvider) GetInstance(ctx context.Context, id string) (CloudInstance, error) {
	response, err := provider.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(id)})
	if err != nil {
		return CloudInstance{}, fmt.Errorf("get OCI instance: %w", err)
	}
	instance := cloudInstance(response.Instance, stringValue(response.Etag))
	if instance.LifecycleState == "RUNNING" || instance.LifecycleState == "STOPPED" {
		if err := provider.verifyInstanceStorageAndNetwork(ctx, instance); err != nil {
			return CloudInstance{}, err
		}
	}
	return instance, nil
}

func (provider *sdkProvider) verifyInstanceStorageAndNetwork(ctx context.Context, instance CloudInstance) error {
	return verifyInstanceStorageAndNetwork(ctx, provider.config, instance, provider.compute, provider.storage, provider.network)
}

type instanceAttachmentReader interface {
	ListBootVolumeAttachments(context.Context, core.ListBootVolumeAttachmentsRequest) (core.ListBootVolumeAttachmentsResponse, error)
	ListVnicAttachments(context.Context, core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error)
}

type bootVolumeReader interface {
	GetBootVolume(context.Context, core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error)
}

type vnicReader interface {
	GetVnic(context.Context, core.GetVnicRequest) (core.GetVnicResponse, error)
}

func verifyInstanceStorageAndNetwork(ctx context.Context, config RegionConfig, instance CloudInstance,
	compute instanceAttachmentReader, storage bootVolumeReader, network vnicReader) error {
	if instance.CompartmentID != config.CompartmentID ||
		instance.AvailabilityDomain != config.AvailabilityDomain {
		return ErrForeignResource
	}
	boots, err := compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{
		CompartmentId: new(instance.CompartmentID), AvailabilityDomain: new(instance.AvailabilityDomain),
		InstanceId: new(instance.ID),
	})
	if err != nil {
		return fmt.Errorf("list exact instance boot attachment: %w", err)
	}
	if len(boots.Items) != 1 || stringValue(boots.OpcNextPage) != "" ||
		boots.Items[0].LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached ||
		stringValue(boots.Items[0].InstanceId) != instance.ID {
		return fmt.Errorf("%w: instance has no single attached boot volume", ErrForeignResource)
	}
	boot, err := storage.GetBootVolume(ctx, core.GetBootVolumeRequest{
		BootVolumeId: boots.Items[0].BootVolumeId,
	})
	if err != nil {
		return fmt.Errorf("get exact instance boot volume: %w", err)
	}
	if stringValue(boot.Id) != stringValue(boots.Items[0].BootVolumeId) ||
		stringValue(boot.CompartmentId) != config.CompartmentID ||
		stringValue(boot.ImageId) != config.ImageID ||
		int64Value(boot.SizeInGBs) != int64(config.BootVolumeGB) ||
		int64Value(boot.VpusPerGB) != int64(config.BootVolumeVPUsPerGB) {
		return fmt.Errorf("%w: instance boot image, size, or tier differs from the fleet pin", ErrImageNotQualified)
	}
	attachments, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
		CompartmentId: new(instance.CompartmentID), InstanceId: new(instance.ID),
	})
	if err != nil {
		return fmt.Errorf("list exact instance VNIC: %w", err)
	}
	if len(attachments.Items) != 1 || stringValue(attachments.OpcNextPage) != "" ||
		attachments.Items[0].LifecycleState != core.VnicAttachmentLifecycleStateAttached ||
		stringValue(attachments.Items[0].InstanceId) != instance.ID {
		return fmt.Errorf("%w: instance has no single attached primary VNIC", ErrForeignResource)
	}
	vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachments.Items[0].VnicId})
	if err != nil {
		return fmt.Errorf("get exact instance VNIC: %w", err)
	}
	gotNSGs := slices.Clone(vnic.NsgIds)
	wantNSGs := slices.Clone(config.NetworkSecurityGroupIDs)
	slices.Sort(gotNSGs)
	slices.Sort(wantNSGs)
	if stringValue(vnic.Id) != stringValue(attachments.Items[0].VnicId) ||
		stringValue(vnic.SubnetId) != config.SubnetID ||
		stringValue(vnic.PrivateIp) == "" || stringValue(vnic.PublicIp) != "" ||
		vnic.LifecycleState != core.VnicLifecycleStateAvailable ||
		!slices.Equal(gotNSGs, wantNSGs) {
		return fmt.Errorf("%w: instance VNIC differs from the private subnet and NSG pins", ErrForeignResource)
	}
	return nil
}

func (provider *sdkProvider) LaunchInstance(ctx context.Context, request LaunchRequest) (CloudInstance, error) {
	return launchInstance(ctx, provider.compute, provider.config, request)
}

type launchInstanceClient interface {
	LaunchInstance(context.Context, core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error)
}

func launchInstance(ctx context.Context, compute launchInstanceClient, config RegionConfig, request LaunchRequest) (CloudInstance, error) {
	if compute == nil || request.RetryToken == "" || request.Shape != config.Shape ||
		request.BootVolumeGB != config.BootVolumeGB || request.BootVolumeVPUsPerGB != config.BootVolumeVPUsPerGB ||
		request.BootVolumeGB < 50 || request.BootVolumeVPUsPerGB != 10 ||
		!validComputeProfile(request.Shape, request.WholeOCPUs, request.MemoryInGBs,
			request.PlacementProfileDigest, request.PlacementGeneration) {
		return CloudInstance{}, ErrPlacementProfileMismatch
	}
	descriptor, err := hostboot.Parse([]byte(request.BootDescriptor))
	if err != nil || request.ImageID != config.ImageID || descriptor.Cell != strings.ToLower(string(config.Region)) ||
		descriptor.Region != string(config.Region) || descriptor.Node != request.Node ||
		descriptor.Owner != config.Owner || descriptor.FleetGeneration != config.Generation ||
		descriptor.CreateKey != request.CreateKey || descriptor.ImageID != request.ImageID ||
		descriptor.ManagedHostProfileDigest != request.PlacementProfileDigest ||
		descriptor.IntentGeneration != request.PlacementGeneration {
		return CloudInstance{}, ErrHostBootBindingMismatch
	}
	networkSecurityGroupIDs := append([]string(nil), config.NetworkSecurityGroupIDs...)
	freeformTags := placementProfileTags(request.FreeformTags, request.PlacementProfileDigest, request.PlacementGeneration)
	details := core.LaunchInstanceDetails{
		AvailabilityDomain: new(config.AvailabilityDomain),
		CompartmentId:      new(config.CompartmentID),
		FaultDomain:        new(request.FaultDomain),
		DisplayName:        new(config.Owner + "-" + request.Node),
		FreeformTags:       freeformTags,
		Metadata: map[string]string{
			"terrascale_host_node": request.Node,
			hostboot.MetadataKey:   request.BootDescriptor,
		},
		Shape: new(request.Shape),
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{
			Ocpus:       new(float32(request.WholeOCPUs)),
			MemoryInGBs: new(float32(request.MemoryInGBs)),
		},
		CreateVnicDetails: &core.CreateVnicDetails{
			SubnetId:       new(config.SubnetID),
			NsgIds:         networkSecurityGroupIDs,
			AssignPublicIp: new(false),
		},
		LaunchOptions: &core.LaunchOptions{IsConsistentVolumeNamingEnabled: new(true)},
		SourceDetails: core.InstanceSourceViaImageDetails{
			ImageId:             new(request.ImageID),
			BootVolumeSizeInGBs: new(int64(request.BootVolumeGB)),
			BootVolumeVpusPerGB: new(int64(request.BootVolumeVPUsPerGB)),
		},
	}
	response, err := compute.LaunchInstance(ctx, core.LaunchInstanceRequest{
		LaunchInstanceDetails: details,
		OpcRetryToken:         new(request.RetryToken),
	})
	if err != nil {
		return CloudInstance{}, fmt.Errorf("launch OCI instance: %w", err)
	}
	return cloudInstance(response.Instance, stringValue(response.Etag)), nil
}

func (provider *sdkProvider) UpdateInstanceTags(ctx context.Context, id, etag string, tags map[string]string) (CloudInstance, error) {
	response, err := provider.compute.UpdateInstance(ctx, core.UpdateInstanceRequest{
		InstanceId: new(id),
		IfMatch:    new(etag),
		UpdateInstanceDetails: core.UpdateInstanceDetails{
			FreeformTags: cloneStringMap(tags),
		},
	})
	if err != nil {
		return CloudInstance{}, fmt.Errorf("update OCI instance tags: %w", err)
	}
	return cloudInstance(response.Instance, stringValue(response.Etag)), nil
}

func (provider *sdkProvider) TerminateInstance(ctx context.Context, id, etag string) error {
	preserve := true
	_, err := provider.compute.TerminateInstance(ctx, core.TerminateInstanceRequest{
		InstanceId:                         new(id),
		IfMatch:                            new(etag),
		PreserveBootVolume:                 &preserve,
		PreserveDataVolumesCreatedAtLaunch: &preserve,
	})
	if err != nil {
		return fmt.Errorf("terminate OCI instance: %w", err)
	}
	return nil
}

func (provider *sdkProvider) ListVolumeAttachments(ctx context.Context, compartmentID, instanceID string) ([]CloudAttachment, error) {
	if compartmentID != provider.config.CompartmentID {
		return nil, ErrForeignResource
	}
	var attachments []CloudAttachment
	var page *string
	for {
		request := core.ListVolumeAttachmentsRequest{
			CompartmentId: new(compartmentID), Page: page, Limit: new(100),
		}
		if instanceID != "" {
			request.InstanceId = new(instanceID)
		}
		response, err := provider.compute.ListVolumeAttachments(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("list OCI volume attachments: %w", err)
		}
		for _, attachment := range response.Items {
			attachments = append(attachments, cloudAttachment(attachment, ""))
			if len(attachments) > maxProviderItems {
				return nil, errors.New("OCI attachment list exceeds its safety bound")
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return attachments, nil
		}
		page = response.OpcNextPage
	}
}

func (provider *sdkProvider) GetVolumeAttachment(ctx context.Context, id string) (CloudAttachment, error) {
	response, err := provider.compute.GetVolumeAttachment(ctx, core.GetVolumeAttachmentRequest{VolumeAttachmentId: new(id)})
	if err != nil {
		return CloudAttachment{}, fmt.Errorf("get OCI volume attachment: %w", err)
	}
	return cloudAttachment(response.VolumeAttachment, stringValue(response.Etag)), nil
}

func (provider *sdkProvider) ListInstanceDevices(ctx context.Context, instanceID string) ([]CloudDevice, error) {
	var devices []CloudDevice
	var page *string
	for {
		response, err := provider.compute.ListInstanceDevices(ctx, core.ListInstanceDevicesRequest{
			InstanceId: new(instanceID), IsAvailable: new(true), Page: page, Limit: new(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list OCI instance devices: %w", err)
		}
		for _, device := range response.Items {
			devices = append(devices, cloudDevice(device))
			if len(devices) > maxProviderItems {
				return nil, errors.New("OCI instance device list exceeds its safety bound")
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return devices, nil
		}
		page = response.OpcNextPage
	}
}

func (provider *sdkProvider) AttachVolume(ctx context.Context, request CloudVolumeAttachRequest) (CloudAttachment, error) {
	response, err := provider.compute.AttachVolume(ctx, core.AttachVolumeRequest{
		AttachVolumeDetails: core.AttachParavirtualizedVolumeDetails{
			InstanceId:                     new(request.InstanceID),
			VolumeId:                       new(request.VolumeID),
			Device:                         new(request.Device),
			IsReadOnly:                     &request.IsReadOnly,
			IsShareable:                    &request.IsShareable,
			IsPvEncryptionInTransitEnabled: &request.IsPvEncryptionInTransitEnabled,
		},
		OpcRetryToken: new(retryToken(request.IdempotencyKey)),
	})
	if err != nil {
		return CloudAttachment{}, fmt.Errorf("attach retained OCI volume: %w", err)
	}
	return cloudAttachment(response.VolumeAttachment, stringValue(response.Etag)), nil
}

func (provider *sdkProvider) DetachVolume(ctx context.Context, attachmentID, etag string) error {
	_, err := provider.compute.DetachVolume(ctx, core.DetachVolumeRequest{
		VolumeAttachmentId: new(attachmentID),
		IfMatch:            new(etag),
	})
	if err != nil {
		return fmt.Errorf("detach retained OCI volume: %w", err)
	}
	return nil
}

func (provider *sdkProvider) ListVolumes(ctx context.Context, compartmentID, availabilityDomain string) ([]CloudVolume, error) {
	if compartmentID != provider.config.CompartmentID || availabilityDomain != provider.config.AvailabilityDomain {
		return nil, ErrForeignResource
	}
	var volumes []CloudVolume
	var page *string
	for {
		response, err := provider.storage.ListVolumes(ctx, core.ListVolumesRequest{
			CompartmentId:      new(compartmentID),
			AvailabilityDomain: new(availabilityDomain),
			Page:               page,
			Limit:              new(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list OCI volumes: %w", err)
		}
		for _, volume := range response.Items {
			volumes = append(volumes, cloudVolume(volume))
			if len(volumes) > maxProviderItems {
				return nil, errors.New("OCI volume list exceeds its safety bound")
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return volumes, nil
		}
		page = response.OpcNextPage
	}
}

func (provider *sdkProvider) CreateVolume(ctx context.Context, request VolumeCreateRequest, tags map[string]string, retry string) (CloudVolume, error) {
	response, err := provider.storage.CreateVolume(ctx, core.CreateVolumeRequest{
		CreateVolumeDetails: core.CreateVolumeDetails{
			CompartmentId:      new(provider.config.CompartmentID),
			AvailabilityDomain: new(request.AvailabilityDomain),
			SizeInGBs:          new(request.SizeGB),
			VpusPerGB:          new(int64(provider.config.DataVolumeVPUsPerGB)),
			DisplayName:        new("ts-member-data-" + digest(request.CreateKey)[:12]),
			FreeformTags:       cloneStringMap(tags),
		},
		OpcRetryToken: new(retry),
	})
	if err != nil {
		return CloudVolume{}, fmt.Errorf("create retained OCI volume: %w", err)
	}
	return cloudVolume(response.Volume), nil
}

func (provider *sdkProvider) GetVolume(ctx context.Context, id string) (CloudVolume, error) {
	response, err := provider.storage.GetVolume(ctx, core.GetVolumeRequest{VolumeId: new(id)})
	if err != nil {
		return CloudVolume{}, fmt.Errorf("get retained OCI volume: %w", err)
	}
	volume := response.Volume
	return CloudVolume{
		ID:                 stringValue(volume.Id),
		CompartmentID:      stringValue(volume.CompartmentId),
		AvailabilityDomain: stringValue(volume.AvailabilityDomain),
		SizeGB:             int64Value(volume.SizeInGBs),
		VPUsPerGB:          int64Value(volume.VpusPerGB),
		LifecycleState:     string(volume.LifecycleState),
		FreeformTags:       cloneStringMap(volume.FreeformTags),
	}, nil
}

func cloudVolume(volume core.Volume) CloudVolume {
	return CloudVolume{
		ID:                 stringValue(volume.Id),
		CompartmentID:      stringValue(volume.CompartmentId),
		AvailabilityDomain: stringValue(volume.AvailabilityDomain),
		SizeGB:             int64Value(volume.SizeInGBs),
		VPUsPerGB:          int64Value(volume.VpusPerGB),
		LifecycleState:     string(volume.LifecycleState),
		FreeformTags:       cloneStringMap(volume.FreeformTags),
	}
}

func cloudInstance(instance core.Instance, etag string) CloudInstance {
	var ocpus, memoryInGBs *float32
	if instance.ShapeConfig != nil {
		ocpus = instance.ShapeConfig.Ocpus
		memoryInGBs = instance.ShapeConfig.MemoryInGBs
	}
	return CloudInstance{
		ID:                            stringValue(instance.Id),
		CompartmentID:                 stringValue(instance.CompartmentId),
		AvailabilityDomain:            stringValue(instance.AvailabilityDomain),
		FaultDomain:                   stringValue(instance.FaultDomain),
		Shape:                         stringValue(instance.Shape),
		Ocpus:                         ocpus,
		MemoryInGBs:                   memoryInGBs,
		LifecycleState:                string(instance.LifecycleState),
		ETag:                          etag,
		ImageID:                       stringValue(instance.ImageId),
		ConsistentVolumeNamingEnabled: consistentVolumeNamingEnabled(instance.LaunchOptions),
		Metadata:                      cloneStringMap(instance.Metadata),
		FreeformTags:                  cloneStringMap(instance.FreeformTags),
	}
}

func cloudAttachment(attachment core.VolumeAttachment, etag string) CloudAttachment {
	return CloudAttachment{
		ID:                             stringValue(attachment.GetId()),
		VolumeID:                       stringValue(attachment.GetVolumeId()),
		InstanceID:                     stringValue(attachment.GetInstanceId()),
		LifecycleState:                 string(attachment.GetLifecycleState()),
		ETag:                           etag,
		Device:                         stringValue(attachment.GetDevice()),
		IsReadOnly:                     attachment.GetIsReadOnly(),
		IsShareable:                    attachment.GetIsShareable(),
		IsPvEncryptionInTransitEnabled: attachment.GetIsPvEncryptionInTransitEnabled(),
	}
}

func cloudDevice(device core.Device) CloudDevice {
	return CloudDevice{Name: stringValue(device.Name), IsAvailable: device.IsAvailable}
}

func consistentVolumeNamingEnabled(options *core.LaunchOptions) *bool {
	if options == nil {
		return nil
	}
	return options.IsConsistentVolumeNamingEnabled
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func int64Value(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func cloneStringMap(values map[string]string) map[string]string {
	return maps.Clone(values)
}
