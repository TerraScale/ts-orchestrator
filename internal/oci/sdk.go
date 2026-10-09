package oci

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const maxProviderItems = 512

type sdkProvider struct {
	config       RegionConfig
	hostMetadata map[string]string
	compute      core.ComputeClient
	storage      core.BlockstorageClient
	network      core.VirtualNetworkClient
	// verified is the optional Observe verification cache; nil disables it.
	verified *verificationCache
}

func newSDKProvider(config RegionConfig, hostMetadata map[string]string) (*sdkProvider, error) {
	ociRegion, err := config.Region.OCIRegion()
	if err != nil {
		return nil, err
	}
	// The shared factory gives the fleet the process-wide per-service token
	// buckets and the 429/5xx retry policy that never replays an unsafe write.
	factory, err := ociclient.InstancePrincipal(ociRegion)
	if err != nil {
		return nil, err
	}
	return sdkProviderFrom(factory, config, hostMetadata)
}

// sdkProviderFrom builds the provider on the clients of one credential
// factory: instance principal for the fleet, the operator's profile for
// member data volumes.
func sdkProviderFrom(factory *ociclient.Factory, config RegionConfig, hostMetadata map[string]string) (*sdkProvider, error) {
	compute, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	storage, err := factory.Blockstorage()
	if err != nil {
		return nil, err
	}
	network, err := factory.Network()
	if err != nil {
		return nil, err
	}
	// Pin both service clients to the configured canonical endpoint. RegionConfig
	// validation rejects realm aliases, ports, custom domains, and cross-region URLs.
	ociclient.PinHost(&compute.BaseClient, config.Endpoint)
	ociclient.PinHost(&storage.BaseClient, config.Endpoint)
	ociclient.PinHost(&network.BaseClient, config.Endpoint)
	// Every OCI call of the managed fleet passes through these three
	// dispatchers, so wrapping them measures calls, errors and latency by
	// templated operation without touching signing, rate limiting or retry
	// behavior (the shared factory installs those on the interceptor and
	// retry policy, which run around the dispatcher).
	compute.HTTPClient = ociclient.Instrument(compute.HTTPClient, "compute")
	storage.HTTPClient = ociclient.Instrument(storage.HTTPClient, "blockstorage")
	network.HTTPClient = ociclient.Instrument(network.HTTPClient, "network")
	return &sdkProvider{config: config, hostMetadata: maps.Clone(hostMetadata),
		compute: compute, storage: storage, network: network}, nil
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
	if instance.LifecycleState != "TERMINATED" && instance.LifecycleState != "TERMINATING" {
		if privateIP, ok := provider.verified.lookup(ctx, instance.ID, instance.ETag); ok &&
			instance.CompartmentID == provider.config.CompartmentID &&
			instance.AvailabilityDomain == provider.config.AvailabilityDomain {
			instance.PrivateIP = privateIP
			return instance, nil
		}
		privateIP, err := provider.verifyInstanceStorageAndNetwork(ctx, instance)
		if err != nil {
			provider.verified.forget(instance.ID)
			return CloudInstance{}, err
		}
		provider.verified.store(instance.ID, instance.ETag, privateIP)
		instance.PrivateIP = privateIP
	}
	return instance, nil
}

func (provider *sdkProvider) verifyInstanceStorageAndNetwork(ctx context.Context, instance CloudInstance) (string, error) {
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
	compute instanceAttachmentReader, storage bootVolumeReader, network vnicReader) (string, error) {
	if instance.CompartmentID != config.CompartmentID ||
		instance.AvailabilityDomain != config.AvailabilityDomain {
		return "", ErrForeignResource
	}
	boots, err := compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{
		CompartmentId: new(instance.CompartmentID), AvailabilityDomain: new(instance.AvailabilityDomain),
		InstanceId: new(instance.ID),
	})
	if err != nil {
		return "", fmt.Errorf("list exact instance boot attachment: %w", err)
	}
	if len(boots.Items) == 0 && stringValue(boots.OpcNextPage) == "" {
		return "", fmt.Errorf("%w: boot volume attachment is not visible yet", ErrOutcomeUnknown)
	}
	if len(boots.Items) == 1 && stringValue(boots.OpcNextPage) == "" &&
		(boots.Items[0].LifecycleState == core.BootVolumeAttachmentLifecycleStateAttaching ||
			boots.Items[0].LifecycleState == core.BootVolumeAttachmentLifecycleStateDetaching) &&
		stringValue(boots.Items[0].InstanceId) == instance.ID {
		return "", fmt.Errorf("%w: boot volume attachment is transitioning", ErrOutcomeUnknown)
	}
	if len(boots.Items) != 1 || stringValue(boots.OpcNextPage) != "" ||
		boots.Items[0].LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached ||
		stringValue(boots.Items[0].InstanceId) != instance.ID ||
		stringValue(boots.Items[0].BootVolumeId) == "" {
		return "", fmt.Errorf("%w: instance has no single attached boot volume", ErrForeignResource)
	}
	boot, err := storage.GetBootVolume(ctx, core.GetBootVolumeRequest{
		BootVolumeId: boots.Items[0].BootVolumeId,
	})
	if err != nil {
		return "", fmt.Errorf("get exact instance boot volume: %w", err)
	}
	if stringValue(boot.Id) != stringValue(boots.Items[0].BootVolumeId) ||
		stringValue(boot.CompartmentId) != config.CompartmentID ||
		instance.ImageID == "" || stringValue(boot.ImageId) != instance.ImageID ||
		int64Value(boot.SizeInGBs) != int64(config.BootVolumeGB) ||
		int64Value(boot.VpusPerGB) != int64(config.BootVolumeVPUsPerGB) {
		return "", errors.Join(ErrForeignResource,
			fmt.Errorf("%w: instance boot image, size, or tier differs from the instance image and fleet pins", ErrImageNotQualified))
	}
	attachments, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
		CompartmentId: new(instance.CompartmentID), InstanceId: new(instance.ID),
	})
	if err != nil {
		return "", fmt.Errorf("list exact instance VNIC: %w", err)
	}
	if len(attachments.Items) == 0 && stringValue(attachments.OpcNextPage) == "" {
		return "", fmt.Errorf("%w: primary VNIC attachment is not visible yet", ErrOutcomeUnknown)
	}
	if len(attachments.Items) == 1 && stringValue(attachments.OpcNextPage) == "" &&
		(attachments.Items[0].LifecycleState == core.VnicAttachmentLifecycleStateAttaching ||
			attachments.Items[0].LifecycleState == core.VnicAttachmentLifecycleStateDetaching) &&
		stringValue(attachments.Items[0].InstanceId) == instance.ID {
		return "", fmt.Errorf("%w: primary VNIC attachment is transitioning", ErrOutcomeUnknown)
	}
	if len(attachments.Items) != 1 || stringValue(attachments.OpcNextPage) != "" ||
		attachments.Items[0].LifecycleState != core.VnicAttachmentLifecycleStateAttached ||
		stringValue(attachments.Items[0].InstanceId) != instance.ID ||
		stringValue(attachments.Items[0].VnicId) == "" {
		return "", fmt.Errorf("%w: instance has no single attached primary VNIC", ErrForeignResource)
	}
	vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachments.Items[0].VnicId})
	if err != nil {
		return "", fmt.Errorf("get exact instance VNIC: %w", err)
	}
	gotNSGs := slices.Clone(vnic.NsgIds)
	wantNSGs := slices.Clone(config.NetworkSecurityGroupIDs)
	slices.Sort(gotNSGs)
	slices.Sort(wantNSGs)
	if stringValue(vnic.Id) != stringValue(attachments.Items[0].VnicId) ||
		stringValue(vnic.SubnetId) != config.SubnetID ||
		!validManagedPrivateIP(stringValue(vnic.PrivateIp)) || stringValue(vnic.PublicIp) != "" ||
		vnic.SkipSourceDestCheck != nil && *vnic.SkipSourceDestCheck ||
		vnic.LifecycleState != core.VnicLifecycleStateAvailable ||
		!slices.Equal(gotNSGs, wantNSGs) {
		return "", fmt.Errorf("%w: instance VNIC differs from the private subnet and NSG pins", ErrForeignResource)
	}
	return stringValue(vnic.PrivateIp), nil
}

func (provider *sdkProvider) LaunchInstance(ctx context.Context, request LaunchRequest) (CloudInstance, error) {
	return launchInstance(ctx, provider.compute, provider.config, request, provider.hostMetadata)
}

type launchInstanceClient interface {
	LaunchInstance(context.Context, core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error)
}

// launchInstance adds the fleet's launch material to the reserved host keys.
// The material may not replace a key the fleet itself binds and observes.
// The fleet chooses and qualifies the image: its pin or the cell spec's
// launch image.
func launchInstance(ctx context.Context, compute launchInstanceClient, config RegionConfig, request LaunchRequest,
	hostMetadata map[string]string,
) (CloudInstance, error) {
	if compute == nil || request.RetryToken == "" || !validManagedPrivateIP(request.PrivateIP) || request.Shape != config.Shape ||
		request.BootVolumeGB != config.BootVolumeGB || request.BootVolumeVPUsPerGB != config.BootVolumeVPUsPerGB ||
		request.BootVolumeGB < 50 || request.BootVolumeVPUsPerGB != 10 ||
		!validComputeProfile(request.Shape, request.WholeOCPUs, request.MemoryInGBs,
			request.PlacementProfileDigest, request.PlacementGeneration) {
		return CloudInstance{}, ErrPlacementProfileMismatch
	}
	descriptor, err := hostboot.Parse([]byte(request.BootDescriptor))
	if err != nil || !isOCID(request.ImageID, "image") || descriptor.Cell != strings.ToLower(string(config.Region)) ||
		descriptor.Region != string(config.Region) || descriptor.Node != request.Node ||
		descriptor.Owner != config.Owner || descriptor.FleetGeneration != config.Generation ||
		descriptor.CreateKey != request.CreateKey || descriptor.ImageID != request.ImageID ||
		descriptor.ManagedHostProfileDigest != request.PlacementProfileDigest ||
		descriptor.IntentGeneration != request.PlacementGeneration {
		return CloudInstance{}, ErrHostBootBindingMismatch
	}
	metadata := maps.Clone(hostMetadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	for key, value := range map[string]string{"terrascale_host_node": request.Node, hostboot.MetadataKey: request.BootDescriptor} {
		if _, reserved := metadata[key]; reserved {
			return CloudInstance{}, ErrHostBootBindingMismatch
		}
		metadata[key] = value
	}
	networkSecurityGroupIDs := append([]string(nil), config.NetworkSecurityGroupIDs...)
	freeformTags := placementProfileTags(request.FreeformTags, request.PlacementProfileDigest, request.PlacementGeneration)
	// Launch options come from the image capability schema: OCI rejects partial
	// LaunchOptions, and volume attach verifies consistent naming on the
	// instance. In-transit encryption is enabled per instance, and retained
	// volumes attach only with it.
	details := core.LaunchInstanceDetails{
		AvailabilityDomain: new(config.AvailabilityDomain),
		CompartmentId:      new(config.CompartmentID),
		FaultDomain:        new(request.FaultDomain),
		DisplayName:        new(request.DisplayName),
		FreeformTags:       freeformTags,
		Metadata:           metadata,
		Shape:              new(request.Shape),
		ShapeConfig: &core.LaunchInstanceShapeConfigDetails{
			Ocpus:       new(float32(request.WholeOCPUs)),
			MemoryInGBs: new(float32(request.MemoryInGBs)),
		},
		CreateVnicDetails: &core.CreateVnicDetails{
			SubnetId:            new(config.SubnetID),
			PrivateIp:           new(request.PrivateIP),
			NsgIds:              networkSecurityGroupIDs,
			AssignPublicIp:      new(false),
			SkipSourceDestCheck: new(false),
		},
		IsPvEncryptionInTransitEnabled: new(retainedVolumeEncryptionInTransit),
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
	return provider.TerminateTerminalInstance(ctx, id, etag)
}

func (provider *sdkProvider) TerminateTerminalInstance(ctx context.Context, id, etag string) error {
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
		OpcRetryToken: new(request.RetryToken),
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
	details := core.CreateVolumeDetails{
		CompartmentId:      new(provider.config.CompartmentID),
		AvailabilityDomain: new(request.AvailabilityDomain),
		SizeInGBs:          new(request.SizeGB),
		VpusPerGB:          new(int64(provider.config.DataVolumeVPUsPerGB)),
		DisplayName:        new(request.Name),
		FreeformTags:       cloneStringMap(tags),
	}
	if request.SourceBackupID != "" {
		details.SourceDetails = core.VolumeSourceFromVolumeBackupDetails{Id: new(request.SourceBackupID)}
	}
	response, err := provider.storage.CreateVolume(ctx, core.CreateVolumeRequest{
		CreateVolumeDetails: details,
		OpcRetryToken:       new(retry),
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
		ETag:               stringValue(response.Etag),
		FreeformTags:       cloneStringMap(volume.FreeformTags),
	}, nil
}

// GetAttachedBootVolume reads the instance's single attached boot volume. The
// fleet checks its image against the instance and the allowed images.
func (provider *sdkProvider) GetAttachedBootVolume(ctx context.Context, instanceID string) (CloudBootVolume, error) {
	response, err := provider.compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{
		CompartmentId: new(provider.config.CompartmentID), AvailabilityDomain: new(provider.config.AvailabilityDomain),
		InstanceId: new(instanceID),
	})
	if err != nil {
		return CloudBootVolume{}, fmt.Errorf("list exact OCI boot attachment: %w", err)
	}
	if len(response.Items) != 1 || stringValue(response.OpcNextPage) != "" ||
		response.Items[0].LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached ||
		stringValue(response.Items[0].InstanceId) != instanceID || stringValue(response.Items[0].BootVolumeId) == "" {
		return CloudBootVolume{}, fmt.Errorf("%w: instance has no single attached boot volume", ErrForeignResource)
	}
	boot, err := provider.GetBootVolume(ctx, stringValue(response.Items[0].BootVolumeId))
	if err != nil {
		return CloudBootVolume{}, err
	}
	if boot.CompartmentID != provider.config.CompartmentID || boot.AvailabilityDomain != provider.config.AvailabilityDomain ||
		boot.ImageID == "" || boot.SizeGB != int64(provider.config.BootVolumeGB) ||
		boot.VPUsPerGB != int64(provider.config.BootVolumeVPUsPerGB) || boot.ETag == "" {
		return CloudBootVolume{}, fmt.Errorf("%w: attached boot volume differs from fleet pins", ErrForeignResource)
	}
	return boot, nil
}

func (provider *sdkProvider) GetBootVolume(ctx context.Context, id string) (CloudBootVolume, error) {
	response, err := provider.storage.GetBootVolume(ctx, core.GetBootVolumeRequest{BootVolumeId: new(id)})
	if err != nil {
		return CloudBootVolume{}, fmt.Errorf("get OCI boot volume: %w", err)
	}
	return CloudBootVolume{
		ID: stringValue(response.Id), CompartmentID: stringValue(response.CompartmentId),
		AvailabilityDomain: stringValue(response.AvailabilityDomain), ImageID: stringValue(response.ImageId),
		SizeGB: int64Value(response.SizeInGBs), VPUsPerGB: int64Value(response.VpusPerGB),
		LifecycleState: string(response.LifecycleState), ETag: stringValue(response.Etag),
	}, nil
}

func (provider *sdkProvider) ListBootVolumeAttachments(ctx context.Context, bootID string) ([]CloudBootAttachment, error) {
	var attachments []CloudBootAttachment
	var page *string
	for {
		response, err := provider.compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{
			CompartmentId: new(provider.config.CompartmentID), AvailabilityDomain: new(provider.config.AvailabilityDomain),
			BootVolumeId: new(bootID), Page: page, Limit: new(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list exact OCI boot attachments: %w", err)
		}
		for _, item := range response.Items {
			attachments = append(attachments, CloudBootAttachment{
				InstanceID: stringValue(item.InstanceId), BootVolumeID: stringValue(item.BootVolumeId),
				LifecycleState: string(item.LifecycleState),
			})
			if len(attachments) > maxProviderItems {
				return nil, errors.New("OCI boot attachment list exceeds its safety bound")
			}
		}
		if stringValue(response.OpcNextPage) == "" {
			return attachments, nil
		}
		page = response.OpcNextPage
	}
}

func (provider *sdkProvider) DeleteBootVolume(ctx context.Context, id, etag string) error {
	_, err := provider.storage.DeleteBootVolume(ctx, core.DeleteBootVolumeRequest{BootVolumeId: new(id), IfMatch: new(etag)})
	if err != nil {
		return fmt.Errorf("delete OCI boot volume: %w", err)
	}
	return nil
}

func (provider *sdkProvider) DeleteVolume(ctx context.Context, id, etag string) error {
	_, err := provider.storage.DeleteVolume(ctx, core.DeleteVolumeRequest{VolumeId: new(id), IfMatch: new(etag)})
	if err != nil {
		return fmt.Errorf("delete OCI retained volume: %w", err)
	}
	return nil
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
		DisplayName:                   stringValue(instance.DisplayName),
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
