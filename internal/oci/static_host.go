package oci

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// StaticHostObserver reads one operator-launched C# TerraBase host, which
// the fleet neither launched nor journaled. See fleet.ObserveStaticHost.
type StaticHostObserver interface {
	ObserveStaticHost(ctx context.Context, instanceID, node string) (CloudInstance, error)
}

// ObserveStaticHost returns a RUNNING instance in the fleet's compartment,
// availability domain and fault domains, booted from the pinned or an allowed
// image with the fleet's boot size, subnet and NSGs (the provider verifies those and
// its primary private IP), tagged with node and no managed launch identity. The
// caller still binds the instance to its own enrollment claim.
func (f *fleet) ObserveStaticHost(ctx context.Context, instanceID, node string) (CloudInstance, error) {
	cloud, err := f.provider.GetInstance(ctx, instanceID)
	if err != nil {
		return CloudInstance{}, err
	}
	tags := cloud.FreeformTags
	if cloud.ID != instanceID || cloud.CompartmentID != f.config.CompartmentID ||
		cloud.AvailabilityDomain != f.config.AvailabilityDomain || !slices.Contains(f.config.FaultDomains, cloud.FaultDomain) ||
		cloud.LifecycleState != "RUNNING" || cloud.PrivateIP == "" || !f.imageAllowed(cloud.ImageID) ||
		tags[tagManagedBy] != "" || tags[tagCreateKey] != "" || node == "" || tags[tagHostNode] != node {
		return CloudInstance{}, fmt.Errorf("%w: instance %s is not a running static host of this regional fleet", ErrForeignResource, instanceID)
	}
	return cloud, nil
}

// NamedHostObserver reads a static host that a cell spec host grant admits, such as
// a controller VM's own host agent. See fleet.ObserveNamedHost.
type NamedHostObserver interface {
	ObserveNamedHost(ctx context.Context, instanceID, node string) (CloudInstance, error)
}

// ObserveNamedHost returns a RUNNING instance named node whose single
// primary VNIC holds its private IP. A granted host may live outside the
// fleet's compartment, image and NSG pins (controllers do), so the caller
// must bind that address to the node through its signed grant.
func (f *fleet) ObserveNamedHost(ctx context.Context, instanceID, node string) (CloudInstance, error) {
	observer, ok := f.provider.(NamedHostObserver)
	if !ok {
		return CloudInstance{}, errors.New("OCI provider cannot observe granted hosts")
	}
	return observer.ObserveNamedHost(ctx, instanceID, node)
}

func (provider *sdkProvider) ObserveNamedHost(ctx context.Context, instanceID, node string) (CloudInstance, error) {
	response, err := provider.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return CloudInstance{}, fmt.Errorf("get OCI instance: %w", err)
	}
	return observeNamedHost(ctx, cloudInstance(response.Instance, stringValue(response.Etag)), instanceID, node,
		provider.compute, provider.network)
}

func observeNamedHost(ctx context.Context, instance CloudInstance, instanceID, node string,
	compute instanceAttachmentReader, network vnicReader,
) (CloudInstance, error) {
	if instance.ID != instanceID || instance.LifecycleState != "RUNNING" || node == "" || instance.DisplayName != node {
		return CloudInstance{}, fmt.Errorf("%w: instance %s is not the running host %s", ErrForeignResource, instanceID, node)
	}
	attachments, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
		CompartmentId: new(instance.CompartmentID), InstanceId: new(instance.ID),
	})
	if err != nil {
		return CloudInstance{}, fmt.Errorf("list host VNIC: %w", err)
	}
	if len(attachments.Items) != 1 || stringValue(attachments.OpcNextPage) != "" ||
		attachments.Items[0].LifecycleState != core.VnicAttachmentLifecycleStateAttached ||
		stringValue(attachments.Items[0].InstanceId) != instance.ID || stringValue(attachments.Items[0].VnicId) == "" {
		return CloudInstance{}, fmt.Errorf("%w: host has no single attached primary VNIC", ErrForeignResource)
	}
	vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachments.Items[0].VnicId})
	if err != nil {
		return CloudInstance{}, fmt.Errorf("get host VNIC: %w", err)
	}
	if stringValue(vnic.Id) != stringValue(attachments.Items[0].VnicId) || !validManagedPrivateIP(stringValue(vnic.PrivateIp)) ||
		stringValue(vnic.PublicIp) != "" || vnic.LifecycleState != core.VnicLifecycleStateAvailable {
		return CloudInstance{}, fmt.Errorf("%w: host VNIC is not one available private address", ErrForeignResource)
	}
	instance.PrivateIP = stringValue(vnic.PrivateIp)
	return instance, nil
}
