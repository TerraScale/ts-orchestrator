package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

// ociNodeCompute finds a node's instance by its display name in the
// leader's own compartment, where a cell's nodes run.
//
// ponytail: one compartment; search the workload compartment too once
// pool hosts take node operations.
type ociNodeCompute struct {
	compute core.ComputeClient
	storage core.BlockstorageClient
	network core.VirtualNetworkClient

	once        sync.Once
	compartment string
	err         error
}

func newOCINodeCompute(region string) (nodeCompute, error) {
	factory, err := ociclient.InstancePrincipal(region)
	if err != nil {
		return nil, err
	}
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
	return &ociNodeCompute{compute: compute, storage: storage, network: network}, nil
}

func (c *ociNodeCompute) ownCompartment(ctx context.Context) (string, error) {
	c.once.Do(func() {
		var id string
		if id, c.err = hostenroll.ReadInstanceID(ctx, hostenroll.NewIMDSClient()); c.err != nil {
			return
		}
		var response core.GetInstanceResponse
		if response, c.err = c.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: common.String(id)}); c.err == nil {
			c.compartment = *response.CompartmentId
		}
	})
	return c.compartment, c.err
}

func (c *ociNodeCompute) Find(ctx context.Context, node string) (nodeInstance, error) {
	instances, err := c.Instances(ctx)
	if err != nil {
		return nodeInstance{}, err
	}
	return findNode(instances, node)
}

// Instances lists the instances of the leader's compartment that are not
// terminated.
func (c *ociNodeCompute) Instances(ctx context.Context) ([]nodeInstance, error) {
	compartment, err := c.ownCompartment(ctx)
	if err != nil {
		return nil, fmt.Errorf("read this controller's compartment: %w", err)
	}
	var found []nodeInstance
	request := core.ListInstancesRequest{CompartmentId: common.String(compartment)}
	for {
		response, err := c.compute.ListInstances(ctx, request)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.Items {
			if state := instance.LifecycleState; state != core.InstanceLifecycleStateTerminated &&
				state != core.InstanceLifecycleStateTerminating {
				found = append(found, instanceOfNode(instance))
			}
		}
		if response.OpcNextPage == nil {
			return found, nil
		}
		request.Page = response.OpcNextPage
	}
}

func (c *ociNodeCompute) Reboot(ctx context.Context, id string) error {
	_, err := c.compute.InstanceAction(ctx, core.InstanceActionRequest{InstanceId: common.String(id),
		Action: core.InstanceActionActionSoftreset})
	return err
}

func (c *ociNodeCompute) Resize(ctx context.Context, id string, ocpus, memoryGB float32) error {
	_, err := c.compute.UpdateInstance(ctx, core.UpdateInstanceRequest{InstanceId: common.String(id),
		UpdateInstanceDetails: core.UpdateInstanceDetails{ShapeConfig: &core.UpdateInstanceShapeConfigDetails{
			Ocpus: common.Float32(ocpus), MemoryInGBs: common.Float32(memoryGB)}}})
	return err
}

func instanceOfNode(instance core.Instance) nodeInstance {
	found := nodeInstance{State: string(instance.LifecycleState)}
	if instance.Id != nil {
		found.ID = *instance.Id
	}
	if instance.DisplayName != nil {
		found.Name = *instance.DisplayName
	}
	if config := instance.ShapeConfig; config != nil && config.Ocpus != nil && config.MemoryInGBs != nil {
		found.OCPUs, found.MemoryGB = *config.Ocpus, *config.MemoryInGBs
	}
	return found
}

// Rename gives the instance, its boot volume and its primary VNIC's hostname
// label, which sets the OS hostname at the next boot, the node's new name.
// The leader's policy may not let it update the VNIC: that is logged, the
// node's name is the instance's.
func (c *ociNodeCompute) Rename(ctx context.Context, id, name string) error {
	if _, err := c.compute.UpdateInstance(ctx, core.UpdateInstanceRequest{InstanceId: common.String(id),
		UpdateInstanceDetails: core.UpdateInstanceDetails{DisplayName: common.String(name)}}); err != nil {
		return err
	}
	instance, err := c.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: common.String(id)})
	if err != nil {
		return err
	}
	volume, err := c.bootVolume(ctx, instance.Instance)
	if err != nil {
		return err
	}
	if _, err := c.storage.UpdateBootVolume(ctx, core.UpdateBootVolumeRequest{BootVolumeId: common.String(volume),
		UpdateBootVolumeDetails: core.UpdateBootVolumeDetails{DisplayName: common.String(name + " (Boot Volume)")}}); err != nil {
		return err
	}
	if err := c.renameHostname(ctx, instance.Instance, name); err != nil {
		slog.Warn("node rename kept the OS hostname", observability.ComponentKey, "nodes", "instance", id, "error", err)
	}
	return nil
}

func (c *ociNodeCompute) renameHostname(ctx context.Context, instance core.Instance, name string) error {
	attachments, err := c.compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
		CompartmentId: instance.CompartmentId, InstanceId: instance.Id})
	if err != nil {
		return err
	}
	for _, attachment := range attachments.Items {
		if attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || attachment.VnicId == nil {
			continue
		}
		vnic, err := c.network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
		if err != nil {
			return err
		}
		if vnic.IsPrimary != nil && *vnic.IsPrimary {
			_, err = c.network.UpdateVnic(ctx, core.UpdateVnicRequest{VnicId: attachment.VnicId,
				UpdateVnicDetails: core.UpdateVnicDetails{HostnameLabel: common.String(name)}})
			return err
		}
	}
	return fmt.Errorf("instance %s has no attached primary VNIC", *instance.Id)
}

// bootVolume is the instance's attached boot volume.
func (c *ociNodeCompute) bootVolume(ctx context.Context, instance core.Instance) (string, error) {
	attachments, err := c.compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: instance.AvailabilityDomain, CompartmentId: instance.CompartmentId, InstanceId: instance.Id})
	if err != nil {
		return "", err
	}
	for _, attachment := range attachments.Items {
		if attachment.LifecycleState == core.BootVolumeAttachmentLifecycleStateAttached && attachment.BootVolumeId != nil {
			return *attachment.BootVolumeId, nil
		}
	}
	return "", fmt.Errorf("instance %s has no attached boot volume", *instance.Id)
}

// Backup takes a FULL backup of the instance's boot volume and waits until
// it is available. token makes a repeated request return the same backup.
func (c *ociNodeCompute) Backup(ctx context.Context, id, name string, tags map[string]string, token string) (string, error) {
	instance, err := c.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: common.String(id)})
	if err != nil {
		return "", err
	}
	volume, err := c.bootVolume(ctx, instance.Instance)
	if err != nil {
		return "", err
	}
	created, err := c.storage.CreateBootVolumeBackup(ctx, core.CreateBootVolumeBackupRequest{OpcRetryToken: common.String(token),
		CreateBootVolumeBackupDetails: core.CreateBootVolumeBackupDetails{BootVolumeId: common.String(volume),
			DisplayName: common.String(name), Type: core.CreateBootVolumeBackupDetailsTypeFull, FreeformTags: tags}})
	if err != nil {
		return "", err
	}
	for {
		backup, err := c.storage.GetBootVolumeBackup(ctx, core.GetBootVolumeBackupRequest{BootVolumeBackupId: created.Id})
		if err != nil {
			return "", err
		}
		switch backup.LifecycleState {
		case core.BootVolumeBackupLifecycleStateAvailable:
			return *created.Id, nil
		case core.BootVolumeBackupLifecycleStateFaulty, core.BootVolumeBackupLifecycleStateTerminated,
			core.BootVolumeBackupLifecycleStateTerminating:
			return "", fmt.Errorf("boot volume backup %s is %s", *created.Id, backup.LifecycleState)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

// Terminate deletes the instance and its boot volume.
func (c *ociNodeCompute) Terminate(ctx context.Context, id string) error {
	_, err := c.compute.TerminateInstance(ctx, core.TerminateInstanceRequest{InstanceId: common.String(id),
		PreserveBootVolume: common.Bool(false)})
	return err
}
