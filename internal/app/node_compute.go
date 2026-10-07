package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
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
	return &ociNodeCompute{compute: compute, storage: storage}, nil
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

// Backup takes a FULL backup of the instance's boot volume and waits until
// it is available. token makes a repeated request return the same backup.
func (c *ociNodeCompute) Backup(ctx context.Context, id, name string, tags map[string]string, token string) (string, error) {
	instance, err := c.compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: common.String(id)})
	if err != nil {
		return "", err
	}
	attachments, err := c.compute.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{
		AvailabilityDomain: instance.AvailabilityDomain, CompartmentId: instance.CompartmentId, InstanceId: common.String(id)})
	if err != nil {
		return "", err
	}
	volume := ""
	for _, attachment := range attachments.Items {
		if attachment.LifecycleState == core.BootVolumeAttachmentLifecycleStateAttached && attachment.BootVolumeId != nil {
			volume = *attachment.BootVolumeId
		}
	}
	if volume == "" {
		return "", fmt.Errorf("instance %s has no attached boot volume", id)
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
