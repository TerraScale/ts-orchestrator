package fleet

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

type admission struct {
	node       SwarmNode
	instanceID string
}

func (a admission) line(region Region) string {
	return fmt.Sprintf("admit     node %s (%s) as instance %s in %s", a.node.Hostname, a.node.ID, a.instanceID, region.OCIRegion)
}

func verifyAdmissions(ctx context.Context, compute core.ComputeClient, network core.VirtualNetworkClient, region Region, view SwarmView) ([]admission, error) {
	var unadmitted []SwarmNode
	for _, node := range view.Nodes {
		if node.InstanceID == "" {
			unadmitted = append(unadmitted, node)
		}
	}
	if len(unadmitted) == 0 {
		return nil, nil
	}
	ownership := ociresource.Ownership{Owner: Owner}
	byName := map[string][]core.Instance{}
	var page *string
	for {
		listed, err := compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &region.CompartmentID, LifecycleState: core.InstanceLifecycleStateRunning, Page: page})
		if err != nil {
			return nil, fmt.Errorf("list instances: %w", err)
		}
		for _, instance := range listed.Items {
			name := deref(instance.DisplayName)
			if instance.Id != nil && (ownership.Owns(region.Key("instance", "node"), ociresource.Tags{Freeform: instance.FreeformTags}) || slices.Contains(region.Nodes.External, name)) {
				byName[name] = append(byName[name], instance)
			}
		}
		if page = listed.OpcNextPage; page == nil {
			break
		}
	}
	var verified []admission
	var refused []error
	for _, node := range unadmitted {
		matches := byName[node.Hostname]
		if node.Hostname == "" || len(matches) != 1 {
			refused = append(refused, fmt.Errorf("node %s (%q): %d running regional instances carry its name", node.ID, node.Hostname, len(matches)))
			continue
		}
		address, err := primaryAddress(ctx, compute, network, region, *matches[0].Id)
		if err != nil {
			refused = append(refused, fmt.Errorf("node %s: %w", node.Hostname, err))
			continue
		}
		if !slices.Contains(node.Addresses, address) {
			refused = append(refused, fmt.Errorf("node %s connects from %v, not instance %s's primary address %s", node.Hostname, node.Addresses, *matches[0].Id, address))
			continue
		}
		verified = append(verified, admission{node: node, instanceID: *matches[0].Id})
	}
	return verified, errors.Join(refused...)
}

func primaryAddress(ctx context.Context, compute core.ComputeClient, network core.VirtualNetworkClient, region Region, instanceID string) (string, error) {
	attachments, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: &region.CompartmentID, InstanceId: &instanceID})
	if err != nil {
		return "", fmt.Errorf("list VNIC attachments of %s: %w", instanceID, err)
	}
	for _, attachment := range attachments.Items {
		if attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || attachment.VnicId == nil {
			continue
		}
		vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
		if err != nil {
			return "", fmt.Errorf("read VNIC %s: %w", *attachment.VnicId, err)
		}
		if vnic.IsPrimary != nil && *vnic.IsPrimary && vnic.PrivateIp != nil {
			return *vnic.PrivateIp, nil
		}
	}
	return "", fmt.Errorf("instance %s has no attached primary VNIC", instanceID)
}
