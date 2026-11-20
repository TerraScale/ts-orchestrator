package fleet

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

type admission struct {
	node       SwarmNode
	instanceID string
}

func (a admission) line(region Region) string {
	return fmt.Sprintf("admit     node %s (%s) at version %d as instance %s in %s", a.node.Hostname, a.node.ID, a.node.Version, a.instanceID, region.OCIRegion)
}

func verifyAdmissions(ctx context.Context, compute core.ComputeClient, network core.VirtualNetworkClient, region Region, view SwarmView) ([]admission, error) {
	var unadmitted []SwarmNode
	claimed := map[string]string{}
	for _, node := range view.Nodes {
		switch {
		case node.InstanceID != "" && node.Ready:
			claimed[node.InstanceID] = cmp.Or(node.Hostname, node.ID)
		case node.InstanceID == "":
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
		switch {
		case !node.Ready:
			refused = append(refused, fmt.Errorf("node %s (%q) is not READY; only a live record is admitted", node.ID, node.Hostname))
			continue
		case node.Hostname == "" || len(matches) != 1:
			refused = append(refused, fmt.Errorf("node %s (%q): %d running regional instances carry its name", node.ID, node.Hostname, len(matches)))
			continue
		}
		instanceID := *matches[0].Id
		if holder, ok := claimed[instanceID]; ok {
			refused = append(refused, fmt.Errorf("node %s (%q): instance %s already has the live Swarm identity %s", node.ID, node.Hostname, instanceID, holder))
			continue
		}
		address, err := primaryAddress(ctx, compute, network, region, instanceID)
		if err != nil {
			refused = append(refused, fmt.Errorf("node %s: %w", node.Hostname, err))
			continue
		}
		if node.Address != address {
			refused = append(refused, fmt.Errorf("node %s connects from %q, not instance %s's primary address %s", node.Hostname, node.Address, instanceID, address))
			continue
		}
		verified = append(verified, admission{node: node, instanceID: instanceID})
	}
	counts := map[string]int{}
	for _, a := range verified {
		counts[a.instanceID]++
	}
	verified = slices.DeleteFunc(verified, func(a admission) bool {
		if counts[a.instanceID] > 1 {
			refused = append(refused, fmt.Errorf("node %s (%q): %d live records claim instance %s", a.node.ID, a.node.Hostname, counts[a.instanceID], a.instanceID))
			return true
		}
		return false
	})
	slices.SortFunc(verified, func(a, b admission) int { return strings.Compare(a.node.ID, b.node.ID) })
	if len(verified) > ociresource.MaxChangesPerTick {
		verified = verified[:ociresource.MaxChangesPerTick]
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
