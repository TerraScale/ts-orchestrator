package fleet

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const externalHostNodeTag = "terrascale-host-node"

func RecheckExternal(ctx context.Context, region Region, compute core.ComputeClient, management core.ComputeManagementClient, network core.VirtualNetworkClient, vcn string, expected map[string]string, separatelyCheckedPool string) (map[string]string, error) {
	current, err := verifyExternal(ctx, region, compute, management, network, vcn, separatelyCheckedPool)
	if err != nil {
		return nil, fmt.Errorf("external capacity changed: %w", err)
	}
	if !maps.Equal(current, expected) {
		return nil, fmt.Errorf("external OCI identities changed during compute; refusing capacity credit")
	}
	return current, nil
}

func VerifyExternal(ctx context.Context, region Region, compute core.ComputeClient, management core.ComputeManagementClient, network core.VirtualNetworkClient, vcn string) (map[string]string, error) {
	return verifyExternal(ctx, region, compute, management, network, vcn, "")
}

func verifyExternal(ctx context.Context, region Region, compute core.ComputeClient, management core.ComputeManagementClient, network core.VirtualNetworkClient, vcn, separatelyCheckedPool string) (map[string]string, error) {
	verified := map[string]string{}
	if len(region.Nodes.External) == 0 {
		return verified, nil
	}
	if vcn == "" {
		return nil, fmt.Errorf("external hosts: region %s has no VCN", region.Label)
	}
	compartment := common.String(region.CompartmentID)
	instances, err := list("external instances", func(page *string) ([]core.Instance, *string, error) {
		r, err := compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return nil, err
	}
	for _, host := range region.Nodes.External {
		matches := slices.DeleteFunc(slices.Clone(instances), func(in core.Instance) bool {
			return in.FreeformTags[externalHostNodeTag] != host || gone(string(in.LifecycleState))
		})
		if len(matches) != 1 || deref(matches[0].Id) == "" {
			return nil, fmt.Errorf("external host %s: expected one live OCI instance in %s, found %d", host, region.CompartmentID, len(matches))
		}
		got, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: matches[0].Id})
		if err != nil {
			return nil, fmt.Errorf("external host %s: read OCI identity: %w", host, err)
		}
		in := got.Instance
		if deref(in.Id) != deref(matches[0].Id) || in.FreeformTags[externalHostNodeTag] != host || deref(in.CompartmentId) != region.CompartmentID || in.LifecycleState != core.InstanceLifecycleStateRunning {
			return nil, fmt.Errorf("external host %s (%s): must be RUNNING in compartment %s with the declared host identity; observed %s in %s", host, deref(in.Id), region.CompartmentID, in.LifecycleState, deref(in.CompartmentId))
		}
		if region.owns("instance", "node", in.FreeformTags) {
			return nil, fmt.Errorf("external host %s (%s): carries pool instance ownership", host, deref(in.Id))
		}
		attachments, err := list("external VNIC attachments", func(page *string) ([]core.VnicAttachment, *string, error) {
			r, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: compartment, InstanceId: in.Id, Page: page})
			return r.Items, r.OpcNextPage, err
		})
		if err != nil {
			return nil, err
		}
		primary := false
		for _, attachment := range attachments {
			if deref(attachment.InstanceId) != deref(in.Id) || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
				continue
			}
			vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
			if err != nil {
				return nil, fmt.Errorf("external host %s: VNIC: %w", host, err)
			}
			if vnic.IsPrimary == nil || !*vnic.IsPrimary {
				continue
			}
			subnet, err := network.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: vnic.SubnetId})
			if err != nil {
				return nil, fmt.Errorf("external host %s: subnet: %w", host, err)
			}
			if deref(subnet.VcnId) != vcn || deref(subnet.CompartmentId) != region.CompartmentID {
				return nil, fmt.Errorf("external host %s (%s): primary VNIC is outside region VCN %s and compartment %s", host, deref(in.Id), vcn, region.CompartmentID)
			}
			primary = true
		}
		if !primary {
			return nil, fmt.Errorf("external host %s (%s): no attached primary VNIC in region VCN %s", host, deref(in.Id), vcn)
		}
		if _, duplicate := verified[deref(in.Id)]; duplicate {
			return nil, fmt.Errorf("external host %s: repeated OCI identity %s", host, deref(in.Id))
		}
		verified[deref(in.Id)] = host
	}
	pools, err := list("external host pool membership", func(page *string) ([]core.InstancePoolSummary, *string, error) {
		r, err := management.ListInstancePools(ctx, core.ListInstancePoolsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return nil, err
	}
	for _, pool := range pools {
		if pool.LifecycleState == core.InstancePoolSummaryLifecycleStateTerminated || separatelyCheckedPool != "" && deref(pool.Id) == separatelyCheckedPool {
			continue
		}
		members, err := list("external host pool members", func(page *string) ([]core.InstanceSummary, *string, error) {
			r, err := management.ListInstancePoolInstances(ctx, core.ListInstancePoolInstancesRequest{CompartmentId: compartment, InstancePoolId: pool.Id, Page: page})
			return r.Items, r.OpcNextPage, err
		})
		if err != nil {
			return nil, err
		}
		for _, member := range members {
			if host, found := verified[deref(member.Id)]; found {
				return nil, fmt.Errorf("external host %s (%s): belongs to instance pool %s", host, deref(member.Id), deref(pool.Id))
			}
		}
	}
	return verified, nil
}
