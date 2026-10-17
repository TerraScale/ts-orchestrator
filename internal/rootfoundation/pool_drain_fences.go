package rootfoundation

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
)

// Empty inventory is accepted only after every bounded SDK page completes.
func (b *Backend) verifyPoolProviderFences(ctx context.Context, call rootoci.Call, record region.FoundationRecord, receipt drainwire.PoolReceipt) error {
	ctx = b.poolReceiptContext(ctx, call, receipt)
	if err := b.guardPoolReceipt(ctx, call, receipt); err != nil {
		return err
	}
	compute, err := b.factory.Compute()
	if err != nil {
		return err
	}
	network, err := b.factory.Network()
	if err != nil {
		return err
	}
	compartment := record.ResourceIDs["workload_compartment"]
	if compartment == "" {
		return ErrScope
	}
	instance, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(receipt.Child.InstanceID)})
	if err != nil {
		return err
	}
	if instance.Id == nil || *instance.Id != receipt.Child.InstanceID || instance.CompartmentId == nil || *instance.CompartmentId != compartment || instance.LifecycleState != core.InstanceLifecycleStateRunning {
		return rootoci.ErrPending
	}
	addresses := map[string]bool{}
	targets := map[string]bool{receipt.Child.InstanceID: true}
	var page *string
	complete := false
	for range 20 {
		attachments, err := compute.ListVnicAttachments(ociclient.RequestContext(ctx), core.ListVnicAttachmentsRequest{CompartmentId: new(compartment), InstanceId: new(receipt.Child.InstanceID), Page: page, Limit: new(100)})
		if err != nil {
			return err
		}
		for _, attachment := range attachments.Items {
			if attachment.LifecycleState == core.VnicAttachmentLifecycleStateDetached {
				continue
			}
			if attachment.InstanceId == nil || *attachment.InstanceId != receipt.Child.InstanceID || attachment.VnicId == nil || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
				return rootoci.ErrPending
			}
			vnic, err := network.GetVnic(ociclient.RequestContext(ctx), core.GetVnicRequest{VnicId: attachment.VnicId})
			if err != nil {
				return err
			}
			if vnic.Id == nil || *vnic.Id != *attachment.VnicId || vnic.LifecycleState != core.VnicLifecycleStateAvailable || vnic.PrivateIp == nil {
				return rootoci.ErrPending
			}
			addresses[*vnic.PrivateIp] = true
			var ipPage *string
			ipsComplete := false
			for range 20 {
				ips, err := network.ListPrivateIps(ociclient.RequestContext(ctx), core.ListPrivateIpsRequest{VnicId: attachment.VnicId, Page: ipPage, Limit: new(100)})
				if err != nil {
					return err
				}
				for _, ip := range ips.Items {
					if ip.IpAddress == nil || ip.Id == nil || ip.VnicId == nil || *ip.VnicId != *attachment.VnicId {
						return ErrScope
					}
					addresses[*ip.IpAddress], targets[*ip.Id] = true, true
				}
				if ips.OpcNextPage == nil || *ips.OpcNextPage == "" {
					ipsComplete = true
					break
				}
				ipPage = ips.OpcNextPage
			}
			if !ipsComplete {
				return rootoci.ErrPending
			}
		}
		if attachments.OpcNextPage == nil || *attachments.OpcNextPage == "" {
			complete = true
			break
		}
		page = attachments.OpcNextPage
	}
	if !complete || len(addresses) == 0 {
		return rootoci.ErrPending
	}
	page, complete = nil, false
	for range 20 {
		volumes, err := compute.ListVolumeAttachments(ociclient.RequestContext(ctx), core.ListVolumeAttachmentsRequest{CompartmentId: new(compartment), InstanceId: new(receipt.Child.InstanceID), Page: page, Limit: new(100)})
		if err != nil {
			return err
		}
		for _, volume := range volumes.Items {
			if volume == nil || volume.GetInstanceId() == nil || *volume.GetInstanceId() != receipt.Child.InstanceID || volume.GetLifecycleState() != core.VolumeAttachmentLifecycleStateDetached {
				return errors.New("pool worker retains a possible DATA volume attachment")
			}
		}
		if volumes.OpcNextPage == nil || *volumes.OpcNextPage == "" {
			complete = true
			break
		}
		page = volumes.OpcNextPage
	}
	if !complete {
		return rootoci.ErrPending
	}
	lb, err := b.factory.LoadBalancer()
	if err != nil {
		return err
	}
	nlb, err := b.factory.NetworkLoadBalancer()
	if err != nil {
		return err
	}
	compartments := []string{compartment, record.ResourceIDs["control_compartment"]}
	if compartments[1] == "" {
		return ErrScope
	}
	for _, scope := range compartments {
		page, complete = nil, false
		for range 20 {
			listed, err := lb.ListLoadBalancers(ociclient.RequestContext(ctx), loadbalancer.ListLoadBalancersRequest{CompartmentId: new(scope), Page: page, Limit: new(int64(100))})
			if err != nil {
				return err
			}
			for _, item := range listed.Items {
				if item.Id == nil {
					return ErrScope
				}
				actual, err := lb.GetLoadBalancer(ociclient.RequestContext(ctx), loadbalancer.GetLoadBalancerRequest{LoadBalancerId: item.Id})
				if err != nil {
					return err
				}
				if actual.Id == nil || *actual.Id != *item.Id {
					return ErrScope
				}
				for _, set := range actual.BackendSets {
					for _, backend := range set.Backends {
						if backend.IpAddress == nil || addresses[*backend.IpAddress] {
							return errors.New("pool worker retains a load-balancer backend")
						}
					}
				}
			}
			if listed.OpcNextPage == nil || *listed.OpcNextPage == "" {
				complete = true
				break
			}
			page = listed.OpcNextPage
		}
		if !complete {
			return rootoci.ErrPending
		}
		page, complete = nil, false
		for range 20 {
			listed, err := nlb.ListNetworkLoadBalancers(ociclient.RequestContext(ctx), networkloadbalancer.ListNetworkLoadBalancersRequest{CompartmentId: new(scope), Page: page, Limit: new(100)})
			if err != nil {
				return err
			}
			for _, item := range listed.Items {
				if item.Id == nil {
					return ErrScope
				}
				actual, err := nlb.GetNetworkLoadBalancer(ociclient.RequestContext(ctx), networkloadbalancer.GetNetworkLoadBalancerRequest{NetworkLoadBalancerId: item.Id})
				if err != nil {
					return err
				}
				if actual.Id == nil || *actual.Id != *item.Id {
					return ErrScope
				}
				for _, set := range actual.BackendSets {
					for _, backend := range set.Backends {
						if backend.IpAddress == nil && backend.TargetId == nil || backend.IpAddress != nil && addresses[*backend.IpAddress] || backend.TargetId != nil && targets[*backend.TargetId] {
							return errors.New("pool worker retains a network-load-balancer backend")
						}
					}
				}
			}
			if listed.OpcNextPage == nil || *listed.OpcNextPage == "" {
				complete = true
				break
			}
			page = listed.OpcNextPage
		}
		if !complete {
			return rootoci.ErrPending
		}
	}
	return b.guardPoolReceipt(ctx, call, receipt)
}
