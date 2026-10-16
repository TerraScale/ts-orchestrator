package confinement

import (
	"context"
	"errors"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func observeNetwork(ctx context.Context, client core.VirtualNetworkClient, s Scope, f *facts) error {
	subnets, err := pages(func(page *string) ([]core.Subnet, *string, error) {
		r, e := client.ListSubnets(ctx, core.ListSubnetsRequest{CompartmentId: new(s.Compartment), Page: page})
		return r.Items, r.OpcNextPage, e
	})
	if err != nil {
		return err
	}
	if len(subnets) != 1 || text(subnets[0].Id) != s.Subnet || text(subnets[0].CompartmentId) != s.Compartment {
		return errors.New("disposable compartment must contain only its exact approved subnet")
	}
	subnet, err := client.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: new(s.Subnet)})
	if err != nil {
		return err
	}
	f.Subnet = subnet.Subnet
	if text(subnet.Id) != s.Subnet || text(subnet.CompartmentId) != s.Compartment || subnet.LifecycleState != core.SubnetLifecycleStateAvailable ||
		text(subnet.CidrBlock) != s.PeerCIDR || len(subnet.Ipv6CidrBlocks) != 0 || text(subnet.Ipv6CidrBlock) != "" ||
		(len(subnet.Ipv4CidrBlocks) != 0 && !slices.Equal(subnet.Ipv4CidrBlocks, []string{s.PeerCIDR})) ||
		subnet.ProhibitPublicIpOnVnic == nil || !*subnet.ProhibitPublicIpOnVnic || text(subnet.VcnId) == "" || text(subnet.RouteTableId) == "" || len(subnet.SecurityListIds) == 0 {
		return errors.New("approved subnet is not isolated private IPv4 disposable network")
	}
	vcn, err := client.GetVcn(ctx, core.GetVcnRequest{VcnId: subnet.VcnId})
	if err != nil {
		return err
	}
	f.VCN = vcn.Vcn
	if text(vcn.Id) != text(subnet.VcnId) || text(vcn.CompartmentId) != s.Compartment || vcn.LifecycleState != core.VcnLifecycleStateAvailable ||
		text(vcn.CidrBlock) != s.VCNCIDR || (len(vcn.CidrBlocks) != 0 && !slices.Equal(vcn.CidrBlocks, []string{s.VCNCIDR})) || len(vcn.Ipv6CidrBlocks) != 0 {
		return errors.New("VCN permits unapproved local network reachability")
	}
	route, err := client.GetRouteTable(ctx, core.GetRouteTableRequest{RtId: subnet.RouteTableId})
	if err != nil {
		return err
	}
	f.Route = route.RouteTable
	if text(route.Id) != text(subnet.RouteTableId) || text(route.CompartmentId) != s.Compartment || text(route.VcnId) != text(vcn.Id) || route.LifecycleState != core.RouteTableLifecycleStateAvailable || len(route.RouteRules) != 0 {
		return errors.New("disposable network route table permits external reachability")
	}
	ids := slices.Clone(subnet.SecurityListIds)
	slices.Sort(ids)
	if len(slices.Compact(slices.Clone(ids))) != len(ids) {
		return errors.New("duplicate security list IDs")
	}
	ssh, peers := false, false
	for _, id := range ids {
		list, err := client.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: new(id)})
		if err != nil {
			return err
		}
		f.Security = append(f.Security, list.SecurityList)
		if text(list.Id) != id || text(list.CompartmentId) != s.Compartment || text(list.VcnId) != text(vcn.Id) || list.LifecycleState != core.SecurityListLifecycleStateAvailable {
			return errors.New("security list identity or lifecycle differs")
		}
		for _, rule := range list.IngressSecurityRules {
			if rule.SourceType != core.IngressSecurityRuleSourceTypeCidrBlock || (rule.IsStateless != nil && *rule.IsStateless) {
				return errors.New("unknown or stateless ingress rule")
			}
			switch text(rule.Source) {
			case s.PeerCIDR:
				if text(rule.Protocol) != "all" || rule.TcpOptions != nil || rule.UdpOptions != nil || rule.IcmpOptions != nil {
					return errors.New("peer ingress differs from exact isolated peer rule")
				}
				peers = true
			case s.RunnerCIDR:
				if text(rule.Protocol) != "6" || rule.TcpOptions == nil || rule.TcpOptions.DestinationPortRange == nil || rule.TcpOptions.DestinationPortRange.Min == nil || *rule.TcpOptions.DestinationPortRange.Min != 22 || rule.TcpOptions.DestinationPortRange.Max == nil || *rule.TcpOptions.DestinationPortRange.Max != 22 || rule.TcpOptions.SourcePortRange != nil || rule.UdpOptions != nil || rule.IcmpOptions != nil {
					return errors.New("runner ingress must be stateful SSH only")
				}
				ssh = true
			default:
				return errors.New("network ingress includes unapproved source")
			}
		}
		for _, rule := range list.EgressSecurityRules {
			if rule.DestinationType != core.EgressSecurityRuleDestinationTypeCidrBlock || text(rule.Destination) != s.PeerCIDR || text(rule.Protocol) != "all" ||
				(rule.IsStateless != nil && *rule.IsStateless) || rule.TcpOptions != nil || rule.UdpOptions != nil || rule.IcmpOptions != nil {
				return errors.New("network egress reaches outside exact disposable peers")
			}
		}
	}
	if !ssh || !peers {
		return errors.New("isolated runner SSH and peer ingress are both required")
	}
	return nil
}

func observeHosts(ctx context.Context, network core.VirtualNetworkClient, compute core.ComputeClient, s Scope, f *facts) error {
	addresses, err := pages(func(page *string) ([]core.PrivateIp, *string, error) {
		r, e := network.ListPrivateIps(ctx, core.ListPrivateIpsRequest{SubnetId: new(s.Subnet), Page: page})
		return r.Items, r.OpcNextPage, e
	})
	if err != nil {
		return err
	}
	attachments, err := pages(func(page *string) ([]core.VnicAttachment, *string, error) {
		r, e := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: new(s.Compartment), Page: page})
		return r.Items, r.OpcNextPage, e
	})
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, address := range addresses {
		if text(address.SubnetId) != s.Subnet || text(address.CompartmentId) != s.Compartment || text(address.VnicId) == "" || address.IsPrimary == nil || !*address.IsPrimary {
			return errors.New("unexpected private IP in disposable subnet")
		}
		var instanceID string
		for _, attachment := range attachments {
			if text(attachment.VnicId) == text(address.VnicId) && attachment.LifecycleState == core.VnicAttachmentLifecycleStateAttached {
				if instanceID != "" || text(attachment.CompartmentId) != s.Compartment {
					return errors.New("ambiguous disposable host VNIC attachment")
				}
				instanceID = text(attachment.InstanceId)
			}
		}
		name, approved := s.ExistingHosts[instanceID]
		if !approved || seen[instanceID] {
			return errors.New("subnet contains a host outside the sealed qualification journal; explicit recovery required")
		}
		seen[instanceID] = true
		vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: address.VnicId})
		if err != nil {
			return err
		}
		if text(vnic.Id) != text(address.VnicId) || text(vnic.CompartmentId) != s.Compartment || text(vnic.SubnetId) != s.Subnet || len(vnic.NsgIds) != 0 || text(vnic.RouteTableId) != "" || text(vnic.PublicIp) != "" || len(vnic.Ipv6Addresses) != 0 {
			return errors.New("host VNIC escapes approved subnet security boundary")
		}
		instance, err := compute.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
		if err != nil {
			return err
		}
		if text(instance.Id) != instanceID || text(instance.CompartmentId) != s.Compartment || text(instance.DisplayName) != name || instance.FreeformTags["terrascale-qualification-approval"] != s.ApprovalSHA256 {
			return errors.New("journal host differs from authenticated OCI instance")
		}
		f.Hosts = append(f.Hosts, core.Instance{Id: instance.Id, CompartmentId: instance.CompartmentId, DisplayName: instance.DisplayName, Shape: instance.Shape, ShapeConfig: instance.ShapeConfig, ImageId: instance.ImageId, LifecycleState: instance.LifecycleState, AvailabilityDomain: instance.AvailabilityDomain, FaultDomain: instance.FaultDomain})
		f.VNICs = append(f.VNICs, vnic.Vnic)
	}
	return nil
}
