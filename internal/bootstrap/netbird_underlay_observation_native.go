package bootstrap

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func observeOriginalUnderlayLaunch(ctx context.Context, factory *ociclient.Factory, endpoint NetBirdUnderlayEndpoint, expected core.LaunchInstanceDetails, bootID, privateIP string, writer bool) error {
	compute, err := factory.Compute()
	if err != nil {
		return err
	}
	response, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(endpoint.InstanceID)})
	if err != nil {
		return err
	}
	i := response.Instance
	image, imageOK := i.SourceDetails.(core.InstanceSourceViaImageDetails)
	expectedImage, expectedOK := expected.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !imageOK || !expectedOK || underlayValue(image.ImageId) != underlayValue(expectedImage.ImageId) || underlayValue(i.Id) != endpoint.InstanceID || underlayValue(i.CompartmentId) != endpoint.CompartmentID ||
		underlayValue(i.AvailabilityDomain) != underlayValue(expected.AvailabilityDomain) || underlayValue(i.FaultDomain) != underlayValue(expected.FaultDomain) || underlayValue(i.Shape) != underlayValue(expected.Shape) ||
		i.ShapeConfig == nil || expected.ShapeConfig == nil || underlayValue(i.ShapeConfig.Ocpus) != underlayValue(expected.ShapeConfig.Ocpus) || underlayValue(i.ShapeConfig.MemoryInGBs) != underlayValue(expected.ShapeConfig.MemoryInGBs) ||
		i.LifecycleState != core.InstanceLifecycleStateRunning || len(i.Metadata) != len(expected.Metadata) || !maps.Equal(i.Metadata, expected.Metadata) || len(i.ExtendedMetadata) != 0 {
		return errors.New("original NetBird launch image, geometry or bootstrap metadata changed")
	}
	vnic, err := observeOriginalUnderlayEndpoint(ctx, factory, endpoint.InstanceID, endpoint.CompartmentID, endpoint.SubnetID, privateIP, []string{endpoint.NSGID}, writer)
	if err != nil || vnic != endpoint.VNICID {
		return errors.Join(errors.New("original NetBird launch primary VNIC changed"), err)
	}
	attachments, err := compute.ListBootVolumeAttachments(ociclient.RequestContext(ctx), core.ListBootVolumeAttachmentsRequest{CompartmentId: new(endpoint.CompartmentID), AvailabilityDomain: expected.AvailabilityDomain, InstanceId: new(endpoint.InstanceID)})
	if err != nil {
		return err
	}
	if len(attachments.Items) != 1 || underlayValue(attachments.OpcNextPage) != "" {
		return errors.New("original NetBird boot attachment is ambiguous")
	}
	a := attachments.Items[0]
	if underlayValue(a.InstanceId) != endpoint.InstanceID || !netBirdUnderlayNativeID("bootvolume", underlayValue(a.BootVolumeId)) || bootID != "" && underlayValue(a.BootVolumeId) != bootID || a.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached {
		return errors.New("original NetBird boot attachment differs from the positive original launch")
	}
	block, err := factory.Blockstorage()
	if err != nil {
		return err
	}
	boot, err := block.GetBootVolume(ociclient.RequestContext(ctx), core.GetBootVolumeRequest{BootVolumeId: a.BootVolumeId})
	if err != nil {
		return err
	}
	b := boot.BootVolume
	if underlayValue(b.Id) != underlayValue(a.BootVolumeId) || underlayValue(b.CompartmentId) != endpoint.CompartmentID || underlayValue(b.ImageId) != underlayValue(expectedImage.ImageId) ||
		underlayValue(b.SizeInGBs) != underlayValue(expectedImage.BootVolumeSizeInGBs) || underlayValue(b.VpusPerGB) != 10 || b.LifecycleState != core.BootVolumeLifecycleStateAvailable {
		return errors.New("original NetBird boot image or billing geometry changed")
	}
	return nil
}

func observeOriginalUnderlayRequest(ctx context.Context, client core.VirtualNetworkClient, r NetBirdUnderlayRecord, key string) error {
	q := r.Requests[key]
	if q.RespondedAt.IsZero() {
		return errors.New("original NetBird underlay has an unresolved dispatch")
	}
	switch key {
	case "manager_gateway", "writer_gateway":
		e := r.Manager
		peerKey := "writer_gateway"
		if key == "writer_gateway" {
			e = r.Writer
			peerKey = "manager_gateway"
		}
		gateway, err := observeOriginalUnderlayGateway(ctx, client, q.ResponseID, e)
		if err != nil {
			return err
		}
		if r.Requests["connect"].RespondedAt.IsZero() {
			if gateway.PeeringStatus != core.LocalPeeringGatewayPeeringStatusNew || underlayValue(gateway.PeerId) != "" || underlayValue(gateway.PeerAdvertisedCidr) != "" || len(gateway.PeerAdvertisedCidrDetails) != 0 {
				return errors.New("NetBird underlay gateway acquired an unjournaled peering")
			}
		} else if gateway.PeeringStatus != core.LocalPeeringGatewayPeeringStatusPeered || underlayValue(gateway.PeerId) != r.Requests[peerKey].ResponseID {
			return errors.New("NetBird underlay gateway no longer peers with its exact original native counterpart")
		}
	case "connect":
		for _, side := range []struct {
			key, peer string
			endpoint  NetBirdUnderlayEndpoint
		}{{"manager_gateway", "writer_gateway", r.Manager}, {"writer_gateway", "manager_gateway", r.Writer}} {
			gateway, err := observeOriginalUnderlayGateway(ctx, client, r.Requests[side.key].ResponseID, side.endpoint)
			if err != nil {
				return err
			}
			peerCIDR := r.Recipe.WriterNetworkCIDR
			if side.key == "writer_gateway" {
				peerCIDR = r.Recipe.ManagerNetworkCIDR
			}
			if gateway.PeeringStatus != core.LocalPeeringGatewayPeeringStatusPeered || underlayValue(gateway.PeerId) != r.Requests[side.peer].ResponseID ||
				underlayValue(gateway.PeerAdvertisedCidr) != peerCIDR || !slices.Equal(gateway.PeerAdvertisedCidrDetails, []string{peerCIDR}) {
				return errors.New("NetBird underlay gateway is not peered to the exact original reciprocal VCN")
			}
		}
	case "manager_route", "writer_route":
		e := r.Manager
		if key == "writer_route" {
			e = r.Writer
		}
		response, err := client.GetRouteTable(ociclient.RequestContext(ctx), core.GetRouteTableRequest{RtId: new(e.RouteTableID)})
		if err != nil {
			return err
		}
		actual, normalizeErr := originalUnderlayWritableRoutes(response.RouteRules)
		if normalizeErr != nil || underlayValue(response.Id) != e.RouteTableID || underlayValue(response.VcnId) != e.NetworkID || underlayValue(response.CompartmentId) != e.NetworkCompartmentID || response.LifecycleState != core.RouteTableLifecycleStateAvailable || !netBirdUnderlayEqual(actual, q.Route.RouteRules) {
			return errors.New("NetBird underlay route readback differs from its exact conditional request")
		}
	case "writer_security":
		response, err := client.GetSecurityList(ociclient.RequestContext(ctx), core.GetSecurityListRequest{SecurityListId: new(r.Writer.SecurityID)})
		if err != nil {
			return err
		}
		if underlayValue(response.Id) != r.Writer.SecurityID || underlayValue(response.VcnId) != r.Writer.NetworkID || underlayValue(response.CompartmentId) != r.Writer.NetworkCompartmentID || response.LifecycleState != core.SecurityListLifecycleStateAvailable ||
			!netBirdUnderlayEqual(response.IngressSecurityRules, q.Security.IngressSecurityRules) || !netBirdUnderlayEqual(response.EgressSecurityRules, q.Security.EgressSecurityRules) {
			return errors.New("NetBird underlay writer security readback differs from its exact conditional request")
		}
	}
	return nil
}

func observeOriginalUnderlayGateway(ctx context.Context, client core.VirtualNetworkClient, id string, endpoint NetBirdUnderlayEndpoint) (core.LocalPeeringGateway, error) {
	response, err := client.GetLocalPeeringGateway(ociclient.RequestContext(ctx), core.GetLocalPeeringGatewayRequest{LocalPeeringGatewayId: new(id)})
	if err != nil {
		return core.LocalPeeringGateway{}, err
	}
	gateway := response.LocalPeeringGateway
	if !netBirdUnderlayNativeID("localpeeringgateway", id) || underlayValue(gateway.Id) != id || underlayValue(gateway.VcnId) != endpoint.NetworkID || underlayValue(gateway.CompartmentId) != endpoint.NetworkCompartmentID ||
		gateway.LifecycleState != core.LocalPeeringGatewayLifecycleStateAvailable || gateway.IsCrossTenancyPeering == nil || *gateway.IsCrossTenancyPeering || underlayValue(gateway.RouteTableId) != "" {
		return core.LocalPeeringGateway{}, errors.New("NetBird underlay gateway differs from its original native VCN or permits transit")
	}
	return gateway, nil
}

func originalUnderlayWritableRoutes(rules []core.RouteRule) ([]core.RouteRule, error) {
	result := slices.Clone(rules)
	for index, rule := range result {
		if rule.RouteType != "" && rule.RouteType != core.RouteRuleRouteTypeStatic || underlayValue(rule.CidrBlock) != "" && underlayValue(rule.Destination) != "" && underlayValue(rule.CidrBlock) != underlayValue(rule.Destination) {
			return nil, errors.New("NetBird underlay cannot rewrite an ambiguous or provider-local route")
		}
		if underlayValue(rule.Destination) != "" {
			result[index].CidrBlock = nil
		}
		result[index].RouteType = ""
	}
	return result, nil
}

func observeOriginalUnderlayNetworks(ctx context.Context, factory *ociclient.Factory, recipe NetBirdJournalUnderlayRecipe, manager, writer NetBirdUnderlayEndpoint) error {
	client, err := factory.Network()
	if err != nil {
		return err
	}
	for _, side := range []struct {
		e            NetBirdUnderlayEndpoint
		cidr, subnet string
		private      bool
	}{{manager, recipe.ManagerNetworkCIDR, recipe.ManagerNetworkCIDR, false}, {writer, recipe.WriterNetworkCIDR, recipe.WriterSubnetCIDR, true}} {
		vcn, err := client.GetVcn(ociclient.RequestContext(ctx), core.GetVcnRequest{VcnId: new(side.e.NetworkID)})
		if err != nil {
			return err
		}
		if underlayValue(vcn.Id) != side.e.NetworkID || underlayValue(vcn.CompartmentId) != side.e.NetworkCompartmentID || vcn.LifecycleState != core.VcnLifecycleStateAvailable ||
			len(vcn.CidrBlocks) != 1 || vcn.CidrBlocks[0] != side.cidr || len(vcn.Ipv6CidrBlocks) != 0 || len(vcn.Ipv6PrivateCidrBlocks) != 0 || len(vcn.Byoipv6CidrBlocks) != 0 {
			return errors.New("NetBird underlay VCN readback differs from its exact signed nonoverlap allocation")
		}
		subnet, err := client.GetSubnet(ociclient.RequestContext(ctx), core.GetSubnetRequest{SubnetId: new(side.e.SubnetID)})
		if err != nil {
			return err
		}
		if underlayValue(subnet.Id) != side.e.SubnetID || underlayValue(subnet.CompartmentId) != side.e.NetworkCompartmentID || underlayValue(subnet.VcnId) != side.e.NetworkID || underlayValue(subnet.CidrBlock) != side.subnet ||
			subnet.LifecycleState != core.SubnetLifecycleStateAvailable || underlayValue(subnet.RouteTableId) != side.e.RouteTableID || !slices.Equal(subnet.SecurityListIds, []string{side.e.SecurityID}) ||
			subnet.ProhibitPublicIpOnVnic == nil || *subnet.ProhibitPublicIpOnVnic != side.private || subnet.ProhibitInternetIngress == nil || *subnet.ProhibitInternetIngress != side.private ||
			underlayValue(subnet.Ipv6CidrBlock) != "" || len(subnet.Ipv6CidrBlocks) != 0 {
			return errors.New("NetBird underlay subnet readback differs from its signed endpoint attachments")
		}
		nsg, err := client.GetNetworkSecurityGroup(ociclient.RequestContext(ctx), core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: new(side.e.NSGID)})
		if err != nil {
			return err
		}
		if underlayValue(nsg.Id) != side.e.NSGID || underlayValue(nsg.CompartmentId) != side.e.NetworkCompartmentID || underlayValue(nsg.VcnId) != side.e.NetworkID || nsg.LifecycleState != core.NetworkSecurityGroupLifecycleStateAvailable {
			return errors.New("original NetBird NSG differs from its protected native VCN attachment")
		}
	}
	return nil
}

func observeOriginalUnderlayEndpoint(ctx context.Context, factory *ociclient.Factory, instanceID, compartment, subnet, privateIP string, nsgs []string, writer bool) (string, error) {
	if ctx == nil || factory == nil || factory.Region() != "sa-saopaulo-1" || !strings.HasPrefix(instanceID, "ocid1.instance.oc1.sa-saopaulo-1.") ||
		!strings.HasPrefix(compartment, "ocid1.compartment.") || !strings.HasPrefix(subnet, "ocid1.subnet.oc1.sa-saopaulo-1.") || len(nsgs) != 1 || !strings.HasPrefix(nsgs[0], "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.") {
		return "", errors.New("NetBird underlay endpoint lacks its exact original native GRU launch attachments")
	}
	compute, err := factory.Compute()
	if err != nil {
		return "", err
	}
	attachments, err := compute.ListVnicAttachments(ociclient.RequestContext(ctx), core.ListVnicAttachmentsRequest{CompartmentId: new(compartment), InstanceId: new(instanceID)})
	if err != nil {
		return "", err
	}
	if len(attachments.Items) != 1 || underlayValue(attachments.OpcNextPage) != "" {
		return "", errors.New("NetBird underlay original instance VNIC attachment is ambiguous")
	}
	attachment := attachments.Items[0]
	if underlayValue(attachment.InstanceId) != instanceID || underlayValue(attachment.CompartmentId) != compartment || underlayValue(attachment.SubnetId) != subnet ||
		attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || !strings.HasPrefix(underlayValue(attachment.VnicId), "ocid1.vnic.oc1.sa-saopaulo-1.") {
		return "", errors.New("NetBird underlay attachment differs from the original instance and subnet")
	}
	network, err := factory.Network()
	if err != nil {
		return "", err
	}
	response, err := network.GetVnic(ociclient.RequestContext(ctx), core.GetVnicRequest{VnicId: attachment.VnicId})
	if err != nil {
		return "", err
	}
	vnic := response.Vnic
	if !writer {
		public, err := netip.ParseAddr(underlayValue(vnic.PublicIp))
		if err != nil || !public.Is4() || !public.IsGlobalUnicast() || public.IsPrivate() {
			return "", errors.New("original NetBird manager no longer has its public primary VNIC")
		}
	}
	if underlayValue(vnic.Id) != underlayValue(attachment.VnicId) || underlayValue(vnic.CompartmentId) != compartment || underlayValue(vnic.SubnetId) != subnet || underlayValue(vnic.PrivateIp) != privateIP ||
		vnic.IsPrimary == nil || !*vnic.IsPrimary || vnic.SkipSourceDestCheck == nil || *vnic.SkipSourceDestCheck || !slices.Equal(vnic.NsgIds, nsgs) ||
		len(vnic.Ipv6Addresses) != 0 || vnic.LifecycleState != core.VnicLifecycleStateAvailable || writer && underlayValue(vnic.PublicIp) != "" {
		return "", errors.New("NetBird underlay current primary VNIC differs from its exact signed endpoint")
	}
	return underlayValue(vnic.Id), nil
}
