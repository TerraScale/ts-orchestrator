package region

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// NetBirdJournalUnderlayRecipe derives public logical intent before signing;
// native resource identities can only come from the protected creation records.
func NetBirdJournalUnderlayRecipe(plan map[string]any, manager NetBirdManagerProfile, writer BootstrapMaterialIntent) (bootstrap.NetBirdJournalUnderlayRecipe, error) {
	var zero bootstrap.NetBirdJournalUnderlayRecipe
	network, networkOK := plan["network_cidr"].(string)
	subnet, subnetOK := plan["subnet_cidr"].(string)
	if plan["cell"] != "GRU" || plan["region"] != foundationHomeRegion || !networkOK || !subnetOK || writer.Startup == nil ||
		writer.Startup.SeedSlot != "controller-a" || writer.Config.Cell != "gru" || writer.Config.Region != foundationHomeRegion || writer.Config.Environment != "production" || writer.Config.SubnetCIDR != subnet {
		return zero, errors.New("NetBird journal underlay requires the original signed GRU writer network and seed")
	}
	managerNetwork, err := netBirdUnderlayPrefix(manager.NetworkCIDR)
	if err != nil || managerNetwork.Bits() != 24 || networkplan.ValidateRegion("GRU", manager.NetworkCIDR) != nil {
		return zero, errors.New("NetBird journal manager network is not its canonical private GRU allocation")
	}
	writerNetwork, err := netBirdUnderlayPrefix(network)
	if err != nil || networkplan.ValidateRegion("GRU", network) != nil || managerNetwork.Overlaps(writerNetwork) {
		return zero, errors.New("NetBird journal VCN allocations overlap or differ from signed GRU bounds")
	}
	writerSubnet, err := netBirdUnderlayPrefix(subnet)
	if err != nil || writerSubnet.Bits() < writerNetwork.Bits() || !writerNetwork.Contains(writerSubnet.Addr()) {
		return zero, errors.New("NetBird journal writer subnet is outside its signed VCN")
	}
	privateIP := ""
	seedCount := 0
	for _, slot := range writer.Config.Slots {
		if slot.Name == writer.Startup.SeedSlot {
			seedCount++
			if seedCount > 1 {
				return zero, errors.New("NetBird journal original seed address is ambiguous")
			}
			privateIP = slot.PrivateIP
		}
	}
	if !netBirdUnderlayAddress(managerNetwork, manager.PrivateIP) || !netBirdUnderlayAddress(writerSubnet, privateIP) {
		return zero, errors.New("NetBird journal endpoint is absent, reserved or outside its signed subnet")
	}
	return bootstrap.NetBirdJournalUnderlayRecipe{
		ManagerVCNKey: "netbird_manager_vcn", ManagerSubnetKey: "netbird_manager_subnet", ManagerRouteTableKey: "netbird_manager_route", ManagerGatewayKey: "netbird_manager_local_peering_gateway",
		ManagerSecurityKey: "netbird_manager_security_list", ManagerNSGKey: "netbird_manager_nsg",
		WriterVCNKey: "vcn", WriterSubnetKey: "subnet", WriterRouteTableKey: "route_table", WriterGatewayKey: "netbird_writer_local_peering_gateway", WriterSecurityKey: "security_list", WriterNSGKey: "network_security_group",
		ManagerNetworkCIDR: manager.NetworkCIDR, WriterNetworkCIDR: network, WriterSubnetCIDR: subnet,
		ManagerPrivateIP: manager.PrivateIP, WriterPrivateIP: privateIP, Protocol: "6", Port: 443,
	}, nil
}

func netBirdUnderlayPrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked().String() != raw || prefix.Bits() > 29 {
		return netip.Prefix{}, errors.New("underlay CIDR is not canonical usable private IPv4")
	}
	return prefix, nil
}

func netBirdUnderlayAddress(prefix netip.Prefix, raw string) bool {
	address, err := netip.ParseAddr(raw)
	return err == nil && address.Is4() && address.IsPrivate() && address.String() == raw && prefix.Contains(address) &&
		address != prefix.Addr() && address != prefix.Addr().Next() && prefix.Contains(address.Next())
}

// observeNetBirdUnderlayEndpoint follows only the exact positive native launch
// ID. A name, discovered address or remote process description admits nothing.
func observeNetBirdUnderlayEndpoint(ctx context.Context, factory *ociclient.Factory, instanceID, compartment, subnet, privateIP string, nsgs []string, writer bool) (string, error) {
	if ctx == nil || factory == nil || factory.Region() != foundationHomeRegion || !strings.HasPrefix(instanceID, "ocid1.instance.oc1.sa-saopaulo-1.") ||
		!strings.HasPrefix(compartment, "ocid1.compartment.") || !strings.HasPrefix(subnet, "ocid1.subnet.oc1.sa-saopaulo-1.") || len(nsgs) != 1 || !strings.HasPrefix(nsgs[0], "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.") {
		return "", errors.New("NetBird underlay endpoint lacks its exact original native GRU launch attachments")
	}
	compute, err := factory.Compute()
	if err != nil {
		return "", err
	}
	instance, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return "", err
	}
	if value(instance.Id) != instanceID || value(instance.CompartmentId) != compartment || instance.LifecycleState != core.InstanceLifecycleStateRunning {
		return "", errors.New("NetBird underlay original instance is not currently running in its signed compartment")
	}
	attachments, err := compute.ListVnicAttachments(ociclient.RequestContext(ctx), core.ListVnicAttachmentsRequest{CompartmentId: new(compartment), InstanceId: new(instanceID)})
	if err != nil {
		return "", err
	}
	if len(attachments.Items) != 1 || value(attachments.OpcNextPage) != "" {
		return "", errors.New("NetBird underlay original instance VNIC attachment is ambiguous")
	}
	attachment := attachments.Items[0]
	if value(attachment.InstanceId) != instanceID || value(attachment.CompartmentId) != compartment || value(attachment.SubnetId) != subnet ||
		attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || !strings.HasPrefix(value(attachment.VnicId), "ocid1.vnic.oc1.sa-saopaulo-1.") {
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
	if value(vnic.Id) != value(attachment.VnicId) || value(vnic.CompartmentId) != compartment || value(vnic.SubnetId) != subnet || value(vnic.PrivateIp) != privateIP ||
		vnic.IsPrimary == nil || !*vnic.IsPrimary || vnic.SkipSourceDestCheck == nil || *vnic.SkipSourceDestCheck || !slices.Equal(vnic.NsgIds, nsgs) ||
		len(vnic.Ipv6Addresses) != 0 || vnic.LifecycleState != core.VnicLifecycleStateAvailable || writer && value(vnic.PublicIp) != "" {
		return "", errors.New("NetBird underlay current primary VNIC differs from its exact signed endpoint")
	}
	return value(vnic.Id), nil
}
