package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// ReconcileNetBirdNetwork uses the same signed foundation attempt and durable
// create journal as the dedicated manager launch. No names or tags admit IDs.
func ReconcileNetBirdNetwork(ctx context.Context, factory *ociclient.Factory, plan map[string]any, profile NetBirdManagerProfile, progress FoundationProgress) (string, string, error) {
	if factory == nil || factory.Region() != foundationHomeRegion || plan["region"] != foundationHomeRegion || plan["cell"] != "GRU" ||
		progress.OperationID == "" || progress.BeforeWrite == nil || progress.PrepareCreate == nil || progress.CheckpointAuxiliary == nil {
		return "", "", errors.New("NetBird network requires the authenticated GRU foundation attempt")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || plan["tenancy_id"] != tenancy {
		return "", "", errors.New("NetBird network differs from authenticated tenancy")
	}
	ids, ok := plan["resource_ids"].(map[string]any)
	if !ok {
		return "", "", errors.New("NetBird network requires checkpointed foundation compartments")
	}
	compartment, _ := ids["network_compartment"].(string)
	if !strings.HasPrefix(compartment, "ocid1.compartment.") {
		return "", "", errors.New("NetBird network compartment is absent")
	}
	cidr, err := netip.ParsePrefix(profile.NetworkCIDR)
	address, addressErr := netip.ParseAddr(profile.PrivateIP)
	if err != nil || addressErr != nil || networkplan.ValidateRegion("GRU", profile.NetworkCIDR) != nil ||
		cidr.Bits() > 29 || !cidr.Contains(address) || address == cidr.Addr() || address == cidr.Addr().Next() || !cidr.Contains(address.Next()) {
		return "", "", errors.New("NetBird network requires a canonical signed private CIDR containing its manager")
	}
	for _, key := range []string{"network_cidr", "subnet_cidr"} {
		other, err := netip.ParsePrefix(fmt.Sprint(plan[key]))
		if err != nil || cidr.Overlaps(other) {
			return "", "", errors.New("NetBird network overlaps the regional network or lacks its signed bounds")
		}
	}
	client, err := factory.Network()
	if err != nil {
		return "", "", err
	}
	n := netBirdNetwork{client: client, progress: progress, ids: map[string]string{}, compartment: compartment}
	for key, id := range progress.AuxiliaryIDs {
		n.ids[key] = id
	}
	name := "gru-1-netbird-manager"
	vcnDetails := core.CreateVcnDetails{CompartmentId: new(compartment), DisplayName: new(name), CidrBlocks: []string{profile.NetworkCIDR}, DnsLabel: new("netbird")}
	var dhcp string
	vcn, err := n.ensure(ctx, "vcn", "vcn", vcnDetails, func(ctx context.Context, token string) (string, error) {
		r, err := client.CreateVcn(ociclient.RequestContext(ctx), core.CreateVcnRequest{CreateVcnDetails: vcnDetails, OpcRetryToken: new(token)})
		return value(r.Id), err
	}, func(ctx context.Context, id string) error {
		r, err := client.GetVcn(ociclient.RequestContext(ctx), core.GetVcnRequest{VcnId: new(id)})
		if err != nil {
			return err
		}
		if value(r.Id) != id || value(r.CompartmentId) != compartment || !slices.Equal(r.CidrBlocks, []string{profile.NetworkCIDR}) ||
			r.LifecycleState != core.VcnLifecycleStateAvailable || value(r.DnsLabel) != "netbird" || len(r.Ipv6CidrBlocks) != 0 || len(r.Ipv6PrivateCidrBlocks) != 0 || len(r.Byoipv6CidrBlocks) != 0 {
			return errors.New("NetBird VCN differs from its signed isolated network")
		}
		dhcp = value(r.DefaultDhcpOptionsId)
		return nil
	})
	if err != nil {
		return "", "", err
	}
	if err := n.verifyDNS(ctx, vcn, dhcp); err != nil {
		return "", "", err
	}
	igwDetails := core.CreateInternetGatewayDetails{CompartmentId: new(compartment), VcnId: new(vcn), DisplayName: new(name), IsEnabled: new(true)}
	igw, err := n.ensure(ctx, "internet_gateway", "internetgateway", igwDetails, func(ctx context.Context, token string) (string, error) {
		r, err := client.CreateInternetGateway(ociclient.RequestContext(ctx), core.CreateInternetGatewayRequest{CreateInternetGatewayDetails: igwDetails, OpcRetryToken: new(token)})
		return value(r.Id), err
	}, func(ctx context.Context, id string) error {
		r, err := client.GetInternetGateway(ociclient.RequestContext(ctx), core.GetInternetGatewayRequest{IgId: new(id)})
		if err != nil {
			return err
		}
		if value(r.Id) != id || value(r.CompartmentId) != compartment || value(r.VcnId) != vcn || r.IsEnabled == nil || !*r.IsEnabled || r.LifecycleState != core.InternetGatewayLifecycleStateAvailable || value(r.RouteTableId) != "" {
			return errors.New("NetBird Internet gateway differs from its checkpoint")
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	rules := []core.RouteRule{{Destination: new("0.0.0.0/0"), DestinationType: core.RouteRuleDestinationTypeCidrBlock, NetworkEntityId: new(igw)}}
	routeDetails := core.CreateRouteTableDetails{CompartmentId: new(compartment), VcnId: new(vcn), DisplayName: new(name), RouteRules: rules}
	route, err := n.ensure(ctx, "route", "routetable", routeDetails, func(ctx context.Context, token string) (string, error) {
		r, err := client.CreateRouteTable(ociclient.RequestContext(ctx), core.CreateRouteTableRequest{CreateRouteTableDetails: routeDetails, OpcRetryToken: new(token)})
		return value(r.Id), err
	}, func(ctx context.Context, id string) error {
		r, err := client.GetRouteTable(ociclient.RequestContext(ctx), core.GetRouteTableRequest{RtId: new(id)})
		if err != nil {
			return err
		}
		if value(r.Id) != id || value(r.CompartmentId) != compartment || value(r.VcnId) != vcn || r.LifecycleState != core.RouteTableLifecycleStateAvailable || !sameNetBirdRoutes(r.RouteRules, rules) {
			return errors.New("NetBird route table permits an unexpected path")
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	ingress, egress := netBirdManagerRules()
	securityDetails := core.CreateSecurityListDetails{CompartmentId: new(compartment), VcnId: new(vcn), DisplayName: new(name), IngressSecurityRules: ingress, EgressSecurityRules: egress}
	security, err := n.ensure(ctx, "security_list", "securitylist", securityDetails, func(ctx context.Context, token string) (string, error) {
		r, err := client.CreateSecurityList(ociclient.RequestContext(ctx), core.CreateSecurityListRequest{CreateSecurityListDetails: securityDetails, OpcRetryToken: new(token)})
		return value(r.Id), err
	}, func(ctx context.Context, id string) error {
		r, err := client.GetSecurityList(ociclient.RequestContext(ctx), core.GetSecurityListRequest{SecurityListId: new(id)})
		if err != nil {
			return err
		}
		if value(r.Id) != id || value(r.CompartmentId) != compartment || value(r.VcnId) != vcn || r.LifecycleState != core.SecurityListLifecycleStateAvailable ||
			!reflect.DeepEqual(r.IngressSecurityRules, ingress) || !reflect.DeepEqual(r.EgressSecurityRules, egress) {
			return errors.New("NetBird security list differs from the fixed upstream traffic graph")
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	// The atomic security-list create owns permissions; an empty NSG cannot widen them.
	nsgDetails := core.CreateNetworkSecurityGroupDetails{CompartmentId: new(compartment), VcnId: new(vcn), DisplayName: new(name)}
	nsg, err := n.ensure(ctx, "nsg", "networksecuritygroup", nsgDetails, func(ctx context.Context, token string) (string, error) {
		r, err := client.CreateNetworkSecurityGroup(ociclient.RequestContext(ctx), core.CreateNetworkSecurityGroupRequest{CreateNetworkSecurityGroupDetails: nsgDetails, OpcRetryToken: new(token)})
		return value(r.Id), err
	}, func(ctx context.Context, id string) error {
		r, err := client.GetNetworkSecurityGroup(ociclient.RequestContext(ctx), core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: new(id)})
		if err != nil {
			return err
		}
		if value(r.Id) != id || value(r.CompartmentId) != compartment || value(r.VcnId) != vcn || r.LifecycleState != core.NetworkSecurityGroupLifecycleStateAvailable {
			return errors.New("NetBird NSG differs from its dedicated checkpoint")
		}
		rules, err := client.ListNetworkSecurityGroupSecurityRules(ociclient.RequestContext(ctx), core.ListNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: new(id)})
		if err != nil {
			return err
		}
		if rules.Items == nil || len(rules.Items) != 0 || value(rules.OpcNextPage) != "" {
			return errors.New("NetBird NSG contains unexpected additional permissions")
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	subnetDetails := core.CreateSubnetDetails{CompartmentId: new(compartment), VcnId: new(vcn), DisplayName: new(name), CidrBlock: new(profile.NetworkCIDR),
		DnsLabel: new("manager"), DhcpOptionsId: new(dhcp), RouteTableId: new(route), SecurityListIds: []string{security}, ProhibitPublicIpOnVnic: new(false)}
	subnet, err := n.ensure(ctx, "subnet", "subnet", subnetDetails, func(ctx context.Context, token string) (string, error) {
		r, err := client.CreateSubnet(ociclient.RequestContext(ctx), core.CreateSubnetRequest{CreateSubnetDetails: subnetDetails, OpcRetryToken: new(token)})
		return value(r.Id), err
	}, func(ctx context.Context, id string) error {
		r, err := client.GetSubnet(ociclient.RequestContext(ctx), core.GetSubnetRequest{SubnetId: new(id)})
		if err != nil {
			return err
		}
		if value(r.Id) != id || value(r.CompartmentId) != compartment || value(r.VcnId) != vcn || r.LifecycleState != core.SubnetLifecycleStateAvailable ||
			value(r.CidrBlock) != profile.NetworkCIDR || value(r.RouteTableId) != route || !slices.Equal(r.SecurityListIds, []string{security}) ||
			value(r.DhcpOptionsId) != dhcp || value(r.DnsLabel) != "manager" || value(r.AvailabilityDomain) != "" ||
			r.ProhibitPublicIpOnVnic == nil || *r.ProhibitPublicIpOnVnic || r.ProhibitInternetIngress == nil || *r.ProhibitInternetIngress ||
			value(r.Ipv6CidrBlock) != "" || len(r.Ipv6CidrBlocks) != 0 || len(r.Ipv4CidrBlocks) > 1 || len(r.Ipv4CidrBlocks) == 1 && r.Ipv4CidrBlocks[0] != profile.NetworkCIDR {
			return errors.New("NetBird subnet attachments or public bootstrap route drifted")
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return subnet, nsg, nil
}

type netBirdNetwork struct {
	client      core.VirtualNetworkClient
	progress    FoundationProgress
	ids         map[string]string
	compartment string
}

func (n *netBirdNetwork) ensure(ctx context.Context, suffix, kind string, details any, create func(context.Context, string) (string, error), observe func(context.Context, string) error) (string, error) {
	key := "netbird_manager_" + suffix
	id := n.ids[key]
	if id == "" {
		wire, err := json.Marshal(struct {
			Operation, Key string
			Details        any
		}{n.progress.OperationID, key, details}, json.Deterministic(true))
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(wire)
		token := hex.EncodeToString(digest[:])
		if err := n.progress.PrepareCreate(ctx, foundation.CreateIdentity{Key: key, Region: foundationHomeRegion, RequestDigest: token, RetryToken: token}, false); err != nil {
			return "", err
		}
		child, release, err := n.progress.BeforeWrite(ctx, false)
		if err != nil {
			return "", err
		}
		if child == nil || release == nil {
			return "", errors.New("NetBird network write lacks a fenced authority context")
		}
		guarded := ociclient.WithAuthority(child, func(ctx context.Context) error {
			_, done, err := n.progress.BeforeWrite(ctx, false)
			if err != nil {
				return err
			}
			if done == nil {
				return errors.New("NetBird network retry authority is absent")
			}
			done()
			return nil
		})
		id, err = create(guarded, token)
		release()
		if err != nil {
			return "", fmt.Errorf("create %s has unresolved provider outcome: %w", key, err)
		}
		if !strings.HasPrefix(id, "ocid1."+kind+".oc1.sa-saopaulo-1.") {
			return "", errors.New("NetBird network create returned an out-of-scope identity")
		}
		if err := n.progress.CheckpointAuxiliary(ctx, key, id); err != nil {
			return "", err
		}
		n.ids[key] = id
	}
	if !strings.HasPrefix(id, "ocid1."+kind+".oc1.sa-saopaulo-1.") {
		return "", errors.New("NetBird network checkpoint is out of scope")
	}
	if err := observe(ctx, id); err != nil {
		return "", fmt.Errorf("observe %s: %w", key, err)
	}
	return id, nil
}

func (n *netBirdNetwork) verifyDNS(ctx context.Context, vcn, id string) error {
	if !strings.HasPrefix(id, "ocid1.dhcpoptions.oc1.sa-saopaulo-1.") {
		return errors.New("NetBird VCN lacks its OCI DNS options")
	}
	r, err := n.client.GetDhcpOptions(ociclient.RequestContext(ctx), core.GetDhcpOptionsRequest{DhcpId: new(id)})
	if err != nil {
		return err
	}
	if value(r.Id) != id || value(r.VcnId) != vcn || value(r.CompartmentId) != n.compartment || r.LifecycleState != core.DhcpOptionsLifecycleStateAvailable {
		return errors.New("NetBird DNS options differ from its isolated VCN")
	}
	servers := 0
	for _, option := range r.Options {
		if dns, ok := option.(core.DhcpDnsOption); ok {
			servers++
			if dns.ServerType != core.DhcpDnsOptionServerTypeVcnlocalplusinternet || len(dns.CustomDnsServers) != 0 {
				return errors.New("NetBird DNS must use the OCI Internet and VCN resolver")
			}
		}
	}
	if servers != 1 {
		return errors.New("NetBird DNS resolver is absent or ambiguous")
	}
	return nil
}

func netBirdManagerRules() ([]core.IngressSecurityRule, []core.EgressSecurityRule) {
	ingress := []core.IngressSecurityRule{}
	for _, port := range []int{80, 443} {
		ingress = append(ingress, core.IngressSecurityRule{Source: new("0.0.0.0/0"), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock, Protocol: new("6"), IsStateless: new(false), TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(port), Max: new(port)}}})
	}
	ingress = append(ingress, core.IngressSecurityRule{Source: new("0.0.0.0/0"), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock, Protocol: new("17"), IsStateless: new(false), UdpOptions: &core.UdpOptions{DestinationPortRange: &core.PortRange{Min: new(3478), Max: new(3478)}}})
	egress := []core.EgressSecurityRule{{Destination: new("0.0.0.0/0"), DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock, Protocol: new("6"), IsStateless: new(false), TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(443), Max: new(443)}}}}
	for _, protocol := range []string{"6", "17"} {
		rule := core.EgressSecurityRule{Destination: new("169.254.169.254/32"), DestinationType: core.EgressSecurityRuleDestinationTypeCidrBlock, Protocol: new(protocol), IsStateless: new(false)}
		if protocol == "6" {
			rule.TcpOptions = &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(53), Max: new(53)}}
		} else {
			rule.UdpOptions = &core.UdpOptions{DestinationPortRange: &core.PortRange{Min: new(53), Max: new(53)}}
		}
		egress = append(egress, rule)
	}
	return ingress, egress
}

func sameNetBirdRoutes(actual, expected []core.RouteRule) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i, rule := range actual {
		want := expected[i]
		if value(rule.Destination) != value(want.Destination) || rule.DestinationType != want.DestinationType || value(rule.NetworkEntityId) != value(want.NetworkEntityId) || value(rule.CidrBlock) != "" && value(rule.CidrBlock) != value(want.Destination) || rule.RouteType != "" && rule.RouteType != core.RouteRuleRouteTypeStatic {
			return false
		}
	}
	return true
}

func value[T any](p *T) (v T) {
	if p != nil {
		return *p
	}
	return v
}
