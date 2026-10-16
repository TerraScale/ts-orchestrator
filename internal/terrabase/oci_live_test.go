package terrabase

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/limits"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// a1Shape is the ARM64 shape TerraBase hosts run on.
const a1Shape = "VM.Standard.A1.Flex"

// TestLiveOCITerraBaseHostsReadOnly checks, against the real OCI API, what a
// C# TerraBase release needs from a cell: the region offers the ARM64 A1
// shape with A1 cores left for another member, an Ubuntu ARM64 base image
// fits that shape, and the cell's running TerraBase hosts are A1 instances on
// distinct fault domains whose network security groups let every member
// reach the others' peer port. It logs the TERRABASE_PEERS value those hosts
// give. Every call is a list or get through the shared OCI client factory
// with the operator's ~/.oci/config DEFAULT profile; nothing is created,
// changed or deleted.
//
// Opt in with TS_OCI_LIVE_COMPARTMENT_ID, the cell's compartment. Optional:
// TS_OCI_LIVE_REGION (default: the profile's region), TS_OCI_LIVE_HOST_PREFIX
// (default gru-1-db-) and TS_OCI_LIVE_PEER_PORT (default 9443). A cell with
// no running host of that prefix yet passes the regional checks and skips
// the host checks.
func TestLiveOCITerraBaseHostsReadOnly(t *testing.T) {
	compartment := tier.Qualification(t, "TS_OCI_LIVE_COMPARTMENT_ID")[0]
	prefix := liveEnv("TS_OCI_LIVE_HOST_PREFIX", "gru-1-db-")
	peerPort, err := parsePort(liveEnv("TS_OCI_LIVE_PEER_PORT", "9443"))
	if err != nil {
		t.Fatalf("TS_OCI_LIVE_PEER_PORT: %v", err)
	}
	region := os.Getenv("TS_OCI_LIVE_REGION")
	if region == "" {
		if region, err = common.DefaultConfigProvider().Region(); err != nil {
			t.Fatal(err)
		}
	}
	factory, err := ociclient.OperatorConfig(region)
	if err != nil {
		t.Fatal(err)
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		t.Fatal(err)
	}
	compute, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	network, err := factory.Network()
	if err != nil {
		t.Fatal(err)
	}
	identities, err := factory.Identity()
	if err != nil {
		t.Fatal(err)
	}
	quotas, err := limits.NewLimitsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		t.Fatal(err)
	}
	quotas.SetRegion(region)
	factory.Configure(&quotas.BaseClient, ociclient.ServiceIdentity)
	ctx := t.Context()

	// The region offers A1 with one OCPU and 6 GB per OCPU, the host profile.
	shapes, err := compute.ListShapes(ctx, core.ListShapesRequest{CompartmentId: &compartment, Limit: common.Int(100)})
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(shapes.Items, func(shape core.Shape) bool { return shape.Shape != nil && *shape.Shape == a1Shape })
	if index < 0 {
		t.Fatalf("%s is not offered in %s", a1Shape, region)
	}
	shape := shapes.Items[index]
	if shape.ProcessorDescription == nil || !strings.Contains(*shape.ProcessorDescription, "Ampere") ||
		shape.OcpuOptions == nil || *shape.OcpuOptions.Min > 1 ||
		shape.MemoryOptions == nil || *shape.MemoryOptions.MaxPerOcpuInGBs < 6 {
		t.Fatalf("%s does not fit the TerraBase host profile: %+v", a1Shape, shape)
	}

	// A1 cores are left for at least one more member.
	domains, err := identities.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{CompartmentId: &tenancy})
	if err != nil {
		t.Fatal(err)
	}
	available := int64(0)
	for _, domain := range domains.Items {
		availability, err := quotas.GetResourceAvailability(ctx, limits.GetResourceAvailabilityRequest{ServiceName: common.String("compute"),
			LimitName: common.String("standard-a1-core-count"), CompartmentId: &tenancy, AvailabilityDomain: domain.Name})
		if err != nil {
			t.Fatal(err)
		}
		if availability.Available != nil {
			available += *availability.Available
		}
	}
	if available < 1 {
		t.Fatalf("no %s cores are available in %s", a1Shape, region)
	}

	// The region publishes an Ubuntu ARM64 base image for A1.
	images, err := compute.ListImages(ctx, core.ListImagesRequest{CompartmentId: &compartment,
		OperatingSystem: common.String("Canonical Ubuntu"), Shape: common.String(a1Shape), Limit: common.Int(20)})
	if err != nil {
		t.Fatal(err)
	}
	if len(images.Items) == 0 {
		t.Fatalf("no Canonical Ubuntu image fits %s in %s", a1Shape, region)
	}
	t.Logf("%s: %s offered (%s), %d A1 cores available, %d Ubuntu A1 images", region, a1Shape,
		*shape.ProcessorDescription, available, len(images.Items))

	// The cell's TerraBase hosts.
	instances, err := compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: &compartment,
		LifecycleState: core.InstanceLifecycleStateRunning, Limit: common.Int(100)})
	if err != nil {
		t.Fatal(err)
	}
	type member struct {
		name, faultDomain string
		address           netip.Addr
		groups            []string
	}
	var members []member
	for _, instance := range instances.Items {
		if instance.DisplayName == nil || !strings.HasPrefix(*instance.DisplayName, prefix) {
			continue
		}
		if instance.Shape == nil || *instance.Shape != a1Shape {
			t.Errorf("host %s runs %v, not %s", *instance.DisplayName, instance.Shape, a1Shape)
		}
		attachments, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: &compartment, InstanceId: instance.Id})
		if err != nil {
			t.Fatal(err)
		}
		for _, attachment := range attachments.Items {
			if attachment.VnicId == nil || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
				continue
			}
			vnic, err := network.GetVnic(ctx, core.GetVnicRequest{VnicId: attachment.VnicId})
			if err != nil {
				t.Fatal(err)
			}
			if vnic.IsPrimary == nil || !*vnic.IsPrimary || vnic.PrivateIp == nil {
				continue
			}
			address, err := netip.ParseAddr(*vnic.PrivateIp)
			if err != nil {
				t.Fatal(err)
			}
			members = append(members, member{name: *instance.DisplayName, faultDomain: *instance.FaultDomain,
				address: address, groups: vnic.NsgIds})
		}
	}
	if len(members) == 0 {
		t.Logf("no running hosts named %s* in the compartment yet; TerraBase host checks skipped", prefix)
		return
	}
	entries := make([]string, len(members))
	domainsUsed := map[string]bool{}
	for i, m := range members {
		entries[i] = m.name + "=" + netip.AddrPortFrom(m.address, uint16(peerPort)).String()
		if domainsUsed[m.faultDomain] && len(members) <= 3 {
			t.Errorf("hosts share fault domain %s", m.faultDomain)
		}
		domainsUsed[m.faultDomain] = true
	}
	peers := strings.Join(entries, ",")
	if _, err := ParsePeers(peers); err != nil {
		t.Fatalf("the hosts give an invalid peer list: %v", err)
	}
	t.Logf("%s=%s", EnvPeers, peers)

	// Every member reaches every other member's peer port through an
	// ingress rule of a group on the receiving member's VNIC.
	rules := map[string][]core.SecurityRule{}
	for _, m := range members {
		for _, group := range m.groups {
			if _, read := rules[group]; read {
				continue
			}
			response, err := network.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{
				NetworkSecurityGroupId: &group, Direction: core.ListNetworkSecurityGroupSecurityRulesDirectionIngress, Limit: common.Int(100)})
			if err != nil {
				t.Fatal(err)
			}
			rules[group] = response.Items
		}
	}
	for _, receiver := range members {
		for _, sender := range members {
			if sender.name != receiver.name && !peerPortOpen(receiver.groups, rules, sender.address, sender.groups, peerPort) {
				t.Errorf("%s cannot reach %s on TCP %d: no ingress rule on %s's groups allows it", sender.name, receiver.name, peerPort, receiver.name)
			}
		}
	}
}

// peerPortOpen reports whether an ingress rule of the receiver's groups lets
// TCP from the sender's address or groups reach port.
func peerPortOpen(receiver []string, rules map[string][]core.SecurityRule, sender netip.Addr, senderGroups []string, port int) bool {
	for _, group := range receiver {
		for _, rule := range rules[group] {
			if rule.Protocol == nil || (*rule.Protocol != "6" && *rule.Protocol != "all") || rule.Source == nil {
				continue
			}
			if *rule.Protocol == "6" && rule.TcpOptions != nil && rule.TcpOptions.DestinationPortRange != nil {
				ports := rule.TcpOptions.DestinationPortRange
				if ports.Min == nil || ports.Max == nil || *ports.Min > port || *ports.Max < port {
					continue
				}
			}
			switch rule.SourceType {
			case core.SecurityRuleSourceTypeNetworkSecurityGroup:
				if slices.Contains(senderGroups, *rule.Source) {
					return true
				}
			default:
				if prefix, err := netip.ParsePrefix(*rule.Source); err == nil && prefix.Contains(sender) {
					return true
				}
			}
		}
	}
	return false
}

func TestPeerPortOpen(t *testing.T) {
	tcp := func(source string, kind core.SecurityRuleSourceTypeEnum, low, high int) core.SecurityRule {
		return core.SecurityRule{Protocol: common.String("6"), Source: &source, SourceType: kind,
			TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: &low, Max: &high}}}
	}
	rules := map[string][]core.SecurityRule{
		"cidr": {tcp("10.251.0.0/24", core.SecurityRuleSourceTypeCidrBlock, 9443, 9443)},
		"nsg":  {tcp("members", core.SecurityRuleSourceTypeNetworkSecurityGroup, 9000, 9500)},
		"miss": {tcp("10.251.0.0/24", core.SecurityRuleSourceTypeCidrBlock, 9465, 9465)},
	}
	sender := netip.MustParseAddr("10.251.0.22")
	for name, want := range map[string]bool{"cidr": true, "nsg": true, "miss": false} {
		if got := peerPortOpen([]string{name}, rules, sender, []string{"members"}, 9443); got != want {
			t.Errorf("%s: open %v, want %v", name, got, want)
		}
	}
	if peerPortOpen([]string{"nsg"}, rules, sender, []string{"0000000000V4MRM46HP1SNGDYW"}, 9443) {
		t.Error("a rule for another group opened the port")
	}
	if peerPortOpen([]string{"cidr"}, rules, netip.MustParseAddr("10.9.0.1"), nil, 9443) {
		t.Error("a rule for another network opened the port")
	}
}

func liveEnv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
