package fleet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/edge/geodns"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
)

const Owner = "terrascale"

type State string

const (
	Ok      State = "ok"
	Foreign State = "foreign"
	Claimed State = "claimed"
	Differs State = "differs"
	Missing State = "missing"
)

var severity = map[State]int{Ok: 0, Foreign: 1, Claimed: 2, Differs: 3, Missing: 4}

type Check struct {
	Kind    string
	State   State
	Details []string
}

type Report struct {
	Name   string
	Scope  string
	Checks []Check
}

type item struct {
	desc  string
	tags  map[string]string
	match bool
	keys  []ociresource.Key
}

func made(it item) (string, State) {
	ownership := ociresource.Ownership{Owner: Owner}
	tags := ociresource.Tags{Freeform: it.tags}
	for _, key := range it.keys {
		if ownership.Owns(key, tags) {
			return "document-made", Ok
		}
	}
	if ownership.Claimed(tags) {
		return strings.TrimSpace("claimed by another owner as " + it.tags["terrascale-owner"] + " " + it.tags["terrascale-resource-key"]), Claimed
	}
	return "hand-made", Foreign
}

func check(kind string, items []item, many bool) Check {
	result := Check{Kind: kind, State: Missing}
	if len(items) == 0 {
		return result
	}
	result.State = Ok
	matched := 0
	for _, it := range items {
		label, state := made(it)
		result.Details = append(result.Details, it.desc+" "+label)
		if it.match {
			matched++
		} else {
			state = Differs
		}
		if severity[state] > severity[result.State] {
			result.State = state
		}
	}
	if matched == 0 || matched > 1 && !many {
		result.State = Differs
	}
	return result
}

func list[T any](what string, call func(page *string) ([]T, *string, error)) ([]T, error) {
	var all []T
	var page *string
	for {
		items, next, err := call(page)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		all = append(all, items...)
		if next == nil || *next == "" {
			return all, nil
		}
		page = next
	}
}

func factory(ctx context.Context, ociRegion string) (*ociclient.Factory, error) {
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".oci", "config")); err == nil {
			return ociclient.OperatorConfig(ociRegion)
		}
	}
	return ociclient.InstancePrincipalContext(ctx, ociRegion)
}

func Plan(ctx context.Context, fleet Fleet) ([]Report, error) {
	var reports []Report
	release, found := newestNodeRelease(ctx)
	for _, region := range fleet.All() {
		report, err := observeRegion(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", region.Label, err)
		}
		report.Checks = append(report.Checks, releaseCheck(release, found, region))
		reports = append(reports, report)
	}
	dns, err := observeDNS(ctx, fleet)
	if err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	return append(reports, dns), nil
}

func gone(state string) bool {
	return state == "TERMINATED" || state == "TERMINATING" || state == "DELETED" || state == "DELETING"
}

func collect[T any](values []T, view func(T) (item, string)) []item {
	var items []item
	for _, v := range values {
		if it, state := view(v); !gone(state) {
			items = append(items, it)
		}
	}
	return items
}

func observeRegion(ctx context.Context, region Region) (Report, error) {
	report := Report{Name: region.Label, Scope: region.OCIRegion}
	f, err := factory(ctx, region.OCIRegion)
	if err != nil {
		return report, err
	}
	network, err := f.Network()
	if err != nil {
		return report, err
	}
	compute, err := f.Compute()
	if err != nil {
		return report, err
	}
	balancers, err := f.NetworkLoadBalancer()
	if err != nil {
		return report, err
	}
	compartment := common.String(region.CompartmentID)
	key := func(kind string, names ...string) []ociresource.Key {
		var keys []ociresource.Key
		for _, name := range names {
			keys = append(keys, region.Key(kind, name))
		}
		return keys
	}
	vcns, err := list("vcn", func(page *string) ([]core.Vcn, *string, error) {
		r, err := network.ListVcns(ctx, core.ListVcnsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	vcn := ""
	report.Checks = append(report.Checks, check("vcn", collect(vcns, func(v core.Vcn) (item, string) {
		match := deref(v.CidrBlock) == region.VCNCIDR
		if match && !gone(string(v.LifecycleState)) {
			vcn = deref(v.Id)
		}
		return item{deref(v.DisplayName) + " " + deref(v.CidrBlock), v.FreeformTags, match, key("vcn", "vcn")}, string(v.LifecycleState)
	}), false))
	inVCN := func(id *string) bool { return vcn != "" && deref(id) == vcn }
	subnets, err := list("subnet", func(page *string) ([]core.Subnet, *string, error) {
		r, err := network.ListSubnets(ctx, core.ListSubnetsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	subnetIDs := map[bool]string{}
	privateRoutes := ""
	for _, want := range []struct {
		kind, cidr, other, name string
		private                 bool
	}{{"public subnet", region.PublicSubnetCIDR, region.PrivateSubnetCIDR, "host-subnet", false}, {"private subnet", region.PrivateSubnetCIDR, region.PublicSubnetCIDR, "private-subnet", true}} {
		var items []item
		for _, s := range subnets {
			if gone(string(s.LifecycleState)) || deref(s.CidrBlock) == want.other {
				continue
			}
			private := s.ProhibitPublicIpOnVnic != nil && *s.ProhibitPublicIpOnVnic
			access := "public addresses"
			if private {
				access = "no public addresses"
			}
			match := inVCN(s.VcnId) && deref(s.CidrBlock) == want.cidr && private == want.private
			if match {
				subnetIDs[want.private] = deref(s.Id)
				if want.private {
					privateRoutes = deref(s.RouteTableId)
				}
			}
			items = append(items, item{fmt.Sprintf("%s %s %s", deref(s.DisplayName), deref(s.CidrBlock), access), s.FreeformTags, match, key("subnet", want.name)})
		}
		report.Checks = append(report.Checks, check(want.kind, items, false))
	}
	internet, err := list("internet gateway", func(page *string) ([]core.InternetGateway, *string, error) {
		r, err := network.ListInternetGateways(ctx, core.ListInternetGatewaysRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	report.Checks = append(report.Checks, check("internet gateway", collect(internet, func(g core.InternetGateway) (item, string) {
		return item{deref(g.DisplayName), g.FreeformTags, inVCN(g.VcnId), key("internet-gateway", "igw")}, string(g.LifecycleState)
	}), false))
	nat, err := list("nat gateway", func(page *string) ([]core.NatGateway, *string, error) {
		r, err := network.ListNatGateways(ctx, core.ListNatGatewaysRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	natID := ""
	report.Checks = append(report.Checks, check("nat gateway", collect(nat, func(g core.NatGateway) (item, string) {
		match := inVCN(g.VcnId) && (g.BlockTraffic == nil || !*g.BlockTraffic)
		if match && !gone(string(g.LifecycleState)) {
			natID = deref(g.Id)
		}
		return item{deref(g.DisplayName) + " " + deref(g.NatIp), g.FreeformTags, match, key("nat-gateway", "nat")}, string(g.LifecycleState)
	}), false))
	service, err := list("service gateway", func(page *string) ([]core.ServiceGateway, *string, error) {
		r, err := network.ListServiceGateways(ctx, core.ListServiceGatewaysRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	sgwID := ""
	report.Checks = append(report.Checks, check("service gateway", collect(service, func(g core.ServiceGateway) (item, string) {
		if inVCN(g.VcnId) && !gone(string(g.LifecycleState)) {
			sgwID = deref(g.Id)
		}
		return item{deref(g.DisplayName), g.FreeformTags, inVCN(g.VcnId), key("service-gateway", "sgw")}, string(g.LifecycleState)
	}), false))
	tables, err := list("route table", func(page *string) ([]core.RouteTable, *string, error) {
		r, err := network.ListRouteTables(ctx, core.ListRouteTablesRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	var routeTables []core.RouteTable
	for _, t := range tables {
		if deref(t.Id) == privateRoutes {
			routeTables = append(routeTables, t)
		}
	}
	report.Checks = append(report.Checks, check("private routes", collect(routeTables, func(t core.RouteTable) (item, string) {
		var routes []string
		for _, r := range t.RouteRules {
			switch deref(r.NetworkEntityId) {
			case natID:
				routes = append(routes, deref(r.Destination)+" nat")
			case sgwID:
				routes = append(routes, deref(r.Destination)+" sgw")
			default:
				routes = append(routes, deref(r.Destination)+" other")
			}
		}
		slices.Sort(routes)
		match := inVCN(t.VcnId) && natID != "" && sgwID != "" && len(t.RouteRules) == 2 && slices.Contains(routes, "0.0.0.0/0 nat") &&
			slices.ContainsFunc(routes, func(r string) bool { return strings.HasSuffix(r, " sgw") })
		return item{deref(t.DisplayName) + " " + strings.Join(routes, ", "), t.FreeformTags, match, key("route-table", "private-routes")}, string(t.LifecycleState)
	}), false))
	nsgs, err := list("nsg", func(page *string) ([]core.NetworkSecurityGroup, *string, error) {
		r, err := network.ListNetworkSecurityGroups(ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	report.Checks = append(report.Checks, check("nsg", collect(nsgs, func(g core.NetworkSecurityGroup) (item, string) {
		return item{deref(g.DisplayName), g.FreeformTags, inVCN(g.VcnId), key("nsg", "edge-nsg", "host-nsg", "node-nsg")}, string(g.LifecycleState)
	}), true))
	instances, err := list("instance", func(page *string) ([]core.Instance, *string, error) {
		r, err := compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	attachments, err := list("vnic attachment", func(page *string) ([]core.VnicAttachment, *string, error) {
		r, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	subnetOf := map[string]string{}
	for _, a := range attachments {
		if a.LifecycleState == core.VnicAttachmentLifecycleStateAttached {
			subnetOf[deref(a.InstanceId)] = deref(a.SubnetId)
		}
	}
	report.Checks = append(report.Checks, nodes(region, instances, subnetOf, subnetIDs[true], key("instance", "node")))
	nlbs, err := list("nlb", func(page *string) ([]networkloadbalancer.NetworkLoadBalancerSummary, *string, error) {
		r, err := balancers.ListNetworkLoadBalancers(ctx, networkloadbalancer.ListNetworkLoadBalancersRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	report.Checks = append(report.Checks, check("nlb", collect(nlbs, func(b networkloadbalancer.NetworkLoadBalancerSummary) (item, string) {
		var public []string
		for _, ip := range b.IpAddresses {
			if ip.IsPublic != nil && *ip.IsPublic {
				public = append(public, deref(ip.IpAddress))
			}
		}
		match := subnetIDs[false] != "" && deref(b.SubnetId) == subnetIDs[false] && len(public) > 0
		return item{deref(b.DisplayName) + " " + strings.Join(public, ","), b.FreeformTags, match, key("network-load-balancer", "nlb")}, string(b.LifecycleState)
	}), false))
	health, err := backendHealth(ctx, nlbPass{region: region, network: network, balancers: balancers}, nlbs, instances, attachments)
	if err != nil {
		return report, err
	}
	report.Checks = append(report.Checks, health)
	reserved, err := list("reserved address", func(page *string) ([]core.PublicIp, *string, error) {
		r, err := network.ListPublicIps(ctx, core.ListPublicIpsRequest{Scope: core.ListPublicIpsScopeRegion, Lifetime: core.ListPublicIpsLifetimeReserved, CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, err
	}
	report.Checks = append(report.Checks, check("reserved address", collect(reserved, func(ip core.PublicIp) (item, string) {
		return item{deref(ip.DisplayName) + " " + deref(ip.IpAddress), ip.FreeformTags, true, key("public-ip", "nlb")}, string(ip.LifecycleState)
	}), false))
	return report, nil
}

func nodes(region Region, instances []core.Instance, subnetOf map[string]string, privateSubnet string, keys []ociresource.Key) Check {
	want := region.Nodes
	external := map[string]string{}
	instances = slices.DeleteFunc(slices.Clone(instances), func(in core.Instance) bool {
		if !slices.Contains(want.External, deref(in.DisplayName)) || gone(string(in.LifecycleState)) {
			return false
		}
		external[deref(in.DisplayName)] = strings.ToLower(string(in.LifecycleState))
		return true
	})
	items := collect(instances, func(in core.Instance) (item, string) {
		var ocpus, memory float32
		if in.ShapeConfig != nil && in.ShapeConfig.Ocpus != nil && in.ShapeConfig.MemoryInGBs != nil {
			ocpus, memory = *in.ShapeConfig.Ocpus, *in.ShapeConfig.MemoryInGBs
		}
		subnet := "private subnet"
		if privateSubnet == "" || subnetOf[deref(in.Id)] != privateSubnet {
			subnet = "not in private subnet"
		}
		match := deref(in.Shape) == want.Shape && ocpus == want.OCPUs && memory == want.MemoryGB && subnet == "private subnet" && in.LifecycleState == core.InstanceLifecycleStateRunning
		desc := fmt.Sprintf("%s %s %g/%g %s %s", deref(in.DisplayName), deref(in.Shape), ocpus, memory, strings.ToLower(string(in.LifecycleState)), subnet)
		return item{desc, in.FreeformTags, match, keys}, string(in.LifecycleState)
	})
	result := check("instances", items, true)
	count := fmt.Sprint(want.Min)
	if want.Max != want.Min {
		count = fmt.Sprintf("%d-%d", want.Min, want.Max)
	}
	result.Details = append([]string{fmt.Sprintf("%d found, document wants %s x %s %g/%g in private subnet", len(items), count, want.Shape, want.OCPUs, want.MemoryGB)}, result.Details...)
	for _, host := range want.External {
		state, ok := external[host]
		if !ok {
			result.State = Differs
			state = "missing"
		}
		result.Details = append(result.Details, fmt.Sprintf("external %s %s, counted toward the region's %d voting hosts", host, state, MinNodes))
	}
	if len(items) < want.Min || len(items) > want.Max {
		result.State = Differs
	}
	return result
}

func observeDNS(ctx context.Context, fleet Fleet) (Report, error) {
	report := Report{Name: "dns", Scope: fleet.DNS.Zone}
	home, _ := fleet.DNSRegion()
	f, err := factory(ctx, home.OCIRegion)
	if err != nil {
		return report, err
	}
	cfg, err := dnsConfig(ctx, fleet, f)
	if err != nil && !errors.Is(err, errDNSNLB) {
		return report, err
	}
	if err != nil {
		report.Checks = append(report.Checks, Check{Kind: "dns prerequisites", State: Missing, Details: []string{err.Error()}})
		return report, nil
	}
	client, err := geodns.New(f)
	if err != nil {
		return report, err
	}
	changes, err := client.Reconcile(ctx, cfg, false, func(geodns.Change) error { return nil })
	if err != nil {
		return report, err
	}
	for _, change := range changes {
		state := State(change.Action)
		if state == "" {
			state = Differs
		}
		report.Checks = append(report.Checks, Check{Kind: change.Kind, State: state, Details: []string{change.Name + " " + change.ID}})
	}
	return report, nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
