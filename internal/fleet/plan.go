package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
	"github.com/oracle/oci-go-sdk/v65/resourcesearch"
)

type State string

const (
	Ok      State = "ok"
	Foreign State = "foreign"
	Differs State = "differs"
	Missing State = "missing"
)

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
}

func documentMade(tags map[string]string) bool {
	return tags["terrascale-managed-by"] == "ts-orchestrator" && tags["terrascale-owner"] != "" && tags["terrascale-resource-key"] != ""
}

func maker(tags map[string]string) string {
	if documentMade(tags) {
		return "document-made"
	}
	return "hand-made"
}

func check(kind string, items []item, many bool) Check {
	result := Check{Kind: kind, State: Missing}
	matched := 0
	for _, it := range items {
		result.Details = append(result.Details, it.desc+" "+maker(it.tags))
		if !it.match {
			result.State = Differs
			continue
		}
		matched++
		if result.State == Missing {
			result.State = Ok
		}
		if !documentMade(it.tags) && result.State == Ok {
			result.State = Foreign
		}
	}
	if matched == 0 && len(items) > 0 || matched > 1 && !many {
		result.State = Differs
	}
	return result
}

func pages[T any](list func(page *string) ([]T, *string, error)) ([]T, error) {
	var all []T
	var page *string
	for {
		items, next, err := list(page)
		if err != nil {
			return nil, err
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
	for _, region := range fleet.Regions {
		report, err := observeRegion(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", region.Label, err)
		}
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
	vcns, err := pages(func(page *string) ([]core.Vcn, *string, error) {
		r, err := network.ListVcns(ctx, core.ListVcnsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("vcn: %w", err)
	}
	var vcnItems []item
	for _, v := range vcns {
		if !gone(string(v.LifecycleState)) {
			vcnItems = append(vcnItems, item{fmt.Sprintf("%s %s", deref(v.DisplayName), deref(v.CidrBlock)), v.FreeformTags, deref(v.CidrBlock) == region.VCNCIDR})
		}
	}
	report.Checks = append(report.Checks, check("vcn", vcnItems, false))
	subnets, err := pages(func(page *string) ([]core.Subnet, *string, error) {
		r, err := network.ListSubnets(ctx, core.ListSubnetsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("subnet: %w", err)
	}
	privateSubnet := ""
	for _, want := range []struct {
		kind, cidr, other string
		private           bool
	}{{"public subnet", region.PublicSubnetCIDR, region.PrivateSubnetCIDR, false}, {"private subnet", region.PrivateSubnetCIDR, region.PublicSubnetCIDR, true}} {
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
			match := deref(s.CidrBlock) == want.cidr && private == want.private
			if match && want.private {
				privateSubnet = deref(s.Id)
			}
			items = append(items, item{fmt.Sprintf("%s %s %s", deref(s.DisplayName), deref(s.CidrBlock), access), s.FreeformTags, match})
		}
		report.Checks = append(report.Checks, check(want.kind, items, false))
	}
	internet, err := pages(func(page *string) ([]core.InternetGateway, *string, error) {
		r, err := network.ListInternetGateways(ctx, core.ListInternetGatewaysRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("internet gateway: %w", err)
	}
	report.Checks = append(report.Checks, check("internet gateway", collect(internet, func(g core.InternetGateway) (string, string, map[string]string) {
		return deref(g.DisplayName), string(g.LifecycleState), g.FreeformTags
	}), false))
	nat, err := pages(func(page *string) ([]core.NatGateway, *string, error) {
		r, err := network.ListNatGateways(ctx, core.ListNatGatewaysRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("nat gateway: %w", err)
	}
	report.Checks = append(report.Checks, check("nat gateway", collect(nat, func(g core.NatGateway) (string, string, map[string]string) {
		return deref(g.DisplayName) + " " + deref(g.NatIp), string(g.LifecycleState), g.FreeformTags
	}), false))
	service, err := pages(func(page *string) ([]core.ServiceGateway, *string, error) {
		r, err := network.ListServiceGateways(ctx, core.ListServiceGatewaysRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("service gateway: %w", err)
	}
	report.Checks = append(report.Checks, check("service gateway", collect(service, func(g core.ServiceGateway) (string, string, map[string]string) {
		return deref(g.DisplayName), string(g.LifecycleState), g.FreeformTags
	}), false))
	nsgs, err := pages(func(page *string) ([]core.NetworkSecurityGroup, *string, error) {
		r, err := network.ListNetworkSecurityGroups(ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("nsg: %w", err)
	}
	report.Checks = append(report.Checks, check("nsg", collect(nsgs, func(g core.NetworkSecurityGroup) (string, string, map[string]string) {
		return deref(g.DisplayName), string(g.LifecycleState), g.FreeformTags
	}), true))
	instances, err := pages(func(page *string) ([]core.Instance, *string, error) {
		r, err := compute.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("instance: %w", err)
	}
	attachments, err := pages(func(page *string) ([]core.VnicAttachment, *string, error) {
		r, err := compute.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("vnic attachment: %w", err)
	}
	subnetOf := map[string]string{}
	for _, a := range attachments {
		if a.LifecycleState == core.VnicAttachmentLifecycleStateAttached {
			subnetOf[deref(a.InstanceId)] = deref(a.SubnetId)
		}
	}
	report.Checks = append(report.Checks, nodes(region, instances, subnetOf, privateSubnet))
	nlbs, err := pages(func(page *string) ([]networkloadbalancer.NetworkLoadBalancerSummary, *string, error) {
		r, err := balancers.ListNetworkLoadBalancers(ctx, networkloadbalancer.ListNetworkLoadBalancersRequest{CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("nlb: %w", err)
	}
	report.Checks = append(report.Checks, check("nlb", collect(nlbs, func(b networkloadbalancer.NetworkLoadBalancerSummary) (string, string, map[string]string) {
		var public []string
		for _, ip := range b.IpAddresses {
			if ip.IsPublic != nil && *ip.IsPublic {
				public = append(public, deref(ip.IpAddress))
			}
		}
		return deref(b.DisplayName) + " " + strings.Join(public, ","), string(b.LifecycleState), b.FreeformTags
	}), false))
	reserved, err := pages(func(page *string) ([]core.PublicIp, *string, error) {
		r, err := network.ListPublicIps(ctx, core.ListPublicIpsRequest{Scope: core.ListPublicIpsScopeRegion, Lifetime: core.ListPublicIpsLifetimeReserved, CompartmentId: compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return report, fmt.Errorf("reserved address: %w", err)
	}
	report.Checks = append(report.Checks, check("reserved address", collect(reserved, func(ip core.PublicIp) (string, string, map[string]string) {
		return deref(ip.DisplayName) + " " + deref(ip.IpAddress), string(ip.LifecycleState), ip.FreeformTags
	}), false))
	return report, nil
}

func collect[T any](values []T, view func(T) (string, string, map[string]string)) []item {
	var items []item
	for _, v := range values {
		desc, state, tags := view(v)
		if !gone(state) {
			items = append(items, item{desc, tags, true})
		}
	}
	return items
}

func nodes(region Region, instances []core.Instance, subnetOf map[string]string, privateSubnet string) Check {
	want := region.Nodes
	var items []item
	for _, in := range instances {
		if gone(string(in.LifecycleState)) {
			continue
		}
		var ocpus, memory float32
		if in.ShapeConfig != nil && in.ShapeConfig.Ocpus != nil && in.ShapeConfig.MemoryInGBs != nil {
			ocpus, memory = *in.ShapeConfig.Ocpus, *in.ShapeConfig.MemoryInGBs
		}
		subnet := "private subnet"
		if subnetOf[deref(in.Id)] != privateSubnet || privateSubnet == "" {
			subnet = "not in private subnet"
		}
		match := deref(in.Shape) == want.Shape && ocpus == want.OCPUs && memory == want.MemoryGB && subnet == "private subnet"
		items = append(items, item{fmt.Sprintf("%s %s %g/%g %s %s", deref(in.DisplayName), deref(in.Shape), ocpus, memory, strings.ToLower(string(in.LifecycleState)), subnet), in.FreeformTags, match})
	}
	result := check("instances", items, true)
	count := fmt.Sprint(want.Min)
	if want.Max != want.Min {
		count = fmt.Sprintf("%d-%d", want.Min, want.Max)
	}
	result.Details = append([]string{fmt.Sprintf("%d found, document wants %s x %s %g/%g in private subnet", len(items), count, want.Shape, want.OCPUs, want.MemoryGB)}, result.Details...)
	if len(items) < want.Min || len(items) > want.Max {
		result.State = Differs
	}
	return result
}

func observeDNS(ctx context.Context, fleet Fleet) (Report, error) {
	report := Report{Name: "dns", Scope: fleet.DNS.Zone}
	f, err := factory(ctx, fleet.Regions[0].OCIRegion)
	if err != nil {
		return report, err
	}
	search, err := f.Search()
	if err != nil {
		return report, err
	}
	find := func(query string) ([]resourcesearch.ResourceSummary, error) {
		return pages(func(page *string) ([]resourcesearch.ResourceSummary, *string, error) {
			r, err := search.SearchResources(ctx, resourcesearch.SearchResourcesRequest{SearchDetails: resourcesearch.StructuredSearchDetails{Query: common.String(query)}, Page: page})
			return r.Items, r.OpcNextPage, err
		})
	}
	view := func(r resourcesearch.ResourceSummary) (string, string, map[string]string) {
		return deref(r.DisplayName), deref(r.LifecycleState), r.FreeformTags
	}
	zones, err := find(fmt.Sprintf("query CustomerDnsZone resources where displayName = '%s'", fleet.DNS.Zone))
	if err != nil {
		return report, fmt.Errorf("zone: %w", err)
	}
	report.Checks = append(report.Checks, check("zone", collect(zones, view), false))
	policies, err := find("query DnsPolicy resources")
	if err != nil {
		return report, fmt.Errorf("steering policy: %w", err)
	}
	live := collect(policies, view)
	steering := check("steering policy", live, true)
	steering.Details = append([]string{fmt.Sprintf("%d policies for %d steered names, ttl %ds, check https %s", len(live), len(fleet.DNS.SteeredNames), fleet.DNS.SteeringTTLSeconds, fleet.DNS.HealthCheckPath)}, steering.Details...)
	if steering.State != Missing && len(live) != len(fleet.DNS.SteeredNames) {
		steering.State = Differs
	}
	report.Checks = append(report.Checks, steering)
	return report, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
