package fleet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/routetable"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var (
	edgePorts = []int{80, 443, 5432}
	meshPorts = []nsg.Rule{
		{Protocol: nsg.ProtocolTCP, PortMin: 4222, PortMax: 4222, Description: "nats client"},
		{Protocol: nsg.ProtocolTCP, PortMin: 6222, PortMax: 6222, Description: "nats cluster"},
		{Protocol: nsg.ProtocolTCP, PortMin: 7422, PortMax: 7422, Description: "nats leafnode"},
		{Protocol: nsg.ProtocolUDP, PortMin: 51820, PortMax: 51820, Description: "netbird wireguard"},
	}
)

type found struct {
	id, name, vcn, state string
	tags                 map[string]string
}

type network struct {
	client      core.VirtualNetworkClient
	routes      routetable.API
	rules       nsg.API
	region      Region
	out         ociresource.Out
	cell        string
	compartment *string
	vcn         *string
	ownership   ociresource.Ownership
}

func applyNetwork(ctx context.Context, _ Fleet, region Region, f *ociclient.Factory, out ociresource.Out) error {
	client, err := f.Network()
	if err != nil {
		return err
	}
	routes, err := routetable.NewSDKAPI(f)
	if err != nil {
		return err
	}
	rules, err := nsg.NewSDKAPI(f)
	if err != nil {
		return err
	}
	entry, _ := catalog.LookupName(region.Label)
	cell, err := naming.RegionCell(entry.Cell).Name()
	if err != nil {
		return err
	}
	n := &network{client: client, routes: routes, rules: rules, region: region, out: out, cell: cell, compartment: common.String(region.CompartmentID),
		ownership: ociresource.Ownership{Owner: Owner}}
	vcns, err := list("vcn", func(page *string) ([]core.Vcn, *string, error) {
		r, err := client.ListVcns(ctx, core.ListVcnsRequest{CompartmentId: n.compartment, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	vcn, err := n.adopt("vcn", "vcn", collectFound(vcns, func(v core.Vcn) found {
		return found{deref(v.Id), deref(v.DisplayName), deref(v.Id), string(v.LifecycleState), v.FreeformTags}
	}))
	if err != nil {
		return err
	}
	i := slices.IndexFunc(vcns, func(v core.Vcn) bool { return deref(v.Id) == vcn.id })
	if !slices.Equal(vcns[i].CidrBlocks, []string{region.VCNCIDR}) {
		return fmt.Errorf("vcn %s has %v, the document wants %s", vcn.name, vcns[i].CidrBlocks, region.VCNCIDR)
	}
	n.vcn = common.String(vcn.id)
	subnets, err := list("subnet", func(page *string) ([]core.Subnet, *string, error) {
		r, err := client.ListSubnets(ctx, core.ListSubnetsRequest{CompartmentId: n.compartment, VcnId: n.vcn, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	subnetFound := func(s core.Subnet) found {
		return found{deref(s.Id), deref(s.DisplayName) + " " + deref(s.CidrBlock), deref(s.VcnId), string(s.LifecycleState), s.FreeformTags}
	}
	for _, want := range []struct {
		name, cidr string
		private    bool
	}{{"host-subnet", region.PublicSubnetCIDR, false}, {"private-subnet", region.PrivateSubnetCIDR, true}} {
		subnet, err := n.adopt("subnet", want.name, collectFound(subnets, subnetFound))
		if err != nil {
			return err
		}
		s := subnets[slices.IndexFunc(subnets, func(s core.Subnet) bool { return deref(s.Id) == subnet.id })]
		if deref(s.CidrBlock) != want.cidr || (s.ProhibitPublicIpOnVnic != nil && *s.ProhibitPublicIpOnVnic) != want.private {
			return fmt.Errorf("subnet %s is not the document's %s (private %t)", subnet.name, want.cidr, want.private)
		}
	}
	internet, err := list("internet gateway", func(page *string) ([]core.InternetGateway, *string, error) {
		r, err := client.ListInternetGateways(ctx, core.ListInternetGatewaysRequest{CompartmentId: n.compartment, VcnId: n.vcn, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	if _, err := n.adopt("internet-gateway", "igw", collectFound(internet, func(g core.InternetGateway) found {
		return found{deref(g.Id), deref(g.DisplayName), deref(g.VcnId), string(g.LifecycleState), g.FreeformTags}
	})); err != nil {
		return err
	}
	services, err := list("service gateway", func(page *string) ([]core.ServiceGateway, *string, error) {
		r, err := client.ListServiceGateways(ctx, core.ListServiceGatewaysRequest{CompartmentId: n.compartment, VcnId: n.vcn, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	sgw, err := n.adopt("service-gateway", "sgw", collectFound(services, func(g core.ServiceGateway) found {
		return found{deref(g.Id), deref(g.DisplayName), deref(g.VcnId), string(g.LifecycleState), g.FreeformTags}
	}))
	if err != nil {
		return err
	}
	servicesCIDR, err := n.servicesCIDR(ctx, services[slices.IndexFunc(services, func(g core.ServiceGateway) bool { return deref(g.Id) == sgw.id })])
	if err != nil {
		return err
	}
	groups, err := list("nsg", func(page *string) ([]core.NetworkSecurityGroup, *string, error) {
		r, err := client.ListNetworkSecurityGroups(ctx, core.ListNetworkSecurityGroupsRequest{CompartmentId: n.compartment, VcnId: n.vcn, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	groupFound := collectFound(groups, func(g core.NetworkSecurityGroup) found {
		return found{deref(g.Id), deref(g.DisplayName), deref(g.VcnId), string(g.LifecycleState), g.FreeformTags}
	})
	for _, name := range []string{"edge-nsg", "host-nsg"} {
		if _, err := n.adopt("nsg", name, groupFound); err != nil {
			return err
		}
	}
	if err := n.nodeNSG(ctx, groupFound); err != nil {
		return err
	}
	nat, err := n.natGateway(ctx)
	if err != nil || nat == "" {
		return err
	}
	return n.privateRoutes(ctx, vcns[i], subnets, nat, sgw.id, servicesCIDR)
}

func collectFound[T any](values []T, view func(T) found) []found {
	var out []found
	for _, v := range values {
		if f := view(v); !gone(f.state) {
			out = append(out, f)
		}
	}
	return out
}

func (n *network) owned(kind, name string, items []found) (*found, error) {
	key := n.region.Key(kind, name)
	var mine []found
	for _, it := range items {
		if n.ownership.Owns(key, ociresource.Tags{Freeform: it.tags}) {
			mine = append(mine, it)
		}
	}
	switch len(mine) {
	case 0:
		return nil, nil
	case 1:
		return &mine[0], nil
	}
	return nil, fmt.Errorf("%d live resources carry %s; remove the extra one by hand", len(mine), key)
}

func (n *network) adopt(kind, name string, items []found) (found, error) {
	it, err := n.owned(kind, name, items)
	if err != nil {
		return found{}, err
	}
	if it == nil {
		return found{}, fmt.Errorf("no document-made %s %s in %s; ts-orch region plan shows what is there", kind, name, n.region.Label)
	}
	return *it, n.print("ok", strings.ReplaceAll(kind, "-", " "), it.name)
}

func (n *network) print(verb, kind, detail string) error {
	w := n.out.Changed
	if verb == "ok" {
		w = n.out.Same
	}
	_, err := fmt.Fprintf(w, "  %-8s %-17s %s\n", verb, kind, detail)
	return err
}

func (n *network) stamp(key ociresource.Key, spec any) (map[string]string, string, error) {
	desired, err := ociresource.NewDesired(key, 1, ociresource.PolicyEnforce, spec)
	if err != nil {
		return nil, "", err
	}
	return n.ownership.Stamp(key, 1, desired.SpecDigest).Freeform, desired.SpecDigest, nil
}

func untilAvailable[R any](state func(R) string) common.RequestMetadata {
	policy := common.NewRetryPolicyWithOptions(common.WithMaximumNumberAttempts(60), common.WithFixedBackoff(2*time.Second),
		common.WithShouldRetryOperation(func(r common.OCIOperationResponse) bool {
			response, ok := r.Response.(R)
			return r.Error == nil && ok && state(response) != "AVAILABLE"
		}))
	return common.RequestMetadata{RetryPolicy: &policy}
}

func available(kind, name, state string, err error) error {
	if err != nil {
		return fmt.Errorf("wait for %s %s: %w", kind, name, err)
	}
	if state != "AVAILABLE" {
		return fmt.Errorf("%s %s is %s, not AVAILABLE", kind, name, state)
	}
	return nil
}

func (n *network) servicesCIDR(ctx context.Context, sgw core.ServiceGateway) (string, error) {
	all, err := list("service", func(page *string) ([]core.Service, *string, error) {
		r, err := n.client.ListServices(ctx, core.ListServicesRequest{Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return "", err
	}
	if len(sgw.Services) != 1 {
		return "", fmt.Errorf("service gateway %s serves %d services, want the one all-services entry", deref(sgw.DisplayName), len(sgw.Services))
	}
	i := slices.IndexFunc(all, func(s core.Service) bool { return deref(s.Id) == deref(sgw.Services[0].ServiceId) })
	if i < 0 || !strings.HasPrefix(deref(all[i].CidrBlock), "all-") {
		return "", fmt.Errorf("service gateway %s does not serve all of the region's Oracle services", deref(sgw.DisplayName))
	}
	return deref(all[i].CidrBlock), nil
}

func (n *network) natGateway(ctx context.Context) (string, error) {
	gateways, err := list("nat gateway", func(page *string) ([]core.NatGateway, *string, error) {
		r, err := n.client.ListNatGateways(ctx, core.ListNatGatewaysRequest{CompartmentId: n.compartment, VcnId: n.vcn, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return "", err
	}
	items := collectFound(gateways, func(g core.NatGateway) found {
		return found{deref(g.Id), deref(g.DisplayName), deref(g.VcnId), string(g.LifecycleState), g.FreeformTags}
	})
	gateway, err := n.owned("nat-gateway", "nat", items)
	if err != nil {
		return "", err
	}
	if gateway != nil {
		g := gateways[slices.IndexFunc(gateways, func(g core.NatGateway) bool { return deref(g.Id) == gateway.id })]
		if g.BlockTraffic != nil && *g.BlockTraffic {
			return "", fmt.Errorf("nat gateway %s blocks traffic; someone blocked it by hand", gateway.name)
		}
		if err := available("nat gateway", gateway.name, gateway.state, nil); err != nil {
			return "", err
		}
		return gateway.id, n.print("ok", "nat gateway", gateway.name)
	}
	if len(items) > 0 {
		return "", fmt.Errorf("nat gateway %s in the VCN is not document-made; refusing to add a second", items[0].name)
	}
	key := n.region.Key("nat-gateway", "nat")
	name := n.cell + "-nat"
	if err := n.print("create", "nat gateway", name); err != nil || !n.out.Apply {
		return "", err
	}
	tags, _, err := n.stamp(key, map[string]string{"vcn": deref(n.vcn), "name": name})
	if err != nil {
		return "", err
	}
	created, err := n.client.CreateNatGateway(ctx, core.CreateNatGatewayRequest{CreateNatGatewayDetails: core.CreateNatGatewayDetails{CompartmentId: n.compartment, VcnId: n.vcn, DisplayName: common.String(name),
		BlockTraffic: common.Bool(false), FreeformTags: tags}})
	if err != nil {
		return "", fmt.Errorf("create nat gateway %s: %w", name, err)
	}
	got, err := n.client.GetNatGateway(ctx, core.GetNatGatewayRequest{NatGatewayId: created.Id,
		RequestMetadata: untilAvailable(func(r core.GetNatGatewayResponse) string { return string(r.LifecycleState) })})
	return "", available("nat gateway", name, string(got.LifecycleState), err)
}

func (n *network) privateRoutes(ctx context.Context, vcn core.Vcn, subnets []core.Subnet, nat, sgw, servicesCIDR string) error {
	tables, err := list("route table", func(page *string) ([]core.RouteTable, *string, error) {
		r, err := n.client.ListRouteTables(ctx, core.ListRouteTablesRequest{CompartmentId: n.compartment, VcnId: n.vcn, Page: page})
		return r.Items, r.OpcNextPage, err
	})
	if err != nil {
		return err
	}
	key := n.region.Key("route-table", "private-routes")
	name := n.cell + "-private-routes"
	table, err := n.owned(key.Kind, key.Name, collectFound(tables, func(t core.RouteTable) found {
		return found{deref(t.Id), deref(t.DisplayName), deref(t.VcnId), string(t.LifecycleState), t.FreeformTags}
	}))
	if err != nil {
		return err
	}
	spec := routetable.Spec{Routes: []routetable.Route{
		{Destination: "0.0.0.0/0", NetworkEntityID: nat, Description: "internet through the nat gateway"},
		{Destination: servicesCIDR, DestinationType: routetable.DestinationService, NetworkEntityID: sgw, Description: "oracle services"},
	}}
	if table == nil {
		if err := n.print("create", "route table", name); err != nil || !n.out.Apply {
			return err
		}
		tags, _, err := n.stamp(key, map[string]string{"vcn": deref(n.vcn), "name": name})
		if err != nil {
			return err
		}
		created, err := n.client.CreateRouteTable(ctx, core.CreateRouteTableRequest{CreateRouteTableDetails: core.CreateRouteTableDetails{CompartmentId: n.compartment, VcnId: n.vcn, DisplayName: common.String(name),
			RouteRules: []core.RouteRule{}, FreeformTags: tags}})
		if err != nil {
			return fmt.Errorf("create route table %s: %w", name, err)
		}
		got, err := n.client.GetRouteTable(ctx, core.GetRouteTableRequest{RtId: created.Id,
			RequestMetadata: untilAvailable(func(r core.GetRouteTableResponse) string { return string(r.LifecycleState) })})
		return available("route table", name, string(got.LifecycleState), err)
	}
	if table.id == deref(vcn.DefaultRouteTableId) {
		return fmt.Errorf("route table %s is the VCN's default table; refusing to route the private subnet through it", table.name)
	}
	var private core.Subnet
	for _, s := range subnets {
		if gone(string(s.LifecycleState)) {
			continue
		}
		if n.ownership.Owns(n.region.Key("subnet", "private-subnet"), ociresource.Tags{Freeform: s.FreeformTags}) {
			private = s
		} else if deref(s.RouteTableId) == table.id {
			return fmt.Errorf("route table %s is also used by subnet %s; refusing to change it", table.name, deref(s.DisplayName))
		}
	}
	spec.RouteTableID = table.id
	if err := converge(ctx, n, "route table", table.name, routetable.Reconciler{API: n.routes}, key, spec); err != nil {
		return err
	}
	if deref(private.RouteTableId) == table.id {
		return n.print("ok", "subnet", deref(private.DisplayName)+" routes through "+table.name)
	}
	if err := n.print("update", "subnet", deref(private.DisplayName)+" routes through "+table.name); err != nil || !n.out.Apply {
		return err
	}
	current, err := n.client.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: private.Id})
	if err != nil {
		return err
	}
	if _, err := n.client.UpdateSubnet(ctx, core.UpdateSubnetRequest{SubnetId: private.Id, IfMatch: current.Etag,
		UpdateSubnetDetails: core.UpdateSubnetDetails{RouteTableId: common.String(table.id)}}); err != nil {
		return fmt.Errorf("attach route table %s to subnet %s: %w", table.name, deref(private.DisplayName), err)
	}
	return nil
}

func (n *network) nodeNSG(ctx context.Context, groups []found) error {
	key := n.region.Key("nsg", "node-nsg")
	name := n.cell + "-node-nsg"
	group, err := n.owned(key.Kind, key.Name, groups)
	if err != nil {
		return err
	}
	if group == nil {
		if err := n.print("create", "nsg", name); err != nil || !n.out.Apply {
			return err
		}
		tags, _, err := n.stamp(key, map[string]string{"vcn": deref(n.vcn), "name": name})
		if err != nil {
			return err
		}
		created, err := n.client.CreateNetworkSecurityGroup(ctx, core.CreateNetworkSecurityGroupRequest{CreateNetworkSecurityGroupDetails: core.CreateNetworkSecurityGroupDetails{CompartmentId: n.compartment, VcnId: n.vcn,
			DisplayName: common.String(name), FreeformTags: tags}})
		if err != nil {
			return fmt.Errorf("create nsg %s: %w", name, err)
		}
		got, err := n.client.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: created.Id,
			RequestMetadata: untilAvailable(func(r core.GetNetworkSecurityGroupResponse) string { return string(r.LifecycleState) })})
		return available("nsg", name, string(got.LifecycleState), err)
	}
	return converge(ctx, n, "nsg", group.name, nsg.Reconciler{API: n.rules}, key, nsg.Spec{NSGID: group.id, Rules: nodeRules(n.region), Exclusive: true})
}

func converge[S, O any](ctx context.Context, n *network, kind, name string, resource ociresource.Resource[S, O], key ociresource.Key, spec S) error {
	desired, err := ociresource.NewDesired(key, 1, ociresource.PolicyEnforce, spec)
	if err != nil {
		return err
	}
	target := ociresource.Target[S]{Key: key, Generation: 1, SpecDigest: desired.SpecDigest, Ownership: n.ownership, Spec: spec,
		Guard: func(ctx context.Context) error { return ctx.Err() }}
	observed, ok, err := resource.Observe(ctx, target)
	if errors.Is(err, ociresource.ErrForeign) {
		return fmt.Errorf("%s %s is not document-made under %s: %w", kind, name, key, err)
	}
	if err != nil {
		return err
	}
	plan := resource.Diff(target, observed, ok)
	if plan.Empty() {
		return n.print("ok", kind, name)
	}
	for _, change := range plan.Changes {
		if err := n.print(change.Op, kind, name+": "+change.Detail); err != nil {
			return err
		}
	}
	if !n.out.Apply {
		return nil
	}
	if err := resource.Apply(ctx, target, observed, ok, plan); err != nil {
		return fmt.Errorf("%s %s: %w", kind, name, err)
	}
	return nil
}

func nodeRules(region Region) []nsg.Rule {
	var rules []nsg.Rule
	for _, port := range edgePorts {
		rules = append(rules, nsg.Rule{Direction: nsg.DirectionIngress, Protocol: nsg.ProtocolTCP, Peer: "0.0.0.0/0",
			PortMin: port, PortMax: port, Description: fmt.Sprintf("client tcp %d through the load balancer", port)})
	}
	for _, rule := range meshPorts {
		rule.Direction, rule.Peer = nsg.DirectionIngress, region.VCNCIDR
		rules = append(rules, rule)
	}
	return append(rules, nsg.Rule{Direction: nsg.DirectionEgress, Protocol: nsg.ProtocolAll, Peer: "0.0.0.0/0", Description: "all egress"})
}
