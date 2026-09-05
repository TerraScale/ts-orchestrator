package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func testNetworkRegion() estate.Region {
	return estate.Region{
		Code:    "gru",
		OCIName: "sa-saopaulo-1",
		Network: estate.Network{
			CIDR: "10.0.0.0/16",
			Subnets: []estate.Subnet{
				{Name: "gru-members", CIDR: "10.0.1.0/24", RegionCode: "gru"},
			},
			SecurityGroups: []estate.NetworkSecurityGroup{
				{
					Name: "gru-members",
					Rules: []estate.NetworkSecurityRule{
						{Direction: "ingress", Protocol: "tcp", Peer: "0.0.0.0/0", PortMin: 443, PortMax: 443},
						{Direction: "ingress", Protocol: "udp", Peer: "10.0.0.0/16", PortMin: 6000, PortMax: 65535},
						{Direction: "egress", Protocol: "icmp", Peer: "0.0.0.0/0"},
					},
				},
			},
			RouteTables: []estate.RouteTable{{
				Name: "gru-members", Subnet: "gru-members",
				Routes: []estate.RouteRule{{Destination: "0.0.0.0/0", ViaNAT: true}},
			}},
		},
	}
}

// fakeNetworkGateway records mutations and serves a mutable observed network.
type fakeNetworkGateway struct {
	vcns        []ObservedVCN
	subnets     []ObservedSubnet
	nsgs        []ObservedNSG
	natGateways []ObservedNATGateway
	routeTables []ObservedRouteTable
	rules       map[string][]ObservedSecurityRule
	nextID      int
	createCalls []string
}

func (f *fakeNetworkGateway) ListVCNs(ctx context.Context, name string) ([]ObservedVCN, error) {
	var match []ObservedVCN
	for _, vcn := range f.vcns {
		if vcn.DisplayName == name {
			match = append(match, vcn)
		}
	}
	return match, nil
}

func (f *fakeNetworkGateway) CreateVCN(ctx context.Context, name, cidr string) (ObservedVCN, error) {
	f.nextID++
	created := ObservedVCN{ID: "ocid1.vcn.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), DisplayName: name, CIDR: cidr, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "vcn")}
	f.vcns = append(f.vcns, created)
	f.createCalls = append(f.createCalls, "vcn:"+name)
	return created, nil
}

func (f *fakeNetworkGateway) ListSubnets(ctx context.Context, vcnID string) ([]ObservedSubnet, error) {
	var match []ObservedSubnet
	for _, subnet := range f.subnets {
		if subnet.VCNID == vcnID {
			match = append(match, subnet)
		}
	}
	return match, nil
}

func (f *fakeNetworkGateway) CreateSubnet(ctx context.Context, vcnID, name, cidr string) (ObservedSubnet, error) {
	f.nextID++
	created := ObservedSubnet{ID: "ocid1.subnet.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), VCNID: vcnID, DisplayName: name, CIDR: cidr, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "subnet")}
	f.subnets = append(f.subnets, created)
	f.createCalls = append(f.createCalls, "subnet:"+name)
	return created, nil
}

func (f *fakeNetworkGateway) ListNSGs(ctx context.Context, vcnID string) ([]ObservedNSG, error) {
	var match []ObservedNSG
	for _, group := range f.nsgs {
		if group.VCNID == vcnID {
			match = append(match, group)
		}
	}
	return match, nil
}

func (f *fakeNetworkGateway) CreateNSG(ctx context.Context, vcnID, name string) (ObservedNSG, error) {
	f.nextID++
	created := ObservedNSG{ID: "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), VCNID: vcnID, DisplayName: name, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "networksecuritygroup")}
	f.nsgs = append(f.nsgs, created)
	f.createCalls = append(f.createCalls, "nsg:"+name)
	return created, nil
}

func (f *fakeNetworkGateway) ListNSGRules(ctx context.Context, nsgID string) ([]ObservedSecurityRule, error) {
	return f.rules[nsgID], nil
}

func (f *fakeNetworkGateway) AddNSGRules(ctx context.Context, nsgID string, rules []SecurityRuleSpec) error {
	for _, spec := range rules {
		f.nextID++
		rule := ObservedSecurityRule{ID: "ocid1.securityrule.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), Direction: ingressDirection(spec.Direction), Protocol: securityProtocolNumbers[spec.Protocol], Peer: spec.Peer, PortMin: spec.PortMin, PortMax: spec.PortMax, Managed: true}
		f.rules[nsgID] = append(f.rules[nsgID], rule)
	}
	f.createCalls = append(f.createCalls, "rules-add:"+nsgID)
	return nil
}

func (f *fakeNetworkGateway) RemoveNSGRules(ctx context.Context, nsgID string, ruleIDs []string) error {
	remaining := f.rules[nsgID][:0]
	for _, rule := range f.rules[nsgID] {
		removed := false
		for _, id := range ruleIDs {
			if rule.ID == id {
				removed = true
				break
			}
		}
		if !removed {
			remaining = append(remaining, rule)
		}
	}
	f.rules[nsgID] = remaining
	f.createCalls = append(f.createCalls, "rules-remove:"+nsgID)
	return nil
}

func (f *fakeNetworkGateway) ListNATGateways(ctx context.Context, vcnID string) ([]ObservedNATGateway, error) {
	var match []ObservedNATGateway
	for _, gateway := range f.natGateways {
		if gateway.VCNID == vcnID {
			match = append(match, gateway)
		}
	}
	return match, nil
}

func (f *fakeNetworkGateway) CreateNATGateway(ctx context.Context, vcnID, name string) (ObservedNATGateway, error) {
	f.nextID++
	created := ObservedNATGateway{ID: "ocid1.natgateway.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), VCNID: vcnID, DisplayName: name, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "natgateway")}
	f.natGateways = append(f.natGateways, created)
	f.createCalls = append(f.createCalls, "nat:"+name)
	return created, nil
}

func (f *fakeNetworkGateway) ListRouteTables(ctx context.Context, vcnID string) ([]ObservedRouteTable, error) {
	var match []ObservedRouteTable
	for _, table := range f.routeTables {
		if table.VCNID == vcnID {
			match = append(match, table)
		}
	}
	return match, nil
}

func (f *fakeNetworkGateway) CreateRouteTable(ctx context.Context, vcnID, name string, rules []RouteRuleSpec) (ObservedRouteTable, error) {
	f.nextID++
	created := ObservedRouteTable{ID: "ocid1.routetable.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), VCNID: vcnID, DisplayName: name, LifecycleState: "AVAILABLE", Routes: observedRouteRules(rules), FreeformTags: networkOwnershipTags("gru", "routetable")}
	f.routeTables = append(f.routeTables, created)
	f.createCalls = append(f.createCalls, "route-table:"+name)
	return created, nil
}

func (f *fakeNetworkGateway) ReplaceRouteRules(ctx context.Context, routeTableID string, rules []RouteRuleSpec) error {
	for i := range f.routeTables {
		if f.routeTables[i].ID != routeTableID {
			continue
		}
		f.routeTables[i].Routes = observedRouteRules(rules)
		f.createCalls = append(f.createCalls, "route-rules:"+routeTableID)
	}
	return nil
}

func (f *fakeNetworkGateway) AttachSubnetRouteTable(ctx context.Context, subnetID, routeTableID string) error {
	for i := range f.subnets {
		if f.subnets[i].ID == subnetID {
			f.subnets[i].RouteTableID = routeTableID
			f.createCalls = append(f.createCalls, "subnet-route:"+subnetID)
		}
	}
	return nil
}

func observedRouteRules(rules []RouteRuleSpec) []ObservedRouteRule {
	observed := make([]ObservedRouteRule, 0, len(rules))
	for _, spec := range rules {
		observed = append(observed, ObservedRouteRule{Destination: spec.Destination, TargetID: spec.NATGatewayID, TargetType: "natgateway"})
	}
	return observed
}

func testOwnedRule(id, direction, protocol, peer string, portMin, portMax uint16) ObservedSecurityRule {
	return ObservedSecurityRule{ID: id, Direction: direction, Protocol: protocol, Peer: peer, PortMin: portMin, PortMax: portMax, Managed: true}
}

func TestNetworkReconcilePlans(t *testing.T) {
	declared := testNetworkRegion()
	vcn := ObservedVCN{ID: "ocid1.vcn.oc1.x", DisplayName: "terrascale-gru", CIDR: "10.0.0.0/16", LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "vcn")}
	nat := ObservedNATGateway{ID: "ocid1.natgateway.oc1.x", VCNID: vcn.ID, DisplayName: NATGatewayName("gru"), LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "natgateway")}
	routes := []ObservedRouteRule{{Destination: "0.0.0.0/0", TargetID: nat.ID, TargetType: "natgateway"}}
	table := ObservedRouteTable{ID: "ocid1.routetable.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", LifecycleState: "AVAILABLE", Routes: routes, FreeformTags: networkOwnershipTags("gru", "routetable")}
	subnet := ObservedSubnet{ID: "ocid1.subnet.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE", RouteTableID: table.ID, FreeformTags: networkOwnershipTags("gru", "subnet")}
	nsg := ObservedNSG{ID: "ocid1.networksecuritygroup.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "networksecuritygroup")}
	cases := []struct {
		name      string
		observed  NetworkObserved
		wantKinds []OCIActionKind
		wantErr   bool
	}{
		{
			name:      "empty tenancy starts with only the vcn",
			observed:  NetworkObserved{Rules: map[string][]ObservedSecurityRule{}},
			wantKinds: []OCIActionKind{OCIActionCreateVCN},
		},
		{
			name: "converged network plans nothing",
			observed: NetworkObserved{
				VCN:         &vcn,
				Subnets:     []ObservedSubnet{subnet},
				NSGs:        []ObservedNSG{nsg},
				NATGateways: []ObservedNATGateway{nat},
				RouteTables: []ObservedRouteTable{table},
				Rules: map[string][]ObservedSecurityRule{
					nsg.DisplayName: {
						testOwnedRule("ocid1.securityrule.oc1.x.1", "INGRESS", "6", "0.0.0.0/0", 443, 443),
						testOwnedRule("ocid1.securityrule.oc1.x.2", "INGRESS", "17", "10.0.0.0/16", 6000, 65535),
						testOwnedRule("ocid1.securityrule.oc1.x.3", "EGRESS", "1", "0.0.0.0/0", 0, 0),
					},
				},
			},
			wantKinds: []OCIActionKind{},
		},
		{
			name: "missing subnet and drifted rules plan repair plus the nat gateway",
			observed: NetworkObserved{
				VCN:  &vcn,
				NSGs: []ObservedNSG{nsg},
				Rules: map[string][]ObservedSecurityRule{
					nsg.DisplayName: {
						testOwnedRule("ocid1.securityrule.oc1.x.9", "INGRESS", "6", "0.0.0.0/0", 22, 22),
					},
				},
			},
			wantKinds: []OCIActionKind{OCIActionCreateSubnet, OCIActionReplaceNSGRules, OCIActionCreateNATGateway},
		},
		{
			name: "missing route table plans its create once the nat gateway is live",
			observed: NetworkObserved{
				VCN:         &vcn,
				Subnets:     []ObservedSubnet{subnet},
				NSGs:        []ObservedNSG{nsg},
				NATGateways: []ObservedNATGateway{nat},
				Rules: map[string][]ObservedSecurityRule{
					nsg.DisplayName: {
						testOwnedRule("ocid1.securityrule.oc1.x.1", "INGRESS", "6", "0.0.0.0/0", 443, 443),
						testOwnedRule("ocid1.securityrule.oc1.x.2", "INGRESS", "17", "10.0.0.0/16", 6000, 65535),
						testOwnedRule("ocid1.securityrule.oc1.x.3", "EGRESS", "1", "0.0.0.0/0", 0, 0),
					},
				},
			},
			wantKinds: []OCIActionKind{OCIActionCreateRouteTable},
		},
		{
			name: "provisioning nat gateway defers route planning",
			observed: NetworkObserved{
				VCN:         &vcn,
				Subnets:     []ObservedSubnet{subnet},
				NSGs:        []ObservedNSG{nsg},
				NATGateways: []ObservedNATGateway{{ID: "ocid1.natgateway.oc1.x", VCNID: vcn.ID, DisplayName: NATGatewayName("gru"), LifecycleState: "PROVISIONING", FreeformTags: networkOwnershipTags("gru", "natgateway")}},
				Rules: map[string][]ObservedSecurityRule{
					nsg.DisplayName: {
						testOwnedRule("ocid1.securityrule.oc1.x.1", "INGRESS", "6", "0.0.0.0/0", 443, 443),
						testOwnedRule("ocid1.securityrule.oc1.x.2", "INGRESS", "17", "10.0.0.0/16", 6000, 65535),
						testOwnedRule("ocid1.securityrule.oc1.x.3", "EGRESS", "1", "0.0.0.0/0", 0, 0),
					},
				},
			},
			wantKinds: []OCIActionKind{},
		},
		{
			name: "drifted routes and subnet attachment plan repair",
			observed: NetworkObserved{
				VCN:         &vcn,
				Subnets:     []ObservedSubnet{{ID: subnet.ID, VCNID: vcn.ID, DisplayName: subnet.DisplayName, CIDR: subnet.CIDR, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "subnet")}},
				NSGs:        []ObservedNSG{nsg},
				NATGateways: []ObservedNATGateway{nat},
				RouteTables: []ObservedRouteTable{{ID: table.ID, VCNID: vcn.ID, DisplayName: table.DisplayName, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "routetable"), Routes: []ObservedRouteRule{
					{Destination: "0.0.0.0/0", TargetID: "ocid1.natgateway.oc1.foreign", TargetType: "natgateway"},
					{Destination: "10.9.0.0/16", TargetID: nat.ID, TargetType: "natgateway"},
				}}},
				Rules: map[string][]ObservedSecurityRule{
					nsg.DisplayName: {
						testOwnedRule("ocid1.securityrule.oc1.x.1", "INGRESS", "6", "0.0.0.0/0", 443, 443),
						testOwnedRule("ocid1.securityrule.oc1.x.2", "INGRESS", "17", "10.0.0.0/16", 6000, 65535),
						testOwnedRule("ocid1.securityrule.oc1.x.3", "EGRESS", "1", "0.0.0.0/0", 0, 0),
					},
				},
			},
			wantKinds: []OCIActionKind{OCIActionReplaceRouteRules, OCIActionAttachSubnetRoute},
		},
		{
			name: "vcn cidr drift is refused",
			observed: NetworkObserved{
				VCN:   &ObservedVCN{ID: "ocid1.vcn.oc1.x", DisplayName: "terrascale-gru", CIDR: "172.16.0.0/16", LifecycleState: "AVAILABLE"},
				Rules: map[string][]ObservedSecurityRule{},
			},
			wantErr: true,
		},
		{
			name: "duplicate nat gateway identity is refused",
			observed: NetworkObserved{
				VCN:         &vcn,
				Subnets:     []ObservedSubnet{subnet},
				NSGs:        []ObservedNSG{nsg},
				NATGateways: []ObservedNATGateway{nat, {ID: "ocid1.natgateway.oc1.x.2", VCNID: vcn.ID, DisplayName: NATGatewayName("gru"), LifecycleState: "AVAILABLE"}},
				Rules:       map[string][]ObservedSecurityRule{},
			},
			wantErr: true,
		},
		{
			name: "duplicate route table identity is refused",
			observed: NetworkObserved{
				VCN:         &vcn,
				Subnets:     []ObservedSubnet{subnet},
				NSGs:        []ObservedNSG{nsg},
				NATGateways: []ObservedNATGateway{nat},
				RouteTables: []ObservedRouteTable{table, {ID: "ocid1.routetable.oc1.x.2", VCNID: vcn.ID, DisplayName: table.DisplayName, LifecycleState: "AVAILABLE"}},
				Rules:       map[string][]ObservedSecurityRule{},
			},
			wantErr: true,
		},
		{
			name: "failed route table is refused",
			observed: NetworkObserved{
				VCN:         &vcn,
				Subnets:     []ObservedSubnet{subnet},
				NSGs:        []ObservedNSG{nsg},
				NATGateways: []ObservedNATGateway{nat},
				RouteTables: []ObservedRouteTable{{ID: table.ID, VCNID: vcn.ID, DisplayName: table.DisplayName, LifecycleState: "FAILED"}},
				Rules:       map[string][]ObservedSecurityRule{},
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler := &NetworkReconciler{Gateway: &fakeNetworkGateway{}}
			plan, err := reconciler.Reconcile(context.Background(), declared, tc.observed)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Reconcile() = %+v, want drift error", plan)
				}
				return
			}
			if err != nil {
				t.Fatalf("Reconcile() failed: %v", err)
			}
			got := plan.Kinds()
			if len(got) != len(tc.wantKinds) {
				t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
			}
			for i := range got {
				if got[i] != tc.wantKinds[i] {
					t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
				}
			}
		})
	}
}

func TestNetworkReconcileRejectsDuplicateActiveNames(t *testing.T) {
	declared := testNetworkRegion()
	vcn := &ObservedVCN{ID: "ocid1.vcn.oc1.x", CIDR: declared.Network.CIDR, LifecycleState: "AVAILABLE"}
	for _, tc := range []struct {
		name     string
		observed NetworkObserved
	}{
		{name: "subnet", observed: NetworkObserved{VCN: vcn, Subnets: []ObservedSubnet{
			{ID: "ocid1.subnet.oc1.x.1", DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE"},
			{ID: "ocid1.subnet.oc1.x.2", DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE"},
		}, Rules: map[string][]ObservedSecurityRule{}}},
		{name: "network security group", observed: NetworkObserved{VCN: vcn, NSGs: []ObservedNSG{
			{ID: "ocid1.networksecuritygroup.oc1.x.1", DisplayName: "gru-members", LifecycleState: "AVAILABLE"},
			{ID: "ocid1.networksecuritygroup.oc1.x.2", DisplayName: "gru-members", LifecycleState: "AVAILABLE"},
		}, Rules: map[string][]ObservedSecurityRule{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (&NetworkReconciler{Gateway: &fakeNetworkGateway{}}).Reconcile(context.Background(), declared, tc.observed); err == nil {
				t.Fatal("duplicate active identity was accepted")
			}
		})
	}
}

func TestNetworkBootstrapConvergenceWaitsForPendingResources(t *testing.T) {
	declared := testNetworkRegion()
	vcn := &ObservedVCN{ID: "ocid1.vcn.oc1.x", DisplayName: VCNName("gru"), CIDR: declared.Network.CIDR, LifecycleState: "CREATING", FreeformTags: networkOwnershipTags("gru", "vcn")}
	reconciler := &NetworkReconciler{Gateway: &fakeNetworkGateway{}}
	converged, err := reconciler.bootstrapConverged(NetworkObserved{VCN: vcn}, declared)
	if err != nil || converged {
		t.Fatalf("pending VCN convergence = %v, %v; want false, nil", converged, err)
	}
	converged, err = reconciler.bootstrapConverged(NetworkObserved{
		VCN:     &ObservedVCN{ID: vcn.ID, DisplayName: VCNName("gru"), CIDR: declared.Network.CIDR, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "vcn")},
		Subnets: []ObservedSubnet{{ID: "ocid1.subnet.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "CREATING", FreeformTags: networkOwnershipTags("gru", "subnet")}},
	}, declared)
	if err != nil || converged {
		t.Fatalf("pending subnet convergence = %v, %v; want false, nil", converged, err)
	}
	_, err = reconciler.bootstrapConverged(NetworkObserved{
		VCN:     &ObservedVCN{ID: vcn.ID, DisplayName: VCNName("gru"), CIDR: declared.Network.CIDR, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "vcn")},
		Subnets: []ObservedSubnet{{ID: "ocid1.subnet.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "subnet")}},
		NSGs:    []ObservedNSG{{ID: "ocid1.networksecuritygroup.oc1.x", DisplayName: "gru-members", LifecycleState: "FAILED", FreeformTags: networkOwnershipTags("gru", "networksecuritygroup")}},
	}, declared)
	if err == nil {
		t.Fatal("failed NSG convergence was accepted")
	}
	natID := "ocid1.natgateway.oc1.x"
	ready := NetworkObserved{
		VCN:         &ObservedVCN{ID: vcn.ID, DisplayName: VCNName("gru"), CIDR: declared.Network.CIDR, LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "vcn")},
		Subnets:     []ObservedSubnet{{ID: "ocid1.subnet.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE", RouteTableID: "ocid1.routetable.oc1.x", FreeformTags: networkOwnershipTags("gru", "subnet")}},
		NSGs:        []ObservedNSG{{ID: "ocid1.networksecuritygroup.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "networksecuritygroup")}},
		NATGateways: []ObservedNATGateway{{ID: natID, VCNID: vcn.ID, DisplayName: NATGatewayName("gru"), LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "natgateway")}},
		RouteTables: []ObservedRouteTable{{ID: "ocid1.routetable.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "routetable"), Routes: []ObservedRouteRule{{Destination: "0.0.0.0/0", TargetID: natID, TargetType: "natgateway"}}}},
		Rules: map[string][]ObservedSecurityRule{"gru-members": {
			{ID: "ocid1.securityrule.oc1.x.1", Direction: "INGRESS", Protocol: "6", Peer: "0.0.0.0/0", PortMin: 443, PortMax: 443},
			{ID: "ocid1.securityrule.oc1.x.2", Direction: "INGRESS", Protocol: "17", Peer: "10.0.0.0/16", PortMin: 6000, PortMax: 65535},
			{ID: "ocid1.securityrule.oc1.x.3", Direction: "EGRESS", Protocol: "1", Peer: "0.0.0.0/0"},
		}},
	}
	converged, err = reconciler.bootstrapConverged(ready, declared)
	if err != nil || !converged {
		t.Fatalf("ready network convergence = %v, %v; want true, nil", converged, err)
	}
	unrouted := ready
	unrouted.Subnets = []ObservedSubnet{{ID: "ocid1.subnet.oc1.x", DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE"}}
	converged, err = reconciler.bootstrapConverged(unrouted, declared)
	if err != nil || converged {
		t.Fatalf("unattached subnet convergence = %v, %v; want false, nil", converged, err)
	}
	converged, err = reconciler.bootstrapConverged(NetworkObserved{
		VCN:         &ObservedVCN{ID: vcn.ID, CIDR: declared.Network.CIDR, LifecycleState: "AVAILABLE"},
		Subnets:     ready.Subnets,
		NSGs:        ready.NSGs,
		RouteTables: ready.RouteTables,
		Rules:       ready.Rules,
	}, declared)
	if err != nil || converged {
		t.Fatalf("missing NAT gateway convergence = %v, %v; want false, nil", converged, err)
	}
}

func TestNetworkApplyConvergesIdempotently(t *testing.T) {
	declared := testNetworkRegion()
	gateway := &fakeNetworkGateway{rules: map[string][]ObservedSecurityRule{}}
	reconciler := &NetworkReconciler{Gateway: gateway}
	ctx := context.Background()

	observed, err := reconciler.Observe(ctx, declared)
	if err != nil {
		t.Fatalf("initial observe failed: %v", err)
	}
	plan, err := reconciler.Reconcile(ctx, declared, observed)
	if err != nil || plan.Empty() {
		t.Fatalf("initial plan = %+v, %v, want full build", plan, err)
	}
	if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
		t.Fatalf("initial apply failed: %v", err)
	}

	// Converge: rules for a group created in the same apply plan their
	// addition on the next pass, so bootstrap runs until the plan is empty.
	for pass := 0; pass < 6; pass++ {
		observed, err = reconciler.Observe(ctx, declared)
		if err != nil {
			t.Fatalf("re-observe failed: %v", err)
		}
		plan, err = reconciler.Reconcile(ctx, declared, observed)
		if err != nil {
			t.Fatalf("re-reconcile failed: %v", err)
		}
		if plan.Empty() {
			// Final state check: subnet, all three rules, and the routed
			// subnet exist.
			if len(gateway.subnets) != 1 || len(gateway.nsgs) != 1 || len(gateway.natGateways) != 1 || len(gateway.routeTables) != 1 {
				t.Fatalf("apply state = %d subnets, %d nsgs, %d nat gateways, %d route tables", len(gateway.subnets), len(gateway.nsgs), len(gateway.natGateways), len(gateway.routeTables))
			}
			if rules := gateway.rules[gateway.nsgs[0].ID]; len(rules) != 3 {
				t.Fatalf("nsg rules = %d, want 3", len(rules))
			}
			table := gateway.routeTables[0]
			if len(table.Routes) != 1 || table.Routes[0].Destination != "0.0.0.0/0" || table.Routes[0].TargetID != gateway.natGateways[0].ID {
				t.Fatalf("route table = %+v, want the declared default route", table)
			}
			if gateway.subnets[0].RouteTableID != table.ID {
				t.Fatalf("subnet attachment = %q, want %q", gateway.subnets[0].RouteTableID, table.ID)
			}
			return
		}
		if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
			t.Fatalf("convergence apply failed: %v", err)
		}
	}
	t.Fatal("network did not converge in five passes")
}

func TestNetworkApplyDriftRepair(t *testing.T) {
	declared := testNetworkRegion()
	gateway := &fakeNetworkGateway{rules: map[string][]ObservedSecurityRule{}}
	reconciler := &NetworkReconciler{Gateway: gateway}
	ctx := context.Background()
	// Seed a live network with one drifted rule.
	if _, err := gateway.CreateVCN(ctx, "terrascale-gru", declared.Network.CIDR); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.CreateSubnet(ctx, gateway.vcns[0].ID, "gru-members", "10.0.1.0/24"); err != nil {
		t.Fatal(err)
	}
	group, err := gateway.CreateNSG(ctx, gateway.vcns[0].ID, "gru-members")
	if err != nil {
		t.Fatal(err)
	}
	drift := []SecurityRuleSpec{{Direction: "ingress", Protocol: "tcp", Peer: "0.0.0.0/0", PortMin: 22, PortMax: 22}}
	if err := gateway.AddNSGRules(ctx, group.ID, drift); err != nil {
		t.Fatal(err)
	}
	observed, err := reconciler.Observe(ctx, declared)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := reconciler.Reconcile(ctx, declared, observed)
	if err != nil {
		t.Fatal(err)
	}
	foundReplace := false
	for _, action := range plan.Actions {
		if replace, ok := action.(ReplaceNSGRulesAction); ok {
			foundReplace = true
			if len(replace.Add) != 3 || len(replace.RemoveIDs) != 1 {
				t.Fatalf("rule repair = +%d/-%d, want +3/-1", len(replace.Add), len(replace.RemoveIDs))
			}
		}
	}
	if !foundReplace {
		t.Fatalf("plan %v lacks rule repair", plan.Kinds())
	}
	if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
		t.Fatal(err)
	}
	if rules := gateway.rules[group.ID]; len(rules) != 3 {
		t.Fatalf("repaired rules = %d, want 3", len(rules))
	}
}

func TestNetworkApplyPreservesUnownedDriftRule(t *testing.T) {
	declared := testNetworkRegion()
	gateway := &fakeNetworkGateway{rules: map[string][]ObservedSecurityRule{}}
	reconciler := &NetworkReconciler{Gateway: gateway}
	ctx := context.Background()
	if _, err := gateway.CreateVCN(ctx, VCNName(declared.Code), declared.Network.CIDR); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.CreateNSG(ctx, gateway.vcns[0].ID, "gru-members"); err != nil {
		t.Fatal(err)
	}
	group := gateway.nsgs[0]
	gateway.rules[group.ID] = []ObservedSecurityRule{{
		ID: "ocid1.securityrule.oc1.sa-saopaulo-1.foreign", Direction: "INGRESS", Protocol: "6",
		Peer: "0.0.0.0/0", PortMin: 22, PortMax: 22,
	}}
	observed, err := reconciler.Observe(ctx, declared)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := reconciler.Reconcile(ctx, declared, observed)
	if err != nil {
		t.Fatal(err)
	}
	var replacement ReplaceNSGRulesAction
	found := false
	for _, action := range plan.Actions {
		if candidate, ok := action.(ReplaceNSGRulesAction); ok {
			replacement, found = candidate, true
		}
	}
	if !found || len(replacement.RemoveIDs) != 0 {
		t.Fatalf("unowned rule repair = %+v, want no removals", replacement)
	}
	if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
		t.Fatal(err)
	}
	for _, call := range gateway.createCalls {
		if len(call) >= len("rules-remove:") && call[:len("rules-remove:")] == "rules-remove:" {
			t.Fatalf("unowned rule was removed: calls = %v", gateway.createCalls)
		}
	}
	if got := len(gateway.rules[group.ID]); got != 4 {
		t.Fatalf("rules after preserving foreign rule = %d, want 4", got)
	}
}

func TestNetworkApplyRefusesStaleOwnedRuleObservation(t *testing.T) {
	declared := testNetworkRegion()
	gateway := &fakeNetworkGateway{rules: map[string][]ObservedSecurityRule{}}
	reconciler := &NetworkReconciler{Gateway: gateway}
	ctx := context.Background()
	if _, err := gateway.CreateVCN(ctx, VCNName(declared.Code), declared.Network.CIDR); err != nil {
		t.Fatal(err)
	}
	group, err := gateway.CreateNSG(ctx, gateway.vcns[0].ID, "gru-members")
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.AddNSGRules(ctx, group.ID, []SecurityRuleSpec{{Direction: "ingress", Protocol: "tcp", Peer: "0.0.0.0/0", PortMin: 22, PortMax: 22}}); err != nil {
		t.Fatal(err)
	}
	observed, err := reconciler.Observe(ctx, declared)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := reconciler.Reconcile(ctx, declared, observed)
	if err != nil {
		t.Fatal(err)
	}
	for i := range gateway.vcns {
		gateway.vcns[i].FreeformTags = nil
	}
	if err := reconciler.Apply(ctx, declared, observed, plan); err == nil {
		t.Fatal("stale VCN rule observation was accepted")
	}
	for _, call := range gateway.createCalls {
		if len(call) >= len("rules-remove:") && call[:len("rules-remove:")] == "rules-remove:" {
			t.Fatalf("stale rule was removed: calls = %v", gateway.createCalls)
		}
	}
}

func TestNetworkApplyRouteDriftRepair(t *testing.T) {
	declared := testNetworkRegion()
	gateway := &fakeNetworkGateway{rules: map[string][]ObservedSecurityRule{}}
	reconciler := &NetworkReconciler{Gateway: gateway}
	ctx := context.Background()
	if _, err := gateway.CreateVCN(ctx, "terrascale-gru", declared.Network.CIDR); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.CreateSubnet(ctx, gateway.vcns[0].ID, "gru-members", "10.0.1.0/24"); err != nil {
		t.Fatal(err)
	}
	nat, err := gateway.CreateNATGateway(ctx, gateway.vcns[0].ID, NATGatewayName("gru"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.CreateRouteTable(ctx, gateway.vcns[0].ID, "gru-members", []RouteRuleSpec{
		{Destination: "10.9.0.0/16", NATGatewayID: nat.ID},
		{Destination: "0.0.0.0/0", NATGatewayID: "ocid1.natgateway.oc1.foreign"},
	}); err != nil {
		t.Fatal(err)
	}
	observed, err := reconciler.Observe(ctx, declared)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := reconciler.Reconcile(ctx, declared, observed)
	if err != nil {
		t.Fatal(err)
	}
	var replace, attach bool
	for _, action := range plan.Actions {
		switch a := action.(type) {
		case ReplaceRouteRulesAction:
			replace = true
			if len(a.Rules) != 1 || a.Rules[0].Destination != "0.0.0.0/0" {
				t.Fatalf("route repair = %+v, want the declared default route", a.Rules)
			}
		case AttachSubnetRouteTableAction:
			attach = true
		}
	}
	if !replace || !attach {
		t.Fatalf("plan %v lacks route repair or subnet attachment", plan.Kinds())
	}
	if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
		t.Fatal(err)
	}
	table := gateway.routeTables[0]
	if len(table.Routes) != 1 || table.Routes[0].Destination != "0.0.0.0/0" || table.Routes[0].TargetID != nat.ID {
		t.Fatalf("repaired routes = %+v", table.Routes)
	}
	if gateway.subnets[0].RouteTableID != table.ID {
		t.Fatalf("subnet attachment = %q, want %q", gateway.subnets[0].RouteTableID, table.ID)
	}
}

func TestOCINetworkGatewayVCNContract(t *testing.T) {
	var requestBody map[string]any
	transport := testOCITransport(t, provider.OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/vcns" {
			t.Fatalf("unexpected vcn request %s %s", request.Method, request.URL.String())
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.vcn.oc1.x","displayName":"terrascale-gru","cidrBlocks":["10.0.0.0/16"],"lifecycleState":"AVAILABLE"}`, http.Header{}), nil
	})
	gateway, err := NewOCINetworkGateway(transport, "ocid1.compartment.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	created, err := gateway.CreateVCN(context.Background(), "terrascale-gru", "10.0.0.0/16")
	if err != nil || created.ID != "ocid1.vcn.oc1.x" || created.CIDR != "10.0.0.0/16" {
		t.Fatalf("CreateVCN = %+v, %v", created, err)
	}
	if requestBody["displayName"] != "terrascale-gru" || requestBody["prohibitPublicIpOnVnic"] != nil {
		t.Fatalf("vcn payload = %+v", requestBody)
	}
	if requestBody == nil {
		t.Fatal("VCN request body was not captured")
	}
}

func TestOCINetworkGatewayReusesStableRetryToken(t *testing.T) {
	var tokens []string
	transport := testOCITransport(t, provider.OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/vcns" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		tokens = append(tokens, request.Header.Get("opc-retry-token"))
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.vcn.oc1.x","displayName":"terrascale-gru","cidrBlocks":["10.0.0.0/16"],"lifecycleState":"AVAILABLE"}`, http.Header{}), nil
	})
	gateway, err := NewOCINetworkGateway(transport, "ocid1.compartment.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := gateway.CreateVCN(context.Background(), "terrascale-gru", "10.0.0.0/16"); err != nil {
			t.Fatal(err)
		}
	}
	if len(tokens) != 2 || tokens[0] == "" || tokens[0] != tokens[1] {
		t.Fatalf("retry tokens = %q, want one stable non-empty token", tokens)
	}
}

func TestOCINetworkGatewayRejectsInvalidScope(t *testing.T) {
	if _, err := NewOCINetworkGateway(nil, "ocid1.compartment.oc1.x"); err == nil {
		t.Fatal("nil transport accepted")
	}
	transport := testOCITransport(t, provider.OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		t.Fatal("no request expected")
		return nil, nil
	})
	if _, err := NewOCINetworkGateway(transport, "not-an-ocid"); err == nil {
		t.Fatal("invalid compartment accepted")
	}
}

func TestSecurityRuleWireMapsProtocols(t *testing.T) {
	wire, err := securityRuleWire(SecurityRuleSpec{Direction: "egress", Protocol: "udp", Peer: "10.0.0.0/8", PortMin: 443, PortMax: 444})
	if err != nil {
		t.Fatal(err)
	}
	if wire.Direction != "EGRESS" || wire.Destination != "10.0.0.0/8" || wire.Source != "" || wire.Protocol != "17" || wire.UDPOptions.DestinationPortRange.Min != 443 {
		t.Fatalf("udp egress wire = %+v", wire)
	}
	if _, err := securityRuleWire(SecurityRuleSpec{Direction: "ingress", Protocol: "sctp", Peer: "0.0.0.0/0", PortMin: 1, PortMax: 2}); err == nil {
		t.Fatal("unknown protocol accepted")
	}
	var quota *OCIQuotaError
	if !errors.As(classifyOCIRejection(429, "", ""), &quota) {
		t.Fatal("429 must classify as quota")
	}
}

func TestOCINetworkGatewayRouteTableContract(t *testing.T) {
	var requestBody map[string]any
	transport := testOCITransport(t, provider.OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/routeTables" {
			t.Fatalf("unexpected route table request %s %s", request.Method, request.URL.String())
		}
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.routetable.oc1.x","displayName":"gru-members","lifecycleState":"AVAILABLE","routeRules":[{"destination":"0.0.0.0/0","destinationType":"CIDR_BLOCK","networkEntityId":"ocid1.natgateway.oc1.x"}]}`, http.Header{}), nil
	})
	gateway, err := NewOCINetworkGateway(transport, "ocid1.compartment.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	created, err := gateway.CreateRouteTable(context.Background(), "ocid1.vcn.oc1.x", "gru-members", []RouteRuleSpec{{Destination: "0.0.0.0/0", NATGatewayID: "ocid1.natgateway.oc1.x"}})
	if err != nil || created.ID != "ocid1.routetable.oc1.x" || len(created.Routes) != 1 {
		t.Fatalf("CreateRouteTable = %+v, %v", created, err)
	}
	rule := created.Routes[0]
	if rule.Destination != "0.0.0.0/0" || rule.TargetID != "ocid1.natgateway.oc1.x" || rule.TargetType != "natgateway" {
		t.Fatalf("parsed route rule = %+v", rule)
	}
	rules, _ := requestBody["routeRules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("route payload = %+v", requestBody)
	}
	first, _ := rules[0].(map[string]any)
	if first["destination"] != "0.0.0.0/0" || first["destinationType"] != "CIDR_BLOCK" || first["networkEntityId"] != "ocid1.natgateway.oc1.x" {
		t.Fatalf("route rule payload = %+v", first)
	}
}

func TestOCINetworkGatewayRouteMutationContract(t *testing.T) {
	var seen []string
	transport := testOCITransport(t, provider.OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		seen = append(seen, request.Method+" "+request.URL.Path)
		switch {
		case request.Method == http.MethodPut && request.URL.Path == "/20160918/routeTables/"+url.PathEscape("ocid1.routetable.oc1.x"):
			return testHTTPResponse(http.StatusOK, `{}`, http.Header{}), nil
		case request.Method == http.MethodPut && request.URL.Path == "/20160918/subnets/"+url.PathEscape("ocid1.subnet.oc1.x"):
			return testHTTPResponse(http.StatusOK, `{"id":"ocid1.subnet.oc1.x","routeTableId":"ocid1.routetable.oc1.x"}`, http.Header{}), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
			return nil, nil
		}
	})
	gateway, err := NewOCINetworkGateway(transport, "ocid1.compartment.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := gateway.ReplaceRouteRules(ctx, "ocid1.routetable.oc1.x", []RouteRuleSpec{{Destination: "0.0.0.0/0", NATGatewayID: "ocid1.natgateway.oc1.x"}}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.AttachSubnetRouteTable(ctx, "ocid1.subnet.oc1.x", "ocid1.routetable.oc1.x"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		http.MethodPut + " /20160918/routeTables/" + url.PathEscape("ocid1.routetable.oc1.x"),
		http.MethodPut + " /20160918/subnets/" + url.PathEscape("ocid1.subnet.oc1.x"),
	}
	if len(seen) != len(want) {
		t.Fatalf("requests = %v, want %v", seen, want)
	}
	for i := range seen {
		if seen[i] != want[i] {
			t.Fatalf("requests = %v, want %v", seen, want)
		}
	}
}

func TestRouteRuleWireRejectsInvalidSpecs(t *testing.T) {
	if _, err := routeRuleWire(RouteRuleSpec{Destination: "not-a-cidr", NATGatewayID: "ocid1.natgateway.oc1.x"}); err == nil {
		t.Fatal("invalid destination accepted")
	}
	if _, err := routeRuleWire(RouteRuleSpec{Destination: "0.0.0.0/0", NATGatewayID: "ocid1.vcn.oc1.x"}); err == nil {
		t.Fatal("non-NAT route target accepted")
	}
	if err := (&OCINetworkGateway{}).ReplaceRouteRules(context.Background(), "ocid1.vcn.oc1.x", []RouteRuleSpec{{Destination: "0.0.0.0/0", NATGatewayID: "ocid1.natgateway.oc1.x"}}); err == nil {
		t.Fatal("non-route-table identity accepted")
	}
}
