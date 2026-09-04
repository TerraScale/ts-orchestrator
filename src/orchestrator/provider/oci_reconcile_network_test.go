package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
		},
	}
}

// fakeNetworkGateway records mutations and serves a mutable observed network.
type fakeNetworkGateway struct {
	vcns        []ObservedVCN
	subnets     []ObservedSubnet
	nsgs        []ObservedNSG
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
	created := ObservedVCN{ID: "ocid1.vcn.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), DisplayName: name, CIDR: cidr, LifecycleState: "AVAILABLE"}
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
	created := ObservedSubnet{ID: "ocid1.subnet.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), VCNID: vcnID, DisplayName: name, CIDR: cidr, LifecycleState: "AVAILABLE"}
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
	created := ObservedNSG{ID: "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), VCNID: vcnID, DisplayName: name, LifecycleState: "AVAILABLE"}
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
		rule := ObservedSecurityRule{ID: "ocid1.securityrule.oc1.sa-saopaulo-1.aaaa" + string(rune('a'+f.nextID)), Direction: ingressDirection(spec.Direction), Protocol: securityProtocolNumbers[spec.Protocol], Peer: spec.Peer, PortMin: spec.PortMin, PortMax: spec.PortMax}
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

func TestNetworkReconcilePlans(t *testing.T) {
	declared := testNetworkRegion()
	vcn := ObservedVCN{ID: "ocid1.vcn.oc1.x", DisplayName: "terrascale-gru", CIDR: "10.0.0.0/16", LifecycleState: "AVAILABLE"}
	subnet := ObservedSubnet{ID: "ocid1.subnet.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE"}
	nsg := ObservedNSG{ID: "ocid1.networksecuritygroup.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", LifecycleState: "AVAILABLE"}
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
				VCN:     &vcn,
				Subnets: []ObservedSubnet{subnet},
				NSGs:    []ObservedNSG{nsg},
				Rules: map[string][]ObservedSecurityRule{
					nsg.DisplayName: {
						{ID: "ocid1.securityrule.oc1.x.1", Direction: "INGRESS", Protocol: "6", Peer: "0.0.0.0/0", PortMin: 443, PortMax: 443},
						{ID: "ocid1.securityrule.oc1.x.2", Direction: "INGRESS", Protocol: "17", Peer: "10.0.0.0/16", PortMin: 6000, PortMax: 65535},
						{ID: "ocid1.securityrule.oc1.x.3", Direction: "EGRESS", Protocol: "1", Peer: "0.0.0.0/0"},
					},
				},
			},
			wantKinds: []OCIActionKind{},
		},
		{
			name: "missing subnet and drifted rules plan repair",
			observed: NetworkObserved{
				VCN:  &vcn,
				NSGs: []ObservedNSG{nsg},
				Rules: map[string][]ObservedSecurityRule{
					nsg.DisplayName: {
						{ID: "ocid1.securityrule.oc1.x.9", Direction: "INGRESS", Protocol: "6", Peer: "0.0.0.0/0", PortMin: 22, PortMax: 22},
					},
				},
			},
			wantKinds: []OCIActionKind{OCIActionCreateSubnet, OCIActionReplaceNSGRules},
		},
		{
			name: "vcn cidr drift is refused",
			observed: NetworkObserved{
				VCN:   &ObservedVCN{ID: "ocid1.vcn.oc1.x", DisplayName: "terrascale-gru", CIDR: "172.16.0.0/16", LifecycleState: "AVAILABLE"},
				Rules: map[string][]ObservedSecurityRule{},
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
	vcn := &ObservedVCN{ID: "ocid1.vcn.oc1.x", CIDR: declared.Network.CIDR, LifecycleState: "CREATING"}
	reconciler := &NetworkReconciler{Gateway: &fakeNetworkGateway{}}
	converged, err := reconciler.bootstrapConverged(NetworkObserved{VCN: vcn}, declared)
	if err != nil || converged {
		t.Fatalf("pending VCN convergence = %v, %v; want false, nil", converged, err)
	}
	converged, err = reconciler.bootstrapConverged(NetworkObserved{
		VCN:     &ObservedVCN{ID: vcn.ID, CIDR: declared.Network.CIDR, LifecycleState: "AVAILABLE"},
		Subnets: []ObservedSubnet{{ID: "ocid1.subnet.oc1.x", DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "CREATING"}},
	}, declared)
	if err != nil || converged {
		t.Fatalf("pending subnet convergence = %v, %v; want false, nil", converged, err)
	}
	_, err = reconciler.bootstrapConverged(NetworkObserved{
		VCN:     &ObservedVCN{ID: vcn.ID, CIDR: declared.Network.CIDR, LifecycleState: "AVAILABLE"},
		Subnets: []ObservedSubnet{{ID: "ocid1.subnet.oc1.x", DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE"}},
		NSGs:    []ObservedNSG{{ID: "ocid1.networksecuritygroup.oc1.x", DisplayName: "gru-members", LifecycleState: "FAILED"}},
	}, declared)
	if err == nil {
		t.Fatal("failed NSG convergence was accepted")
	}
	ready := NetworkObserved{
		VCN:     &ObservedVCN{ID: vcn.ID, CIDR: declared.Network.CIDR, LifecycleState: "AVAILABLE"},
		Subnets: []ObservedSubnet{{ID: "ocid1.subnet.oc1.x", DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE"}},
		NSGs:    []ObservedNSG{{ID: "ocid1.networksecuritygroup.oc1.x", DisplayName: "gru-members", LifecycleState: "AVAILABLE"}},
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
	for pass := 0; pass < 4; pass++ {
		observed, err = reconciler.Observe(ctx, declared)
		if err != nil {
			t.Fatalf("re-observe failed: %v", err)
		}
		plan, err = reconciler.Reconcile(ctx, declared, observed)
		if err != nil {
			t.Fatalf("re-reconcile failed: %v", err)
		}
		if plan.Empty() {
			// Final state check: subnet and all three rules exist.
			if len(gateway.subnets) != 1 || len(gateway.nsgs) != 1 {
				t.Fatalf("apply state = %d subnets, %d nsgs", len(gateway.subnets), len(gateway.nsgs))
			}
			if rules := gateway.rules[gateway.nsgs[0].ID]; len(rules) != 3 {
				t.Fatalf("nsg rules = %d, want 3", len(rules))
			}
			return
		}
		if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
			t.Fatalf("convergence apply failed: %v", err)
		}
	}
	t.Fatal("network did not converge in three passes")
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

func TestOCINetworkGatewayVCNContract(t *testing.T) {
	var requestBody map[string]any
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
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
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
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
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
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
