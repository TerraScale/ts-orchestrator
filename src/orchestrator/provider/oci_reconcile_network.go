package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// The network reconciler creates and repairs each Region's VCN, private
// subnets, network security groups, NAT gateway, and route tables from the
// declared estate (D-67). VCN and subnet CIDR drift is refused loudly
// instead of repaired: renumbering a live network strands every attached
// resource. Route rules are repaired to the declared set.

// VCNName derives the deterministic VCN display name for a Region code.
func VCNName(regionCode string) string { return "terrascale-" + regionCode }

// NATGatewayName derives the deterministic NAT gateway display name for a
// Region code. Private member subnets egress only through it (D-66).
func NATGatewayName(regionCode string) string { return "terrascale-" + regionCode + "-nat" }

type ObservedVCN struct {
	ID             string
	DisplayName    string
	CIDR           string
	LifecycleState string
	CompartmentID  string
	FreeformTags   map[string]string
}

type ObservedSubnet struct {
	ID             string
	VCNID          string
	DisplayName    string
	CIDR           string
	LifecycleState string
	RouteTableID   string
	CompartmentID  string
	FreeformTags   map[string]string
}

type ObservedNSG struct {
	ID             string
	VCNID          string
	DisplayName    string
	LifecycleState string
	CompartmentID  string
	FreeformTags   map[string]string
}

type ObservedNATGateway struct {
	ID             string
	VCNID          string
	DisplayName    string
	LifecycleState string
	CompartmentID  string
	FreeformTags   map[string]string
}

// ObservedRouteRule is one route table rule as OCI reports it. TargetType is
// normalized from the wire or derived from the target OCID ("natgateway",
// "internetgateway", ...).
type ObservedRouteRule struct {
	Destination string
	TargetID    string
	TargetType  string
}

type ObservedRouteTable struct {
	ID             string
	VCNID          string
	DisplayName    string
	LifecycleState string
	Routes         []ObservedRouteRule
	CompartmentID  string
	FreeformTags   map[string]string
}

// ObservedSecurityRule is one NSG rule as OCI reports it. Protocol is the
// IANA number OCI uses on the wire ("6" tcp, "17" udp, "1" icmp); Peer is the
// source for ingress and the destination for egress.
type ObservedSecurityRule struct {
	ID        string
	Direction string // INGRESS | EGRESS
	Protocol  string
	Peer      string
	PortMin   uint16
	PortMax   uint16
	Managed   bool
}

type NetworkObserved struct {
	VCN         *ObservedVCN
	Subnets     []ObservedSubnet
	NSGs        []ObservedNSG
	NATGateways []ObservedNATGateway
	RouteTables []ObservedRouteTable
	Rules       map[string][]ObservedSecurityRule
}

// SecurityRuleSpec is the provider-neutral rule shape the estate declares
// (direction, protocol name, peer CIDR, port range).
type SecurityRuleSpec struct {
	Direction string // ingress | egress
	Protocol  string // tcp | udp | icmp
	Peer      string
	PortMin   uint16
	PortMax   uint16
}

// RouteRuleSpec is the provider-neutral route shape the estate declares:
// one destination CIDR forwarded through the Region's NAT gateway. The
// gateway identity is filled in at apply time from the live NAT gateway.
type RouteRuleSpec struct {
	Destination  string
	NATGatewayID string
}

// NetworkGateway is the OCI core-service seam for network reconciliation.
// Implementations hold the compartment scope; identities are validated by the
// real gateway before use.
type NetworkGateway interface {
	ListVCNs(ctx context.Context, name string) ([]ObservedVCN, error)
	CreateVCN(ctx context.Context, name, cidr string) (ObservedVCN, error)
	ListSubnets(ctx context.Context, vcnID string) ([]ObservedSubnet, error)
	CreateSubnet(ctx context.Context, vcnID, name, cidr string) (ObservedSubnet, error)
	ListNSGs(ctx context.Context, vcnID string) ([]ObservedNSG, error)
	CreateNSG(ctx context.Context, vcnID, name string) (ObservedNSG, error)
	ListNSGRules(ctx context.Context, nsgID string) ([]ObservedSecurityRule, error)
	AddNSGRules(ctx context.Context, nsgID string, rules []SecurityRuleSpec) error
	RemoveNSGRules(ctx context.Context, nsgID string, ruleIDs []string) error
	ListNATGateways(ctx context.Context, vcnID string) ([]ObservedNATGateway, error)
	CreateNATGateway(ctx context.Context, vcnID, name string) (ObservedNATGateway, error)
	ListRouteTables(ctx context.Context, vcnID string) ([]ObservedRouteTable, error)
	CreateRouteTable(ctx context.Context, vcnID, name string, rules []RouteRuleSpec) (ObservedRouteTable, error)
	ReplaceRouteRules(ctx context.Context, routeTableID string, rules []RouteRuleSpec) error
	AttachSubnetRouteTable(ctx context.Context, subnetID, routeTableID string) error
}

type CreateVCNAction struct{ Name, CIDR string }

func (a CreateVCNAction) Kind() OCIActionKind { return OCIActionCreateVCN }
func (a CreateVCNAction) Summary() string     { return "create VCN " + a.Name + " " + a.CIDR }

type CreateSubnetAction struct{ Name, CIDR string }

func (a CreateSubnetAction) Kind() OCIActionKind { return OCIActionCreateSubnet }
func (a CreateSubnetAction) Summary() string     { return "create subnet " + a.Name + " " + a.CIDR }

type CreateNSGAction struct{ Name string }

func (a CreateNSGAction) Kind() OCIActionKind { return OCIActionCreateNSG }
func (a CreateNSGAction) Summary() string     { return "create network security group " + a.Name }

type ReplaceNSGRulesAction struct {
	Name      string
	Add       []SecurityRuleSpec
	RemoveIDs []string
}

func (a ReplaceNSGRulesAction) Kind() OCIActionKind { return OCIActionReplaceNSGRules }
func (a ReplaceNSGRulesAction) Summary() string {
	return "replace " + strconv.Itoa(len(a.Add)) + " added and " + strconv.Itoa(len(a.RemoveIDs)) + " removed rules in " + a.Name
}

type CreateNATGatewayAction struct{ Name string }

func (a CreateNATGatewayAction) Kind() OCIActionKind { return OCIActionCreateNATGateway }
func (a CreateNATGatewayAction) Summary() string     { return "create NAT gateway " + a.Name }

type CreateRouteTableAction struct {
	Name   string
	Subnet string
	Rules  []RouteRuleSpec
}

func (a CreateRouteTableAction) Kind() OCIActionKind { return OCIActionCreateRouteTable }
func (a CreateRouteTableAction) Summary() string {
	return "create route table " + a.Name + " with " + strconv.Itoa(len(a.Rules)) + " routes for subnet " + a.Subnet
}

type ReplaceRouteRulesAction struct {
	Name  string
	Rules []RouteRuleSpec
}

func (a ReplaceRouteRulesAction) Kind() OCIActionKind { return OCIActionReplaceRouteRules }
func (a ReplaceRouteRulesAction) Summary() string {
	return "replace routes in " + a.Name + " with " + strconv.Itoa(len(a.Rules)) + " declared routes"
}

type AttachSubnetRouteTableAction struct {
	Subnet     string
	RouteTable string
}

func (a AttachSubnetRouteTableAction) Kind() OCIActionKind { return OCIActionAttachSubnetRoute }
func (a AttachSubnetRouteTableAction) Summary() string {
	return "attach subnet " + a.Subnet + " to route table " + a.RouteTable
}

// NetworkReconciler converges one Region's network toward its declaration.
type NetworkReconciler struct {
	Gateway NetworkGateway
}

var _ OCIReconciler[estate.Region, NetworkObserved] = (*NetworkReconciler)(nil)

// securityProtocolNumbers maps declared protocol names to OCI wire numbers.
var securityProtocolNumbers = map[string]string{"tcp": "6", "udp": "17", "icmp": "1"}

func (r *NetworkReconciler) Observe(ctx context.Context, declared estate.Region) (NetworkObserved, error) {
	if r == nil || r.Gateway == nil {
		return NetworkObserved{}, &InvalidOperationError{Message: "network reconciler is unavailable"}
	}
	if ctx == nil {
		return NetworkObserved{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return NetworkObserved{}, err
	}
	observed := NetworkObserved{Rules: map[string][]ObservedSecurityRule{}}
	vcns, err := r.Gateway.ListVCNs(ctx, VCNName(declared.Code))
	if err != nil {
		return NetworkObserved{}, err
	}
	for i := range vcns {
		if vcns[i].LifecycleState != "TERMINATED" && vcns[i].LifecycleState != "TERMINATING" {
			if !networkVCNOwned(vcns[i], declared.Code) {
				return NetworkObserved{}, &InvalidDataError{Message: "a VCN with the declared name is not positively owned"}
			}
			if observed.VCN != nil {
				return NetworkObserved{}, &InvalidDataError{Message: "multiple VCNs share the declared name"}
			}
			vcn := vcns[i]
			observed.VCN = &vcn
		}
	}
	if observed.VCN == nil {
		return observed, nil
	}
	if observedNetworkState(observed.VCN.LifecycleState) != networkStateActive {
		return observed, nil
	}
	observed.Subnets, err = r.Gateway.ListSubnets(ctx, observed.VCN.ID)
	if err != nil {
		return NetworkObserved{}, err
	}
	observed.NSGs, err = r.Gateway.ListNSGs(ctx, observed.VCN.ID)
	if err != nil {
		return NetworkObserved{}, err
	}
	observed.NATGateways, err = r.Gateway.ListNATGateways(ctx, observed.VCN.ID)
	if err != nil {
		return NetworkObserved{}, err
	}
	observed.RouteTables, err = r.Gateway.ListRouteTables(ctx, observed.VCN.ID)
	if err != nil {
		return NetworkObserved{}, err
	}
	for _, group := range observed.NSGs {
		if observedNetworkState(group.LifecycleState) != networkStateActive {
			continue
		}
		rules, err := r.Gateway.ListNSGRules(ctx, group.ID)
		if err != nil {
			return NetworkObserved{}, err
		}
		observed.Rules[group.DisplayName] = rules
	}
	return observed, nil
}

func (r *NetworkReconciler) Reconcile(ctx context.Context, declared estate.Region, observed NetworkObserved) (OCIPlan, error) {
	if ctx == nil {
		return OCIPlan{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return OCIPlan{}, err
	}
	plan := OCIPlan{}
	if observed.VCN == nil {
		plan.Actions = append(plan.Actions, CreateVCNAction{Name: VCNName(declared.Code), CIDR: declared.Network.CIDR})
		// The VCN create is asynchronous. Do not submit dependent subnet/NSG
		// mutations against an ID that does not exist in the observation yet.
		return plan, nil
	} else {
		if !networkVCNOwned(*observed.VCN, declared.Code) {
			return OCIPlan{}, &InvalidDataError{Message: "observed VCN is not positively owned"}
		}
		switch observedNetworkState(observed.VCN.LifecycleState) {
		case networkStatePending:
			// Do not create dependent resources until the VCN is usable.
			return plan, nil
		case networkStateFailed, networkStateUnknown, networkStateAbsent:
			return OCIPlan{}, &InvalidDataError{Message: "observed VCN has an unusable lifecycle state"}
		case networkStateActive:
			if observed.VCN.CIDR != declared.Network.CIDR {
				return OCIPlan{}, &InvalidDataError{Message: "observed VCN CIDR does not match the declared network and cannot be renumbered"}
			}
		}
	}
	subnets := make(map[string]ObservedSubnet, len(observed.Subnets))
	for _, subnet := range observed.Subnets {
		for _, declaredSubnet := range declared.Network.Subnets {
			if subnet.DisplayName == declaredSubnet.Name && !networkSubnetOwned(subnet, declared.Code) {
				return OCIPlan{}, &InvalidDataError{Message: "declared subnet " + subnet.DisplayName + " is not positively owned"}
			}
		}
		if networkSubnetOwned(subnet, declared.Code) && observed.VCN != nil && subnet.VCNID != observed.VCN.ID {
			return OCIPlan{}, &InvalidDataError{Message: "owned subnet is outside the declared VCN"}
		}
		switch observedNetworkState(subnet.LifecycleState) {
		case networkStateAbsent:
			continue
		case networkStateFailed:
			return OCIPlan{}, &InvalidDataError{Message: "observed subnet " + subnet.DisplayName + " failed and cannot be used"}
		case networkStateUnknown:
			return OCIPlan{}, &InvalidDataError{Message: "observed subnet " + subnet.DisplayName + " has an unusable lifecycle state"}
		}
		if _, duplicate := subnets[subnet.DisplayName]; duplicate {
			return OCIPlan{}, &InvalidDataError{Message: "multiple subnets share the declared name " + subnet.DisplayName}
		}
		subnets[subnet.DisplayName] = subnet
	}
	for _, declaredSubnet := range declared.Network.Subnets {
		if existing, ok := subnets[declaredSubnet.Name]; ok {
			if existing.CIDR != declaredSubnet.CIDR {
				return OCIPlan{}, &InvalidDataError{Message: "observed subnet " + declaredSubnet.Name + " CIDR drift cannot be repaired in place"}
			}
			continue
		}
		plan.Actions = append(plan.Actions, CreateSubnetAction{Name: declaredSubnet.Name, CIDR: declaredSubnet.CIDR})
	}
	groups := make(map[string]ObservedNSG, len(observed.NSGs))
	for _, group := range observed.NSGs {
		for _, declaredGroup := range declared.Network.SecurityGroups {
			if group.DisplayName == declaredGroup.Name && !networkNSGOwned(group, declared.Code) {
				return OCIPlan{}, &InvalidDataError{Message: "declared network security group " + group.DisplayName + " is not positively owned"}
			}
		}
		if networkNSGOwned(group, declared.Code) && observed.VCN != nil && group.VCNID != observed.VCN.ID {
			return OCIPlan{}, &InvalidDataError{Message: "owned network security group is outside the declared VCN"}
		}
		switch observedNetworkState(group.LifecycleState) {
		case networkStateAbsent:
			continue
		case networkStateFailed:
			return OCIPlan{}, &InvalidDataError{Message: "observed network security group " + group.DisplayName + " failed and cannot be used"}
		case networkStateUnknown:
			return OCIPlan{}, &InvalidDataError{Message: "observed network security group " + group.DisplayName + " has an unusable lifecycle state"}
		}
		if _, duplicate := groups[group.DisplayName]; duplicate {
			return OCIPlan{}, &InvalidDataError{Message: "multiple network security groups share the declared name " + group.DisplayName}
		}
		groups[group.DisplayName] = group
	}
	for _, declaredGroup := range declared.Network.SecurityGroups {
		if _, ok := groups[declaredGroup.Name]; !ok {
			plan.Actions = append(plan.Actions, CreateNSGAction{Name: declaredGroup.Name})
			// The group is created asynchronously; rules are applied after the
			// next observation confirms the group is usable.
			continue
		}
		if existing, ok := groups[declaredGroup.Name]; ok && observedNetworkState(existing.LifecycleState) != networkStateActive {
			continue
		}
		add, remove := diffSecurityRules(declaredGroup.Rules, observed.Rules[declaredGroup.Name])
		if len(add) > 0 || len(remove) > 0 {
			plan.Actions = append(plan.Actions, ReplaceNSGRulesAction{Name: declaredGroup.Name, Add: add, RemoveIDs: remove})
		}
	}
	if len(declared.Network.RouteTables) > 0 {
		natID, natMissing, err := resolveDeclaredNAT(declared, observed)
		if err != nil {
			return OCIPlan{}, err
		}
		if natMissing {
			plan.Actions = append(plan.Actions, CreateNATGatewayAction{Name: NATGatewayName(declared.Code)})
			// The NAT gateway create is asynchronous; route tables reference it
			// after the next observation confirms it is usable.
			return plan, nil
		}
		if natID == "" {
			// The NAT gateway is still provisioning; routes replan once it is
			// usable.
			return plan, nil
		}
		routeTables := make(map[string]ObservedRouteTable, len(observed.RouteTables))
		for _, table := range observed.RouteTables {
			if networkRouteTableOwned(table, declared.Code) && observed.VCN != nil && table.VCNID != observed.VCN.ID {
				return OCIPlan{}, &InvalidDataError{Message: "owned route table is outside the declared VCN"}
			}
			switch observedNetworkState(table.LifecycleState) {
			case networkStateAbsent:
				continue
			case networkStateFailed:
				return OCIPlan{}, &InvalidDataError{Message: "observed route table " + table.DisplayName + " failed and cannot be used"}
			case networkStateUnknown:
				return OCIPlan{}, &InvalidDataError{Message: "observed route table " + table.DisplayName + " has an unusable lifecycle state"}
			}
			if _, duplicate := routeTables[table.DisplayName]; duplicate {
				return OCIPlan{}, &InvalidDataError{Message: "multiple route tables share the declared name " + table.DisplayName}
			}
			routeTables[table.DisplayName] = table
		}
		for _, declaredTable := range declared.Network.RouteTables {
			existing, ok := routeTables[declaredTable.Name]
			if !ok {
				plan.Actions = append(plan.Actions, CreateRouteTableAction{Name: declaredTable.Name, Subnet: declaredTable.Subnet, Rules: routeRuleSpecs(declaredTable.Routes)})
				// The table is created asynchronously; subnet association is
				// planned after the next observation confirms it is usable.
				continue
			}
			if !networkRouteTableOwned(existing, declared.Code) {
				return OCIPlan{}, &InvalidDataError{Message: "declared route table " + existing.DisplayName + " is not positively owned"}
			}
			if observedNetworkState(existing.LifecycleState) != networkStateActive {
				continue
			}
			if !routeRulesMatch(declaredTable.Routes, existing.Routes, natID) {
				plan.Actions = append(plan.Actions, ReplaceRouteRulesAction{Name: declaredTable.Name, Rules: routeRuleSpecs(declaredTable.Routes)})
			}
			if subnet, ok := subnets[declaredTable.Subnet]; ok && subnet.RouteTableID != existing.ID {
				plan.Actions = append(plan.Actions, AttachSubnetRouteTableAction{Subnet: declaredTable.Subnet, RouteTable: declaredTable.Name})
			}
		}
	}
	return plan, nil
}

// resolveDeclaredNAT resolves the Region's NAT gateway from the
// observation. It returns the live gateway identity, whether the gateway is
// missing entirely (so the caller plans its create), or an empty identity
// while it is still provisioning. Ambiguous or unusable gateways fail
// closed.
func resolveDeclaredNAT(declared estate.Region, observed NetworkObserved) (natID string, missing bool, err error) {
	natName := NATGatewayName(declared.Code)
	seen := false
	for _, gateway := range observed.NATGateways {
		if networkNATOwned(gateway, declared.Code) && observed.VCN != nil && gateway.VCNID != observed.VCN.ID {
			return "", false, &InvalidDataError{Message: "owned NAT gateway is outside the declared VCN"}
		}
		switch observedNetworkState(gateway.LifecycleState) {
		case networkStateAbsent:
			continue
		case networkStateFailed:
			return "", false, &InvalidDataError{Message: "observed NAT gateway " + gateway.DisplayName + " failed and cannot be used"}
		case networkStateUnknown:
			return "", false, &InvalidDataError{Message: "observed NAT gateway " + gateway.DisplayName + " has an unusable lifecycle state"}
		}
		if gateway.DisplayName != natName {
			continue
		}
		if !networkNATOwned(gateway, declared.Code) {
			return "", false, &InvalidDataError{Message: "declared NAT gateway is not positively owned"}
		}
		if seen {
			return "", false, &InvalidDataError{Message: "multiple NAT gateways share the declared name " + natName}
		}
		seen = true
		if observedNetworkState(gateway.LifecycleState) == networkStateActive {
			natID = gateway.ID
		}
	}
	return natID, !seen, nil
}

type networkResourceState uint8

const (
	networkStateAbsent networkResourceState = iota
	networkStatePending
	networkStateActive
	networkStateFailed
	networkStateUnknown
)

func observedNetworkState(state string) networkResourceState {
	switch state {
	case "AVAILABLE", "ACTIVE":
		return networkStateActive
	case "CREATING", "PROVISIONING", "UPDATING":
		return networkStatePending
	case "TERMINATED", "TERMINATING", "DELETED", "DELETING", "":
		return networkStateAbsent
	case "FAILED", "ERROR":
		return networkStateFailed
	default:
		return networkStateUnknown
	}
}

func (r *NetworkReconciler) bootstrapConverged(value, declaration any) (bool, error) {
	observed, ok := value.(NetworkObserved)
	if !ok {
		return false, &InvalidDataError{Message: "network convergence observation has the wrong type"}
	}
	declared, ok := declaration.(estate.Region)
	if !ok {
		return false, &InvalidDataError{Message: "network convergence declaration has the wrong type"}
	}
	if observed.VCN == nil {
		return false, nil
	}
	if !networkVCNOwned(*observed.VCN, declared.Code) {
		return false, nil
	}
	if observedNetworkState(observed.VCN.LifecycleState) != networkStateActive || observed.VCN.CIDR != declared.Network.CIDR {
		return false, nil
	}
	subnets := make(map[string]ObservedSubnet, len(observed.Subnets))
	for _, subnet := range observed.Subnets {
		for _, want := range declared.Network.Subnets {
			if subnet.DisplayName == want.Name && !networkSubnetOwned(subnet, declared.Code) {
				return false, nil
			}
		}
		switch observedNetworkState(subnet.LifecycleState) {
		case networkStateAbsent:
			continue
		case networkStateFailed:
			return false, &InvalidDataError{Message: "observed subnet " + subnet.DisplayName + " failed and cannot be used"}
		case networkStateUnknown:
			return false, &InvalidDataError{Message: "observed subnet " + subnet.DisplayName + " has an unusable lifecycle state"}
		}
		if _, duplicate := subnets[subnet.DisplayName]; duplicate {
			return false, &InvalidDataError{Message: "multiple subnets share the declared name " + subnet.DisplayName}
		}
		if networkSubnetOwned(subnet, declared.Code) && subnet.VCNID != observed.VCN.ID {
			return false, &InvalidDataError{Message: "owned subnet is outside the declared VCN"}
		}
		subnets[subnet.DisplayName] = subnet
	}
	for _, want := range declared.Network.Subnets {
		subnet, exists := subnets[want.Name]
		if !exists || observedNetworkState(subnet.LifecycleState) != networkStateActive || subnet.CIDR != want.CIDR {
			return false, nil
		}
	}
	groups := make(map[string]ObservedNSG, len(observed.NSGs))
	for _, group := range observed.NSGs {
		for _, want := range declared.Network.SecurityGroups {
			if group.DisplayName == want.Name && !networkNSGOwned(group, declared.Code) {
				return false, nil
			}
		}
		switch observedNetworkState(group.LifecycleState) {
		case networkStateAbsent:
			continue
		case networkStateFailed:
			return false, &InvalidDataError{Message: "observed network security group " + group.DisplayName + " failed and cannot be used"}
		case networkStateUnknown:
			return false, &InvalidDataError{Message: "observed network security group " + group.DisplayName + " has an unusable lifecycle state"}
		}
		if _, duplicate := groups[group.DisplayName]; duplicate {
			return false, &InvalidDataError{Message: "multiple network security groups share the declared name " + group.DisplayName}
		}
		if networkNSGOwned(group, declared.Code) && group.VCNID != observed.VCN.ID {
			return false, &InvalidDataError{Message: "owned network security group is outside the declared VCN"}
		}
		groups[group.DisplayName] = group
	}
	for _, want := range declared.Network.SecurityGroups {
		group, exists := groups[want.Name]
		if !exists || observedNetworkState(group.LifecycleState) != networkStateActive {
			return false, nil
		}
		add, remove := diffSecurityRules(want.Rules, observed.Rules[want.Name])
		if len(add) != 0 || len(remove) != 0 {
			return false, nil
		}
	}
	if len(declared.Network.RouteTables) > 0 {
		natID, natMissing, err := resolveDeclaredNAT(declared, observed)
		if err != nil {
			return false, err
		}
		if natMissing || natID == "" {
			return false, nil
		}
		routeTables := make(map[string]ObservedRouteTable, len(observed.RouteTables))
		for _, table := range observed.RouteTables {
			for _, want := range declared.Network.RouteTables {
				if table.DisplayName == want.Name && !networkRouteTableOwned(table, declared.Code) {
					return false, nil
				}
			}
			if networkRouteTableOwned(table, declared.Code) && table.VCNID != observed.VCN.ID {
				return false, &InvalidDataError{Message: "owned route table is outside the declared VCN"}
			}
			switch observedNetworkState(table.LifecycleState) {
			case networkStateAbsent:
				continue
			case networkStateFailed:
				return false, &InvalidDataError{Message: "observed route table " + table.DisplayName + " failed and cannot be used"}
			case networkStateUnknown:
				return false, &InvalidDataError{Message: "observed route table " + table.DisplayName + " has an unusable lifecycle state"}
			}
			if _, duplicate := routeTables[table.DisplayName]; duplicate {
				return false, &InvalidDataError{Message: "multiple route tables share the declared name " + table.DisplayName}
			}
			routeTables[table.DisplayName] = table
		}
		for _, want := range declared.Network.RouteTables {
			table, exists := routeTables[want.Name]
			if !exists || observedNetworkState(table.LifecycleState) != networkStateActive || !routeRulesMatch(want.Routes, table.Routes, natID) {
				return false, nil
			}
			subnet, exists := subnets[want.Subnet]
			if !exists || observedNetworkState(subnet.LifecycleState) != networkStateActive || subnet.RouteTableID != table.ID {
				return false, nil
			}
		}
	}
	return true, nil
}

func (r *NetworkReconciler) Apply(ctx context.Context, declared estate.Region, observed NetworkObserved, plan OCIPlan) error {
	if r == nil || r.Gateway == nil {
		return &InvalidOperationError{Message: "network reconciler is unavailable"}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	vcnID := ""
	if observed.VCN != nil {
		vcnID = observed.VCN.ID
	}
	createdNSGs := make(map[string]string)
	for _, group := range observed.NSGs {
		createdNSGs[group.DisplayName] = group.ID
	}
	subnetIDs := make(map[string]string, len(observed.Subnets))
	for _, subnet := range observed.Subnets {
		subnetIDs[subnet.DisplayName] = subnet.ID
	}
	routeTableIDs := make(map[string]string, len(observed.RouteTables))
	for _, table := range observed.RouteTables {
		routeTableIDs[table.DisplayName] = table.ID
	}
	natID := ""
	for _, gateway := range observed.NATGateways {
		if gateway.DisplayName == NATGatewayName(declared.Code) && observedNetworkState(gateway.LifecycleState) == networkStateActive {
			natID = gateway.ID
		}
	}
	routedSpecs := func(rules []RouteRuleSpec) ([]RouteRuleSpec, error) {
		if !isOCID(natID, "natgateway") {
			return nil, &InvalidOperationError{Message: "route reconciliation requires a live NAT gateway"}
		}
		resolved := make([]RouteRuleSpec, 0, len(rules))
		for _, spec := range rules {
			resolved = append(resolved, RouteRuleSpec{Destination: spec.Destination, NATGatewayID: natID})
		}
		return resolved, nil
	}
	for _, action := range plan.Actions {
		switch a := action.(type) {
		case CreateVCNAction:
			created, err := r.Gateway.CreateVCN(ctx, a.Name, a.CIDR)
			if err != nil {
				return err
			}
			vcnID = created.ID
		case CreateSubnetAction:
			if !isOCID(vcnID, "vcn") {
				return &InvalidOperationError{Message: "subnet create requires a live VCN"}
			}
			if _, err := r.Gateway.CreateSubnet(ctx, vcnID, a.Name, a.CIDR); err != nil {
				return err
			}
		case CreateNSGAction:
			if !isOCID(vcnID, "vcn") {
				return &InvalidOperationError{Message: "network security group create requires a live VCN"}
			}
			created, err := r.Gateway.CreateNSG(ctx, vcnID, a.Name)
			if err != nil {
				return err
			}
			createdNSGs[created.DisplayName] = created.ID
		case ReplaceNSGRulesAction:
			nsgID := createdNSGs[a.Name]
			if !isOCID(nsgID, "networksecuritygroup") {
				return &InvalidOperationError{Message: "security rule replacement requires a live network security group"}
			}
			if err := r.verifyOwnedNSG(ctx, declared, observed, a.Name, nsgID); err != nil {
				return err
			}
			if len(a.RemoveIDs) > 0 {
				if err := r.removeOwnedNSGRules(ctx, declared, observed, a.Name, nsgID, a.RemoveIDs); err != nil {
					return err
				}
			}
			if len(a.Add) > 0 {
				if err := r.Gateway.AddNSGRules(ctx, nsgID, a.Add); err != nil {
					return err
				}
			}
		case CreateNATGatewayAction:
			if !isOCID(vcnID, "vcn") {
				return &InvalidOperationError{Message: "NAT gateway create requires a live VCN"}
			}
			created, err := r.Gateway.CreateNATGateway(ctx, vcnID, a.Name)
			if err != nil {
				return err
			}
			natID = created.ID
		case CreateRouteTableAction:
			if !isOCID(vcnID, "vcn") {
				return &InvalidOperationError{Message: "route table create requires a live VCN"}
			}
			rules, err := routedSpecs(a.Rules)
			if err != nil {
				return err
			}
			created, err := r.Gateway.CreateRouteTable(ctx, vcnID, a.Name, rules)
			if err != nil {
				return err
			}
			routeTableIDs[created.DisplayName] = created.ID
		case ReplaceRouteRulesAction:
			tableID := routeTableIDs[a.Name]
			if !isOCID(tableID, "routetable") {
				return &InvalidOperationError{Message: "route rule replacement requires a live route table"}
			}
			rules, err := routedSpecs(a.Rules)
			if err != nil {
				return err
			}
			if err := r.Gateway.ReplaceRouteRules(ctx, tableID, rules); err != nil {
				return err
			}
		case AttachSubnetRouteTableAction:
			subnetID, tableID := subnetIDs[a.Subnet], routeTableIDs[a.RouteTable]
			if !isOCID(subnetID, "subnet") || !isOCID(tableID, "routetable") {
				return &InvalidOperationError{Message: "subnet route attachment requires a live subnet and route table"}
			}
			if err := r.Gateway.AttachSubnetRouteTable(ctx, subnetID, tableID); err != nil {
				return err
			}
		default:
			return &InvalidOperationError{Message: "network reconciler received a foreign action"}
		}
	}
	return nil
}

func networkVCNOwned(v ObservedVCN, region string) bool {
	return isOCID(v.ID, "vcn") && v.DisplayName == VCNName(region) && positiveOCIOwnership(v.FreeformTags, "vcn", region)
}

func networkSubnetOwned(v ObservedSubnet, region string) bool {
	return isOCID(v.ID, "subnet") && positiveOCIOwnership(v.FreeformTags, "subnet", region)
}

func networkNSGOwned(v ObservedNSG, region string) bool {
	return isOCID(v.ID, "networksecuritygroup") && positiveOCIOwnership(v.FreeformTags, "networksecuritygroup", region)
}

func networkNATOwned(v ObservedNATGateway, region string) bool {
	return isOCID(v.ID, "natgateway") && v.DisplayName == NATGatewayName(region) && positiveOCIOwnership(v.FreeformTags, "natgateway", region)
}

func networkRouteTableOwned(v ObservedRouteTable, region string) bool {
	return isOCID(v.ID, "routetable") && positiveOCIOwnership(v.FreeformTags, "routetable", region)
}

func sameObservedVCN(a, b ObservedVCN) bool {
	return a.ID == b.ID && a.DisplayName == b.DisplayName && a.CIDR == b.CIDR && a.LifecycleState == b.LifecycleState && a.CompartmentID == b.CompartmentID && sameStringMap(a.FreeformTags, b.FreeformTags)
}

func sameObservedNSG(a, b ObservedNSG) bool {
	return a.ID == b.ID && a.VCNID == b.VCNID && a.DisplayName == b.DisplayName && a.LifecycleState == b.LifecycleState && a.CompartmentID == b.CompartmentID && sameStringMap(a.FreeformTags, b.FreeformTags)
}

// verifyOwnedNSG re-reads the complete parent and NSG identity immediately
// before a rule mutation. An earlier observation is a plan input, not current
// authorization; ownership or parent identity changes must stop the plan.
func (r *NetworkReconciler) verifyOwnedNSG(ctx context.Context, declared estate.Region, observed NetworkObserved, name, id string) error {
	if observed.VCN == nil || !networkVCNOwned(*observed.VCN, declared.Code) {
		return &InvalidOperationError{Message: "security rule mutation requires an owned VCN"}
	}
	vcns, err := r.Gateway.ListVCNs(ctx, VCNName(declared.Code))
	if err != nil {
		return err
	}
	var currentVCN *ObservedVCN
	for index := range vcns {
		if vcns[index].ID == observed.VCN.ID {
			currentVCN = &vcns[index]
			break
		}
	}
	if currentVCN == nil || !networkVCNOwned(*currentVCN, declared.Code) || !sameObservedVCN(*currentVCN, *observed.VCN) {
		return &InvalidOperationError{Message: "refusing stale or ownership-changed VCN rule mutation"}
	}
	groups, err := r.Gateway.ListNSGs(ctx, observed.VCN.ID)
	if err != nil {
		return err
	}
	var currentNSG *ObservedNSG
	for index := range groups {
		if groups[index].ID == id && groups[index].DisplayName == name {
			currentNSG = &groups[index]
			break
		}
	}
	var expected ObservedNSG
	for _, group := range observed.NSGs {
		if group.ID == id && group.DisplayName == name {
			expected = group
			break
		}
	}
	if currentNSG == nil || !networkNSGOwned(*currentNSG, declared.Code) || currentNSG.VCNID != observed.VCN.ID || !sameObservedNSG(*currentNSG, expected) {
		return &InvalidOperationError{Message: "refusing stale or ownership-changed NSG rule mutation"}
	}
	return nil
}

func (r *NetworkReconciler) removeOwnedNSGRules(ctx context.Context, declared estate.Region, observed NetworkObserved, name, nsgID string, ids []string) error {
	if err := r.verifyOwnedNSG(ctx, declared, observed, name, nsgID); err != nil {
		return err
	}
	var expected ObservedNSG
	for _, group := range observed.NSGs {
		if group.DisplayName == name && group.ID == nsgID {
			expected = group
			break
		}
	}
	if !networkNSGOwned(expected, declared.Code) || expected.VCNID != observed.VCN.ID {
		return &InvalidOperationError{Message: "security rule removal requires an owned NSG in the declared VCN"}
	}
	current, err := r.Gateway.ListNSGRules(ctx, nsgID)
	if err != nil {
		return err
	}
	byID := make(map[string]ObservedSecurityRule, len(current))
	for _, rule := range current {
		byID[rule.ID] = rule
	}
	expectedRules := make(map[string]ObservedSecurityRule, len(observed.Rules[name]))
	for _, rule := range observed.Rules[name] {
		expectedRules[rule.ID] = rule
	}
	for _, id := range ids {
		rule, ok := byID[id]
		expected, expectedOK := expectedRules[id]
		if !ok || !expectedOK || !rule.Managed || !isOCID(id, "securityrule") || !sameObservedSecurityRule(rule, expected) {
			return &InvalidOperationError{Message: "refusing unowned or stale security rule removal"}
		}
	}
	return r.Gateway.RemoveNSGRules(ctx, nsgID, ids)
}

func sameObservedSecurityRule(a, b ObservedSecurityRule) bool {
	return a.ID == b.ID && a.Direction == b.Direction && a.Protocol == b.Protocol && a.Peer == b.Peer && a.PortMin == b.PortMin && a.PortMax == b.PortMax && a.Managed == b.Managed
}

// SecurityRuleSpecs converts one declared security group into provider rule
// specs.
func SecurityRuleSpecs(group estate.NetworkSecurityGroup) []SecurityRuleSpec {
	specs := make([]SecurityRuleSpec, 0, len(group.Rules))
	for _, rule := range group.Rules {
		specs = append(specs, SecurityRuleSpec{Direction: rule.Direction, Protocol: rule.Protocol, Peer: rule.Peer, PortMin: rule.PortMin, PortMax: rule.PortMax})
	}
	return specs
}

// routeRuleSpecs converts declared routes into provider route specs. The
// NAT gateway identity is resolved at apply time.
func routeRuleSpecs(rules []estate.RouteRule) []RouteRuleSpec {
	specs := make([]RouteRuleSpec, 0, len(rules))
	for _, rule := range rules {
		specs = append(specs, RouteRuleSpec{Destination: rule.Destination})
	}
	return specs
}

// routeRulesMatch reports whether the observed rule set is exactly the
// declared routes through the Region NAT gateway.
func routeRulesMatch(declared []estate.RouteRule, observed []ObservedRouteRule, natID string) bool {
	if len(declared) != len(observed) {
		return false
	}
	matched := make([]bool, len(observed))
	for _, rule := range declared {
		found := false
		for i, candidate := range observed {
			if matched[i] || candidate.TargetID != natID || !sameRouteDestination(rule.Destination, candidate.Destination) {
				continue
			}
			matched[i] = true
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

// sameRouteDestination compares two CIDR destinations canonically.
func sameRouteDestination(declared, observed string) bool {
	want, err := netip.ParsePrefix(declared)
	if err != nil {
		return false
	}
	have, err := netip.ParsePrefix(observed)
	if err != nil {
		return false
	}
	return want.Masked() == have.Masked()
}

// diffSecurityRules returns the rules to add and the observed rule ids to
// remove so the group matches its declaration exactly.
func diffSecurityRules(declared []estate.NetworkSecurityRule, observed []ObservedSecurityRule) (add []SecurityRuleSpec, removeIDs []string) {
	unmatched := make([]ObservedSecurityRule, len(observed))
	copy(unmatched, observed)
	for _, rule := range declared {
		spec := SecurityRuleSpec{Direction: rule.Direction, Protocol: rule.Protocol, Peer: rule.Peer, PortMin: rule.PortMin, PortMax: rule.PortMax}
		matched := false
		for i, candidate := range unmatched {
			if candidate.ID == "" || !spec.MatchesObserved(candidate) {
				continue
			}
			unmatched = append(unmatched[:i], unmatched[i+1:]...)
			matched = true
			break
		}
		if !matched {
			add = append(add, spec)
		}
	}
	for _, candidate := range unmatched {
		if candidate.ID != "" && candidate.Managed {
			removeIDs = append(removeIDs, candidate.ID)
		}
	}
	sort.Strings(removeIDs)
	return add, removeIDs
}

// MatchesObserved reports whether the spec describes the observed rule.
func (s SecurityRuleSpec) MatchesObserved(observed ObservedSecurityRule) bool {
	if observed.Direction != ingressDirection(s.Direction) || observed.Protocol != securityProtocolNumbers[s.Protocol] || observed.Peer != s.Peer {
		return false
	}
	if s.Protocol == "icmp" {
		return true
	}
	return observed.PortMin == s.PortMin && observed.PortMax == s.PortMax
}

func ingressDirection(declared string) string {
	if declared == "egress" {
		return "EGRESS"
	}
	return "INGRESS"
}

// OCINetworkGateway is the real core-service gateway over the signed OCI
// HTTP transport. It performs no retries beyond the transport's own.
type OCINetworkGateway struct {
	Core          *OCIHTTPTransport
	CompartmentID string
	Scope         string
}

var _ NetworkGateway = (*OCINetworkGateway)(nil)

// networkRetryToken is deterministic for one logical mutation. Hashing the
// operation identity keeps the OCI header bounded while allowing an
// ambiguous response to be retried without creating a second resource.
func networkRetryToken(kind string, value any) string {
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(append([]byte(kind+"\x00"), raw...))
	return "terrascale-" + kind + "-" + hex.EncodeToString(digest[:])
}

// NewOCINetworkGateway validates the compartment scope and service authority.
func NewOCINetworkGateway(core *OCIHTTPTransport, compartmentID string, scope ...string) (*OCINetworkGateway, error) {
	if core == nil || core.Config.Service != OCIServiceCore {
		return nil, &errs.Argument{Message: "network gateway requires the OCI core transport"}
	}
	if !isOCID(compartmentID, "compartment") {
		return nil, &errs.Argument{Message: "network gateway requires a compartment identity"}
	}
	region := ""
	if len(scope) > 0 {
		region = scope[0]
	}
	return &OCINetworkGateway{Core: core, CompartmentID: compartmentID, Scope: region}, nil
}

func networkOwnershipTags(region, kind string) map[string]string {
	if region == "" {
		return map[string]string{OCIManagedTag: kind}
	}
	return map[string]string{OCIManagedTag: kind, OCIScopeTag: region}
}

type ociVCNDocument struct {
	ID             string            `json:"id"`
	CompartmentID  string            `json:"compartmentId"`
	DisplayName    string            `json:"displayName"`
	CIDRBlocks     []string          `json:"cidrBlocks"`
	LifecycleState string            `json:"lifecycleState"`
	FreeformTags   map[string]string `json:"freeformTags"`
}

func ociVCNObserved(document ociVCNDocument) (ObservedVCN, error) {
	if !isOCID(document.ID, "vcn") || len(document.CIDRBlocks) == 0 {
		return ObservedVCN{}, &InvalidDataError{Message: "OCI VCN response is invalid"}
	}
	return ObservedVCN{ID: document.ID, DisplayName: document.DisplayName, CIDR: document.CIDRBlocks[0], LifecycleState: document.LifecycleState, CompartmentID: document.CompartmentID, FreeformTags: copyOCITags(document.FreeformTags)}, nil
}

func (g *OCINetworkGateway) ListVCNs(ctx context.Context, name string) ([]ObservedVCN, error) {
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	query.Set("displayName", name)
	var list struct {
		Items []ociVCNDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/vcns?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	vcns := make([]ObservedVCN, 0, len(list.Items))
	for _, item := range list.Items {
		observed, err := ociVCNObserved(item)
		if err != nil {
			return nil, err
		}
		vcns = append(vcns, observed)
	}
	return vcns, nil
}

func (g *OCINetworkGateway) CreateVCN(ctx context.Context, name, cidr string) (ObservedVCN, error) {
	if !validEstateName(name) || !validCIDR(cidr) {
		return ObservedVCN{}, &errs.Argument{Message: "VCN create request is invalid"}
	}
	var document ociVCNDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/vcns", struct {
		CompartmentID string            `json:"compartmentId"`
		DisplayName   string            `json:"displayName"`
		CIDRBlocks    []string          `json:"cidrBlocks"`
		FreeformTags  map[string]string `json:"freeformTags"`
	}{CompartmentID: g.CompartmentID, DisplayName: name, CIDRBlocks: []string{cidr}, FreeformTags: networkOwnershipTags(g.Scope, "vcn")}, map[string]string{"opc-retry-token": networkRetryToken("vcn", struct{ Compartment, Name, CIDR string }{g.CompartmentID, name, cidr})}, &document); err != nil {
		return ObservedVCN{}, err
	}
	return ociVCNObserved(document)
}

type ociSubnetDocument struct {
	ID                     string            `json:"id"`
	CompartmentID          string            `json:"compartmentId"`
	VCNID                  string            `json:"vcnId"`
	DisplayName            string            `json:"displayName"`
	CIDRBlock              string            `json:"cidrBlock"`
	LifecycleState         string            `json:"lifecycleState"`
	ProhibitPublicIPOnVNIC bool              `json:"prohibitPublicIpOnVnic"`
	RouteTableID           string            `json:"routeTableId"`
	FreeformTags           map[string]string `json:"freeformTags"`
}

func (g *OCINetworkGateway) ListSubnets(ctx context.Context, vcnID string) ([]ObservedSubnet, error) {
	if !isOCID(vcnID, "vcn") {
		return nil, &errs.Argument{Message: "subnet list requires a VCN identity"}
	}
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	query.Set("vcnId", vcnID)
	var list struct {
		Items []ociSubnetDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/subnets?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	subnets := make([]ObservedSubnet, 0, len(list.Items))
	for _, item := range list.Items {
		if !isOCID(item.ID, "subnet") {
			return nil, &InvalidDataError{Message: "OCI subnet response is invalid"}
		}
		subnets = append(subnets, ObservedSubnet{ID: item.ID, VCNID: item.VCNID, DisplayName: item.DisplayName, CIDR: item.CIDRBlock, LifecycleState: item.LifecycleState, RouteTableID: item.RouteTableID, CompartmentID: item.CompartmentID, FreeformTags: copyOCITags(item.FreeformTags)})
	}
	return subnets, nil
}

func (g *OCINetworkGateway) CreateSubnet(ctx context.Context, vcnID, name, cidr string) (ObservedSubnet, error) {
	if !isOCID(vcnID, "vcn") || !validEstateName(name) || !validCIDR(cidr) {
		return ObservedSubnet{}, &errs.Argument{Message: "subnet create request is invalid"}
	}
	var document ociSubnetDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/subnets", struct {
		CompartmentID          string            `json:"compartmentId"`
		VCNID                  string            `json:"vcnId"`
		DisplayName            string            `json:"displayName"`
		CIDRBlock              string            `json:"cidrBlock"`
		ProhibitPublicIPOnVNIC bool              `json:"prohibitPublicIpOnVnic"`
		FreeformTags           map[string]string `json:"freeformTags"`
	}{CompartmentID: g.CompartmentID, VCNID: vcnID, DisplayName: name, CIDRBlock: cidr, ProhibitPublicIPOnVNIC: true, FreeformTags: networkOwnershipTags(g.Scope, "subnet")}, map[string]string{"opc-retry-token": networkRetryToken("subnet", struct{ VCN, Name, CIDR string }{vcnID, name, cidr})}, &document); err != nil {
		return ObservedSubnet{}, err
	}
	if !isOCID(document.ID, "subnet") {
		return ObservedSubnet{}, &InvalidDataError{Message: "OCI subnet create response is invalid"}
	}
	return ObservedSubnet{ID: document.ID, VCNID: document.VCNID, DisplayName: document.DisplayName, CIDR: document.CIDRBlock, LifecycleState: document.LifecycleState, RouteTableID: document.RouteTableID, CompartmentID: document.CompartmentID, FreeformTags: copyOCITags(document.FreeformTags)}, nil
}

type ociNSGDocument struct {
	ID             string            `json:"id"`
	CompartmentID  string            `json:"compartmentId"`
	VCNID          string            `json:"vcnId"`
	DisplayName    string            `json:"displayName"`
	LifecycleState string            `json:"lifecycleState"`
	FreeformTags   map[string]string `json:"freeformTags"`
}

func (g *OCINetworkGateway) ListNSGs(ctx context.Context, vcnID string) ([]ObservedNSG, error) {
	if !isOCID(vcnID, "vcn") {
		return nil, &errs.Argument{Message: "network security group list requires a VCN identity"}
	}
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	query.Set("vcnId", vcnID)
	var list struct {
		Items []ociNSGDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/networkSecurityGroups?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	groups := make([]ObservedNSG, 0, len(list.Items))
	for _, item := range list.Items {
		if !isOCID(item.ID, "networksecuritygroup") {
			return nil, &InvalidDataError{Message: "OCI network security group response is invalid"}
		}
		groups = append(groups, ObservedNSG{ID: item.ID, VCNID: item.VCNID, DisplayName: item.DisplayName, LifecycleState: item.LifecycleState, CompartmentID: item.CompartmentID, FreeformTags: copyOCITags(item.FreeformTags)})
	}
	return groups, nil
}

func (g *OCINetworkGateway) CreateNSG(ctx context.Context, vcnID, name string) (ObservedNSG, error) {
	if !isOCID(vcnID, "vcn") || !validEstateName(name) {
		return ObservedNSG{}, &errs.Argument{Message: "network security group create request is invalid"}
	}
	var document ociNSGDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/networkSecurityGroups", struct {
		CompartmentID string            `json:"compartmentId"`
		VCNID         string            `json:"vcnId"`
		DisplayName   string            `json:"displayName"`
		FreeformTags  map[string]string `json:"freeformTags"`
	}{CompartmentID: g.CompartmentID, VCNID: vcnID, DisplayName: name, FreeformTags: networkOwnershipTags(g.Scope, "networksecuritygroup")}, map[string]string{"opc-retry-token": networkRetryToken("nsg", struct{ VCN, Name string }{vcnID, name})}, &document); err != nil {
		return ObservedNSG{}, err
	}
	if !isOCID(document.ID, "networksecuritygroup") {
		return ObservedNSG{}, &InvalidDataError{Message: "OCI network security group create response is invalid"}
	}
	return ObservedNSG{ID: document.ID, VCNID: document.VCNID, DisplayName: document.DisplayName, LifecycleState: document.LifecycleState, CompartmentID: document.CompartmentID, FreeformTags: copyOCITags(document.FreeformTags)}, nil
}

type ociPortRange struct {
	Min uint16 `json:"min"`
	Max uint16 `json:"max"`
}

type ociRuleOptions struct {
	DestinationPortRange *ociPortRange `json:"destinationPortRange,omitempty"`
}

type ociSecurityRuleDocument struct {
	ID          string          `json:"id"`
	Direction   string          `json:"direction"`
	Protocol    string          `json:"protocol"`
	Source      string          `json:"source,omitempty"`
	Destination string          `json:"destination,omitempty"`
	TCPOptions  *ociRuleOptions `json:"tcpOptions,omitempty"`
	UDPOptions  *ociRuleOptions `json:"udpOptions,omitempty"`
}

type ociSecurityRuleWire struct {
	Direction   string          `json:"direction"`
	Protocol    string          `json:"protocol"`
	Source      string          `json:"source,omitempty"`
	Destination string          `json:"destination,omitempty"`
	TCPOptions  *ociRuleOptions `json:"tcpOptions,omitempty"`
	UDPOptions  *ociRuleOptions `json:"udpOptions,omitempty"`
	IsStateless bool            `json:"isStateless"`
}

func observedSecurityRule(document ociSecurityRuleDocument) (ObservedSecurityRule, error) {
	if !isOCID(document.ID, "securityrule") || (document.Source == "" && document.Destination == "") {
		return ObservedSecurityRule{}, &InvalidDataError{Message: "OCI security rule response is invalid"}
	}
	peer := document.Source
	if peer == "" {
		peer = document.Destination
	}
	rule := ObservedSecurityRule{ID: document.ID, Direction: document.Direction, Protocol: document.Protocol, Peer: peer}
	switch document.Protocol {
	case "6":
		if document.TCPOptions != nil && document.TCPOptions.DestinationPortRange != nil {
			rule.PortMin, rule.PortMax = document.TCPOptions.DestinationPortRange.Min, document.TCPOptions.DestinationPortRange.Max
		}
	case "17":
		if document.UDPOptions != nil && document.UDPOptions.DestinationPortRange != nil {
			rule.PortMin, rule.PortMax = document.UDPOptions.DestinationPortRange.Min, document.UDPOptions.DestinationPortRange.Max
		}
	case "1":
	default:
		return ObservedSecurityRule{}, &InvalidDataError{Message: "OCI security rule response has an unknown protocol"}
	}
	return rule, nil
}

func securityRuleWire(spec SecurityRuleSpec) (ociSecurityRuleWire, error) {
	if err := validateSecurityRuleSpec(spec); err != nil {
		return ociSecurityRuleWire{}, err
	}
	wire := ociSecurityRuleWire{Protocol: securityProtocolNumbers[strings.ToLower(spec.Protocol)], IsStateless: false}
	if spec.Direction == "egress" {
		wire.Direction = "EGRESS"
		wire.Destination = spec.Peer
	} else {
		wire.Direction = "INGRESS"
		wire.Source = spec.Peer
	}
	if spec.Protocol != "icmp" {
		options := &ociRuleOptions{DestinationPortRange: &ociPortRange{Min: spec.PortMin, Max: spec.PortMax}}
		if spec.Protocol == "udp" {
			wire.UDPOptions = options
		} else {
			wire.TCPOptions = options
		}
	}
	return wire, nil
}

func validateSecurityRuleSpec(spec SecurityRuleSpec) error {
	direction := strings.ToLower(strings.TrimSpace(spec.Direction))
	protocol := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if direction != "ingress" && direction != "egress" {
		return &errs.Argument{Message: "security rule direction is invalid"}
	}
	if _, known := securityProtocolNumbers[protocol]; !known {
		return &errs.Argument{Message: "security rule protocol is invalid"}
	}
	if _, err := netip.ParsePrefix(spec.Peer); err != nil {
		return &errs.Argument{Message: "security rule peer must be a CIDR prefix"}
	}
	if protocol == "icmp" {
		if spec.PortMin != 0 || spec.PortMax != 0 {
			return &errs.Argument{Message: "ICMP security rule cannot declare ports"}
		}
		return nil
	}
	if spec.PortMin == 0 || spec.PortMax < spec.PortMin {
		return &errs.Argument{Message: "security rule port range is invalid"}
	}
	return nil
}

func (g *OCINetworkGateway) ListNSGRules(ctx context.Context, nsgID string) ([]ObservedSecurityRule, error) {
	if !isOCID(nsgID, "networksecuritygroup") {
		return nil, &errs.Argument{Message: "security rule list requires a network security group identity"}
	}
	var list struct {
		Items []ociSecurityRuleDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/networkSecurityGroups/"+url.PathEscape(nsgID)+"/securityRules", nil, nil, &list); err != nil {
		return nil, err
	}
	rules := make([]ObservedSecurityRule, 0, len(list.Items))
	for _, item := range list.Items {
		rule, err := observedSecurityRule(item)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (g *OCINetworkGateway) AddNSGRules(ctx context.Context, nsgID string, rules []SecurityRuleSpec) error {
	if !isOCID(nsgID, "networksecuritygroup") || len(rules) == 0 || len(rules) > 64 {
		return &errs.Argument{Message: "security rule add request is invalid"}
	}
	wire := make([]ociSecurityRuleWire, 0, len(rules))
	for _, spec := range rules {
		rule, err := securityRuleWire(spec)
		if err != nil {
			return err
		}
		wire = append(wire, rule)
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodPost, "/20160918/networkSecurityGroups/"+url.PathEscape(nsgID)+"/securityRules", struct {
		SecurityRules []ociSecurityRuleWire `json:"securityRules"`
	}{SecurityRules: wire}, map[string]string{"opc-retry-token": networkRetryToken("nsg-rules-add", struct {
		NSG   string
		Rules []SecurityRuleSpec
	}{nsgID, rules})}, nil)
}

func (g *OCINetworkGateway) RemoveNSGRules(ctx context.Context, nsgID string, ruleIDs []string) error {
	if !isOCID(nsgID, "networksecuritygroup") || len(ruleIDs) == 0 || len(ruleIDs) > 64 {
		return &errs.Argument{Message: "security rule remove request is invalid"}
	}
	for _, id := range ruleIDs {
		if !isOCID(id, "securityrule") {
			return &errs.Argument{Message: "security rule remove request contains an invalid identity"}
		}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodPost, "/20160918/networkSecurityGroups/"+url.PathEscape(nsgID)+"/securityRules/actions/remove", struct {
		SecurityRuleIDs []string `json:"securityRuleIds"`
	}{SecurityRuleIDs: ruleIDs}, map[string]string{"opc-retry-token": networkRetryToken("nsg-rules-remove", struct {
		NSG string
		IDs []string
	}{nsgID, ruleIDs})}, nil)
}

type ociNATGatewayDocument struct {
	ID             string            `json:"id"`
	CompartmentID  string            `json:"compartmentId"`
	VCNID          string            `json:"vcnId"`
	DisplayName    string            `json:"displayName"`
	LifecycleState string            `json:"lifecycleState"`
	FreeformTags   map[string]string `json:"freeformTags"`
}

func ociNATGatewayObserved(document ociNATGatewayDocument) (ObservedNATGateway, error) {
	if !isOCID(document.ID, "natgateway") {
		return ObservedNATGateway{}, &InvalidDataError{Message: "OCI NAT gateway response is invalid"}
	}
	return ObservedNATGateway{ID: document.ID, VCNID: document.VCNID, DisplayName: document.DisplayName, LifecycleState: document.LifecycleState, CompartmentID: document.CompartmentID, FreeformTags: copyOCITags(document.FreeformTags)}, nil
}

func (g *OCINetworkGateway) ListNATGateways(ctx context.Context, vcnID string) ([]ObservedNATGateway, error) {
	if !isOCID(vcnID, "vcn") {
		return nil, &errs.Argument{Message: "NAT gateway list requires a VCN identity"}
	}
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	query.Set("vcnId", vcnID)
	var list struct {
		Items []ociNATGatewayDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/natGateways?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	gateways := make([]ObservedNATGateway, 0, len(list.Items))
	for _, item := range list.Items {
		observed, err := ociNATGatewayObserved(item)
		if err != nil {
			return nil, err
		}
		gateways = append(gateways, observed)
	}
	return gateways, nil
}

func (g *OCINetworkGateway) CreateNATGateway(ctx context.Context, vcnID, name string) (ObservedNATGateway, error) {
	if !isOCID(vcnID, "vcn") || !validEstateName(name) {
		return ObservedNATGateway{}, &errs.Argument{Message: "NAT gateway create request is invalid"}
	}
	var document ociNATGatewayDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/natGateways", struct {
		CompartmentID string            `json:"compartmentId"`
		VCNID         string            `json:"vcnId"`
		DisplayName   string            `json:"displayName"`
		FreeformTags  map[string]string `json:"freeformTags"`
	}{CompartmentID: g.CompartmentID, VCNID: vcnID, DisplayName: name, FreeformTags: networkOwnershipTags(g.Scope, "natgateway")}, map[string]string{"opc-retry-token": networkRetryToken("nat-gateway", struct{ VCN, Name string }{vcnID, name})}, &document); err != nil {
		return ObservedNATGateway{}, err
	}
	return ociNATGatewayObserved(document)
}

type ociRouteRuleDocument struct {
	Destination     string `json:"destination"`
	DestinationType string `json:"destinationType"`
	NetworkEntityID string `json:"networkEntityId"`
}

type ociRouteTableDocument struct {
	ID             string                 `json:"id"`
	CompartmentID  string                 `json:"compartmentId"`
	VCNID          string                 `json:"vcnId"`
	DisplayName    string                 `json:"displayName"`
	LifecycleState string                 `json:"lifecycleState"`
	RouteRules     []ociRouteRuleDocument `json:"routeRules"`
	FreeformTags   map[string]string      `json:"freeformTags"`
}

// networkEntityType derives the OCI entity kind from a target OCID
// (ocid1.natgateway.oc1... -> "natgateway"); empty when unrecognized.
func networkEntityType(ocid string) string {
	rest, ok := strings.CutPrefix(ocid, "ocid1.")
	if !ok {
		return ""
	}
	kind, _, ok := strings.Cut(rest, ".")
	if !ok {
		return ""
	}
	return kind
}

// observedRouteRule normalizes one reported route rule. Rules without a
// target entity or destination are rejected: they cannot be matched against
// a declaration.
func observedRouteRule(document ociRouteRuleDocument) (ObservedRouteRule, error) {
	if document.NetworkEntityID == "" || document.Destination == "" {
		return ObservedRouteRule{}, &InvalidDataError{Message: "OCI route rule response is invalid"}
	}
	targetType := networkEntityType(document.NetworkEntityID)
	if targetType == "" {
		return ObservedRouteRule{}, &InvalidDataError{Message: "OCI route rule target is unrecognized"}
	}
	if _, err := netip.ParsePrefix(document.Destination); err != nil {
		return ObservedRouteRule{}, &InvalidDataError{Message: "OCI route rule destination is invalid"}
	}
	return ObservedRouteRule{Destination: document.Destination, TargetID: document.NetworkEntityID, TargetType: targetType}, nil
}

func ociRouteTableObserved(document ociRouteTableDocument) (ObservedRouteTable, error) {
	if !isOCID(document.ID, "routetable") {
		return ObservedRouteTable{}, &InvalidDataError{Message: "OCI route table response is invalid"}
	}
	rules := make([]ObservedRouteRule, 0, len(document.RouteRules))
	for _, item := range document.RouteRules {
		rule, err := observedRouteRule(item)
		if err != nil {
			return ObservedRouteTable{}, err
		}
		rules = append(rules, rule)
	}
	return ObservedRouteTable{ID: document.ID, VCNID: document.VCNID, DisplayName: document.DisplayName, LifecycleState: document.LifecycleState, Routes: rules, CompartmentID: document.CompartmentID, FreeformTags: copyOCITags(document.FreeformTags)}, nil
}

func (g *OCINetworkGateway) ListRouteTables(ctx context.Context, vcnID string) ([]ObservedRouteTable, error) {
	if !isOCID(vcnID, "vcn") {
		return nil, &errs.Argument{Message: "route table list requires a VCN identity"}
	}
	query := url.Values{}
	query.Set("compartmentId", g.CompartmentID)
	query.Set("vcnId", vcnID)
	var list struct {
		Items []ociRouteTableDocument `json:"items"`
	}
	if err := doOCIJSON(ctx, g.Core, http.MethodGet, "/20160918/routeTables?"+query.Encode(), nil, nil, &list); err != nil {
		return nil, err
	}
	tables := make([]ObservedRouteTable, 0, len(list.Items))
	for _, item := range list.Items {
		observed, err := ociRouteTableObserved(item)
		if err != nil {
			return nil, err
		}
		tables = append(tables, observed)
	}
	return tables, nil
}

// routeRuleWire renders one declared route for the OCI API: a CIDR_BLOCK
// destination through the Region's NAT gateway.
func routeRuleWire(spec RouteRuleSpec) (ociRouteRuleDocument, error) {
	destination, err := netip.ParsePrefix(spec.Destination)
	if err != nil {
		return ociRouteRuleDocument{}, &errs.Argument{Message: "route destination must be a CIDR prefix"}
	}
	if !isOCID(spec.NATGatewayID, "natgateway") {
		return ociRouteRuleDocument{}, &errs.Argument{Message: "route target must be a NAT gateway identity"}
	}
	return ociRouteRuleDocument{Destination: destination.Masked().String(), DestinationType: "CIDR_BLOCK", NetworkEntityID: spec.NATGatewayID}, nil
}

func routeRulesWire(rules []RouteRuleSpec) ([]ociRouteRuleDocument, error) {
	if len(rules) == 0 {
		return nil, &errs.Argument{Message: "route table must declare at least one route"}
	}
	wire := make([]ociRouteRuleDocument, 0, len(rules))
	for _, spec := range rules {
		rule, err := routeRuleWire(spec)
		if err != nil {
			return nil, err
		}
		wire = append(wire, rule)
	}
	return wire, nil
}

func (g *OCINetworkGateway) CreateRouteTable(ctx context.Context, vcnID, name string, rules []RouteRuleSpec) (ObservedRouteTable, error) {
	if !isOCID(vcnID, "vcn") || !validEstateName(name) {
		return ObservedRouteTable{}, &errs.Argument{Message: "route table create request is invalid"}
	}
	wire, err := routeRulesWire(rules)
	if err != nil {
		return ObservedRouteTable{}, err
	}
	var document ociRouteTableDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/routeTables", struct {
		CompartmentID string                 `json:"compartmentId"`
		VCNID         string                 `json:"vcnId"`
		DisplayName   string                 `json:"displayName"`
		RouteRules    []ociRouteRuleDocument `json:"routeRules"`
		FreeformTags  map[string]string      `json:"freeformTags"`
	}{CompartmentID: g.CompartmentID, VCNID: vcnID, DisplayName: name, RouteRules: wire, FreeformTags: networkOwnershipTags(g.Scope, "routetable")}, map[string]string{"opc-retry-token": networkRetryToken("route-table", struct {
		VCN   string
		Name  string
		Rules []RouteRuleSpec
	}{vcnID, name, rules})}, &document); err != nil {
		return ObservedRouteTable{}, err
	}
	return ociRouteTableObserved(document)
}

func (g *OCINetworkGateway) ReplaceRouteRules(ctx context.Context, routeTableID string, rules []RouteRuleSpec) error {
	if !isOCID(routeTableID, "routetable") {
		return &errs.Argument{Message: "route rule replacement requires a route table identity"}
	}
	wire, err := routeRulesWire(rules)
	if err != nil {
		return err
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodPut, "/20160918/routeTables/"+url.PathEscape(routeTableID), struct {
		RouteRules []ociRouteRuleDocument `json:"routeRules"`
	}{RouteRules: wire}, map[string]string{"opc-retry-token": networkRetryToken("route-table-rules", struct {
		Table string
		Rules []RouteRuleSpec
	}{routeTableID, rules})}, nil)
}

func (g *OCINetworkGateway) AttachSubnetRouteTable(ctx context.Context, subnetID, routeTableID string) error {
	if !isOCID(subnetID, "subnet") || !isOCID(routeTableID, "routetable") {
		return &errs.Argument{Message: "subnet route attachment request is invalid"}
	}
	return doOCIJSON[struct{}](ctx, g.Core, http.MethodPut, "/20160918/subnets/"+url.PathEscape(subnetID), struct {
		RouteTableID string `json:"routeTableId"`
	}{RouteTableID: routeTableID}, map[string]string{"opc-retry-token": networkRetryToken("subnet-route-attach", struct{ Subnet, Table string }{subnetID, routeTableID})}, nil)
}

func validEstateName(name string) bool {
	return len(name) >= 1 && len(name) <= 63 && tokenPattern.MatchString(name)
}

func validCIDR(cidr string) bool {
	_, err := netip.ParsePrefix(cidr)
	return err == nil
}
