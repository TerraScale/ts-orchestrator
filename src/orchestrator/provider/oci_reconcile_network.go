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
// subnets, and network security groups from the declared estate (D-67). VCN
// and subnet CIDR drift is refused loudly instead of repaired: renumbering a
// live network strands every attached resource.

// VCNName derives the deterministic VCN display name for a Region code.
func VCNName(regionCode string) string { return "terrascale-" + regionCode }

type ObservedVCN struct {
	ID             string
	DisplayName    string
	CIDR           string
	LifecycleState string
}

type ObservedSubnet struct {
	ID             string
	VCNID          string
	DisplayName    string
	CIDR           string
	LifecycleState string
}

type ObservedNSG struct {
	ID             string
	VCNID          string
	DisplayName    string
	LifecycleState string
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
}

type NetworkObserved struct {
	VCN     *ObservedVCN
	Subnets []ObservedSubnet
	NSGs    []ObservedNSG
	Rules   map[string][]ObservedSecurityRule
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
	return plan, nil
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
	if observedNetworkState(observed.VCN.LifecycleState) != networkStateActive || observed.VCN.CIDR != declared.Network.CIDR {
		return false, nil
	}
	subnets := make(map[string]ObservedSubnet, len(observed.Subnets))
	for _, subnet := range observed.Subnets {
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
			if len(a.RemoveIDs) > 0 {
				if err := r.Gateway.RemoveNSGRules(ctx, nsgID, a.RemoveIDs); err != nil {
					return err
				}
			}
			if len(a.Add) > 0 {
				if err := r.Gateway.AddNSGRules(ctx, nsgID, a.Add); err != nil {
					return err
				}
			}
		default:
			return &InvalidOperationError{Message: "network reconciler received a foreign action"}
		}
	}
	return nil
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
		if candidate.ID != "" {
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
func NewOCINetworkGateway(core *OCIHTTPTransport, compartmentID string) (*OCINetworkGateway, error) {
	if core == nil || core.Config.Service != OCIServiceCore {
		return nil, &errs.Argument{Message: "network gateway requires the OCI core transport"}
	}
	if !isOCID(compartmentID, "compartment") {
		return nil, &errs.Argument{Message: "network gateway requires a compartment identity"}
	}
	return &OCINetworkGateway{Core: core, CompartmentID: compartmentID}, nil
}

type ociVCNDocument struct {
	ID             string   `json:"id"`
	DisplayName    string   `json:"displayName"`
	CIDRBlocks     []string `json:"cidrBlocks"`
	LifecycleState string   `json:"lifecycleState"`
}

func ociVCNObserved(document ociVCNDocument) (ObservedVCN, error) {
	if !isOCID(document.ID, "vcn") || len(document.CIDRBlocks) == 0 {
		return ObservedVCN{}, &InvalidDataError{Message: "OCI VCN response is invalid"}
	}
	return ObservedVCN{ID: document.ID, DisplayName: document.DisplayName, CIDR: document.CIDRBlocks[0], LifecycleState: document.LifecycleState}, nil
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
		CompartmentID string   `json:"compartmentId"`
		DisplayName   string   `json:"displayName"`
		CIDRBlocks    []string `json:"cidrBlocks"`
	}{CompartmentID: g.CompartmentID, DisplayName: name, CIDRBlocks: []string{cidr}}, map[string]string{"opc-retry-token": networkRetryToken("vcn", struct{ Compartment, Name, CIDR string }{g.CompartmentID, name, cidr})}, &document); err != nil {
		return ObservedVCN{}, err
	}
	return ociVCNObserved(document)
}

type ociSubnetDocument struct {
	ID                     string `json:"id"`
	VCNID                  string `json:"vcnId"`
	DisplayName            string `json:"displayName"`
	CIDRBlock              string `json:"cidrBlock"`
	LifecycleState         string `json:"lifecycleState"`
	ProhibitPublicIPOnVNIC bool   `json:"prohibitPublicIpOnVnic"`
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
		subnets = append(subnets, ObservedSubnet{ID: item.ID, VCNID: item.VCNID, DisplayName: item.DisplayName, CIDR: item.CIDRBlock, LifecycleState: item.LifecycleState})
	}
	return subnets, nil
}

func (g *OCINetworkGateway) CreateSubnet(ctx context.Context, vcnID, name, cidr string) (ObservedSubnet, error) {
	if !isOCID(vcnID, "vcn") || !validEstateName(name) || !validCIDR(cidr) {
		return ObservedSubnet{}, &errs.Argument{Message: "subnet create request is invalid"}
	}
	var document ociSubnetDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/subnets", struct {
		CompartmentID          string `json:"compartmentId"`
		VCNID                  string `json:"vcnId"`
		DisplayName            string `json:"displayName"`
		CIDRBlock              string `json:"cidrBlock"`
		ProhibitPublicIPOnVNIC bool   `json:"prohibitPublicIpOnVnic"`
	}{CompartmentID: g.CompartmentID, VCNID: vcnID, DisplayName: name, CIDRBlock: cidr, ProhibitPublicIPOnVNIC: true}, map[string]string{"opc-retry-token": networkRetryToken("subnet", struct{ VCN, Name, CIDR string }{vcnID, name, cidr})}, &document); err != nil {
		return ObservedSubnet{}, err
	}
	if !isOCID(document.ID, "subnet") {
		return ObservedSubnet{}, &InvalidDataError{Message: "OCI subnet create response is invalid"}
	}
	return ObservedSubnet{ID: document.ID, VCNID: document.VCNID, DisplayName: document.DisplayName, CIDR: document.CIDRBlock, LifecycleState: document.LifecycleState}, nil
}

type ociNSGDocument struct {
	ID             string `json:"id"`
	VCNID          string `json:"vcnId"`
	DisplayName    string `json:"displayName"`
	LifecycleState string `json:"lifecycleState"`
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
		groups = append(groups, ObservedNSG{ID: item.ID, VCNID: item.VCNID, DisplayName: item.DisplayName, LifecycleState: item.LifecycleState})
	}
	return groups, nil
}

func (g *OCINetworkGateway) CreateNSG(ctx context.Context, vcnID, name string) (ObservedNSG, error) {
	if !isOCID(vcnID, "vcn") || !validEstateName(name) {
		return ObservedNSG{}, &errs.Argument{Message: "network security group create request is invalid"}
	}
	var document ociNSGDocument
	if err := doOCIJSON(ctx, g.Core, http.MethodPost, "/20160918/networkSecurityGroups", struct {
		CompartmentID string `json:"compartmentId"`
		VCNID         string `json:"vcnId"`
		DisplayName   string `json:"displayName"`
	}{CompartmentID: g.CompartmentID, VCNID: vcnID, DisplayName: name}, map[string]string{"opc-retry-token": networkRetryToken("nsg", struct{ VCN, Name string }{vcnID, name})}, &document); err != nil {
		return ObservedNSG{}, err
	}
	if !isOCID(document.ID, "networksecuritygroup") {
		return ObservedNSG{}, &InvalidDataError{Message: "OCI network security group create response is invalid"}
	}
	return ObservedNSG{ID: document.ID, VCNID: document.VCNID, DisplayName: document.DisplayName, LifecycleState: document.LifecycleState}, nil
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

func validEstateName(name string) bool {
	return len(name) >= 1 && len(name) <= 63 && tokenPattern.MatchString(name)
}

func validCIDR(cidr string) bool {
	_, err := netip.ParsePrefix(cidr)
	return err == nil
}
