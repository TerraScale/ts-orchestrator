package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var ErrOriginalFoundationNetworkPending = fmt.Errorf("%w: original private network retained; original actor and startup remain unavailable", ErrOriginalSourceProducerHold)

// OriginalFoundationNetwork is an original prerequisite journal, never a runtime binding.
type OriginalFoundationNetwork struct {
	Plan          map[string]any                     `json:"plan"`
	CompartmentID string                             `json:"compartmentId"`
	Requests      OriginalFoundationNetworkRequests  `json:"requests"`
	Creates       [6]OriginalFoundationNetworkCreate `json:"creates"`
	Rules         OriginalFoundationNetworkRules     `json:"rules"`
	Complete      bool                               `json:"complete,omitzero"`
}
type OriginalFoundationNetworkRequests struct {
	VCN            core.CreateVcnDetails                  `json:"vcn"`
	ServiceGateway core.CreateServiceGatewayDetails       `json:"serviceGateway"`
	RouteTable     core.CreateRouteTableDetails           `json:"routeTable"`
	SecurityList   core.CreateSecurityListDetails         `json:"securityList"`
	Subnet         core.CreateSubnetDetails               `json:"subnet"`
	ControllerNSG  core.CreateNetworkSecurityGroupDetails `json:"controllerNsg"`
}
type OriginalFoundationNetworkCreate struct {
	Key            string                        `json:"key"`
	Pending        *PendingFoundationCreate      `json:"pending,omitempty"`
	Provenance     *FoundationResourceProvenance `json:"provenance,omitempty"`
	ReadbackSHA256 string                        `json:"readbackSha256,omitempty"`
	VerifiedAt     time.Time                     `json:"verifiedAt,omitzero"`
	HoldReason     string                        `json:"holdReason,omitempty"`
}
type OriginalFoundationNetworkRules struct {
	Request        core.AddNetworkSecurityGroupSecurityRulesDetails `json:"request"`
	RequestSHA256  string                                           `json:"requestSha256,omitempty"`
	ReservedAt     time.Time                                        `json:"reservedAt,omitzero"`
	ReturnedRules  []core.SecurityRule                              `json:"returnedRules,omitempty"`
	ReadbackSHA256 string                                           `json:"readbackSha256,omitempty"`
	VerifiedAt     time.Time                                        `json:"verifiedAt,omitzero"`
	HoldReason     string                                           `json:"holdReason,omitempty"`
}

var originalNetworkKeys = [6]string{"vcn", "service_gateway", "route_table", "security_list", "subnet", "controller_nsg"}
var originalNetworkID = regexp.MustCompile(`^ocid1\.(vcn|servicegateway|routetable|securitylist|subnet|networksecuritygroup)\.oc1\.[a-z0-9-]+\.[a-zA-Z0-9]+$`)

func provisionOriginalFoundationNetwork(ctx context.Context, authority *HomeIAMAuthority) error {
	if err := retainOriginalFoundationNetwork(ctx, authority); err != nil {
		return err
	}
	return provisionOriginalFoundationVault(ctx, authority)
}

func retainOriginalFoundationNetwork(ctx context.Context, authority *HomeIAMAuthority) error {
	expected, err := originalCompartmentScope(ctx, authority)
	if err != nil {
		return err
	}
	reader, ok := authority.resolver.Footprint.(*SignedFootprint)
	if !ok {
		return ErrOriginalSourceProducerHold
	}
	grant, _, err := reader.verifyOriginalDocument(authority.operator.bundle.GrantWire)
	if err != nil {
		return err
	}
	record, etag, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	if record.OriginalFoundationCompartments == nil || !sameOriginalSourceValue(record.OriginalFoundationCompartments.scopeOnly(), expected) {
		return ErrOriginalSourceProducerHold
	}
	if err := record.validateOriginalFoundationNetwork(); err != nil {
		return err
	}
	changed := false
	for index, region := range record.OriginalFoundationCompartments.Regions {
		if err := originalNetworkPrerequisites(ctx, authority, index, true); err != nil {
			return err
		}
		var plan map[string]any
		for _, intent := range grant.Regions {
			if intent.Plan["cell"] == region.Cell {
				plan = intent.Plan
			}
		}
		if plan == nil {
			return ErrOriginalSourceProducerHold
		}
		compartment := originalCompartmentID(region.Compartments[1])
		network := record.OriginalFoundationCompartments.Regions[index].Network
		if network == nil {
			network = &OriginalFoundationNetwork{Plan: plan, CompartmentID: compartment}
			for slot, key := range originalNetworkKeys {
				network.Creates[slot].Key = key
			}
			record.OriginalFoundationCompartments.Regions[index].Network = network
			changed = true
		} else if network.CompartmentID != compartment || !sameOriginalSourceValue(network.Plan, plan) {
			return ErrOriginalSourceProducerHold
		}
	}
	if changed {
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	for index := range record.OriginalFoundationCompartments.Regions {
		region := record.OriginalFoundationCompartments.Regions[index]
		n := region.Network
		if n.Complete {
			expected, desired, err := originalNetworkRequests(n, region)
			if err != nil {
				return err
			}
			regional, err := authority.factory.ForRegion(region.OCIRegion)
			if err != nil {
				return err
			}
			client, err := regional.Network()
			if err != nil {
				return err
			}
			for slot, entry := range n.Creates {
				readback, err := readOriginalNetworkResource(ctx, client, expected, slot, entry.Provenance.ResourceID)
				if err != nil {
					return err
				}
				if readback != entry.ReadbackSHA256 {
					return ErrOriginalSourceProducerHold
				}
			}
			pins, err := originalNetworkRulePins(n.Rules.ReturnedRules, desired)
			if err != nil {
				return err
			}
			readback, err := readOriginalNetworkRules(ctx, client, n.Creates[5].Provenance.ResourceID, desired, pins)
			if err != nil {
				return err
			}
			if readback != n.Rules.ReadbackSHA256 {
				return ErrOriginalSourceProducerHold
			}
			continue
		}
		for slot := range originalNetworkKeys {
			if err := provisionOriginalNetworkCreate(ctx, authority, index, slot); err != nil {
				return err
			}
		}
		if err := provisionOriginalNetworkRules(ctx, authority, index); err != nil {
			return err
		}
	}
	return nil
}

func originalCompartmentID(entry OriginalFoundationCompartment) string {
	if entry.Provenance != nil {
		return entry.Provenance.ResourceID
	}
	return entry.SelectedID
}

// originalNetworkPrerequisites requires both verified original compartments of
// region index. With fresh it also re-reads them; the network stage does that
// once per region per run, while each create and its dispatch guard rely on the
// validated journal.
func originalNetworkPrerequisites(ctx context.Context, authority *HomeIAMAuthority, index int, fresh bool) error {
	if _, err := originalCompartmentScope(ctx, authority); err != nil {
		return err
	}
	if !fresh {
		record, _, err := authority.resolver.Store.Load(ctx, "GRU")
		if err != nil {
			return err
		}
		if record.OriginalFoundationCompartments == nil || index < 0 || index >= len(record.OriginalFoundationCompartments.Regions) {
			return ErrOriginalSourceProducerHold
		}
		for _, compartment := range record.OriginalFoundationCompartments.Regions[index].Compartments {
			if compartment.VerifiedAt.IsZero() || compartment.ReadbackSHA256 == "" || compartment.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
		}
		return nil
	}
	for role := range 2 {
		if err := provisionOriginalCompartment(ctx, authority, index, role); err != nil {
			return err
		}
	}
	return nil
}

func originalNetworkCreateIdentity(region OriginalFoundationCompartmentRegion, key, digest string) foundation.CreateIdentity {
	return foundation.CreateIdentity{Key: key, Region: region.OCIRegion, RequestDigest: digest, RetryToken: BootstrapRetryToken(region.OperationID, digest)}
}

func originalNetworkRequests(n *OriginalFoundationNetwork, region OriginalFoundationCompartmentRegion) (OriginalFoundationNetworkRequests, core.AddNetworkSecurityGroupSecurityRulesDetails, error) {
	var requests OriginalFoundationNetworkRequests
	var rules core.AddNetworkSecurityGroupSecurityRulesDetails
	sec, ok := n.Plan["network_security"].(map[string]any)
	ids, idsOK := n.Plan["resource_ids"].(map[string]any)
	if !ok || !idsOK {
		return requests, rules, ErrOriginalSourceProducerHold
	}
	// The original unbound graph cannot adopt resources from a name, list or profile.
	for _, key := range []string{"vcn", "service_gateway", "route_table", "security_list", "subnet", "network_security_group"} {
		if ids[key] != nil && ids[key] != "" {
			return requests, rules, ErrOriginalSourceProducerHold
		}
	}
	text := func(v any) string { s, _ := v.(string); return s }
	name := strings.ToLower(region.Cell) + "-1"
	id := func(slot int) string {
		if n.Creates[slot].Provenance != nil {
			return n.Creates[slot].Provenance.ResourceID
		}
		return ""
	}
	vcn := id(0)
	if text(n.Plan["network_cidr"]) == "" || text(n.Plan["subnet_cidr"]) == "" || text(sec["service_gateway_service_id"]) == "" || text(sec["service_gateway_cidr_block"]) == "" {
		return requests, rules, ErrOriginalSourceProducerHold
	}
	requests.VCN = core.CreateVcnDetails{CompartmentId: new(n.CompartmentID), DisplayName: new(name + "-vcn"), CidrBlock: new(text(n.Plan["network_cidr"])), DnsLabel: new(strings.ReplaceAll(name, "-", ""))}
	requests.ServiceGateway = core.CreateServiceGatewayDetails{CompartmentId: new(n.CompartmentID), VcnId: new(vcn), DisplayName: new(name + "-service-gateway"), Services: []core.ServiceIdRequestDetails{{ServiceId: new(text(sec["service_gateway_service_id"]))}}}
	routes, ok := sec["route_rules"].([]any)
	if !ok || len(routes) != 1 {
		return requests, rules, ErrOriginalSourceProducerHold
	}
	route, ok := routes[0].(map[string]any)
	if !ok || len(route) != 3 || route["destination"] != sec["service_gateway_cidr_block"] || route["destination_type"] != "SERVICE_CIDR_BLOCK" || route["network_entity_id"] != "{service_gateway_id}" {
		return requests, rules, ErrOriginalSourceProducerHold
	}
	requests.RouteTable = core.CreateRouteTableDetails{CompartmentId: new(n.CompartmentID), VcnId: new(vcn), DisplayName: new(name + "-private-routes"), RouteRules: []core.RouteRule{{Destination: new(text(sec["service_gateway_cidr_block"])), DestinationType: core.RouteRuleDestinationTypeServiceCidrBlock, NetworkEntityId: new(id(1))}}}
	ingress, err := originalNetworkPlanRules(sec["security_list_ingress_rules"], "INGRESS")
	if err != nil {
		return requests, rules, err
	}
	egress, err := originalNetworkPlanRules(sec["security_list_egress_rules"], "EGRESS")
	if err != nil {
		return requests, rules, err
	}
	requests.SecurityList = core.CreateSecurityListDetails{CompartmentId: new(n.CompartmentID), VcnId: new(vcn), DisplayName: new(name + "-private-security"), IngressSecurityRules: []core.IngressSecurityRule{}, EgressSecurityRules: []core.EgressSecurityRule{}}
	for _, rule := range ingress {
		requests.SecurityList.IngressSecurityRules = append(requests.SecurityList.IngressSecurityRules, core.IngressSecurityRule{Protocol: rule.Protocol, Source: rule.Source, SourceType: core.IngressSecurityRuleSourceTypeEnum(rule.SourceType), IsStateless: rule.IsStateless, TcpOptions: rule.TcpOptions, UdpOptions: rule.UdpOptions})
	}
	for _, rule := range egress {
		requests.SecurityList.EgressSecurityRules = append(requests.SecurityList.EgressSecurityRules, core.EgressSecurityRule{Protocol: rule.Protocol, Destination: rule.Destination, DestinationType: core.EgressSecurityRuleDestinationTypeEnum(rule.DestinationType), IsStateless: rule.IsStateless, TcpOptions: rule.TcpOptions, UdpOptions: rule.UdpOptions})
	}
	// OCI accepts only one private flag on create; readback must attest both effective flags.
	requests.Subnet = core.CreateSubnetDetails{CompartmentId: new(n.CompartmentID), VcnId: new(vcn), DisplayName: new(name + "-private"), CidrBlock: new(text(n.Plan["subnet_cidr"])), DnsLabel: new("private"), ProhibitInternetIngress: new(true), RouteTableId: new(id(2)), SecurityListIds: []string{id(3)}}
	requests.ControllerNSG = core.CreateNetworkSecurityGroupDetails{CompartmentId: new(n.CompartmentID), VcnId: new(vcn), DisplayName: new(name + "-controllers-nsg")}
	rules.SecurityRules, err = originalNetworkPlanRules(sec["nsg_rules"], "")
	if err != nil || len(rules.SecurityRules) == 0 || len(rules.SecurityRules) > 25 {
		return requests, rules, ErrOriginalSourceProducerHold
	}
	return requests, rules, nil
}

func originalNetworkPlanRules(value any, direction string) ([]core.AddSecurityRuleDetails, error) {
	rows, ok := value.([]any)
	if !ok || len(rows) > 25 {
		return nil, ErrOriginalSourceProducerHold
	}
	result := make([]core.AddSecurityRuleDetails, 0, len(rows))
	seen := map[string]bool{}
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok || len(row) != 11 {
			return nil, ErrOriginalSourceProducerHold
		}
		for _, key := range []string{"direction", "protocol", "source", "source_type", "destination", "destination_type", "tcp_min", "tcp_max", "udp_min", "udp_max", "stateless"} {
			if _, exists := row[key]; !exists {
				return nil, ErrOriginalSourceProducerHold
			}
		}
		text := func(key string) string { s, _ := row[key].(string); return s }
		stateless, ok := row["stateless"].(bool)
		dir := text("direction")
		protocol := text("protocol")
		if !ok || direction != "" && dir != direction || dir != "INGRESS" && dir != "EGRESS" || !slices.Contains([]string{"all", "6", "17"}, protocol) {
			return nil, ErrOriginalSourceProducerHold
		}
		rule := core.AddSecurityRuleDetails{Direction: core.AddSecurityRuleDetailsDirectionEnum(dir), Protocol: new(protocol), IsStateless: new(stateless)}
		if dir == "INGRESS" {
			if text("source") == "" || text("source_type") != "CIDR_BLOCK" || row["destination"] != nil || row["destination_type"] != nil {
				return nil, ErrOriginalSourceProducerHold
			}
			rule.Source, rule.SourceType = new(text("source")), core.AddSecurityRuleDetailsSourceTypeCidrBlock
		} else {
			if text("destination") == "" || !slices.Contains([]string{"CIDR_BLOCK", "SERVICE_CIDR_BLOCK"}, text("destination_type")) || row["source"] != nil || row["source_type"] != nil {
				return nil, ErrOriginalSourceProducerHold
			}
			rule.Destination, rule.DestinationType = new(text("destination")), core.AddSecurityRuleDetailsDestinationTypeEnum(text("destination_type"))
		}
		for _, kind := range []string{"tcp", "udp"} {
			if row[kind+"_min"] == nil && row[kind+"_max"] == nil {
				continue
			}
			if kind == "tcp" && protocol != "6" || kind == "udp" && protocol != "17" {
				return nil, ErrOriginalSourceProducerHold
			}
			wire, err := json.Marshal(map[string]any{"min": row[kind+"_min"], "max": row[kind+"_max"]})
			if err != nil {
				return nil, err
			}
			var ports core.PortRange
			if err := json.Unmarshal(wire, &ports); err != nil || ports.Min == nil || ports.Max == nil || *ports.Min < 1 || *ports.Max > 65535 || *ports.Min > *ports.Max {
				return nil, ErrOriginalSourceProducerHold
			}
			if kind == "tcp" {
				rule.TcpOptions = &core.TcpOptions{DestinationPortRange: &ports}
			} else {
				rule.UdpOptions = &core.UdpOptions{DestinationPortRange: &ports}
			}
		}
		wire, err := json.Marshal(rule, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		digest := digestSource(wire)
		if seen[digest] {
			return nil, ErrOriginalSourceProducerHold
		}
		seen[digest] = true
		result = append(result, rule)
	}
	return result, nil
}

func originalNetworkRequestSHA(key string, details any) (string, error) {
	var request http.Request
	var err error
	switch key {
	case "vcn":
		value, ok := details.(core.CreateVcnDetails)
		if !ok {
			return "", ErrOriginalSourceProducerHold
		}
		request, err = (core.CreateVcnRequest{CreateVcnDetails: value}).HTTPRequest(http.MethodPost, "/20160918/vcns", nil, nil)
	case "service_gateway":
		value, ok := details.(core.CreateServiceGatewayDetails)
		if !ok {
			return "", ErrOriginalSourceProducerHold
		}
		request, err = (core.CreateServiceGatewayRequest{CreateServiceGatewayDetails: value}).HTTPRequest(http.MethodPost, "/20160918/serviceGateways", nil, nil)
	case "route_table":
		value, ok := details.(core.CreateRouteTableDetails)
		if !ok {
			return "", ErrOriginalSourceProducerHold
		}
		request, err = (core.CreateRouteTableRequest{CreateRouteTableDetails: value}).HTTPRequest(http.MethodPost, "/20160918/routeTables", nil, nil)
	case "security_list":
		value, ok := details.(core.CreateSecurityListDetails)
		if !ok {
			return "", ErrOriginalSourceProducerHold
		}
		request, err = (core.CreateSecurityListRequest{CreateSecurityListDetails: value}).HTTPRequest(http.MethodPost, "/20160918/securityLists", nil, nil)
	case "subnet":
		value, ok := details.(core.CreateSubnetDetails)
		if !ok {
			return "", ErrOriginalSourceProducerHold
		}
		request, err = (core.CreateSubnetRequest{CreateSubnetDetails: value}).HTTPRequest(http.MethodPost, "/20160918/subnets", nil, nil)
	case "controller_nsg":
		value, ok := details.(core.CreateNetworkSecurityGroupDetails)
		if !ok {
			return "", ErrOriginalSourceProducerHold
		}
		request, err = (core.CreateNetworkSecurityGroupRequest{CreateNetworkSecurityGroupDetails: value}).HTTPRequest(http.MethodPost, "/20160918/networkSecurityGroups", nil, nil)
	case "controller_nsg_rules":
		value, ok := details.(core.AddNetworkSecurityGroupSecurityRulesDetails)
		if !ok {
			return "", ErrOriginalSourceProducerHold
		}
		request, err = (core.AddNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: new("original"), AddNetworkSecurityGroupSecurityRulesDetails: value}).HTTPRequest(http.MethodPost, "/20160918/networkSecurityGroups/{networkSecurityGroupId}/actions/addSecurityRules", nil, nil)
	default:
		return "", ErrOriginalSourceProducerHold
	}
	if err != nil || request.Body == nil {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	defer request.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(request.Body, 65537))
	if err != nil || len(wire) > 65536 {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	var object map[string]any
	if err := json.Unmarshal(wire, &object); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(object, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(canonical), nil
}
func originalNetworkDetails(requests OriginalFoundationNetworkRequests, slot int) any {
	switch slot {
	case 0:
		return requests.VCN
	case 1:
		return requests.ServiceGateway
	case 2:
		return requests.RouteTable
	case 3:
		return requests.SecurityList
	case 4:
		return requests.Subnet
	case 5:
		return requests.ControllerNSG
	}
	return nil
}
func setOriginalNetworkDetails(requests *OriginalFoundationNetworkRequests, expected OriginalFoundationNetworkRequests, slot int) {
	switch slot {
	case 0:
		requests.VCN = expected.VCN
	case 1:
		requests.ServiceGateway = expected.ServiceGateway
	case 2:
		requests.RouteTable = expected.RouteTable
	case 3:
		requests.SecurityList = expected.SecurityList
	case 4:
		requests.Subnet = expected.Subnet
	case 5:
		requests.ControllerNSG = expected.ControllerNSG
	}
}
func createOriginalNetworkResource(ctx context.Context, client core.VirtualNetworkClient, requests OriginalFoundationNetworkRequests, slot int, token string) (string, error) {
	noRetry := common.NoRetryPolicy()
	metadata := common.RequestMetadata{RetryPolicy: &noRetry}
	switch slot {
	case 0:
		response, err := client.CreateVcn(ociclient.RequestContext(ctx), core.CreateVcnRequest{CreateVcnDetails: requests.VCN, OpcRetryToken: new(token), RequestMetadata: metadata})
		return deref(response.Id), err
	case 1:
		response, err := client.CreateServiceGateway(ociclient.RequestContext(ctx), core.CreateServiceGatewayRequest{CreateServiceGatewayDetails: requests.ServiceGateway, OpcRetryToken: new(token), RequestMetadata: metadata})
		return deref(response.Id), err
	case 2:
		response, err := client.CreateRouteTable(ociclient.RequestContext(ctx), core.CreateRouteTableRequest{CreateRouteTableDetails: requests.RouteTable, OpcRetryToken: new(token), RequestMetadata: metadata})
		return deref(response.Id), err
	case 3:
		response, err := client.CreateSecurityList(ociclient.RequestContext(ctx), core.CreateSecurityListRequest{CreateSecurityListDetails: requests.SecurityList, OpcRetryToken: new(token), RequestMetadata: metadata})
		return deref(response.Id), err
	case 4:
		response, err := client.CreateSubnet(ociclient.RequestContext(ctx), core.CreateSubnetRequest{CreateSubnetDetails: requests.Subnet, OpcRetryToken: new(token), RequestMetadata: metadata})
		return deref(response.Id), err
	case 5:
		response, err := client.CreateNetworkSecurityGroup(ociclient.RequestContext(ctx), core.CreateNetworkSecurityGroupRequest{CreateNetworkSecurityGroupDetails: requests.ControllerNSG, OpcRetryToken: new(token), RequestMetadata: metadata})
		return deref(response.Id), err
	}
	return "", ErrOriginalSourceProducerHold
}

func readOriginalNetworkResource(ctx context.Context, client core.VirtualNetworkClient, requests OriginalFoundationNetworkRequests, slot int, id string) (string, error) {
	valid := false
	switch slot {
	case 0:
		response, err := client.GetVcn(ociclient.RequestContext(ctx), core.GetVcnRequest{VcnId: new(id)})
		if err != nil {
			return "", err
		}
		v := response.Vcn
		r := requests.VCN
		valid = deref(v.Id) == id && v.LifecycleState == core.VcnLifecycleStateAvailable && deref(v.CompartmentId) == deref(r.CompartmentId) && deref(v.DisplayName) == deref(r.DisplayName) && deref(v.DnsLabel) == deref(r.DnsLabel) && deref(v.CidrBlock) == deref(r.CidrBlock) && (len(v.CidrBlocks) == 0 || slices.Equal(v.CidrBlocks, []string{deref(r.CidrBlock)})) && len(v.Ipv6CidrBlocks) == 0 && len(v.Byoipv6CidrBlocks) == 0 && len(v.Ipv6PrivateCidrBlocks) == 0 && (v.IsZprOnly == nil || !*v.IsZprOnly)
	case 1:
		response, err := client.GetServiceGateway(ociclient.RequestContext(ctx), core.GetServiceGatewayRequest{ServiceGatewayId: new(id)})
		if err != nil {
			return "", err
		}
		v := response.ServiceGateway
		r := requests.ServiceGateway
		valid = deref(v.Id) == id && v.LifecycleState == core.ServiceGatewayLifecycleStateAvailable && deref(v.CompartmentId) == deref(r.CompartmentId) && deref(v.DisplayName) == deref(r.DisplayName) && deref(v.VcnId) == deref(r.VcnId) && v.BlockTraffic != nil && !*v.BlockTraffic && deref(v.RouteTableId) == "" && len(v.Services) == 1 && deref(v.Services[0].ServiceId) == deref(r.Services[0].ServiceId)
	case 2:
		response, err := client.GetRouteTable(ociclient.RequestContext(ctx), core.GetRouteTableRequest{RtId: new(id)})
		if err != nil {
			return "", err
		}
		v := response.RouteTable
		r := requests.RouteTable
		actual := v.RouteRules
		for i := range actual {
			if actual[i].RouteType == core.RouteRuleRouteTypeStatic {
				actual[i].RouteType = ""
			}
		}
		valid = deref(v.Id) == id && v.LifecycleState == core.RouteTableLifecycleStateAvailable && deref(v.CompartmentId) == deref(r.CompartmentId) && deref(v.DisplayName) == deref(r.DisplayName) && deref(v.VcnId) == deref(r.VcnId) && sameOriginalSourceValue(actual, r.RouteRules)
	case 3:
		response, err := client.GetSecurityList(ociclient.RequestContext(ctx), core.GetSecurityListRequest{SecurityListId: new(id)})
		if err != nil {
			return "", err
		}
		v := response.SecurityList
		r := requests.SecurityList
		valid = deref(v.Id) == id && v.LifecycleState == core.SecurityListLifecycleStateAvailable && deref(v.CompartmentId) == deref(r.CompartmentId) && deref(v.DisplayName) == deref(r.DisplayName) && deref(v.VcnId) == deref(r.VcnId) && sameOriginalSourceValue(v.IngressSecurityRules, r.IngressSecurityRules) && sameOriginalSourceValue(v.EgressSecurityRules, r.EgressSecurityRules)
	case 4:
		response, err := client.GetSubnet(ociclient.RequestContext(ctx), core.GetSubnetRequest{SubnetId: new(id)})
		if err != nil {
			return "", err
		}
		v := response.Subnet
		r := requests.Subnet
		valid = deref(v.Id) == id && v.LifecycleState == core.SubnetLifecycleStateAvailable && deref(v.CompartmentId) == deref(r.CompartmentId) && deref(v.DisplayName) == deref(r.DisplayName) && deref(v.VcnId) == deref(r.VcnId) && deref(v.CidrBlock) == deref(r.CidrBlock) && deref(v.DnsLabel) == deref(r.DnsLabel) && deref(v.RouteTableId) == deref(r.RouteTableId) && slices.Equal(v.SecurityListIds, r.SecurityListIds) && v.ProhibitInternetIngress != nil && *v.ProhibitInternetIngress && v.ProhibitPublicIpOnVnic != nil && *v.ProhibitPublicIpOnVnic && deref(v.AvailabilityDomain) == "" && deref(v.Ipv6CidrBlock) == "" && len(v.Ipv6CidrBlocks) == 0 && (len(v.Ipv4CidrBlocks) == 0 || slices.Equal(v.Ipv4CidrBlocks, []string{deref(r.CidrBlock)}))
	case 5:
		response, err := client.GetNetworkSecurityGroup(ociclient.RequestContext(ctx), core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: new(id)})
		if err != nil {
			return "", err
		}
		v := response.NetworkSecurityGroup
		r := requests.ControllerNSG
		valid = deref(v.Id) == id && v.LifecycleState == core.NetworkSecurityGroupLifecycleStateAvailable && deref(v.CompartmentId) == deref(r.CompartmentId) && deref(v.DisplayName) == deref(r.DisplayName) && deref(v.VcnId) == deref(r.VcnId)
	}
	if !valid {
		return "", ErrOriginalSourceProducerHold
	}
	digest, err := originalNetworkRequestSHA(originalNetworkKeys[slot], originalNetworkDetails(requests, slot))
	if err != nil {
		return "", err
	}
	wire, err := json.Marshal([]string{id, digest, "AVAILABLE"}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(wire), nil
}

func provisionOriginalNetworkCreate(ctx context.Context, authority *HomeIAMAuthority, index, slot int) error {
	if err := originalNetworkPrerequisites(ctx, authority, index, false); err != nil {
		return err
	}
	record, etag, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	n := region.Network
	if n == nil {
		return ErrOriginalSourceProducerHold
	}
	entry := &n.Creates[slot]
	if entry.HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	regional, err := authority.factory.ForRegion(region.OCIRegion)
	if err != nil {
		return err
	}
	client, err := regional.Network()
	if err != nil {
		return err
	}
	expected, _, err := originalNetworkRequests(n, region)
	if err != nil {
		return err
	}
	for previous := 0; previous < slot; previous++ {
		accepted := n.Creates[previous]
		if accepted.Provenance == nil || accepted.VerifiedAt.IsZero() {
			return ErrOriginalSourceProducerHold
		}
		if _, err := readOriginalNetworkResource(ctx, client, expected, previous, accepted.Provenance.ResourceID); err != nil {
			return err
		}
	}
	digest, err := originalNetworkRequestSHA(entry.Key, originalNetworkDetails(expected, slot))
	if err != nil {
		return err
	}
	if entry.Provenance == nil {
		if entry.Pending == nil {
			setOriginalNetworkDetails(&n.Requests, expected, slot)
			entry.Pending = &PendingFoundationCreate{OperationID: region.OperationID, IntentDigest: region.IntentSHA256, FirstAttemptAt: time.Now().UTC(), Request: originalNetworkCreateIdentity(region, entry.Key, digest)}
			if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
				return err
			}
		}
		pending := *entry.Pending
		if !time.Now().Before(pending.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
			entry.HoldReason = "retry-expired"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		guard := func(dispatchCtx context.Context) error {
			checkCtx := ociclient.CheckpointContext(dispatchCtx)
			if err := originalNetworkPrerequisites(checkCtx, authority, index, false); err != nil {
				return err
			}
			current, _, err := authority.resolver.Store.Load(checkCtx, "GRU")
			if err != nil {
				return err
			}
			if current.OriginalFoundationCompartments == nil {
				return ErrOriginalSourceProducerHold
			}
			saved := current.OriginalFoundationCompartments.Regions[index].Network
			if saved == nil || !sameOriginalSourceValue(saved, n) || saved.Creates[slot].Provenance != nil || !sameOriginalSourceValue(saved.Creates[slot].Pending, pending) {
				return ErrOriginalSourceProducerHold
			}
			for previous := 0; previous < slot; previous++ {
				if _, err := readOriginalNetworkResource(checkCtx, client, expected, previous, n.Creates[previous].Provenance.ResourceID); err != nil {
					return err
				}
			}
			for _, deadline := range []time.Time{authority.operator.deadline, pending.FirstAttemptAt.Add(bootstrapRetryLifetime)} {
				if err := ociclient.LimitAdmission(dispatchCtx, deadline); err != nil {
					return err
				}
			}
			return nil
		}
		if err := guard(ctx); err != nil {
			return err
		}
		// HomeWrite cannot physically fence an already paused SDK send; live dispatch stays on HOLD.
		id, err := createOriginalNetworkResource(ociclient.WithAuthority(ctx, guard), client, n.Requests, slot, pending.Request.RetryToken)
		if err != nil {
			if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() >= 400 && service.GetHTTPStatusCode() < 500 && service.GetHTTPStatusCode() != 408 && service.GetHTTPStatusCode() != 429 {
				entry.HoldReason = "create-refused"
				return errors.Join(err, checkpointOriginalCompartments(ctx, authority, &record, &etag))
			}
			return err
		}
		if !validOriginalNetworkID(slot, id) {
			entry.HoldReason = "create-unresolved"
			return errors.Join(ErrOriginalSourceProducerHold, checkpointOriginalCompartments(ctx, authority, &record, &etag))
		}
		entry.Provenance = &FoundationResourceProvenance{Create: pending, ResourceID: id, Generation: region.Generation, GrantSHA256: record.OriginalFoundationCompartments.GrantSHA256}
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
	}
	readback, err := readOriginalNetworkResource(ctx, client, n.Requests, slot, entry.Provenance.ResourceID)
	if err != nil {
		return err
	}
	if entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != readback {
		return ErrOriginalSourceProducerHold
	}
	if entry.VerifiedAt.IsZero() {
		entry.ReadbackSHA256, entry.VerifiedAt = readback, time.Now().UTC()
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	return nil
}

func validOriginalNetworkID(slot int, id string) bool {
	kinds := [6]string{"vcn", "servicegateway", "routetable", "securitylist", "subnet", "networksecuritygroup"}
	return slot >= 0 && slot < len(kinds) && len(id) <= 512 && originalNetworkID.MatchString(id) && strings.HasPrefix(id, "ocid1."+kinds[slot]+".")
}

func originalNetworkRuleSemantics(rule core.SecurityRule) (core.AddSecurityRuleDetails, error) {
	if rule.Id == nil || strings.TrimSpace(*rule.Id) != *rule.Id || len(*rule.Id) == 0 || len(*rule.Id) > 256 || rule.IsValid == nil || !*rule.IsValid {
		return core.AddSecurityRuleDetails{}, ErrOriginalSourceProducerHold
	}
	return core.AddSecurityRuleDetails{Direction: core.AddSecurityRuleDetailsDirectionEnum(rule.Direction), Protocol: rule.Protocol, Description: rule.Description, Destination: rule.Destination, DestinationType: core.AddSecurityRuleDetailsDestinationTypeEnum(rule.DestinationType), IcmpOptions: rule.IcmpOptions, IsStateless: rule.IsStateless, Source: rule.Source, SourceType: core.AddSecurityRuleDetailsSourceTypeEnum(rule.SourceType), TcpOptions: rule.TcpOptions, UdpOptions: rule.UdpOptions}, nil
}

func originalNetworkRulePins(rules []core.SecurityRule, expected core.AddNetworkSecurityGroupSecurityRulesDetails) (map[string]string, error) {
	if len(rules) != len(expected.SecurityRules) || len(rules) == 0 || len(rules) > 25 {
		return nil, ErrOriginalSourceProducerHold
	}
	desired := map[string]int{}
	for _, rule := range expected.SecurityRules {
		wire, err := json.Marshal(rule, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		desired[digestSource(wire)]++
	}
	pins := map[string]string{}
	for _, rule := range rules {
		semantics, err := originalNetworkRuleSemantics(rule)
		if err != nil {
			return nil, err
		}
		wire, err := json.Marshal(semantics, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		digest := digestSource(wire)
		if _, exists := pins[*rule.Id]; exists || desired[digest] != 1 {
			return nil, ErrOriginalSourceProducerHold
		}
		desired[digest]--
		pins[*rule.Id] = digest
	}
	for _, count := range desired {
		if count != 0 {
			return nil, ErrOriginalSourceProducerHold
		}
	}
	return pins, nil
}

func listOriginalNetworkRules(ctx context.Context, client core.VirtualNetworkClient, id string) ([]core.SecurityRule, error) {
	result := []core.SecurityRule{}
	seenPages := map[string]bool{}
	seenIDs := map[string]bool{}
	page := ""
	for range 26 {
		if seenPages[page] {
			return nil, ErrOriginalSourceProducerHold
		}
		seenPages[page] = true
		request := core.ListNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: new(id), Limit: new(25)}
		if page != "" {
			request.Page = new(page)
		}
		response, err := client.ListNetworkSecurityGroupSecurityRules(ociclient.RequestContext(ctx), request)
		if err != nil {
			return nil, err
		}
		for _, rule := range response.Items {
			if rule.Id == nil || *rule.Id == "" || seenIDs[*rule.Id] || len(result) >= 25 {
				return nil, ErrOriginalSourceProducerHold
			}
			seenIDs[*rule.Id] = true
			result = append(result, rule)
		}
		page = deref(response.OpcNextPage)
		if page == "" {
			return result, nil
		}
	}
	return nil, ErrOriginalSourceProducerHold
}

func readOriginalNetworkRules(ctx context.Context, client core.VirtualNetworkClient, id string, desired core.AddNetworkSecurityGroupSecurityRulesDetails, pins map[string]string) (string, error) {
	live, err := listOriginalNetworkRules(ctx, client, id)
	if err != nil {
		return "", err
	}
	observed, err := originalNetworkRulePins(live, desired)
	if err != nil || !sameOriginalSourceValue(pins, observed) {
		return "", errors.Join(ErrOriginalSourceProducerHold, err)
	}
	wire, err := json.Marshal(pins, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestSource(wire), nil
}

func provisionOriginalNetworkRules(ctx context.Context, authority *HomeIAMAuthority, index int) error {
	if err := originalNetworkPrerequisites(ctx, authority, index, false); err != nil {
		return err
	}
	record, etag, err := authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	region := record.OriginalFoundationCompartments.Regions[index]
	n := region.Network
	if n == nil {
		return ErrOriginalSourceProducerHold
	}
	rules := &n.Rules
	if rules.HoldReason != "" {
		return ErrOriginalSourceProducerHold
	}
	expected, desired, err := originalNetworkRequests(n, region)
	if err != nil {
		return err
	}
	regional, err := authority.factory.ForRegion(region.OCIRegion)
	if err != nil {
		return err
	}
	client, err := regional.Network()
	if err != nil {
		return err
	}
	for slot, entry := range n.Creates {
		if entry.Provenance == nil || entry.VerifiedAt.IsZero() {
			return ErrOriginalSourceProducerHold
		}
		if _, err := readOriginalNetworkResource(ctx, client, expected, slot, entry.Provenance.ResourceID); err != nil {
			return err
		}
	}
	id := n.Creates[5].Provenance.ResourceID
	hold := func(reason string, cause error) error {
		rules.HoldReason = reason
		return errors.Join(ErrOriginalSourceProducerHold, cause, checkpointOriginalCompartments(ctx, authority, &record, &etag))
	}
	if rules.ReservedAt.IsZero() {
		live, err := listOriginalNetworkRules(ctx, client, id)
		if err != nil {
			return err
		}
		if len(live) != 0 {
			return hold("rules-preexisting", nil)
		}
		digest, err := originalNetworkRequestSHA("controller_nsg_rules", desired)
		if err != nil {
			return err
		}
		rules.Request, rules.RequestSHA256, rules.ReservedAt = desired, digest, time.Now().UTC()
		// Reservation permanently consumes dispatch, including a crash before the SDK send.
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return err
		}
		reservation := *rules
		guard := func(dispatchCtx context.Context) error {
			checkCtx := ociclient.CheckpointContext(dispatchCtx)
			if err := originalNetworkPrerequisites(checkCtx, authority, index, false); err != nil {
				return err
			}
			saved, _, err := authority.resolver.Store.Load(checkCtx, "GRU")
			if err != nil {
				return err
			}
			if saved.OriginalFoundationCompartments == nil {
				return ErrOriginalSourceProducerHold
			}
			current := saved.OriginalFoundationCompartments.Regions[index].Network
			if current == nil || !sameOriginalSourceValue(current, n) || !sameOriginalSourceValue(current.Rules, reservation) {
				return ErrOriginalSourceProducerHold
			}
			for slot, entry := range n.Creates {
				if _, err := readOriginalNetworkResource(checkCtx, client, expected, slot, entry.Provenance.ResourceID); err != nil {
					return err
				}
			}
			live, err := listOriginalNetworkRules(checkCtx, client, id)
			if err != nil {
				return err
			}
			if len(live) != 0 {
				return ErrOriginalSourceProducerHold
			}
			return ociclient.LimitAdmission(dispatchCtx, authority.operator.deadline)
		}
		if err := guard(ctx); err != nil {
			return hold("rules-dispatch-unknown", err)
		}
		noRetry := common.NoRetryPolicy()
		response, err := client.AddNetworkSecurityGroupSecurityRules(ociclient.RequestContext(ociclient.WithAuthority(ctx, guard)), core.AddNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: new(id), AddNetworkSecurityGroupSecurityRulesDetails: rules.Request, RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		if err != nil {
			return hold("rules-dispatch-unknown", err)
		}
		if _, err := originalNetworkRulePins(response.SecurityRules, desired); err != nil {
			return hold("rules-response-unresolved", err)
		}
		rules.ReturnedRules = response.SecurityRules
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			// Reopen only from durable complete actual response pins; never resend or adopt List IDs.
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
	} else if len(rules.ReturnedRules) == 0 {
		return hold("rules-dispatch-unknown", nil)
	}
	pins, err := originalNetworkRulePins(rules.ReturnedRules, desired)
	if err != nil {
		return hold("rules-response-unresolved", err)
	}
	digest, err := readOriginalNetworkRules(ctx, client, id, desired, pins)
	if err != nil {
		return err
	}
	if rules.ReadbackSHA256 != "" && rules.ReadbackSHA256 != digest {
		return ErrOriginalSourceProducerHold
	}
	if rules.VerifiedAt.IsZero() {
		rules.ReadbackSHA256, rules.VerifiedAt = digest, time.Now().UTC()
		n.Complete = true
		return checkpointOriginalCompartments(ctx, authority, &record, &etag)
	}
	if !n.Complete {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

func (r FoundationRecord) validateOriginalFoundationNetwork() error {
	return rememberOriginalRecordCheck("network", r, FoundationRecord.validateOriginalFoundationNetworkChecked)
}

func (r FoundationRecord) validateOriginalFoundationNetworkChecked() error {
	root := r.OriginalFoundationCompartments
	if root == nil {
		return nil
	}
	attached := 0
	seenIDs := map[string]bool{}
	for index, region := range root.Regions {
		n := region.Network
		if n == nil {
			continue
		}
		attached++
		if n.CompartmentID == "" || n.CompartmentID != originalCompartmentID(region.Compartments[1]) {
			return ErrOriginalSourceProducerHold
		}
		for _, prerequisite := range region.Compartments {
			if prerequisite.VerifiedAt.IsZero() || prerequisite.ReadbackSHA256 == "" || prerequisite.HoldReason != "" {
				return ErrOriginalSourceProducerHold
			}
		}
		selections, err := json.Marshal(struct {
			ParentCompartmentID string         `json:"parentCompartmentId"`
			SharedCompartmentID string         `json:"sharedCompartmentId"`
			Plan                map[string]any `json:"plan"`
		}{r.ParentCompartmentID, r.SharedCompartmentID, n.Plan}, json.Deterministic(true))
		if err != nil || digestSource(selections) != (*r.OriginalSourceProducers)[index].Intent.ResourceSelectionsSHA256 {
			return ErrOriginalSourceProducerHold
		}
		requests, rules, err := originalNetworkRequests(n, region)
		if err != nil {
			return err
		}
		for slot, entry := range n.Creates {
			if entry.Key != originalNetworkKeys[slot] {
				return ErrOriginalSourceProducerHold
			}
			if entry.Pending == nil {
				if entry.Provenance != nil || entry.ReadbackSHA256 != "" || !entry.VerifiedAt.IsZero() || entry.HoldReason != "" || !sameOriginalSourceValue(originalNetworkDetails(n.Requests, slot), originalNetworkDetails(OriginalFoundationNetworkRequests{}, slot)) {
					return ErrOriginalSourceProducerHold
				}
				continue
			}
			for previous := 0; previous < slot; previous++ {
				if n.Creates[previous].Provenance == nil || n.Creates[previous].VerifiedAt.IsZero() || n.Creates[previous].HoldReason != "" {
					return ErrOriginalSourceProducerHold
				}
			}
			if !sameOriginalSourceValue(originalNetworkDetails(n.Requests, slot), originalNetworkDetails(requests, slot)) {
				return ErrOriginalSourceProducerHold
			}
			digest, err := originalNetworkRequestSHA(entry.Key, originalNetworkDetails(n.Requests, slot))
			if err != nil {
				return err
			}
			p := *entry.Pending
			if p.OperationID != region.OperationID || p.IntentDigest != region.IntentSHA256 || p.Request != originalNetworkCreateIdentity(region, entry.Key, digest) || p.FirstAttemptAt.IsZero() || p.FirstAttemptAt.Before(root.BornAt) || p.FirstAttemptAt.After(r.UpdatedAt) {
				return ErrOriginalSourceProducerHold
			}
			if entry.Provenance != nil {
				proof := entry.Provenance
				if !sameOriginalSourceValue(proof.Create, p) || proof.GrantSHA256 != root.GrantSHA256 || proof.Generation != region.Generation || !validOriginalNetworkID(slot, proof.ResourceID) || seenIDs[proof.ResourceID] || entry.HoldReason != "" {
					return ErrOriginalSourceProducerHold
				}
				seenIDs[proof.ResourceID] = true
			}
			if entry.HoldReason != "" && (entry.Provenance != nil || !slices.Contains([]string{"create-refused", "retry-expired", "create-unresolved"}, entry.HoldReason)) {
				return ErrOriginalSourceProducerHold
			}
			if entry.VerifiedAt.IsZero() != (entry.ReadbackSHA256 == "") || !entry.VerifiedAt.IsZero() && (entry.Provenance == nil || entry.VerifiedAt.Before(p.FirstAttemptAt) || entry.VerifiedAt.After(r.UpdatedAt)) {
				return ErrOriginalSourceProducerHold
			}
			if entry.ReadbackSHA256 != "" {
				wire, err := json.Marshal([]string{entry.Provenance.ResourceID, digest, "AVAILABLE"}, json.Deterministic(true))
				if err != nil || entry.ReadbackSHA256 != digestSource(wire) {
					return ErrOriginalSourceProducerHold
				}
			}
		}
		journal := n.Rules
		if journal.ReservedAt.IsZero() {
			if journal.RequestSHA256 != "" || len(journal.ReturnedRules) != 0 || journal.ReadbackSHA256 != "" || !journal.VerifiedAt.IsZero() || n.Complete || !sameOriginalSourceValue(journal.Request, core.AddNetworkSecurityGroupSecurityRulesDetails{}) || journal.HoldReason != "" && journal.HoldReason != "rules-preexisting" {
				return ErrOriginalSourceProducerHold
			}
		} else {
			for _, entry := range n.Creates {
				if entry.Provenance == nil || entry.VerifiedAt.IsZero() || entry.HoldReason != "" {
					return ErrOriginalSourceProducerHold
				}
			}
			digest, err := originalNetworkRequestSHA("controller_nsg_rules", journal.Request)
			if err != nil || !sameOriginalSourceValue(journal.Request, rules) || journal.RequestSHA256 != digest || journal.ReservedAt.Before(root.BornAt) || journal.ReservedAt.After(r.UpdatedAt) {
				return ErrOriginalSourceProducerHold
			}
			if journal.HoldReason != "" && !slices.Contains([]string{"rules-dispatch-unknown", "rules-response-unresolved"}, journal.HoldReason) {
				return ErrOriginalSourceProducerHold
			}
			var pins map[string]string
			if len(journal.ReturnedRules) != 0 {
				pins, err = originalNetworkRulePins(journal.ReturnedRules, rules)
				if err != nil {
					return err
				}
			}
			if journal.VerifiedAt.IsZero() != (journal.ReadbackSHA256 == "") || n.Complete != !journal.VerifiedAt.IsZero() {
				return ErrOriginalSourceProducerHold
			}
			if !journal.VerifiedAt.IsZero() {
				wire, err := json.Marshal(pins, json.Deterministic(true))
				if err != nil || len(pins) == 0 || journal.HoldReason != "" || journal.VerifiedAt.Before(journal.ReservedAt) || journal.VerifiedAt.After(r.UpdatedAt) || journal.ReadbackSHA256 != digestSource(wire) {
					return ErrOriginalSourceProducerHold
				}
			}
		}
	}
	if attached != 0 && attached != 3 {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

func (next FoundationRecord) retainOriginalFoundationNetwork(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil {
		return nil
	}
	for index, region := range before.Regions {
		old := region.Network
		current := after.Regions[index].Network
		if old == nil {
			continue
		}
		if current == nil || !sameOriginalSourceValue(old.Plan, current.Plan) || old.CompartmentID != current.CompartmentID || old.Complete && !current.Complete {
			return ErrOriginalSourceProducerHold
		}
		for slot, entry := range old.Creates {
			retained := current.Creates[slot]
			if entry.Key != retained.Key || entry.Pending != nil && (!sameOriginalSourceValue(entry.Pending, retained.Pending) || !sameOriginalSourceValue(originalNetworkDetails(old.Requests, slot), originalNetworkDetails(current.Requests, slot))) || entry.Provenance != nil && !sameOriginalSourceValue(entry.Provenance, retained.Provenance) || entry.ReadbackSHA256 != "" && entry.ReadbackSHA256 != retained.ReadbackSHA256 || !entry.VerifiedAt.IsZero() && !entry.VerifiedAt.Equal(retained.VerifiedAt) || entry.HoldReason != "" && entry.HoldReason != retained.HoldReason {
				return ErrOriginalSourceProducerHold
			}
		}
		rules, retained := old.Rules, current.Rules
		if !rules.ReservedAt.IsZero() && (!rules.ReservedAt.Equal(retained.ReservedAt) || rules.RequestSHA256 != retained.RequestSHA256 || !sameOriginalSourceValue(rules.Request, retained.Request)) || len(rules.ReturnedRules) != 0 && !sameOriginalSourceValue(rules.ReturnedRules, retained.ReturnedRules) || rules.ReadbackSHA256 != "" && rules.ReadbackSHA256 != retained.ReadbackSHA256 || !rules.VerifiedAt.IsZero() && !rules.VerifiedAt.Equal(retained.VerifiedAt) || rules.HoldReason != "" && rules.HoldReason != retained.HoldReason {
			return ErrOriginalSourceProducerHold
		}
	}
	return nil
}
