package nsg

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

const maxPages = 32

type sdkAPI struct{ network core.VirtualNetworkClient }

// NewSDKAPI builds the NSG API on the shared rate-limited factory.
func NewSDKAPI(factory *ociclient.Factory) (API, error) {
	network, err := factory.Network()
	if err != nil {
		return nil, err
	}
	return sdkAPI{network: network}, nil
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (a sdkAPI) GetGroup(ctx context.Context, id string) (Group, error) {
	response, err := a.network.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: new(id)})
	if err != nil {
		if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
			return Group{}, fmt.Errorf("get OCI NSG: %w: %w", ociresource.ErrGone, err)
		}
		return Group{}, fmt.Errorf("get OCI NSG: %w", err)
	}
	return Group{ID: deref(response.Id), ETag: deref(response.Etag),
		Tags: ociresource.Tags{Freeform: response.FreeformTags, Defined: response.DefinedTags}}, nil
}

// PortRange extracts the destination port range of TCP or UDP options. ok is
// false when a source port range is set, which Rule does not model.
func PortRange(options *core.TcpOptions, udp *core.UdpOptions) (int, int, bool) {
	var destination, source *core.PortRange
	if options != nil {
		destination, source = options.DestinationPortRange, options.SourcePortRange
	}
	if udp != nil {
		destination, source = udp.DestinationPortRange, udp.SourcePortRange
	}
	if source != nil {
		return 0, 0, false
	}
	if destination == nil || destination.Min == nil || destination.Max == nil {
		return 0, 0, true
	}
	return *destination.Min, *destination.Max, true
}

// normalize maps an OCI rule onto Rule. Features the reconciler does not
// model (source port ranges, ICMP type filters) set unsupported so the rule
// never matches a desired rule.
func normalize(rule core.SecurityRule) Rule {
	normalized := Rule{Direction: string(rule.Direction), Protocol: deref(rule.Protocol), Description: deref(rule.Description),
		Stateless: rule.IsStateless != nil && *rule.IsStateless}
	if rule.Direction == core.SecurityRuleDirectionIngress {
		normalized.Peer, normalized.PeerType = deref(rule.Source), string(rule.SourceType)
	} else {
		normalized.Peer, normalized.PeerType = deref(rule.Destination), string(rule.DestinationType)
	}
	if normalized.PeerType == PeerCIDR {
		normalized.PeerType = ""
	}
	low, high, ok := PortRange(rule.TcpOptions, rule.UdpOptions)
	normalized.PortMin, normalized.PortMax = low, high
	if !ok || rule.IcmpOptions != nil {
		normalized.unsupported = true
	}
	return normalized
}

func (a sdkAPI) ListRules(ctx context.Context, id string) ([]ObservedRule, error) {
	var rules []ObservedRule
	var page *string
	for range maxPages {
		response, err := a.network.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{
			NetworkSecurityGroupId: new(id), Page: page})
		if err != nil {
			return nil, fmt.Errorf("list OCI NSG rules: %w", err)
		}
		for _, rule := range response.Items {
			rules = append(rules, ObservedRule{ID: deref(rule.Id), Rule: normalize(rule)})
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return rules, nil
		}
		page = response.OpcNextPage
	}
	return nil, errors.New("OCI NSG rule list exceeds its page bound")
}

func addDetails(rule Rule) core.AddSecurityRuleDetails {
	details := core.AddSecurityRuleDetails{Direction: core.AddSecurityRuleDetailsDirectionEnum(rule.Direction),
		Protocol: new(rule.Protocol), IsStateless: new(rule.Stateless)}
	if rule.Description != "" {
		details.Description = new(rule.Description)
	}
	if rule.Direction == DirectionIngress {
		details.Source, details.SourceType = new(rule.Peer), core.AddSecurityRuleDetailsSourceTypeEnum(rule.peerType())
	} else {
		details.Destination, details.DestinationType = new(rule.Peer), core.AddSecurityRuleDetailsDestinationTypeEnum(rule.peerType())
	}
	details.TcpOptions, details.UdpOptions = PortOptions(rule)
	return details
}

// PortOptions returns the TCP or UDP destination-port options of rule, or
// nil options when the rule has no port range.
func PortOptions(rule Rule) (*core.TcpOptions, *core.UdpOptions) {
	if rule.PortMin == 0 {
		return nil, nil
	}
	ports := &core.PortRange{Min: new(rule.PortMin), Max: new(rule.PortMax)}
	switch rule.Protocol {
	case ProtocolTCP:
		return &core.TcpOptions{DestinationPortRange: ports}, nil
	case ProtocolUDP:
		return nil, &core.UdpOptions{DestinationPortRange: ports}
	}
	return nil, nil
}

func (a sdkAPI) AddRules(ctx context.Context, id string, rules []Rule) error {
	details := make([]core.AddSecurityRuleDetails, 0, len(rules))
	for _, rule := range rules {
		details = append(details, addDetails(rule))
	}
	_, err := a.network.AddNetworkSecurityGroupSecurityRules(ctx, core.AddNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId:                      new(id),
		AddNetworkSecurityGroupSecurityRulesDetails: core.AddNetworkSecurityGroupSecurityRulesDetails{SecurityRules: details}})
	if err != nil {
		return fmt.Errorf("add OCI NSG rules: %w", err)
	}
	return nil
}

func (a sdkAPI) RemoveRules(ctx context.Context, id string, ruleIDs []string) error {
	_, err := a.network.RemoveNetworkSecurityGroupSecurityRules(ctx, core.RemoveNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId:                         new(id),
		RemoveNetworkSecurityGroupSecurityRulesDetails: core.RemoveNetworkSecurityGroupSecurityRulesDetails{SecurityRuleIds: ruleIDs}})
	if err != nil {
		return fmt.Errorf("remove OCI NSG rules: %w", err)
	}
	return nil
}

func (a sdkAPI) UpdateTags(ctx context.Context, id, etag string, tags ociresource.Tags) error {
	request := core.UpdateNetworkSecurityGroupRequest{NetworkSecurityGroupId: new(id),
		UpdateNetworkSecurityGroupDetails: core.UpdateNetworkSecurityGroupDetails{
			FreeformTags: maps.Clone(tags.Freeform), DefinedTags: tags.Defined}}
	if etag != "" {
		request.IfMatch = new(etag)
	}
	if _, err := a.network.UpdateNetworkSecurityGroup(ctx, request); err != nil {
		return fmt.Errorf("update OCI NSG tags: %w", err)
	}
	return nil
}
