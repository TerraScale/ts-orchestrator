package seclist

import (
	"context"
	"fmt"
	"maps"
	"net/http"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nsg"
)

type sdkAPI struct{ network core.VirtualNetworkClient }

// NewSDKAPI builds the security list API on the shared rate-limited factory.
func NewSDKAPI(factory *ociclient.Factory) (API, error) { return newSDKAPI(factory, "") }

// newSDKAPI pins the client to endpoint when set; only tests pass one.
func newSDKAPI(factory *ociclient.Factory, endpoint string) (API, error) {
	network, err := factory.Network()
	if err != nil {
		return nil, err
	}
	ociclient.PinHost(&network.BaseClient, endpoint)
	return sdkAPI{network: network}, nil
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func ingressRule(rule core.IngressSecurityRule) nsg.Rule {
	normalized := nsg.Rule{Direction: nsg.DirectionIngress, Protocol: deref(rule.Protocol), Peer: deref(rule.Source),
		PeerType: string(rule.SourceType), Stateless: rule.IsStateless != nil && *rule.IsStateless,
		Description: deref(rule.Description)}
	return finish(normalized, rule.TcpOptions, rule.UdpOptions, rule.IcmpOptions != nil)
}

func egressRule(rule core.EgressSecurityRule) nsg.Rule {
	normalized := nsg.Rule{Direction: nsg.DirectionEgress, Protocol: deref(rule.Protocol), Peer: deref(rule.Destination),
		PeerType: string(rule.DestinationType), Stateless: rule.IsStateless != nil && *rule.IsStateless,
		Description: deref(rule.Description)}
	return finish(normalized, rule.TcpOptions, rule.UdpOptions, rule.IcmpOptions != nil)
}

func finish(rule nsg.Rule, tcp *core.TcpOptions, udp *core.UdpOptions, icmp bool) nsg.Rule {
	if rule.PeerType == nsg.PeerCIDR {
		rule.PeerType = ""
	}
	low, high, ok := nsg.PortRange(tcp, udp)
	rule.PortMin, rule.PortMax = low, high
	if !ok || icmp {
		rule = rule.MarkUnsupported()
	}
	return rule
}

func (a sdkAPI) GetList(ctx context.Context, id string) (List, error) {
	response, err := a.network.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: new(id)})
	if err != nil {
		if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
			return List{}, fmt.Errorf("get OCI security list: %w: %w", ociresource.ErrGone, err)
		}
		return List{}, fmt.Errorf("get OCI security list: %w", err)
	}
	list := List{ID: deref(response.Id), ETag: deref(response.Etag),
		Tags: ociresource.Tags{Freeform: response.FreeformTags, Defined: response.DefinedTags}}
	for _, rule := range response.IngressSecurityRules {
		list.Rules = append(list.Rules, ingressRule(rule))
	}
	for _, rule := range response.EgressSecurityRules {
		list.Rules = append(list.Rules, egressRule(rule))
	}
	return list, nil
}

func updateDetails(rules []nsg.Rule, tags ociresource.Tags) core.UpdateSecurityListDetails {
	// Empty, non-nil slices: a nil slice is omitted from the request body
	// and would leave that direction's rules in place.
	details := core.UpdateSecurityListDetails{IngressSecurityRules: []core.IngressSecurityRule{},
		EgressSecurityRules: []core.EgressSecurityRule{}, FreeformTags: maps.Clone(tags.Freeform), DefinedTags: tags.Defined}
	for _, rule := range rules {
		tcp, udp := nsg.PortOptions(rule)
		var description *string
		if rule.Description != "" {
			description = new(rule.Description)
		}
		if rule.Direction == nsg.DirectionIngress {
			details.IngressSecurityRules = append(details.IngressSecurityRules, core.IngressSecurityRule{
				Protocol: new(rule.Protocol), Source: new(rule.Peer),
				SourceType:  core.IngressSecurityRuleSourceTypeEnum(rule.EffectivePeerType()),
				IsStateless: new(rule.Stateless), TcpOptions: tcp, UdpOptions: udp, Description: description})
			continue
		}
		details.EgressSecurityRules = append(details.EgressSecurityRules, core.EgressSecurityRule{
			Protocol: new(rule.Protocol), Destination: new(rule.Peer),
			DestinationType: core.EgressSecurityRuleDestinationTypeEnum(rule.EffectivePeerType()),
			IsStateless:     new(rule.Stateless), TcpOptions: tcp, UdpOptions: udp, Description: description})
	}
	return details
}

func (a sdkAPI) UpdateList(ctx context.Context, id, etag string, rules []nsg.Rule, tags ociresource.Tags) error {
	_, err := a.network.UpdateSecurityList(ctx, core.UpdateSecurityListRequest{SecurityListId: new(id), IfMatch: new(etag),
		UpdateSecurityListDetails: updateDetails(rules, tags)})
	if err != nil {
		return fmt.Errorf("update OCI security list: %w", err)
	}
	return nil
}
