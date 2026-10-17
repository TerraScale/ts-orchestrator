package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func netBirdUnderlayRequestWire(q NetBirdUnderlayRequest) ([]byte, error) {
	var request common.OCIRequest
	switch {
	case q.Create != nil:
		request = core.CreateLocalPeeringGatewayRequest{CreateLocalPeeringGatewayDetails: *q.Create}
	case q.Connect != nil:
		request = core.ConnectLocalPeeringGatewaysRequest{LocalPeeringGatewayId: new(q.ResourceID), ConnectLocalPeeringGatewaysDetails: *q.Connect}
	case q.Route != nil:
		request = core.UpdateRouteTableRequest{RtId: new(q.ResourceID), UpdateRouteTableDetails: *q.Route}
	case q.Security != nil:
		request = core.UpdateSecurityListRequest{SecurityListId: new(q.ResourceID), UpdateSecurityListDetails: *q.Security}
	default:
		return nil, errors.New("NetBird underlay has no typed SDK request")
	}
	r, err := request.HTTPRequest(http.MethodPost, "/", nil, nil)
	if err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, errors.New("NetBird underlay SDK request has no body")
	}
	defer r.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(wire) > 64<<10 {
		return nil, errors.Join(errors.New("NetBird underlay SDK request exceeds its fixed body bound"), err)
	}
	var body map[string]any
	if err := json.Unmarshal(wire, &body); err != nil {
		return nil, err
	}
	return json.Marshal(body, json.Deterministic(true))
}

func netBirdUnderlayIngress(managerIP string) core.IngressSecurityRule {
	return core.IngressSecurityRule{Protocol: new("6"), Source: new(managerIP + "/32"), SourceType: core.IngressSecurityRuleSourceTypeCidrBlock, IsStateless: new(false),
		TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(443), Max: new(443)}}}
}

func netBirdUnderlayHasRoute(rules []core.RouteRule, destination, gateway string) bool {
	expected := core.RouteRule{Destination: new(destination), DestinationType: core.RouteRuleDestinationTypeCidrBlock, NetworkEntityId: new(gateway)}
	count := 0
	peer := netip.MustParsePrefix(destination).Addr()
	for _, rule := range rules {
		if value(rule.NetworkEntityId) == gateway || value(rule.Destination) == destination {
			if !sameNetBirdRoutes([]core.RouteRule{rule}, []core.RouteRule{expected}) {
				return false
			}
			count++
		} else if prefix, err := netip.ParsePrefix(value(rule.Destination)); err == nil && prefix.Contains(peer) && prefix.Bits() != 0 {
			// The pre-existing Internet default remains; a competing private path does not.
			return false
		}
	}
	return count == 1
}

func prepareNetBirdUnderlayRequest(ctx context.Context, client core.VirtualNetworkClient, r NetBirdUnderlayRecord, key string) (NetBirdUnderlayRequest, error) {
	var q NetBirdUnderlayRequest
	switch key {
	case "manager_gateway", "writer_gateway":
		e := r.Manager
		if key == "writer_gateway" {
			e = r.Writer
		}
		q.Create = &core.CreateLocalPeeringGatewayDetails{CompartmentId: new(e.NetworkCompartmentID), VcnId: new(e.NetworkID), DisplayName: new("gru-1-netbird-journal")}
	case "connect":
		q.ResourceID = r.Requests["manager_gateway"].ResponseID
		q.Connect = &core.ConnectLocalPeeringGatewaysDetails{PeerId: new(r.Requests["writer_gateway"].ResponseID)}
	case "manager_route", "writer_route":
		e, destination, gateway := r.Manager, r.Recipe.WriterPrivateIP+"/32", r.Requests["manager_gateway"].ResponseID
		if key == "writer_route" {
			e, destination, gateway = r.Writer, r.Recipe.ManagerPrivateIP+"/32", r.Requests["writer_gateway"].ResponseID
		}
		response, err := client.GetRouteTable(ociclient.RequestContext(ctx), core.GetRouteTableRequest{RtId: new(e.RouteTableID)})
		if err != nil {
			return q, err
		}
		if value(response.Id) != e.RouteTableID || value(response.VcnId) != e.NetworkID || value(response.CompartmentId) != e.NetworkCompartmentID || response.LifecycleState != core.RouteTableLifecycleStateAvailable || value(response.ETag) == "" {
			return q, errors.New("NetBird underlay route preparation lacks its exact current VCN table and ETag")
		}
		rules, err := netBirdUnderlayWritableRoutes(response.RouteRules)
		if err != nil {
			return q, err
		}
		for _, rule := range rules {
			if value(rule.NetworkEntityId) == gateway || value(rule.Destination) == destination {
				return q, errors.New("NetBird underlay cannot adopt an unjournaled peer route")
			}
		}
		rules = append(rules, core.RouteRule{Destination: new(destination), DestinationType: core.RouteRuleDestinationTypeCidrBlock, NetworkEntityId: new(gateway)})
		q.ResourceID, q.IfMatch, q.Route = e.RouteTableID, value(response.ETag), &core.UpdateRouteTableDetails{RouteRules: rules}
	case "writer_security":
		response, err := client.GetSecurityList(ociclient.RequestContext(ctx), core.GetSecurityListRequest{SecurityListId: new(r.Writer.SecurityID)})
		if err != nil {
			return q, err
		}
		if value(response.Id) != r.Writer.SecurityID || value(response.VcnId) != r.Writer.NetworkID || value(response.CompartmentId) != r.Writer.NetworkCompartmentID || response.LifecycleState != core.SecurityListLifecycleStateAvailable || value(response.ETag) == "" {
			return q, errors.New("NetBird underlay security preparation lacks its exact current writer list and ETag")
		}
		ingress := slices.Clone(response.IngressSecurityRules)
		if slices.ContainsFunc(ingress, func(rule core.IngressSecurityRule) bool {
			return netBirdUnderlayEqual(rule, netBirdUnderlayIngress(r.Recipe.ManagerPrivateIP))
		}) {
			return q, errors.New("NetBird underlay cannot adopt an unjournaled manager ingress rule")
		}
		ingress = append(ingress, netBirdUnderlayIngress(r.Recipe.ManagerPrivateIP))
		q.ResourceID, q.IfMatch, q.Security = r.Writer.SecurityID, value(response.ETag), &core.UpdateSecurityListDetails{IngressSecurityRules: ingress, EgressSecurityRules: slices.Clone(response.EgressSecurityRules)}
	default:
		return q, errors.New("unknown NetBird underlay request step")
	}
	return q, nil
}

// dispatchNetBirdUnderlay sends once; even connect has SDK retries disabled.
func dispatchNetBirdUnderlay(ctx context.Context, client core.VirtualNetworkClient, q NetBirdUnderlayRequest) (string, error) {
	policy := common.NoRetryPolicy()
	metadata := common.RequestMetadata{RetryPolicy: &policy}
	switch {
	case q.Create != nil:
		r, err := client.CreateLocalPeeringGateway(ociclient.RequestContext(ctx), core.CreateLocalPeeringGatewayRequest{CreateLocalPeeringGatewayDetails: *q.Create, OpcRetryToken: new(q.RetryToken), RequestMetadata: metadata})
		if err == nil && !netBirdUnderlayNativeID("localpeeringgateway", value(r.Id)) {
			return "", errors.New("NetBird underlay create returned no exact positive native gateway ID")
		}
		return value(r.Id), err
	case q.Connect != nil:
		_, err := client.ConnectLocalPeeringGateways(ociclient.RequestContext(ctx), core.ConnectLocalPeeringGatewaysRequest{LocalPeeringGatewayId: new(q.ResourceID), ConnectLocalPeeringGatewaysDetails: *q.Connect, RequestMetadata: metadata})
		return "", err
	case q.Route != nil:
		_, err := client.UpdateRouteTable(ociclient.RequestContext(ctx), core.UpdateRouteTableRequest{RtId: new(q.ResourceID), IfMatch: new(q.IfMatch), UpdateRouteTableDetails: *q.Route, RequestMetadata: metadata})
		return "", err
	case q.Security != nil:
		_, err := client.UpdateSecurityList(ociclient.RequestContext(ctx), core.UpdateSecurityListRequest{SecurityListId: new(q.ResourceID), IfMatch: new(q.IfMatch), UpdateSecurityListDetails: *q.Security, RequestMetadata: metadata})
		return "", err
	}
	return "", errors.New("NetBird underlay dispatch has no exact typed SDK body")
}

func observeNetBirdUnderlayRequest(ctx context.Context, client core.VirtualNetworkClient, r NetBirdUnderlayRecord, key string) error {
	q := r.Requests[key]
	if q.RespondedAt.IsZero() {
		return ErrNetBirdUnderlayPending
	}
	switch key {
	case "manager_gateway", "writer_gateway":
		e := r.Manager
		peerKey := "writer_gateway"
		if key == "writer_gateway" {
			e = r.Writer
			peerKey = "manager_gateway"
		}
		gateway, err := observeNetBirdUnderlayGateway(ctx, client, q.ResponseID, e)
		if err != nil {
			return err
		}
		if r.Requests["connect"].RespondedAt.IsZero() {
			if gateway.PeeringStatus != core.LocalPeeringGatewayPeeringStatusNew || value(gateway.PeerId) != "" || value(gateway.PeerAdvertisedCidr) != "" || len(gateway.PeerAdvertisedCidrDetails) != 0 {
				return errors.New("NetBird underlay gateway acquired an unjournaled peering")
			}
		} else if gateway.PeeringStatus != core.LocalPeeringGatewayPeeringStatusPeered || value(gateway.PeerId) != r.Requests[peerKey].ResponseID {
			return errors.New("NetBird underlay gateway no longer peers with its exact original native counterpart")
		}
	case "connect":
		for _, side := range []struct {
			key, peer string
			endpoint  NetBirdUnderlayEndpoint
		}{{"manager_gateway", "writer_gateway", r.Manager}, {"writer_gateway", "manager_gateway", r.Writer}} {
			gateway, err := observeNetBirdUnderlayGateway(ctx, client, r.Requests[side.key].ResponseID, side.endpoint)
			if err != nil {
				return err
			}
			peerCIDR := r.Recipe.WriterNetworkCIDR
			if side.key == "writer_gateway" {
				peerCIDR = r.Recipe.ManagerNetworkCIDR
			}
			if gateway.PeeringStatus != core.LocalPeeringGatewayPeeringStatusPeered || value(gateway.PeerId) != r.Requests[side.peer].ResponseID ||
				value(gateway.PeerAdvertisedCidr) != peerCIDR || !slices.Equal(gateway.PeerAdvertisedCidrDetails, []string{peerCIDR}) {
				return errors.New("NetBird underlay gateway is not peered to the exact original reciprocal VCN")
			}
		}
	case "manager_route", "writer_route":
		e := r.Manager
		if key == "writer_route" {
			e = r.Writer
		}
		response, err := client.GetRouteTable(ociclient.RequestContext(ctx), core.GetRouteTableRequest{RtId: new(e.RouteTableID)})
		if err != nil {
			return err
		}
		actual, normalizeErr := netBirdUnderlayWritableRoutes(response.RouteRules)
		if normalizeErr != nil || value(response.Id) != e.RouteTableID || value(response.VcnId) != e.NetworkID || value(response.CompartmentId) != e.NetworkCompartmentID || response.LifecycleState != core.RouteTableLifecycleStateAvailable || !netBirdUnderlayEqual(actual, q.Route.RouteRules) {
			return errors.New("NetBird underlay route readback differs from its exact conditional request")
		}
	case "writer_security":
		response, err := client.GetSecurityList(ociclient.RequestContext(ctx), core.GetSecurityListRequest{SecurityListId: new(r.Writer.SecurityID)})
		if err != nil {
			return err
		}
		if value(response.Id) != r.Writer.SecurityID || value(response.VcnId) != r.Writer.NetworkID || value(response.CompartmentId) != r.Writer.NetworkCompartmentID || response.LifecycleState != core.SecurityListLifecycleStateAvailable ||
			!netBirdUnderlayEqual(response.IngressSecurityRules, q.Security.IngressSecurityRules) || !netBirdUnderlayEqual(response.EgressSecurityRules, q.Security.EgressSecurityRules) {
			return errors.New("NetBird underlay writer security readback differs from its exact conditional request")
		}
	}
	return nil
}

func observeNetBirdUnderlayGateway(ctx context.Context, client core.VirtualNetworkClient, id string, endpoint NetBirdUnderlayEndpoint) (core.LocalPeeringGateway, error) {
	response, err := client.GetLocalPeeringGateway(ociclient.RequestContext(ctx), core.GetLocalPeeringGatewayRequest{LocalPeeringGatewayId: new(id)})
	if err != nil {
		return core.LocalPeeringGateway{}, err
	}
	gateway := response.LocalPeeringGateway
	if !netBirdUnderlayNativeID("localpeeringgateway", id) || value(gateway.Id) != id || value(gateway.VcnId) != endpoint.NetworkID || value(gateway.CompartmentId) != endpoint.NetworkCompartmentID ||
		gateway.LifecycleState != core.LocalPeeringGatewayLifecycleStateAvailable || gateway.IsCrossTenancyPeering == nil || *gateway.IsCrossTenancyPeering || value(gateway.RouteTableId) != "" {
		return core.LocalPeeringGateway{}, errors.New("NetBird underlay gateway differs from its original native VCN or permits transit")
	}
	return gateway, nil
}

func netBirdUnderlayWritableRoutes(rules []core.RouteRule) ([]core.RouteRule, error) {
	result := slices.Clone(rules)
	for index, rule := range result {
		if rule.RouteType != "" && rule.RouteType != core.RouteRuleRouteTypeStatic || value(rule.CidrBlock) != "" && value(rule.Destination) != "" && value(rule.CidrBlock) != value(rule.Destination) {
			return nil, errors.New("NetBird underlay cannot rewrite an ambiguous or provider-local route")
		}
		if value(rule.Destination) != "" {
			result[index].CidrBlock = nil
		}
		result[index].RouteType = ""
	}
	return result, nil
}
