package routetable

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

type sdkAPI struct{ network core.VirtualNetworkClient }

// NewSDKAPI builds the route table API on the shared rate-limited factory.
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

func (a sdkAPI) GetTable(ctx context.Context, id string) (Table, error) {
	response, err := a.network.GetRouteTable(ociclient.RequestContext(ctx), core.GetRouteTableRequest{RtId: new(id)})
	if err != nil {
		if serviceErr, ok := common.IsServiceError(err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
			return Table{}, fmt.Errorf("get OCI route table: %w: %w", ociresource.ErrGone, err)
		}
		return Table{}, fmt.Errorf("get OCI route table: %w", err)
	}
	table := Table{ID: deref(response.Id), ETag: deref(response.Etag),
		Tags: ociresource.Tags{Freeform: response.FreeformTags, Defined: response.DefinedTags}}
	for _, rule := range response.RouteRules {
		if rule.RouteType == core.RouteRuleRouteTypeLocal {
			continue
		}
		destination := deref(rule.Destination)
		if destination == "" {
			// Older tables carry only the deprecated cidrBlock field.
			destination = deref(rule.CidrBlock)
		}
		route := Route{Destination: destination, DestinationType: string(rule.DestinationType),
			NetworkEntityID: deref(rule.NetworkEntityId), Description: deref(rule.Description)}
		if route.DestinationType == DestinationCIDR {
			route.DestinationType = ""
		}
		table.Routes = append(table.Routes, route)
	}
	return table, nil
}

func (a sdkAPI) UpdateTable(ctx context.Context, id, etag string, routes []Route, tags ociresource.Tags) error {
	if etag == "" {
		return errors.New("update OCI route table requires an ETag")
	}
	// A non-nil empty slice: nil would be omitted and leave the rules.
	rules := []core.RouteRule{}
	for _, route := range routes {
		rule := core.RouteRule{Destination: new(route.Destination),
			DestinationType: core.RouteRuleDestinationTypeEnum(route.destinationType()),
			NetworkEntityId: new(route.NetworkEntityID), RouteType: core.RouteRuleRouteTypeStatic}
		if route.Description != "" {
			rule.Description = new(route.Description)
		}
		rules = append(rules, rule)
	}
	_, err := a.network.UpdateRouteTable(ociclient.RequestContext(ctx), core.UpdateRouteTableRequest{RtId: new(id), IfMatch: new(etag),
		UpdateRouteTableDetails: core.UpdateRouteTableDetails{RouteRules: rules,
			FreeformTags: maps.Clone(tags.Freeform), DefinedTags: tags.Defined}})
	if err != nil {
		return fmt.Errorf("update OCI route table: %w", err)
	}
	return nil
}
