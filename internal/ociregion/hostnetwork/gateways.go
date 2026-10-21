package hostnetwork

import (
	"errors"
	"slices"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func (n network) internetGateway() (*string, error) {
	ctx, name := n.ctx, n.s.cell+"-igw"
	list, err := n.net.ListInternetGateways(ctx, core.ListInternetGatewaysRequest{CompartmentId: &n.compartment, VcnId: n.vcn, DisplayName: &name})
	if err != nil {
		return nil, err
	}
	g, err := one(list.Items, name, func(g core.InternetGateway) (string, string) { return deref(g.DisplayName), string(g.LifecycleState) })
	if err != nil {
		return nil, err
	}
	if g == nil {
		var id *string
		return id, n.step("create internet gateway "+name, func() error {
			t, _ := n.tags("internet-gateway", "igw", nil)
			c, err := n.net.CreateInternetGateway(ctx, core.CreateInternetGatewayRequest{CreateInternetGatewayDetails: core.CreateInternetGatewayDetails{
				CompartmentId: &n.compartment, VcnId: n.vcn, IsEnabled: new(true), DisplayName: &name, FreeformTags: t}})
			id = c.Id
			return err
		})
	}
	t, err := n.tags("internet-gateway", "igw", g.FreeformTags)
	if err != nil || t == nil && deref(g.IsEnabled) {
		return g.Id, err
	}
	return g.Id, n.step("enable and tag internet gateway "+name, func() error {
		_, err := n.net.UpdateInternetGateway(ctx, core.UpdateInternetGatewayRequest{IgId: g.Id, UpdateInternetGatewayDetails: core.UpdateInternetGatewayDetails{
			IsEnabled: new(true), FreeformTags: t}})
		return err
	})
}

// serviceGateway returns the gateway to all of the region's Oracle services
// and that services CIDR label. It is free and needs no public IP.
func (n network) serviceGateway() (*string, *string, error) {
	ctx, name := n.ctx, n.s.cell+"-service-gateway"
	services, err := n.net.ListServices(ctx, core.ListServicesRequest{})
	if err != nil {
		return nil, nil, err
	}
	i := slices.IndexFunc(services.Items, func(s core.Service) bool { return strings.HasPrefix(deref(s.CidrBlock), "all-") })
	if i < 0 {
		return nil, nil, errors.New("region offers no all-services gateway service")
	}
	service := services.Items[i]
	list, err := n.net.ListServiceGateways(ctx, core.ListServiceGatewaysRequest{CompartmentId: &n.compartment, VcnId: n.vcn})
	if err != nil {
		return nil, nil, err
	}
	g, err := one(list.Items, name, func(g core.ServiceGateway) (string, string) { return deref(g.DisplayName), string(g.LifecycleState) })
	if err != nil {
		return nil, nil, err
	}
	want := []core.ServiceIdRequestDetails{{ServiceId: service.Id}}
	if g == nil {
		var id *string
		return id, service.CidrBlock, n.step("create service gateway "+name, func() error {
			t, _ := n.tags("service-gateway", "sgw", nil)
			c, err := n.net.CreateServiceGateway(ctx, core.CreateServiceGatewayRequest{CreateServiceGatewayDetails: core.CreateServiceGatewayDetails{
				CompartmentId: &n.compartment, VcnId: n.vcn, Services: want, DisplayName: &name, FreeformTags: t}})
			id = c.Id
			return errors.Join(err, n.await(func() (string, error) {
				g, err := n.net.GetServiceGateway(ctx, core.GetServiceGatewayRequest{ServiceGatewayId: c.Id})
				return string(g.LifecycleState), err
			}))
		})
	}
	t, err := n.tags("service-gateway", "sgw", g.FreeformTags)
	same := len(g.Services) == 1 && deref(g.Services[0].ServiceId) == deref(service.Id)
	if err != nil || t == nil && same {
		return g.Id, service.CidrBlock, err
	}
	return g.Id, service.CidrBlock, n.step("converge service gateway "+name, func() error {
		_, err := n.net.UpdateServiceGateway(ctx, core.UpdateServiceGatewayRequest{ServiceGatewayId: g.Id, UpdateServiceGatewayDetails: core.UpdateServiceGatewayDetails{
			Services: want, FreeformTags: t}})
		return err
	})
}

// routeTable converges the table with id, or the one named name, to rules.
func (n network) routeTable(key string, id *string, name string, rules []core.RouteRule) (*string, error) {
	ctx := n.ctx
	var rt *core.RouteTable
	if id != nil {
		g, err := n.net.GetRouteTable(ctx, core.GetRouteTableRequest{RtId: id})
		if err != nil {
			return nil, err
		}
		rt = &g.RouteTable
	} else {
		list, err := n.net.ListRouteTables(ctx, core.ListRouteTablesRequest{CompartmentId: &n.compartment, VcnId: n.vcn, DisplayName: &name})
		if err != nil {
			return nil, err
		}
		if rt, err = one(list.Items, name, func(t core.RouteTable) (string, string) { return deref(t.DisplayName), string(t.LifecycleState) }); err != nil {
			return nil, err
		}
	}
	if rt == nil {
		var created *string
		return created, n.step("create route table "+name, func() error {
			t, _ := n.tags("route-table", key, nil)
			c, err := n.net.CreateRouteTable(ctx, core.CreateRouteTableRequest{CreateRouteTableDetails: core.CreateRouteTableDetails{
				CompartmentId: &n.compartment, VcnId: n.vcn, RouteRules: rules, DisplayName: &name, FreeformTags: t}})
			created = c.Id
			return errors.Join(err, n.await(func() (string, error) {
				g, err := n.net.GetRouteTable(ctx, core.GetRouteTableRequest{RtId: c.Id})
				return string(g.LifecycleState), err
			}))
		})
	}
	t, err := n.tags("route-table", key, rt.FreeformTags)
	if err != nil || t == nil && sameRoutes(rt.RouteRules, rules) {
		return rt.Id, err
	}
	return rt.Id, n.step("converge route table "+deref(rt.DisplayName), func() error {
		_, err := n.net.UpdateRouteTable(ctx, core.UpdateRouteTableRequest{RtId: rt.Id, UpdateRouteTableDetails: core.UpdateRouteTableDetails{
			RouteRules: rules, FreeformTags: t}})
		return err
	})
}

func sameRoutes(live, want []core.RouteRule) bool {
	return slices.EqualFunc(live, want, func(a, b core.RouteRule) bool {
		return deref(a.Destination) == deref(b.Destination) && a.DestinationType == b.DestinationType && deref(a.NetworkEntityId) == deref(b.NetworkEntityId)
	})
}
