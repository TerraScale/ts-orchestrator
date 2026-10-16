package foundation

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
)

func (f *Foundation) privateEgress(ctx context.Context, plan Object, network string, id func(string) string) error {
	if id("route_table") == "" || id("security_list") == "" {
		return nil // A dry run has no provider IDs yet.
	}
	read := func(key string, args ...string) (Object, string, error) {
		response, err := f.Region.Call(ctx, args...)
		if err != nil {
			return nil, "", err
		}
		row, err := command.Object(response["data"])
		if err != nil {
			return nil, "", err
		}
		if row["id"] != id(key) || row["compartment-id"] != network || row["vcn-id"] != id("vcn") || row["lifecycle-state"] != "AVAILABLE" {
			return nil, "", errors.New("private egress read differs from its recorded network scope")
		}
		etag, _ := response["etag"].(string)
		return row, etag, nil
	}
	route, routeTag, err := read("route_table", "network", "route-table", "get", "--rt-id", id("route_table"))
	if err != nil {
		return err
	}
	security, securityTag, err := read("security_list", "network", "security-list", "get", "--security-list-id", id("security_list"))
	if err != nil {
		return err
	}
	ids := Object{"service_gateway": id("service_gateway"), "nat_gateway": id("nat_gateway"), "local_peering_gateway": id("local_peering_gateway")}
	routes, egress, err := ociregion.PrivateEgressUpdates(plan, ids, route["route-rules"], security["ingress-security-rules"], security["egress-security-rules"])
	if err != nil {
		return err
	}
	if len(routes) > 0 && routeTag == "" || len(egress) > 0 && securityTag == "" {
		return errors.New("private egress updates require the current route and security ETags")
	}
	if len(routes) > 0 {
		if err := f.change(ctx, "private NAT default route", f.Region, "network", "route-table", "update", "--rt-id", id("route_table"), "--route-rules", command.JSON(routes), "--if-match", routeTag); err != nil {
			return err
		}
	}
	if len(egress) > 0 {
		return f.change(ctx, "private NetBird HTTPS and STUN egress", f.Region, "network", "security-list", "update", "--security-list-id", id("security_list"), "--egress-security-rules", command.JSON(rules(egress, false)), "--if-match", securityTag)
	}
	return nil
}
