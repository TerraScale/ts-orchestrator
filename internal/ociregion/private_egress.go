package ociregion

// PrivateEgressUpdates admits only the exact desired private egress state or
// the previous Service-Gateway-only state. Unknown routes and security drift
// are refused before either full-list update can overwrite them.
func PrivateEgressUpdates(plan, ids Object, routes, ingress, egress any) (routeUpdate, egressUpdate []any, err error) {
	_, err = capture(func() bool {
		sec := obj(plan["network_security"])
		want, previous := []any{}, []any{}
		targets := map[string]string{"{service_gateway_id}": "service_gateway", "{nat_gateway_id}": "nat_gateway", "{local_peering_gateway_id}": "local_peering_gateway"}
		for _, value := range arr(sec["route_rules"]) {
			r := obj(value)
			target := text(ids[targets[text(r["network_entity_id"])]])
			if target == "" {
				fail("private egress requires every exact route target")
			}
			row := Object{"destination": r["destination"], "destination_type": r["destination_type"], "network_entity_id": target}
			want = append(want, row)
			if r["network_entity_id"] != "{nat_gateway_id}" {
				previous = append(previous, row)
			}
		}
		actual := []any{}
		for _, value := range rows(routes) {
			r := obj(value)
			if r["route-type"] != nil && r["route-type"] != "STATIC" {
				fail("private egress refuses non-static route rules")
			}
			actual = append(actual, Object{"destination": r["destination"], "destination_type": r["destination-type"], "network_entity_id": r["network-entity-id"]})
		}
		if !eq(orderedRows(actual), orderedRows(want)) {
			if !eq(orderedRows(actual), orderedRows(previous)) {
				fail("private egress refuses unexpected route table rules")
			}
			for _, value := range want {
				r := obj(value)
				routeUpdate = append(routeUpdate, Object{"destination": r["destination"], "destinationType": r["destination_type"], "networkEntityId": r["network_entity_id"]})
			}
		}
		compareSecurity(ingress, sec["security_list_ingress_rules"], "private egress ingress", "INGRESS")
		want, previous, actual = arr(sec["security_list_egress_rules"]), []any{}, []any{}
		for _, value := range want {
			r := obj(value)
			if r["destination"] != "0.0.0.0/0" || !gatewayPorts(r) {
				previous = append(previous, r)
			}
		}
		for _, value := range rows(egress) {
			actual = append(actual, normalizedSecurity(obj(value), "EGRESS"))
		}
		if !eq(orderedRows(actual), orderedRows(want)) {
			if !eq(orderedRows(actual), orderedRows(previous)) {
				fail("private egress refuses unexpected security list rules")
			}
			egressUpdate = want
		}
		return true
	})
	if err != nil {
		return nil, nil, err
	}
	return routeUpdate, egressUpdate, nil
}
