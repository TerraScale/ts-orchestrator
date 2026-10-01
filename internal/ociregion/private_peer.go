package ociregion

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

var privatePeerCellFields = []string{"plan_sha256", "drg_id", "vcn_attachment_id", "rpc_id", "rpc_attachment_id", "vcn_drg_route_table_id", "rpc_drg_route_table_id", "vcn_import_distribution_id", "rpc_import_distribution_id", "monthly_cross_region_egress_gb"}

func ocidRealm(id string) string {
	m := regexp.MustCompile(`^ocid1\.[a-z]+\.(oc[0-9]+)\.`).FindStringSubmatch(id)
	if m == nil {
		fail("private peer plans must use an OCI realm OCID")
	}
	return m[1]
}

func privatePeerNetwork(value any, label string) netip.Prefix {
	s, ok := value.(string)
	if !ok {
		fail("private peer " + label + " CIDR must be a string")
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p != p.Masked() {
		fail("private peer " + label + " CIDR has invalid host bits or format")
	}
	valid := false
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		r := netip.MustParsePrefix(cidr)
		if p.Addr().Is4() && p.Bits() >= r.Bits() && r.Contains(p.Addr()) {
			valid = true
		}
	}
	if !valid {
		fail("private peer " + label + " CIDR must be inside an RFC1918 IPv4 range")
	}
	return p
}

type privatePeerContext struct {
	side, planPath, inventoryPath, admissionPath, planSHA string
	plan, ids, intent, admission                          Object
	network, subnet                                       netip.Prefix
}

func (e *Engine) privatePeerInputs(intent Object, intentPath string, paths map[string]string, intentSHA string) (Object, map[string]*privatePeerContext, Object) {
	if !exact(intent, "schema_version", "tenancy_id", "realm", "allowed_tcp_ports", "cells") {
		fail("private peer intent has unexpected or missing fields")
	}
	if !integer(intent["schema_version"]) || !eq(intent["schema_version"], 1) {
		fail("unsupported private peer intent schema")
	}
	tenancy := requireOCID(intent["tenancy_id"], "tenancy", "")
	realm := ocidRealm(tenancy)
	if intent["realm"] != realm {
		fail("private peer intent realm differs from its tenancy")
	}
	if len(paths) != 2 || paths["left"] == "" || paths["right"] == "" {
		fail("private peer inspection requires two regional plans")
	}
	plans := Object{}
	hashes := map[string]string{}
	for _, side := range []string{"left", "right"} {
		hashes[side] = fileSHA(paths[side])
		plans[side] = e.loadPlan(paths[side])
	}
	for _, side := range []string{"left", "right"} {
		if fileSHA(paths[side]) != hashes[side] {
			fail("private peer regional plan changed while its intent was being read")
		}
	}
	left, right := obj(plans["left"]), obj(plans["right"])
	if left["cell"] == right["cell"] || left["region"] == right["region"] {
		fail("private peer plans must name two distinct mapped cells and regions")
	}
	for _, side := range []string{"left", "right"} {
		p := obj(plans[side])
		if p["tenancy_id"] != tenancy || ocidRealm(text(p["tenancy_id"])) != realm {
			fail("private peer plans do not share the exact tenancy and realm")
		}
	}
	if !exact(intent["cells"], text(left["cell"]), text(right["cell"])) {
		fail("private peer intent cell map differs from the two regional plans")
	}
	ports, ok := intent["allowed_tcp_ports"].([]any)
	if !ok || len(ports) == 0 || len(ports) > 32 {
		fail("private peer intent must list sorted, unique, exact TCP ports")
	}
	previous := 0.0
	for _, port := range ports {
		if !integer(port) || number(port) < 1 || number(port) > 65535 || number(port) <= previous {
			fail("private peer intent must list sorted, unique, exact TCP ports")
		}
		previous = number(port)
	}
	contexts := map[string]*privatePeerContext{}
	seen := map[string]bool{}
	for _, side := range []string{"left", "right"} {
		p := obj(plans[side])
		cell := text(p["cell"])
		row := obj(intent["cells"])[cell]
		if !exact(row, privatePeerCellFields...) {
			fail("private peer intent has an incomplete or unexpected " + cell + " mapping")
		}
		r := obj(row)
		if r["plan_sha256"] != hashes[side] {
			fail("private peer intent is stale for the " + cell + " plan")
		}
		ids := e.requiredIDs(p)
		for _, pair := range [][2]string{{"drg_id", "drg"}, {"vcn_attachment_id", "drgattachment"}, {"rpc_id", "remotepeeringconnection"}, {"rpc_attachment_id", "drgattachment"}, {"vcn_drg_route_table_id", "drgroutetable"}, {"rpc_drg_route_table_id", "drgroutetable"}, {"vcn_import_distribution_id", "drgroutedistribution"}, {"rpc_import_distribution_id", "drgroutedistribution"}} {
			id := requireOCID(r[pair[0]], pair[1], text(p["region"]))
			if seen[id] {
				fail("private peer intent reuses a resource OCID")
			}
			seen[id] = true
		}
		sec := obj(p["network_security"])
		if ids["vcn"] == nil || ids["subnet"] == nil || ids["route_table"] == nil || ids["service_gateway"] == nil || len(arr(sec["route_rules"])) != 1 || sec["service_gateway_service_id"] == nil {
			fail("private peer plans must preserve their exact local service-gateway route")
		}
		if rat(r["monthly_cross_region_egress_gb"]).Sign() < 0 || greater(r["monthly_cross_region_egress_gb"], obj(p["budget"])["egress_gb_max"]) {
			fail("private peer " + cell + " traffic exceeds the regional plan's priced egress reserve")
		}
		network := privatePeerNetwork(p["network_cidr"], "VCN")
		subnet := privatePeerNetwork(p["subnet_cidr"], "subnet")
		if subnet.Bits() < network.Bits() || !network.Contains(subnet.Addr()) {
			fail("private peer subnet CIDR is outside its regional VCN")
		}
		contexts[cell] = &privatePeerContext{side: side, plan: p, planPath: paths[side], planSHA: hashes[side], ids: ids, intent: r, network: network, subnet: subnet}
	}
	cells := slices.Sorted(func(yield func(string) bool) {
		for cell := range contexts {
			if !yield(cell) {
				return
			}
		}
	})
	if contexts[cells[0]].network.Overlaps(contexts[cells[1]].network) || contexts[cells[0]].subnet.Overlaps(contexts[cells[1]].subnet) {
		fail("private peer VCN and subnet CIDRs must not overlap")
	}
	if fileSHA(intentPath) != intentSHA {
		fail("private peer intent changed while it was being read")
	}
	return plans, contexts, Object{"realm": realm, "tenancy_id": tenancy, "ports": ports, "intent_sha256": intentSHA}
}

func exactPeerRows(actual any, expected []any, label string) []any {
	r := rows(actual)
	if !slices.Equal(orderedRows(r), orderedRows(expected)) {
		fail("live " + label + " differs from the exact private peer intent")
	}
	return r
}

func privatePeerSecurity(plan Object, peer string, ports []any) ([]any, []any) {
	sec := obj(plan["network_security"])
	nsg := slices.Clone(arr(sec["nsg_rules"]))
	egress := slices.Clone(arr(sec["security_list_egress_rules"]))
	for _, port := range ports {
		nsg = append(nsg, Object{"direction": "INGRESS", "protocol": "6", "source": peer, "source_type": "CIDR_BLOCK", "destination": nil, "destination_type": nil, "tcp_min": port, "tcp_max": port, "udp_min": nil, "udp_max": nil, "stateless": false})
		egress = append(egress, Object{"direction": "EGRESS", "protocol": "6", "source": nil, "source_type": nil, "destination": peer, "destination_type": "CIDR_BLOCK", "tcp_min": port, "tcp_max": port, "udp_min": nil, "udp_max": nil, "stateless": false})
	}
	return nsg, egress
}

func normalizedDRGRoute(r Object) Object {
	result := Object{}
	for _, key := range []string{"destination", "destination_type", "next_hop_drg_attachment_id", "route_type", "is_conflict", "is_blackhole"} {
		value, ok := r[strings.ReplaceAll(key, "_", "-")]
		if !ok {
			value = r[key]
		}
		result[key] = value
	}
	return result
}

func peerLive(v any, id, label string) Object {
	r, ok := v.(Object)
	if !ok || r["id"] != id {
		fail("live " + label + " identity differs from the exact plan")
	}
	return r
}

func (e *Engine) peerDistribution(region, id, drg, compartment, accepted string) Object {
	r := peerLive(e.oci(region, "network", "drg-route-distribution", "get", "--route-distribution-id", id), id, "DRG route import distribution")
	if r["lifecycle-state"] != "AVAILABLE" || r["distribution-type"] != "IMPORT" || r["drg-id"] != drg || r["compartment-id"] != compartment {
		fail("live DRG import distribution has an unexpected type, DRG, compartment, or state")
	}
	statements := rows(e.oci(region, "network", "drg-route-distribution-statement", "list", "--route-distribution-id", id, "--all"))
	if len(statements) != 1 {
		fail("live DRG import distribution is broad or contains extra statements")
	}
	statement := obj(statements[0])
	if !exact(statement, "action", "priority", "match-criteria") && !exact(statement, "id", "action", "priority", "match-criteria") {
		fail("live DRG import distribution statement has unexpected fields")
	}
	criteria := rows(statement["match-criteria"])
	if statement["action"] != "ACCEPT" || !integer(statement["priority"]) || number(statement["priority"]) < 0 || number(statement["priority"]) > 65535 || len(criteria) != 1 || !exact(criteria[0], "match-type", "drg-attachment-id") || obj(criteria[0])["match-type"] != "DRG_ATTACHMENT_ID" || obj(criteria[0])["drg-attachment-id"] != accepted {
		fail("live DRG import distribution is not scoped to the exact paired attachment")
	}
	return Object{"id": id, "distribution_type": "IMPORT", "drg_id": drg, "compartment_id": compartment, "statement": Object{"id": statement["id"], "action": statement["action"], "priority": statement["priority"], "match_criteria": []any{Object{"match_type": "DRG_ATTACHMENT_ID", "drg_attachment_id": accepted}}}}
}

func (e *Engine) inspectPrivatePeerSide(c, peer *privatePeerContext, ports []any) Object {
	p, ids, intent := c.plan, c.ids, c.intent
	region, compartment := text(p["region"]), text(ids["network_compartment"])
	drgID, vcnAttachmentID, rpcID, rpcAttachmentID := text(intent["drg_id"]), text(intent["vcn_attachment_id"]), text(intent["rpc_id"]), text(intent["rpc_attachment_id"])
	get := func(kind, flag, id, label string) Object {
		return peerLive(e.oci(region, "network", kind, "get", flag, id), id, label)
	}
	vcn := get("vcn", "--vcn-id", text(ids["vcn"]), "VCN")
	if vcn["lifecycle-state"] != "AVAILABLE" || vcn["compartment-id"] != compartment || vcn["cidr-block"] != p["network_cidr"] {
		fail("live private peer VCN state, compartment, or CIDR differs from its plan")
	}
	subnet := get("subnet", "--subnet-id", text(ids["subnet"]), "subnet")
	if subnet["lifecycle-state"] != "AVAILABLE" || subnet["compartment-id"] != compartment || subnet["vcn-id"] != ids["vcn"] || subnet["cidr-block"] != p["subnet_cidr"] || subnet["prohibit-public-ip-on-vnic"] != true || subnet["prohibit-internet-ingress"] != true || !eq(subnet["security-list-ids"], []any{ids["security_list"]}) || subnet["route-table-id"] != ids["route_table"] {
		fail("live private peer subnet identity or private security differs from its plan")
	}
	nsg := get("nsg", "--nsg-id", text(ids["network_security_group"]), "network security group")
	if nsg["compartment-id"] != compartment || nsg["vcn-id"] != ids["vcn"] {
		fail("live private peer NSG belongs to an unexpected VCN or compartment")
	}
	wantNSG, wantEgress := privatePeerSecurity(p, peer.subnet.String(), ports)
	normalized := func(v any, direction string) []any {
		r := []any{}
		for _, v := range rows(v) {
			r = append(r, normalizedSecurity(obj(v), direction))
		}
		return r
	}
	nsgRules := normalized(e.oci(region, "network", "nsg", "rules", "list", "--nsg-id", text(ids["network_security_group"])), "")
	exactPeerRows(nsgRules, wantNSG, "peer NSG rules")
	security := get("security-list", "--security-list-id", text(ids["security_list"]), "security list")
	if security["compartment-id"] != compartment || security["vcn-id"] != ids["vcn"] {
		fail("live private peer security list belongs to an unexpected VCN or compartment")
	}
	ingress, egress := normalized(security["ingress-security-rules"], "INGRESS"), normalized(security["egress-security-rules"], "EGRESS")
	exactPeerRows(ingress, arr(obj(p["network_security"])["security_list_ingress_rules"]), "peer security-list ingress rules")
	exactPeerRows(egress, wantEgress, "peer security-list egress rules")
	route := get("route-table", "--rt-id", text(ids["route_table"]), "subnet route table")
	if route["compartment-id"] != compartment || route["vcn-id"] != ids["vcn"] {
		fail("live subnet route table belongs to an unexpected VCN or compartment")
	}
	routes := []any{}
	for _, v := range rows(route["route-rules"]) {
		r := obj(v)
		routes = append(routes, Object{"destination": r["destination"], "destination_type": r["destination-type"], "network_entity_id": r["network-entity-id"]})
	}
	wantRoutes := []any{}
	for _, v := range arr(obj(p["network_security"])["route_rules"]) {
		r := Object{}
		for k, value := range obj(v) {
			r[k] = value
		}
		r["network_entity_id"] = ids["service_gateway"]
		wantRoutes = append(wantRoutes, r)
	}
	wantRoutes = append(wantRoutes, Object{"destination": peer.subnet.String(), "destination_type": "CIDR_BLOCK", "network_entity_id": drgID})
	exactPeerRows(routes, wantRoutes, "reciprocal subnet route table")
	gateway := get("service-gateway", "--service-gateway-id", text(ids["service_gateway"]), "service gateway")
	services := []any{}
	for _, v := range arr(gateway["services"]) {
		if r, ok := v.(Object); ok {
			services = append(services, r["service-id"])
		}
	}
	if gateway["compartment-id"] != compartment || gateway["vcn-id"] != ids["vcn"] || gateway["lifecycle-state"] != "AVAILABLE" || !eq(services, []any{obj(p["network_security"])["service_gateway_service_id"]}) {
		fail("live local service gateway differs from the exact regional plan")
	}
	drg := get("drg", "--drg-id", drgID, "DRG")
	if drg["lifecycle-state"] != "AVAILABLE" || drg["compartment-id"] != compartment {
		fail("live DRG is unavailable or owned by another compartment")
	}
	attachments := rows(e.oci(region, "network", "drg-attachment", "list", "--compartment-id", compartment, "--drg-id", drgID, "--attachment-type", "ALL", "--all"))
	seen := map[string]bool{}
	for _, v := range attachments {
		r := obj(v)
		seen[text(r["id"])] = true
		if r["lifecycle-state"] != "ATTACHED" {
			fail("live DRG has an unexpected, missing, or disconnected attachment")
		}
	}
	if len(seen) != 2 || !seen[vcnAttachmentID] || !seen[rpcAttachmentID] {
		fail("live DRG has an unexpected, missing, or disconnected attachment")
	}
	vcnAttachment := get("drg-attachment", "--drg-attachment-id", vcnAttachmentID, "VCN DRG attachment")
	details := obj(vcnAttachment["network-details"])
	if vcnAttachment["compartment-id"] != compartment || vcnAttachment["drg-id"] != drgID || vcnAttachment["lifecycle-state"] != "ATTACHED" || (vcnAttachment["vcn-id"] != nil && vcnAttachment["vcn-id"] != ids["vcn"]) || details["type"] != "VCN" || details["id"] != ids["vcn"] || vcnAttachment["is-cross-tenancy"] != false || vcnAttachment["drg-route-table-id"] != intent["vcn_drg_route_table_id"] {
		fail("live VCN DRG attachment identity, ownership, or route-table mapping differs from the intent")
	}
	rpcAttachment := get("drg-attachment", "--drg-attachment-id", rpcAttachmentID, "RPC DRG attachment")
	details = obj(rpcAttachment["network-details"])
	if rpcAttachment["compartment-id"] != compartment || rpcAttachment["drg-id"] != drgID || rpcAttachment["lifecycle-state"] != "ATTACHED" || details["type"] != "REMOTE_PEERING_CONNECTION" || details["id"] != rpcID || rpcAttachment["is-cross-tenancy"] == true || rpcAttachment["drg-route-table-id"] != intent["rpc_drg_route_table_id"] {
		fail("live RPC DRG attachment identity, ownership, or route-table mapping differs from the intent")
	}
	rpc := get("remote-peering-connection", "--remote-peering-connection-id", rpcID, "remote peering connection")
	if rpc["compartment-id"] != compartment || rpc["drg-id"] != drgID || rpc["lifecycle-state"] != "AVAILABLE" || rpc["peering-status"] != "PEERED" || rpc["peer-id"] != peer.intent["rpc_id"] || rpc["peer-region-name"] != peer.plan["region"] || rpc["peer-tenancy-id"] != p["tenancy_id"] || rpc["is-cross-tenancy-peering"] != false {
		fail("live RPC is disconnected, asymmetric, cross-tenancy, or linked to an unexpected peer")
	}
	tables := Object{}
	for _, role := range []string{"vcn", "rpc"} {
		tableID, distributionID := text(intent[role+"_drg_route_table_id"]), text(intent[role+"_import_distribution_id"])
		accepted, destination := rpcAttachmentID, peer.network.String()
		if role == "rpc" {
			accepted, destination = vcnAttachmentID, c.network.String()
		}
		table := get("drg-route-table", "--drg-route-table-id", tableID, role+" DRG route table")
		if table["lifecycle-state"] != "AVAILABLE" || table["compartment-id"] != compartment || table["drg-id"] != drgID || table["import-drg-route-distribution-id"] != distributionID || table["is-ecmp-enabled"] != false {
			fail("live " + role + " DRG route table ownership or import mapping differs from the pair intent")
		}
		distribution := e.peerDistribution(region, distributionID, drgID, compartment, accepted)
		actual := []any{}
		for _, v := range rows(e.oci(region, "network", "drg-route-rule", "list", "--drg-route-table-id", tableID, "--all")) {
			actual = append(actual, normalizedDRGRoute(obj(v)))
		}
		exactPeerRows(actual, []any{Object{"destination": destination, "destination_type": "CIDR_BLOCK", "next_hop_drg_attachment_id": accepted, "route_type": "DYNAMIC", "is_conflict": false, "is_blackhole": false}}, role+" DRG route table rules")
		tables[role] = Object{"id": tableID, "drg_id": drgID, "import_distribution": distribution, "routes": actual}
	}
	return Object{"cell": p["cell"], "region": region, "vcn_id": ids["vcn"], "vcn_cidr": c.network.String(), "subnet_id": ids["subnet"], "subnet_cidr": c.subnet.String(), "subnet_route_table_id": ids["route_table"], "subnet_routes": routes, "drg": Object{"id": drgID, "compartment_id": compartment, "lifecycle_state": drg["lifecycle-state"]}, "vcn_attachment": Object{"id": vcnAttachmentID, "vcn_id": ids["vcn"], "route_table_id": intent["vcn_drg_route_table_id"]}, "rpc": Object{"id": rpcID, "peer_id": rpc["peer-id"], "peer_region": rpc["peer-region-name"], "peering_status": rpc["peering-status"], "lifecycle_state": rpc["lifecycle-state"]}, "rpc_attachment": Object{"id": rpcAttachmentID, "rpc_id": rpcID, "route_table_id": intent["rpc_drg_route_table_id"]}, "drg_route_tables": tables, "nsg_id": ids["network_security_group"], "nsg_rules": nsgRules, "security_list_id": ids["security_list"], "security_list_ingress_rules": ingress, "security_list_egress_rules": egress}
}

// InspectPrivatePeer reads back the exact reciprocal network intent without claiming budget or dataplane readiness.
func (e *Engine) InspectPrivatePeer(paths ...string) (Object, error) {
	return capture(func() Object { return e.inspectPrivatePeer(paths) })
}

func (e *Engine) inspectPrivatePeer(paths []string) Object {
	if len(paths) != 7 {
		fail("private peer inspection requires intent and both plan, inventory, admission paths")
	}
	wire := readBytes(paths[0], 64*1024, "private peer intent")
	value, err := decodeJSON(wire)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			fail("JSON document has duplicate fields")
		}
		fail("private peer intent is unreadable or invalid JSON")
	}
	intent, ok := value.(Object)
	if !ok {
		fail("private peer intent must be an object")
	}
	intentSHA := wireSHA(wire)
	if fileSHA(paths[0]) != intentSHA {
		fail("private peer intent changed while it was being read")
	}
	planPaths := map[string]string{"left": paths[1], "right": paths[4]}
	plans, contexts, pair := e.privatePeerInputs(intent, paths[0], planPaths, intentSHA)
	evidence, admissions := Object{}, Object{}
	for i, side := range []string{"left", "right"} {
		p := obj(plans[side])
		inventoryPath, admissionPath := paths[2+i*3], paths[3+i*3]
		inventorySHA, admissionSHA := fileSHA(inventoryPath), fileSHA(admissionPath)
		inventory := readJSON(inventoryPath, 4*1024*1024, "manual region inventory")
		e.verifyInventory(p, inventory, planPaths[side], e.now(), 15)
		if !contains(inventory["regions"], p["region"]) {
			fail(text(p["cell"]) + " plan region is absent from its ready-region inventory")
		}
		cost, admission, _ := e.currentAdmission(p, inventory, inventoryPath, admissionPath, planPaths[side])
		cell := text(p["cell"])
		c := contexts[cell]
		c.inventoryPath = inventoryPath
		c.admissionPath = admissionPath
		c.admission = admission
		if fileSHA(planPaths[side]) != c.planSHA || fileSHA(inventoryPath) != inventorySHA || fileSHA(admissionPath) != admissionSHA {
			fail(cell + " private peer plan, inventory, or admission changed during inspection")
		}
		evidence[cell] = Object{"plan_sha256": c.planSHA, "inventory_sha256": inventorySHA, "admission_sha256": admissionSHA, "estimate": cost}
		admissions[cell] = admission
	}
	cells := keys(admissions)
	if len(cells) != 2 {
		fail("private peer inspection requires two regional estimates")
	}
	observed := Object{}
	// Each regional client read remains bounded and cancellation-aware. Keeping reads
	// sequential avoids concurrent calls into provider hooks used by native tests.
	for i, cell := range cells {
		observed[cell] = e.inspectPrivatePeerSide(contexts[cell], contexts[cells[1-i]], arr(pair["ports"]))
	}
	inspected := e.now()
	expires := time.Time{}
	traffic := Object{}
	for _, cell := range cells {
		admission := obj(admissions[cell])
		admitted, ok := parseTime(admission["admitted_at"])
		end, endOK := parseTime(admission["expires_at"])
		if !ok || !endOK || inspected.Before(admitted) || !inspected.Before(end) {
			fail("private peer budget admission expired during live network inspection")
		}
		if expires.IsZero() || end.Before(expires) {
			expires = end
		}
		c := contexts[cell]
		ev := obj(evidence[cell])
		if fileSHA(c.planPath) != c.planSHA || fileSHA(c.inventoryPath) != ev["inventory_sha256"] || fileSHA(c.admissionPath) != ev["admission_sha256"] {
			fail(cell + " private peer plan, inventory, or admission changed during live network inspection")
		}
		traffic[cell] = str(c.intent["monthly_cross_region_egress_gb"])
	}
	if fileSHA(paths[0]) != pair["intent_sha256"] {
		fail("private peer intent changed during live network inspection")
	}
	return Object{"schema_version": 1, "kind": "oci_private_peer_foundation_configuration_readback", "status": "configuration_readback_pass", "pair_intent_sha256": pair["intent_sha256"], "tenancy_id": pair["tenancy_id"], "realm": pair["realm"], "inspected_at": rfc3339(inspected), "readback_expires_at": rfc3339(expires), "cells": observed, "source_evidence": evidence, "allowed_tcp_ports": pair["ports"], "monthly_cross_region_egress_gb_by_cell": traffic, "budget_admission": Object{"status": "blocked", "reason": "Per-region estimates independently count shared baselines and apply free allowances; they cannot prove the combined USD 200 monthly ceiling."}, "dataplane_reachability": "not_tested", "application_mtls_required": true, "application_mtls_verified": false, "native_replication_ready": false}
}
