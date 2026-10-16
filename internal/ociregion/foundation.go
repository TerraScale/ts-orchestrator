package ociregion

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
)

func requireLiveID(v any, id any, label string) Object {
	m, ok := v.(Object)
	if !ok || m["id"] != id {
		fail("live " + label + " identity differs from the exact plan")
	}
	return m
}
func requireRouteIDs(plan, ids Object) {
	sec := obj(plan["network_security"])
	required := truth(sec["service_gateway_service_id"]) || truth(sec["route_rules"])
	if truth(ids["route_table"]) != truth(ids["service_gateway"]) || required != truth(ids["route_table"]) {
		fail("foundation inspection requires the exact route table and service gateway IDs declared by the plan")
	}
	if plan["operator_gateway"] != nil && (!truth(ids["local_peering_gateway"]) || !truth(obj(plan["operator_gateway"])["local_peering_gateway_id"])) {
		fail("foundation inspection requires the exact cell and operator gateway local peering gateway IDs")
	}
	publicBound(plan, ids)
}

// publicBound reports whether the declared public API exists yet. Its
// resources are created together in a later stage, so all or none are bound.
func publicBound(plan, ids Object) bool {
	if plan["public_api"] == nil {
		return false
	}
	n := 0
	for key := range publicIDs {
		if truth(ids[key]) {
			n++
		}
	}
	if n != 0 && n != len(publicIDs) {
		fail("foundation inspection requires every public API resource ID or none")
	}
	return n > 0
}

// liveS3Bound reports whether the Rust-era host LiveS3Credential secret and
// its policy are bound. A C# cell creates neither.
func liveS3Bound(plan, ids Object) bool {
	secret := obj(plan["host_credential_secret"])
	n := 0
	for _, v := range []any{secret["compartment_id"], secret["secret_id"], ids["host_policy"]} {
		if truth(v) {
			n++
		}
	}
	if n != 0 && n != 3 {
		fail("foundation inspection requires the host LiveS3Credential secret and policy together or not at all")
	}
	return n == 3
}
func requireNetbirdIDs(plan Object) {
	if plan["netbird"] != nil {
		config := obj(plan["netbird"])
		for _, key := range []string{"secret_compartment_id", "setup_key_secret_id", "policy_id"} {
			if !truth(config[key]) {
				fail("foundation inspection requires the exact NetBird setup-key secret and IAM policy OCIDs")
			}
		}
	}
}
func (e *Engine) requiredIDs(plan Object) Object {
	ids := obj(plan["resource_ids"])
	for _, key := range []string{"control_compartment", "network_compartment", "workload_compartment", "vault", "key", "vcn", "subnet", "network_security_group", "security_list", "controller_dynamic_group", "controller_policy", "objectstorage_key_policy", "host_dynamic_group"} {
		if !truth(ids[key]) {
			fail("foundation inspection requires every plan-bound compartment, network, Vault, key, and IAM OCID")
		}
	}
	liveS3Bound(plan, ids)
	requireRouteIDs(plan, ids)
	requireNetbirdIDs(plan)
	return ids
}
func normalizedSecurity(rule Object, direction string) Object {
	get := func(name string, fallback any) any {
		if v, ok := rule[name]; ok {
			return v
		}
		if v, ok := rule[strings.ReplaceAll(name, "_", "-")]; ok {
			return v
		}
		return fallback
	}
	empty := func(v any) bool { return v == nil || eq(v, Object{}) }
	if !empty(get("icmp_options", nil)) {
		fail("live security rule uses an unsupported shape")
	}
	r := Object{"direction": get("direction", nil), "protocol": str(get("protocol", nil)), "source": get("source", nil), "source_type": get("source_type", nil), "destination": get("destination", nil), "destination_type": get("destination_type", nil), "tcp_min": nil, "tcp_max": nil, "udp_min": nil, "udp_max": nil, "stateless": get("is_stateless", false)}
	if _, ok := rule["direction"]; !ok && direction != "" {
		r["direction"] = direction
	}
	for _, kind := range []string{"tcp", "udp"} {
		v := get(kind+"_options", nil)
		if v == nil {
			continue
		}
		options, ok := v.(Object)
		if !ok || !empty(options["source-port-range"]) {
			fail("live security rule uses unsupported port options")
		}
		v = options["destination-port-range"]
		if v == nil {
			continue
		}
		if !exact(v, "min", "max") {
			fail("live security rule has an unsupported destination port range")
		}
		r[kind+"_min"] = obj(v)["min"]
		r[kind+"_max"] = obj(v)["max"]
	}
	return r
}
func compareSecurity(actual, expected any, label, direction string) {
	normalized := []any{}
	for _, v := range rows(actual) {
		normalized = append(normalized, normalizedSecurity(obj(v), direction))
	}
	if !eq(orderedRows(normalized), orderedRows(expected)) {
		fail("live " + label + " rules differ from the exact plan")
	}
}
func (e *Engine) liveCompartments(plan, ids Object) {
	for _, role := range []string{"control", "network", "workload"} {
		id := ids[role+"_compartment"]
		m := requireLiveID(e.oci("", "iam", "compartment", "get", "--compartment-id", str(id)), id, role+" compartment")
		if m["lifecycle-state"] != "ACTIVE" || m["compartment-id"] != plan["parent_compartment_id"] || m["name"] != obj(plan["preview_compartment_names"])[role] {
			fail("live " + role + " compartment is not active under the plan parent")
		}
	}
}
func (e *Engine) liveNetwork(plan, ids Object) {
	expected := obj(plan["network_security"])
	requireRouteIDs(plan, ids)
	region := text(plan["region"])
	vcn := requireLiveID(e.oci(region, "network", "vcn", "get", "--vcn-id", str(ids["vcn"])), ids["vcn"], "VCN")
	if vcn["lifecycle-state"] != "AVAILABLE" || vcn["compartment-id"] != ids["network_compartment"] || vcn["cidr-block"] != plan["network_cidr"] {
		fail("live VCN state or CIDR differs from the plan")
	}
	subnet := requireLiveID(e.oci(region, "network", "subnet", "get", "--subnet-id", str(ids["subnet"])), ids["subnet"], "subnet")
	if subnet["lifecycle-state"] != "AVAILABLE" || subnet["compartment-id"] != ids["network_compartment"] || subnet["vcn-id"] != ids["vcn"] || subnet["cidr-block"] != plan["subnet_cidr"] || subnet["prohibit-public-ip-on-vnic"] != true || subnet["prohibit-internet-ingress"] != true || !eq(subnet["security-list-ids"], []any{ids["security_list"]}) || subnet["route-table-id"] != ids["route_table"] {
		fail("live subnet security, route, compartment, or CIDR differs from the plan")
	}
	for _, row := range []struct{ key, rules, label string }{{"network_security_group", "nsg_rules", "controller network security group"}, {"workload_network_security_group", "workload_nsg_rules", "member workload network security group"}} {
		id := ids[row.key]
		if !truth(id) {
			if truth(expected[row.rules]) {
				fail("plan declares member workload rules without their exact network security group OCID")
			}
			continue
		}
		m := requireLiveID(e.oci(region, "network", "nsg", "get", "--nsg-id", str(id)), id, strings.TrimPrefix(row.label, "controller "))
		if m["compartment-id"] != ids["network_compartment"] || m["vcn-id"] != ids["vcn"] {
			label := row.label
			if row.key == "network_security_group" {
				label = "network security group"
			}
			fail("live " + label + " is attached to an unexpected compartment or VCN")
		}
		rules := e.oci(region, "network", "nsg", "rules", "list", "--nsg-id", str(id))
		compareSecurity(rules, expected[row.rules], row.label, "")
	}
	security := requireLiveID(e.oci(region, "network", "security-list", "get", "--security-list-id", str(ids["security_list"])), ids["security_list"], "security list")
	if security["compartment-id"] != ids["network_compartment"] || security["vcn-id"] != ids["vcn"] {
		fail("live security list is attached to an unexpected compartment or VCN")
	}
	compareSecurity(security["ingress-security-rules"], expected["security_list_ingress_rules"], "subnet security-list ingress", "INGRESS")
	compareSecurity(security["egress-security-rules"], expected["security_list_egress_rules"], "subnet security-list egress", "EGRESS")
	if truth(expected["route_rules"]) {
		m := requireLiveID(e.oci(region, "network", "route-table", "get", "--rt-id", str(ids["route_table"])), ids["route_table"], "route table")
		if m["compartment-id"] != ids["network_compartment"] || m["vcn-id"] != ids["vcn"] {
			fail("live route table is attached to an unexpected compartment or VCN")
		}
		actual, want := []any{}, []any{}
		for _, v := range rows(m["route-rules"]) {
			r := obj(v)
			actual = append(actual, Object{"destination": r["destination"], "destination_type": r["destination-type"], "network_entity_id": r["network-entity-id"]})
		}
		targets := map[string]string{"{service_gateway_id}": "service_gateway", "{local_peering_gateway_id}": "local_peering_gateway"}
		for _, v := range arr(expected["route_rules"]) {
			r := obj(v)
			want = append(want, Object{"destination": r["destination"], "destination_type": r["destination_type"], "network_entity_id": ids[targets[text(r["network_entity_id"])]]})
		}
		if !eq(orderedRows(actual), orderedRows(want)) {
			fail("live route table rules differ from the exact plan")
		}
		id := ids["service_gateway"]
		g := requireLiveID(e.oci(region, "network", "service-gateway", "get", "--service-gateway-id", str(id)), id, "service gateway")
		services := []string{}
		for _, v := range arr(g["services"]) {
			services = append(services, text(obj(v)["service-id"]))
		}
		slices.Sort(services)
		if g["compartment-id"] != ids["network_compartment"] || g["vcn-id"] != ids["vcn"] || g["lifecycle-state"] != "AVAILABLE" || !eq(services, []any{expected["service_gateway_service_id"]}) {
			fail("live service gateway services differ from the exact plan")
		}
	}
	e.call("check_live_operator_gateway", []any{plan, ids}, Object{})
	e.call("check_live_public_api", []any{plan, ids}, Object{})
}
func tcpRule(port any, extra Object) Object {
	r := Object{"protocol": "6", "source": nil, "source_type": nil, "destination": nil, "destination_type": nil, "tcp_min": port, "tcp_max": port, "udp_min": nil, "udp_max": nil, "stateless": false}
	for k, v := range extra {
		r[k] = v
	}
	return r
}
func (e *Engine) livePublic(plan, ids Object) {
	if !publicBound(plan, ids) {
		return
	}
	public := obj(plan["public_api"])
	region := text(plan["region"])
	network, vcn := ids["network_compartment"], ids["vcn"]
	gateway := requireLiveID(e.oci(region, "network", "internet-gateway", "get", "--ig-id", str(ids["internet_gateway"])), ids["internet_gateway"], "public API internet gateway")
	if gateway["lifecycle-state"] != "AVAILABLE" || gateway["is-enabled"] != true || gateway["compartment-id"] != network || gateway["vcn-id"] != vcn || gateway["route-table-id"] != nil {
		fail("live public API internet gateway differs from the exact plan")
	}
	subnet := requireLiveID(e.oci(region, "network", "subnet", "get", "--subnet-id", str(ids["public_subnet"])), ids["public_subnet"], "public API subnet")
	if subnet["lifecycle-state"] != "AVAILABLE" || subnet["compartment-id"] != network || subnet["vcn-id"] != vcn || subnet["cidr-block"] != public["subnet_cidr"] || subnet["prohibit-public-ip-on-vnic"] != false || subnet["route-table-id"] != ids["public_route_table"] || !eq(subnet["security-list-ids"], []any{ids["public_security_list"]}) {
		fail("live public API subnet differs from the exact plan")
	}
	routes := requireLiveID(e.oci(region, "network", "route-table", "get", "--rt-id", str(ids["public_route_table"])), ids["public_route_table"], "public API route table")
	triples := []any{}
	for _, v := range rows(routes["route-rules"]) {
		r := obj(v)
		triples = append(triples, []any{r["destination"], r["destination-type"], r["network-entity-id"]})
	}
	if routes["compartment-id"] != network || routes["vcn-id"] != vcn || !eq(triples, []any{[]any{"0.0.0.0/0", "CIDR_BLOCK", ids["internet_gateway"]}}) {
		fail("live public API route table differs from the exact plan")
	}
	security := requireLiveID(e.oci(region, "network", "security-list", "get", "--security-list-id", str(ids["public_security_list"])), ids["public_security_list"], "public API security list")
	if security["compartment-id"] != network || security["vcn-id"] != vcn {
		fail("live public API security list is attached to an unexpected compartment or VCN")
	}
	if l7Public(plan) {
		e.livePublicBalancer(plan, ids, public, security)
		return
	}
	compareSecurity(security["ingress-security-rules"], []any{tcpRule(public["listener_port"], Object{"direction": "INGRESS", "source": "0.0.0.0/0", "source_type": "CIDR_BLOCK"})}, "public API security-list ingress", "INGRESS")
	compareSecurity(security["egress-security-rules"], []any{tcpRule(public["client_port"], Object{"direction": "EGRESS", "destination": plan["subnet_cidr"], "destination_type": "CIDR_BLOCK"})}, "public API security-list egress", "EGRESS")
	balancer := requireLiveID(e.oci(region, "nlb", "network-load-balancer", "get", "--network-load-balancer-id", str(ids["network_load_balancer"])), ids["network_load_balancer"], "public API network load balancer")
	listeners, sets := obj(balancer["listeners"]), obj(balancer["backend-sets"])
	valid := balancer["lifecycle-state"] == "ACTIVE" && balancer["compartment-id"] == network && balancer["subnet-id"] == ids["public_subnet"] && balancer["is-private"] == false && balancer["is-preserve-source-destination"] == false && !truth(balancer["network-security-group-ids"]) && len(listeners) == 1 && len(sets) == 1
	members := map[string]bool{}
	for _, v := range arr(plan["hosts"]) {
		h := obj(v)
		if strings.HasPrefix(text(h["slot"]), "member-") {
			members[text(h["private_ip"])] = true
		}
	}
	for _, v := range listeners {
		l := obj(v)
		_, found := sets[text(l["default-backend-set-name"])]
		valid = valid && l["protocol"] == "TCP" && eq(l["port"], public["listener_port"]) && found
	}
	seen := map[string]bool{}
	for _, v := range sets {
		s := obj(v)
		valid = valid && s["is-preserve-source"] == false
		for _, v := range arr(s["backends"]) {
			r := obj(v)
			key := canonical([]any{r["ip-address"], r["port"]})
			valid = valid && !seen[key] && members[text(r["ip-address"])] && eq(r["port"], public["client_port"])
			seen[key] = true
		}
	}
	if !valid || len(seen) == 0 {
		fail("live public API network load balancer differs from the exact plan")
	}
}

// livePublicBalancer reads back the flexible load balancer behind
// Cloudflare against the configuration public-api apply creates, and its NSG
// against Cloudflare's currently published ranges.
func (e *Engine) livePublicBalancer(plan, ids, public, security Object) {
	region, network := text(plan["region"]), ids["network_compartment"]
	d, err := publicapi.ParsePlan([]byte(canonical(plan)))
	if err != nil {
		fail("plan public API: " + err.Error())
	}
	private := Object{"direction": "EGRESS", "destination": plan["subnet_cidr"], "destination_type": "CIDR_BLOCK"}
	compareSecurity(security["ingress-security-rules"], []any{}, "public API security-list ingress", "INGRESS")
	egress := []any{}
	for _, r := range d.Egress() {
		egress = append(egress, tcpRule(r.Port, private))
	}
	compareSecurity(security["egress-security-rules"], egress, "public API security-list egress", "EGRESS")
	var balancer Object
	for _, v := range rows(e.oci(region, "lb", "load-balancer", "list", "--compartment-id", str(network), "--all")) {
		if obj(v)["id"] == ids["network_load_balancer"] {
			balancer = obj(v)
		}
	}
	nsgs := arr(balancer["network-security-group-ids"])
	if balancer == nil || balancer["compartment-id"] != network || !eq(balancer["subnet-ids"], []any{ids["public_subnet"]}) || len(nsgs) != 1 {
		fail("live public API load balancer differs from the exact plan")
	}
	if err := d.CheckBalancer(balancer); err != nil {
		fail("live public API " + err.Error())
	}
	group := requireLiveID(e.oci(region, "network", "nsg", "get", "--nsg-id", str(nsgs[0])), nsgs[0], "public API network security group")
	if group["compartment-id"] != network || group["vcn-id"] != ids["vcn"] {
		fail("live public API network security group is attached to an unexpected compartment or VCN")
	}
	var ranges []string
	for _, v := range arr(e.call("cloudflare_origin_ips", nil, Object{})) {
		ranges = append(ranges, text(v))
	}
	var rules []map[string]any
	for _, v := range rows(e.oci(region, "network", "nsg", "rules", "list", "--nsg-id", str(nsgs[0]))) {
		rules = append(rules, obj(v))
	}
	if err := publicapi.CheckOriginRules(rules, ranges); err != nil {
		fail("live public API " + err.Error())
	}
}
func (e *Engine) liveOperator(plan, ids Object) {
	if plan["operator_gateway"] == nil {
		return
	}
	gateway, existing := obj(plan["operator_gateway"]), obj(plan["existing_forgejo"])
	region := text(plan["region"])
	for _, row := range [][]any{{ids["local_peering_gateway"], gateway["local_peering_gateway_id"], ids["network_compartment"], ids["vcn"], gateway["vcn_cidr"]}, {gateway["local_peering_gateway_id"], ids["local_peering_gateway"], plan["shared_compartment_id"], existing["vcn_id"], plan["network_cidr"]}} {
		m := requireLiveID(e.oci(region, "network", "local-peering-gateway", "get", "--local-peering-gateway-id", str(row[0])), row[0], "local peering gateway")
		if m["lifecycle-state"] != "AVAILABLE" || m["peering-status"] != "PEERED" || m["compartment-id"] != row[2] || m["vcn-id"] != row[3] || m["peer-id"] != row[1] || m["is-cross-tenancy-peering"] != false || m["route-table-id"] != nil || m["peer-advertised-cidr"] != row[4] || !eq(m["peer-advertised-cidr-details"], []any{row[4]}) {
			fail("live operator gateway peering differs from the exact plan")
		}
	}
	vnics := rows(e.oci(region, "compute", "instance", "list-vnics", "--instance-id", str(existing["instance_id"]), "--compartment-id", str(plan["shared_compartment_id"]), "--all"))
	if len(vnics) != 1 || obj(vnics[0])["lifecycle-state"] != "AVAILABLE" || obj(vnics[0])["is-primary"] != true || obj(vnics[0])["private-ip"] != gateway["private_ip"] || obj(vnics[0])["skip-source-dest-check"] != false {
		fail("live operator gateway VNIC differs from the exact plan")
	}
	e.liveNetbirdIngress(plan, obj(vnics[0]))
}
func (e *Engine) liveNetbirdIngress(plan, vnic Object) {
	ids, ok := vnic["nsg-ids"].([]any)
	if !ok || len(ids) == 0 {
		fail("live NetBird gateway must have explicit network security groups")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if text(id) == "" || seen[text(id)] {
			fail("live NetBird gateway must have explicit network security groups")
		}
		seen[text(id)] = true
	}
	allowed := map[string]bool{}
	for _, id := range ids {
		requireOCID(id, "networksecuritygroup", text(plan["region"]))
		nsg := requireLiveID(e.oci(text(plan["region"]), "network", "nsg", "get", "--nsg-id", str(id)), id, "NetBird gateway network security group")
		if nsg["compartment-id"] != plan["shared_compartment_id"] || nsg["vcn-id"] != obj(plan["existing_forgejo"])["vcn_id"] {
			fail("live NetBird gateway network security group ownership differs from the plan")
		}
		for _, v := range rows(e.oci(text(plan["region"]), "network", "nsg", "rules", "list", "--nsg-id", str(id), "--all")) {
			r := obj(v)
			if r["direction"] != "INGRESS" || r["source"] != plan["subnet_cidr"] || !contains([]string{"6", "17"}, str(r["protocol"])) {
				continue
			}
			n := normalizedSecurity(r, "")
			if n["source_type"] == "CIDR_BLOCK" && !truth(n["stateless"]) && n["destination"] == nil && n["destination_type"] == nil && gatewayPorts(n) {
				allowed[text(n["protocol"])] = true
			}
		}
	}
	if len(allowed) != 2 {
		fail("live NetBird gateway lacks private-subnet HTTPS or STUN ingress")
	}
}
func canonicalPrefix(v any) string {
	s, ok := v.(string)
	if !ok || len(s) > 128 {
		fail("bootstrap storage prefix is not canonical")
	}
	if s != "" {
		if strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.Contains(s, "//") {
			fail("bootstrap storage prefix is not canonical")
		}
		for segment := range strings.SplitSeq(s, "/") {
			if segment == "." || segment == ".." || !safeMatch(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, segment) {
				fail("bootstrap storage prefix is not canonical")
			}
		}
	}
	return s
}
func requiredPrefix(plan Object) string {
	v, ok := plan["bootstrap_object_prefix"]
	if !ok {
		fail("manual plan lacks an explicit bootstrap storage prefix")
	}
	return canonicalPrefix(v)
}
func storageStatements(plan, ids Object, prefix string) []string {
	identity, names, buckets := obj(plan["identity"]), obj(plan["preview_compartment_names"]), obj(plan["foundation_buckets"])
	dg, control := str(identity["controller_dynamic_group_name"]), str(names["control"])
	prefix = canonicalPrefix(prefix)
	r := []string{}
	for _, role := range []string{"ledger", "head"} {
		permissions := "request.permission='OBJECT_READ', request.permission='OBJECT_CREATE'"
		if role == "head" {
			permissions += ", request.permission='OBJECT_OVERWRITE'"
		}
		for _, version := range []string{"v1", "v2"} {
			name := "bootstrap/" + version + "/*"
			if prefix != "" {
				name = prefix + "/" + name
			}
			r = append(r, fmt.Sprintf("Allow dynamic-group %s to manage objects in compartment %s where all {target.bucket.name='%s', target.object.name='%s', any {%s}}", dg, control, str(buckets[role]), name, permissions))
		}
	}
	// The leader keeps the configuration KV buckets in the versioned head
	// bucket (controller.kv_snapshot, docs/storage.md).
	r = append(r, fmt.Sprintf("Allow dynamic-group %s to manage objects in compartment %s where all {target.bucket.name='%s', target.object.name='kv-snapshot/v1/*', any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}", dg, control, str(buckets["head"])))
	// The leader follows the region's orchestrator release channel, which CI
	// writes, and reports its progress there (docs/continuous-delivery.md).
	r = append(r, fmt.Sprintf("Allow dynamic-group %s to manage objects in compartment %s where all {target.bucket.name='%s', target.object.name='releases/*', request.permission='OBJECT_READ'}", dg, control, str(buckets["head"])),
		fmt.Sprintf("Allow dynamic-group %s to manage objects in compartment %s where all {target.bucket.name='%s', target.object.name='releases/orchestrator/status.json', any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}", dg, control, str(buckets["head"])))
	// ... and each service release channel's report (TS-610), one statement
	// per role of internal/app's serviceReleaseRoles: OCI matches a * only
	// at the end of an object name, so services/*/status.json grants nothing.
	for _, role := range []string{"terrabase", "ts-auth"} {
		r = append(r, fmt.Sprintf("Allow dynamic-group %s to manage objects in compartment %s where all {target.bucket.name='%s', target.object.name='releases/services/%s/status.json', any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE'}}", dg, control, str(buckets["head"]), role))
	}
	return append(r, fmt.Sprintf("Allow dynamic-group %s to manage objects in compartment %s where all {target.bucket.name='%s', target.object.name='material/v2/*', any {request.permission='OBJECT_READ', request.permission='OBJECT_CREATE'}}", dg, control, str(buckets["material"])), fmt.Sprintf("Allow dynamic-group %s to use keys in compartment %s where all {target.key.id='%s', any {request.permission='KEY_ENCRYPT', request.permission='KEY_DECRYPT'}}", dg, control, str(ids["key"])), fmt.Sprintf("Allow dynamic-group %s to use key-delegate in compartment %s where target.key.id='%s'", dg, control, str(ids["key"])))
}
func controllerStatements(plan, ids Object, prefix string) []string {
	dg := str(obj(plan["identity"])["controller_dynamic_group_name"])
	names := obj(plan["preview_compartment_names"])
	r := []string{}
	for _, row := range [][3]string{{"manage", "instance-family", "control"}, {"manage", "instance-family", "workload"}, {"read", "instance-images", "control"}, {"use", "virtual-network-family", "network"}, {"use", "load-balancers", "network"}, {"manage", "volume-family", "control"}, {"manage", "volume-family", "workload"}, {"read", "secret-bundles", "control"}} {
		r = append(r, fmt.Sprintf("Allow dynamic-group %s to %s %s in compartment %s", dg, row[0], row[1], str(names[row[2]])))
	}
	return append(r, storageStatements(plan, ids, prefix)...)
}
func RequiredControllerStatements(plan, ids Object, prefix string) ([]string, error) {
	return capture(func() []string { return controllerStatements(plan, ids, prefix) })
}

// ObjectStorageKeyStatement is the Object Storage key policy's one statement:
// the region's Object Storage may use exactly the plan's key.
func ObjectStorageKeyStatement(plan, ids Object) string {
	return fmt.Sprintf("Allow service objectstorage-%s to use keys in compartment %s where all {target.key.id='%s', any {request.permission='KEY_READ', request.permission='KEY_ENCRYPT', request.permission='KEY_DECRYPT'}}", str(plan["region"]), str(obj(plan["preview_compartment_names"])["control"]), str(ids["key"]))
}
func netbirdStatements(plan Object) []string {
	c := obj(plan["netbird"])
	r := []string{}
	for _, role := range []string{"controller_dynamic_group_name", "host_dynamic_group_name"} {
		r = append(r, fmt.Sprintf("Allow dynamic-group %s to read secret-bundles in compartment id %s where target.secret.id = '%s'", str(obj(plan["identity"])[role]), str(c["secret_compartment_id"]), str(c["setup_key_secret_id"])))
	}
	return r
}
func (e *Engine) liveNetbirdIAM(plan Object) {
	if plan["netbird"] == nil {
		return
	}
	requireNetbirdIDs(plan)
	c := obj(plan["netbird"])
	policy := requireLiveID(e.oci("", "iam", "policy", "get", "--policy-id", str(c["policy_id"])), c["policy_id"], "NetBird server enrollment IAM policy")
	if policy["lifecycle-state"] != "ACTIVE" || policy["name"] != c["policy_name"] || policy["compartment-id"] != c["secret_compartment_id"] || !eq(policy["statements"], netbirdStatements(plan)) {
		fail("live NetBird server enrollment policy differs from exact secret read grants")
	}
	secret := requireLiveID(e.oci(text(plan["region"]), "vault", "secret", "get", "--secret-id", str(c["setup_key_secret_id"])), c["setup_key_secret_id"], "NetBird setup-key secret")
	if secret["lifecycle-state"] != "ACTIVE" || secret["compartment-id"] != c["secret_compartment_id"] {
		fail("live NetBird setup-key secret is not active in its selected compartment")
	}
}
func (e *Engine) liveIAM(plan, ids Object, prefix string) {
	identity := obj(plan["identity"])
	bound := liveS3Bound(plan, ids)
	group := requireLiveID(e.oci("", "iam", "dynamic-group", "get", "--dynamic-group-id", str(ids["controller_dynamic_group"])), ids["controller_dynamic_group"], "controller dynamic group")
	if group["lifecycle-state"] != "ACTIVE" || group["name"] != identity["controller_dynamic_group_name"] || group["matching-rule"] != fmt.Sprintf("ALL {instance.compartment.id = '%s'}", str(ids["control_compartment"])) {
		fail("live controller dynamic group does not exactly isolate controller instances")
	}
	policy := requireLiveID(e.oci("", "iam", "policy", "get", "--policy-id", str(ids["controller_policy"])), ids["controller_policy"], "controller IAM policy")
	if policy["lifecycle-state"] != "ACTIVE" || policy["name"] != identity["controller_policy_name"] || policy["compartment-id"] != plan["parent_compartment_id"] || !eq(policy["statements"], controllerStatements(plan, ids, prefix)) {
		fail("live controller IAM policy differs from exact reviewed statements")
	}
	kp := requireLiveID(e.oci("", "iam", "policy", "get", "--policy-id", str(ids["objectstorage_key_policy"])), ids["objectstorage_key_policy"], "Object Storage key IAM policy")
	if kp["lifecycle-state"] != "ACTIVE" || kp["name"] != identity["objectstorage_key_policy_name"] || kp["compartment-id"] != ids["control_compartment"] {
		fail("live Object Storage key policy differs from exact reviewed statements")
	}
	statement := ObjectStorageKeyStatement(plan, ids)
	if !eq(kp["statements"], []string{statement}) {
		fail("Object Storage key policy is not limited to the reviewed region and key")
	}
	hg := requireLiveID(e.oci("", "iam", "dynamic-group", "get", "--dynamic-group-id", str(ids["host_dynamic_group"])), ids["host_dynamic_group"], "workload host dynamic group")
	if hg["lifecycle-state"] != "ACTIVE" || hg["name"] != identity["host_dynamic_group_name"] || hg["matching-rule"] != fmt.Sprintf("ALL {instance.compartment.id = '%s'}", str(ids["workload_compartment"])) {
		fail("live workload host dynamic group does not exactly isolate workload instances")
	}
	if !bound {
		e.call("check_live_netbird_iam", []any{plan}, Object{})
		return
	}
	secretConfig := obj(plan["host_credential_secret"])
	compartment, secretID := secretConfig["compartment_id"], secretConfig["secret_id"]
	hp := requireLiveID(e.oci("", "iam", "policy", "get", "--policy-id", str(ids["host_policy"])), ids["host_policy"], "host LiveS3Credential IAM policy")
	statement = fmt.Sprintf("Allow dynamic-group %s to read secret-bundles in compartment id %s where target.secret.id = '%s'", str(identity["host_dynamic_group_name"]), str(compartment), str(secretID))
	if hp["lifecycle-state"] != "ACTIVE" || hp["name"] != identity["host_policy_name"] || hp["compartment-id"] != compartment || !eq(hp["statements"], []string{statement}) {
		fail("host LiveS3Credential policy is not limited to the selected secret and compartment")
	}
	secret := requireLiveID(e.oci(text(plan["region"]), "vault", "secret", "get", "--secret-id", str(secretID)), secretID, "host LiveS3Credential secret")
	if secret["lifecycle-state"] != "ACTIVE" || secret["compartment-id"] != compartment {
		fail("live host LiveS3Credential secret is not active in its selected compartment")
	}
	e.call("check_live_netbird_iam", []any{plan}, Object{})
}
func (e *Engine) liveVault(plan, ids Object) {
	vault := requireLiveID(e.oci(text(plan["region"]), "kms", "management", "vault", "get", "--vault-id", str(ids["vault"])), ids["vault"], "Vault")
	if vault["lifecycle-state"] != "ACTIVE" || vault["vault-type"] != "DEFAULT" || vault["compartment-id"] != ids["control_compartment"] {
		fail("live Vault is not active in the plan control compartment")
	}
	endpoint := text(vault["management-endpoint"])
	if !strings.HasPrefix(endpoint, "https://") || len(endpoint) > 512 {
		fail("live Vault management endpoint is invalid")
	}
	key := requireLiveID(e.oci(text(plan["region"]), "kms", "management", "key", "get", "--key-id", str(ids["key"]), "--endpoint", endpoint), ids["key"], "KMS key")
	state := key["lifecycle-state"]
	if state == nil {
		state = key["key-state"]
	}
	shape := obj(key["key-shape"])
	if state != "ENABLED" || key["compartment-id"] != ids["control_compartment"] || key["vault-id"] != ids["vault"] || key["protection-mode"] != "HSM" || shape["algorithm"] != "AES" || !eq(shape["length"], 32) {
		fail("live KMS key state or cryptographic shape differs from the plan")
	}
}
func (e *Engine) liveBuckets(plan, ids Object) string {
	namespace := str(e.oci(text(plan["region"]), "os", "ns", "get"))
	names := obj(plan["foundation_buckets"])
	for _, role := range []string{"ledger", "head", "backup", "material"} {
		name := str(names[role])
		bucket := obj(e.oci(text(plan["region"]), "os", "bucket", "get", "--namespace-name", namespace, "--bucket-name", name))
		versioning, retentionName := "Disabled", ""
		if role == "head" || role == "material" {
			versioning = "Enabled"
		} else {
			retentionName = role + "-retention"
		}
		if bucket["name"] != name || bucket["compartment-id"] != ids["control_compartment"] || bucket["public-access-type"] != "NoPublicAccess" || bucket["storage-tier"] != "Standard" || bucket["versioning"] != versioning || bucket["kms-key-id"] != ids["key"] {
			fail("live " + role + " bucket privacy, KMS, tier, compartment, or versioning differs from the plan")
		}
		retention := rows(e.oci(text(plan["region"]), "os", "retention-rule", "list", "--namespace-name", namespace, "--bucket-name", name, "--all"))
		if retentionName == "" {
			if len(retention) > 0 {
				fail("live " + role + " bucket has an unplanned retention rule")
			}
		} else if len(retention) != 1 || obj(retention[0])["display-name"] != retentionName {
			fail("live " + role + " bucket retention differs from the exact plan")
		} else {
			duration := obj(obj(retention[0])["duration"])
			if duration["time-amount"] == nil {
				fail("live " + role + " bucket retention duration is invalid")
			}
			if duration["time-unit"] != "DAYS" || !eq(number(duration["time-amount"]), number(plan["bucket_retention_days"])) {
				fail("live " + role + " bucket retention differs from the exact plan")
			}
		}
	}
	return namespace
}
func (e *Engine) currentAdmission(plan, inventory Object, inventoryPath, admissionPath, planPath string) (Object, Object, time.Time) {
	cost := e.estimate(plan, inventory, planPath, e.now(), 15)
	admission := readJSON(admissionPath, 64*1024, "manual budget admission")
	admitted, aok := parseTime(admission["admitted_at"])
	expires, eok := parseTime(admission["expires_at"])
	captured, cok := parseTime(inventory["captured_at"])
	if !aok || !eok || !cok {
		fail("budget admission has invalid timestamps")
	}
	_, ao := admitted.Zone()
	_, eo := expires.Zone()
	now := e.now()
	if !eq(admission["schema_version"], 2) || ao != 0 || eo != 0 || admitted.After(now.Add(30*time.Second)) || now.Before(admitted) || !now.Before(expires) || expires.After(admitted.Add(15*time.Minute+30*time.Second)) || captured.After(admitted) || admission["plan_sha256"] != fileSHA(planPath) || admission["inventory_sha256"] != fileSHA(inventoryPath) || !eq(admission["preview_compartment_ids"], inventory["preview_compartment_ids"]) || !eq(admission["estimate"], cost) {
		fail("budget admission is stale or does not match the exact current plan and inventory")
	}
	return cost, admission, admitted
}

// checkFoundation runs inspect-foundation's live checks of every plan-bound
// foundation resource.
func (e *Engine) checkFoundation(plan Object, prefix string) Object {
	ids := e.requiredIDs(plan)
	for _, name := range []string{"check_live_compartments", "check_live_vault", "check_live_network", "check_live_buckets"} {
		e.call(name, []any{plan, ids}, Object{})
	}
	e.call("check_live_iam", []any{plan, ids, prefix}, Object{})
	return ids
}

// CheckFoundation runs inspect-foundation's live checks against plan,
// without its inventory and budget admission.
func (e *Engine) CheckFoundation(plan Object) error {
	_, err := capture(func() Object { return e.checkFoundation(plan, requiredPrefix(plan)) })
	return err
}
func (e *Engine) inspectFoundation(plan Object, planPath, inventoryPath, admissionPath string) Object {
	prefix := requiredPrefix(plan)
	inventory := readJSON(inventoryPath, 4*1024*1024, "manual region inventory")
	e.verifyInventory(plan, inventory, planPath, e.now(), 15)
	cost, admission, admitted := e.currentAdmission(plan, inventory, inventoryPath, admissionPath, planPath)
	if greater(cost["total"], 200) {
		fail("live foundation inspection exceeds the USD 200 monthly ceiling")
	}
	ids := e.checkFoundation(plan, prefix)
	now := e.now()
	expires, _ := parseTime(admission["expires_at"])
	if now.Before(admitted) {
		fail("local clock precedes the current budget admission")
	}
	if !now.Before(expires) {
		fail("budget admission expired during live foundation inspection")
	}
	return Object{"schema_version": 1, "plan_sha256": fileSHA(planPath), "inventory_sha256": fileSHA(inventoryPath), "inspected_at": rfc3339(now), "tenancy_id": plan["tenancy_id"], "cell": plan["cell"], "oci_region": plan["region"], "control_compartment_id": ids["control_compartment"], "network_compartment_id": ids["network_compartment"], "workload_compartment_id": ids["workload_compartment"], "vault_id": ids["vault"], "key_id": ids["key"]}
}
