package ociregion

import (
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/networkplan"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
)

var publicIDs = map[string]string{"internet_gateway": "internetgateway", "public_subnet": "subnet", "public_route_table": "routetable", "public_security_list": "securitylist", "network_load_balancer": "networkloadbalancer"}
var resourceKinds = map[string]string{"control_compartment": "compartment", "network_compartment": "compartment", "workload_compartment": "compartment", "vault": "vault", "key": "key", "vcn": "vcn", "subnet": "subnet", "network_security_group": "networksecuritygroup", "workload_network_security_group": "networksecuritygroup", "security_list": "securitylist", "route_table": "routetable", "service_gateway": "servicegateway", "local_peering_gateway": "localpeeringgateway", "internet_gateway": "internetgateway", "public_subnet": "subnet", "public_route_table": "routetable", "public_security_list": "securitylist", "network_load_balancer": "networkloadbalancer", "controller_dynamic_group": "dynamicgroup", "controller_policy": "policy", "objectstorage_key_policy": "policy", "host_dynamic_group": "dynamicgroup", "host_policy": "policy"}
var ingressLists = []string{"nsg_rules", "workload_nsg_rules", "security_list_ingress_rules"}

// TSAuthPort is ts-auth's plain-HTTP port on the controllers. The public API
// load balancer in the public API subnet reaches it through one exact
// controller NSG rule.
const TSAuthPort = 8080

var ruleFields = []string{"direction", "protocol", "source", "source_type", "destination", "destination_type", "tcp_min", "tcp_max", "udp_min", "udp_max", "stateless"}

func requireOCID(value any, kind, region string) string {
	s := text(value)
	parts := strings.Split(s, ".")
	if len(parts) < 5 || parts[0] != "ocid1" || parts[1] != kind || parts[2] != "oc1" || (region != "" && parts[3] != region) || !safeMatch(`ocid1\.[a-z]+\.oc1\.[a-z0-9-]*\.[a-z0-9]+(?:\.[a-z0-9]+)*`, s) {
		fail("manual plan has an invalid " + kind + " OCID")
	}
	return s
}
func prefix(v any) (netip.Prefix, bool) {
	s, ok := v.(string)
	if !ok {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(s)
	return p, err == nil && p.Addr().Is4() && p == p.Masked() && p.String() == s
}
func privateAddr(a netip.Addr) bool {
	private := []string{"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32"}
	if a == netip.MustParseAddr("192.0.0.9") || a == netip.MustParseAddr("192.0.0.10") {
		return false
	}
	for _, cidr := range private {
		if netip.MustParsePrefix(cidr).Contains(a) {
			return true
		}
	}
	return false
}
func privatePrefix(p netip.Prefix) bool {
	// Inventory plans accept non-global IPv4 space; private peer intents require
	// RFC1918. Check both boundary addresses, as in the original contract.
	if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() {
		return false
	}
	last := p.Addr().As4()
	for bit := p.Bits(); bit < 32; bit++ {
		last[bit/8] |= 1 << uint(7-bit%8)
	}
	return privateAddr(p.Addr()) && privateAddr(netip.AddrFrom4(last))
}
func within(v any, p netip.Prefix) bool {
	x, ok := prefix(v)
	return ok && x.Bits() >= p.Bits() && p.Contains(x.Addr())
}
func validateRules(value any, label string) []any {
	a, ok := value.([]any)
	if !ok {
		fail("manual plan " + label + " must declare complete normalized security rules")
	}
	seen := map[string]bool{}
	for _, v := range a {
		if !exact(v, ruleFields...) {
			fail("manual plan " + label + " must declare complete normalized security rules")
		}
		r := obj(v)
		_, stateless := r["stateless"].(bool)
		if !contains([]string{"INGRESS", "EGRESS"}, r["direction"]) || !contains([]string{"all", "1", "6", "17", "58"}, r["protocol"]) || !stateless {
			fail("manual plan " + label + " has an unsupported rule")
		}
		for _, k := range []string{"source", "source_type", "destination", "destination_type"} {
			if r[k] != nil && (text(r[k]) == "" || len(text(r[k])) > 200) {
				fail("manual plan " + label + " has an invalid rule " + k)
			}
		}
		for _, kind := range []string{"tcp", "udp"} {
			low, high := r[kind+"_min"], r[kind+"_max"]
			if (low == nil) != (high == nil) || (low != nil && (!integer(low) || !integer(high) || number(low) < 1 || number(high) < number(low) || number(high) > 65535)) {
				fail("manual plan " + label + " has an invalid port range")
			}
			protocol := "6"
			if kind == "udp" {
				protocol = "17"
			}
			if r["protocol"] != protocol && (low != nil || high != nil) {
				fail("manual plan " + label + " has " + strings.ToUpper(kind) + " ports on a non-" + strings.ToUpper(kind) + " rule")
			}
		}
		marker := canonical(r)
		if seen[marker] {
			fail("manual plan " + label + " contains duplicate rules")
		}
		seen[marker] = true
	}
	return a
}
func validateGateway(plan Object, network netip.Prefix) Object {
	v, ok := plan["operator_gateway"]
	if !ok {
		fail("manual plan must declare its operator gateway or null")
	}
	if v == nil {
		return nil
	}
	if !exact(v, "private_ip", "vcn_cidr", "local_peering_gateway_id") || text(obj(v)["private_ip"]) == "" || text(obj(v)["vcn_cidr"]) == "" {
		fail("manual operator gateway must declare exactly its private IP, VCN CIDR, and peering gateway")
	}
	g := obj(v)
	p, valid := prefix(g["vcn_cidr"])
	a, err := netip.ParseAddr(text(g["private_ip"]))
	if !valid || err != nil || !a.Is4() {
		fail("manual operator gateway address or VCN CIDR is invalid")
	}
	if !privatePrefix(p) || !privateAddr(a) || a.IsLoopback() || a.IsLinkLocalUnicast() || !p.Contains(a) || p.Overlaps(network) || a.String() != g["private_ip"] {
		fail("manual operator gateway must be a private address in its own VCN outside the cell")
	}
	if g["local_peering_gateway_id"] != nil {
		requireOCID(g["local_peering_gateway_id"], "localpeeringgateway", text(plan["region"]))
	}
	return g
}

// l7Public reports a public API on an OCI flexible load balancer behind
// Cloudflare (publicapi); without bandwidth fields it is the older TLS passthrough
// network load balancer. resource_ids.network_load_balancer records either.
func l7Public(plan Object) bool {
	_, flexible := obj(plan["public_api"])["max_mbps"]
	return flexible
}
func validatePublic(plan Object, network, subnet netip.Prefix) Object {
	v, ok := plan["public_api"]
	if !ok {
		fail("manual plan must declare its public TerraBase API or null")
	}
	if v == nil {
		return nil
	}
	flexible := []string{"subnet_cidr", "listener_port", "client_port", "min_mbps", "max_mbps", "terrabase_members"}
	if !exact(v, "subnet_cidr", "listener_port", "client_port") && !exact(v, flexible...) &&
		!exact(v, append(flexible, "origin_pull")...) && !exact(v, append(flexible, "orch")...) &&
		!exact(v, append(flexible, "origin_pull", "orch")...) {
		fail("manual public API must declare exactly its subnet CIDR, listener port, and client port")
	}
	p := obj(v)
	if orch, present := p["orch"]; present && orch != true {
		fail("manual public API orch must be true or absent")
	}
	if origin, present := p["origin_pull"]; present {
		if !exact(origin, "ca_certificate", "certificate_id") {
			fail("manual public API origin_pull must declare exactly its customer CA certificate and Cloudflare certificate ID")
		}
		o := obj(origin)
		ca, caOK := o["ca_certificate"].(string)
		id, idOK := o["certificate_id"].(string)
		if !caOK || !idOK {
			fail("manual public API origin_pull certificate and ID must be strings")
		}
		if err := (publicapi.OriginPull{CACertificate: ca, CertificateID: id}).Validate(); err != nil {
			fail(err.Error())
		}
	}
	for _, k := range []string{"listener_port", "client_port"} {
		if !integer(p[k]) || number(p[k]) < 1 || number(p[k]) > 65535 {
			fail("manual public API must declare exactly its subnet CIDR, listener port, and client port")
		}
	}
	if l7Public(plan) && !eq(p["listener_port"], 443) {
		fail("manual public API flexible load balancer listener_port must be 443")
	}
	if l7Public(plan) && (!integer(p["min_mbps"]) || !integer(p["max_mbps"]) || number(p["min_mbps"]) < 10 || number(p["max_mbps"]) < number(p["min_mbps"]) || number(p["max_mbps"]) > 8000) {
		fail("manual public API load balancer bandwidth must satisfy 10 <= min_mbps <= max_mbps <= 8000")
	}
	seen := map[string]bool{}
	cell := naming.RegionCell(text(plan["cell"]))
	for _, v := range arr(p["terrabase_members"]) {
		ok := false
		for n := 1; n <= int(number(plan["database_members"])); n++ {
			name, err := cell.Server(naming.Member, n)
			ok = ok || err == nil && v == name
		}
		// A colocated cell's controllers are its TerraBase members.
		for _, h := range arr(plan["hosts"]) {
			name, err := cell.ControllerSlot(text(obj(h)["slot"]))
			ok = ok || err == nil && v == name
		}
		if !ok || seen[text(v)] {
			fail("manual public API terrabase_members must name distinct planned database members")
		}
		seen[text(v)] = true
	}
	if l7Public(plan) && len(seen) == 0 {
		fail("manual public API terrabase_members must name distinct planned database members")
	}
	cidr, _ := prefix(p["subnet_cidr"])
	if !within(p["subnet_cidr"], network) || cidr.Overlaps(subnet) {
		fail("manual public API subnet must be inside the cell VCN and outside the private subnet")
	}
	return p
}
func gatewayPorts(r Object) bool {
	return eq([]any{r["protocol"], r["tcp_min"], r["tcp_max"], r["udp_min"], r["udp_max"]}, []any{"6", 443, 443, nil, nil}) || eq([]any{r["protocol"], r["tcp_min"], r["tcp_max"], r["udp_min"], r["udp_max"]}, []any{"17", nil, nil, 3478, 3478})
}
func validateBoundary(sec Object, network netip.Prefix, gateway, public Object) {
	source := ""
	if gateway != nil {
		source = text(gateway["private_ip"]) + "/32"
	}
	ports := map[string][]int{"nsg_rules": {22, 4222}, "workload_nsg_rules": {22, 9465}}
	for _, key := range ingressLists {
		for _, v := range arr(sec[key]) {
			r := obj(v)
			if r["direction"] != "INGRESS" || r["source_type"] != "CIDR_BLOCK" || truth(r["stateless"]) || r["destination"] != nil || r["destination_type"] != nil {
				fail("manual plan " + key + " must hold stateful CIDR ingress rules only")
			}
			if source != "" && r["source"] == source {
				allowed := false
				for _, port := range ports[key] {
					allowed = allowed || eq(r["tcp_min"], port)
				}
				if !allowed || r["protocol"] != "6" || !eq(r["tcp_min"], r["tcp_max"]) {
					fail("manual plan " + key + " admits the operator gateway outside its allowed ports")
				}
			} else if !within(r["source"], network) {
				fail("manual plan " + key + " admits a source outside the private cell")
			} else if public != nil {
				if _, flexible := public["max_mbps"]; !flexible && tsAuthBackendRule(key, r, public) {
					fail("manual legacy public API must not admit the ts-auth controller port")
				}
				p, _ := prefix(public["subnet_cidr"])
				s, _ := prefix(r["source"])
				// Members, or a colocated cell's controllers, serve the
				// client port to the load balancer.
				if p.Overlaps(s) && !tsAuthBackendRule(key, r, public) && (r["source"] != public["subnet_cidr"] || r["protocol"] != "6" || !eq(r["tcp_min"], public["client_port"]) || !eq(r["tcp_max"], public["client_port"])) {
					fail("manual plan " + key + " admits the public API subnet beyond the member client port")
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, v := range arr(sec["security_list_egress_rules"]) {
		r := obj(v)
		if r["direction"] != "EGRESS" || truth(r["stateless"]) || r["source"] != nil || r["source_type"] != nil {
			fail("manual plan security_list_egress_rules must hold stateful egress rules only")
		}
		service := r["destination_type"] == "SERVICE_CIDR_BLOCK" && eq(r["destination"], sec["service_gateway_cidr_block"])
		ntp := r["destination_type"] == "CIDR_BLOCK" && r["destination"] == "169.254.169.254/32" && r["protocol"] == "17" && eq(r["udp_min"], 123) && eq(r["udp_max"], 123)
		cell := r["destination_type"] == "CIDR_BLOCK" && within(r["destination"], network)
		netbird := source != "" && r["destination_type"] == "CIDR_BLOCK" && r["destination"] == source && gatewayPorts(r)
		if netbird {
			seen[text(r["protocol"])] = true
		}
		if !service && !ntp && !cell && !netbird {
			fail("manual plan egress leaves the private cell, Oracle services, NTP, and scoped NetBird gateway")
		}
	}
	if gateway != nil && len(seen) != 2 {
		fail("manual plan must allow NetBird HTTPS and STUN to the operator gateway")
	}
}

// tsAuthBackendRule is the controller NSG rule that lets the public API load
// balancer's subnet reach ts-auth, TCP TSAuthPort, or with public_api.orch
// the Machines API, TCP publicapi.OrchPort, and nothing else.
func tsAuthBackendRule(key string, r, public Object) bool {
	port := func(want int) bool { return eq(r["tcp_min"], want) && eq(r["tcp_max"], want) }
	return key == "nsg_rules" && r["source"] == public["subnet_cidr"] && r["protocol"] == "6" &&
		(port(TSAuthPort) || public["orch"] == true && port(publicapi.OrchPort))
}
func validateNetbird(plan Object, gateway Object) {
	v, ok := plan["netbird"]
	if !ok {
		fail("manual plan must declare its NetBird enrollment configuration or null")
	}
	if v == nil {
		if gateway != nil {
			fail("manual operator gateway requires private NetBird enrollment configuration")
		}
		return
	}
	if !exact(v, "management_url", "management_ip", "secret_compartment_id", "setup_key_secret_id", "policy_id", "policy_name") {
		fail("manual NetBird configuration must declare exact nonsecret manager and Vault policy fields")
	}
	c := obj(v)
	if c["management_url"] != "https://netbird.terrascale.tech" {
		fail("manual NetBird management URL must be the TerraScale HTTPS DNS origin on port 443")
	}
	if gateway == nil || c["management_ip"] != gateway["private_ip"] {
		fail("manual NetBird management IP must equal the private operator gateway")
	}
	if !safeMatch(`[A-Za-z0-9._-]{1,100}`, c["policy_name"]) {
		fail("manual NetBird policy name is invalid")
	}
	if c["secret_compartment_id"] != nil || c["setup_key_secret_id"] != nil {
		requireOCID(c["secret_compartment_id"], "compartment", "")
		requireOCID(c["setup_key_secret_id"], "vaultsecret", text(plan["region"]))
	}
	if c["policy_id"] != nil {
		requireOCID(c["policy_id"], "policy", "")
	}
}
func (e *Engine) loadPlan(path string) Object {
	p := readJSON(path, 64*1024, "manual region plan")
	if !eq(p["schema_version"], 2) || catalog.OCIRegion(text(p["cell"])) == "" || p["region"] != catalog.OCIRegion(text(p["cell"])) {
		fail("unexpected manual plan schema, cell, or OCI region")
	}
	p["_source_path"] = Path(must(filepath.Abs(path)))
	names := obj(p["preview_compartment_names"])
	if !exact(names, "control", "network", "workload") {
		fail("manual compartment names must be distinct safe names for control, network, and workload")
	}
	seen := map[string]bool{}
	for _, v := range names {
		if !safeMatch(`[A-Za-z0-9._-]{1,100}`, v) || seen[text(v)] {
			fail("manual compartment names must be distinct safe names for control, network, and workload")
		}
		seen[text(v)] = true
	}
	hosts, ok := p["hosts"].([]any)
	if !ok || len(hosts) == 0 {
		fail("manual plan must define at least one host")
	}
	slots, members := []string{}, []string{}
	controllers := 0
	seen = map[string]bool{}
	for _, v := range hosts {
		h, ok := v.(Object)
		if !ok || seen[text(h["slot"])] {
			fail("manual host slots must be unique objects")
		}
		slot := text(h["slot"])
		seen[slot] = true
		slots = append(slots, slot)
		if strings.HasPrefix(slot, "controller-") {
			controllers++
		} else if strings.HasPrefix(slot, "member-") {
			members = append(members, slot)
		}
	}
	if !eq(controllers, p["controller_replicas"]) || !eq(len(members), p["database_members"]) || controllers+len(members) != len(hosts) {
		fail("manual host roster differs from its controller and database member counts")
	}
	for _, v := range hosts {
		h := obj(v)
		slot := text(h["slot"])
		if !safeMatch(`(?:controller|member)-[a-z][a-z0-9-]{0,30}`, slot) || h["shape"] != "VM.Standard.A1.Flex" || number(h["ocpus"]) <= 0 || number(h["memory_gb"]) < number(h["ocpus"]) || number(h["boot_gb"]) < 50 || number(h["data_gb"]) < 0 || (strings.HasPrefix(slot, "controller-") && number(h["data_gb"]) != 0) || (strings.HasPrefix(slot, "member-") && number(h["data_gb"]) <= 0) {
			fail("unexpected manual shape or size for " + slot)
		}
	}
	network, nok := prefix(p["network_cidr"])
	subnet, sok := prefix(p["subnet_cidr"])
	if !nok || !sok || !privatePrefix(network) || !privatePrefix(subnet) || !within(p["subnet_cidr"], network) {
		fail("manual VCN and subnet must be nested private CIDRs")
	}
	if err := networkplan.ValidateRegion(text(p["cell"]), text(p["network_cidr"])); err != nil {
		fail(err.Error())
	}
	seen = map[string]bool{}
	for _, v := range hosts {
		ip := text(obj(v)["private_ip"])
		a, err := netip.ParseAddr(ip)
		if err != nil || seen[ip] || !subnet.Contains(a) {
			fail("manual host addresses must be unique and inside the private subnet")
		}
		seen[ip] = true
	}
	ids := obj(p["resource_ids"])
	fields := append(keysAny(resourceKinds), "instances", "boot_volumes", "data_volumes")
	if !exact(ids, fields...) {
		fail("manual plan must bind the exact foundation and host resource ID map")
	}
	for _, key := range fields {
		kind, ok := resourceKinds[key]
		if !ok || ids[key] == nil {
			continue
		}
		if key == "network_load_balancer" && l7Public(p) {
			kind = "loadbalancer"
		}
		region := text(p["region"])
		if kind == "compartment" || kind == "policy" || kind == "dynamicgroup" {
			region = ""
		}
		requireOCID(ids[key], kind, region)
	}
	for _, key := range []string{"instances", "boot_volumes", "data_volumes"} {
		expected := slots
		kind := "instance"
		if key == "boot_volumes" {
			kind = "bootvolume"
		}
		if key == "data_volumes" {
			kind = "volume"
			expected = members
		}
		if !exact(ids[key], expected...) {
			fail("manual " + key + " must map every planned slot to an exact OCID or null")
		}
		seen = map[string]bool{}
		for _, id := range obj(ids[key]) {
			if id == nil {
				continue
			}
			requireOCID(id, kind, text(p["region"]))
			if seen[text(id)] {
				fail("manual " + key + " OCIDs must be unique")
			}
			seen[text(id)] = true
		}
	}
	if p["seed_a_create_identity"] != nil && !safeMatch(`[A-Za-z0-9][A-Za-z0-9._~-]{0,127}`, p["seed_a_create_identity"]) {
		fail("manual seed-A create identity is invalid")
	}
	b := obj(p["budget"])
	if b["currency"] != "USD" || number(b["monthly_limit"]) <= 0 || number(b["monthly_limit"]) > 200 {
		fail("manual monthly budget must be positive USD and no more than $200")
	}
	if !eq(b["replacement_hosts_max"], 1) || number(b["replacement_overlap_hours_max"]) > 72 {
		fail("replacement allowance exceeds the bounded plan")
	}
	if number(b["snapshot_gb_max"]) > 350 || number(b["object_storage_gb_max"]) < 0 || number(b["object_storage_gb_max"]) > 10 || number(b["staging_object_storage_gb_max"]) < 0 || number(b["staging_object_storage_gb_max"]) > 10 {
		fail("storage allowance exceeds the bounded plan")
	}
	existing := obj(p["existing_forgejo"])
	if !exact(existing, "instance_id", "boot_volume_id", "data_volume_id", "public_ip_id", "vcn_id", "internet_gateway_id", "expected_ocpus", "expected_memory_gb", "expected_volume_gb", "expected_volume_vpus_per_gb") {
		fail("manual plan must bind the exact existing Forgejo baseline")
	}
	for key, kind := range map[string]string{"instance_id": "instance", "boot_volume_id": "bootvolume", "data_volume_id": "volume", "public_ip_id": "publicip", "vcn_id": "vcn", "internet_gateway_id": "internetgateway"} {
		requireOCID(existing[key], kind, "")
	}
	if !eq(existing["expected_volume_gb"], 50) || !eq(existing["expected_volume_vpus_per_gb"], 10) {
		fail("existing Forgejo data volume differs from the bounded cost model")
	}
	gateway := validateGateway(p, network)
	if ids["local_peering_gateway"] != nil && gateway == nil {
		fail("manual cell peering gateway requires a declared operator gateway")
	}
	public := validatePublic(p, network, subnet)
	if public == nil {
		for key := range publicIDs {
			if ids[key] != nil {
				fail("manual public API resources require a declared public API")
			}
		}
	}
	sec := obj(p["network_security"])
	if !exact(sec, "nsg_rules", "workload_nsg_rules", "security_list_ingress_rules", "security_list_egress_rules", "route_rules", "service_gateway_service_id", "service_gateway_cidr_block") {
		fail("manual plan must declare exact network and security state")
	}
	for _, key := range append(append([]string{}, ingressLists...), "security_list_egress_rules") {
		validateRules(sec[key], key)
	}
	validateBoundary(sec, network, gateway, public)
	routes, ok := sec["route_rules"].([]any)
	if !ok {
		fail("manual plan route_rules must declare exact destination, type, and target triples")
	}
	for _, v := range routes {
		if !exact(v, "destination", "destination_type", "network_entity_id") {
			fail("manual plan route_rules must declare exact destination, type, and target triples")
		}
		for _, x := range obj(v) {
			if text(x) == "" {
				fail("manual plan route_rules must declare exact destination, type, and target triples")
			}
		}
	}
	service, cidr := sec["service_gateway_service_id"], sec["service_gateway_cidr_block"]
	if (service == nil) != (cidr == nil) {
		fail("manual service gateway ID and service CIDR must be configured together")
	}
	if service != nil {
		requireOCID(service, "service", text(p["region"]))
		expected := []any{Object{"destination": cidr, "destination_type": "SERVICE_CIDR_BLOCK", "network_entity_id": "{service_gateway_id}"}}
		if gateway != nil {
			expected = append(expected, Object{"destination": text(gateway["private_ip"]) + "/32", "destination_type": "CIDR_BLOCK", "network_entity_id": "{local_peering_gateway_id}"})
		}
		if !eq(routes, expected) {
			fail("manual routes must be the exact service gateway route and operator gateway /32 peering route")
		}
	} else if ids["service_gateway"] != nil || ids["route_table"] != nil || len(routes) > 0 || gateway != nil {
		fail("manual plan has route resources without a service gateway declaration")
	}
	identity := obj(p["identity"])
	if !exact(identity, "controller_dynamic_group_name", "controller_policy_name", "objectstorage_key_policy_name", "host_dynamic_group_name", "host_policy_name") {
		fail("manual plan must declare exact live controller IAM readiness expectations")
	}
	for k, v := range identity {
		if !safeMatch(`[A-Za-z0-9._-]{1,100}`, v) {
			fail("manual IAM " + k + " is invalid")
		}
	}
	secret := obj(p["host_credential_secret"])
	if !exact(secret, "compartment_id", "secret_id") {
		fail("manual plan must bind the exact host LiveS3Credential secret and compartment")
	}
	if secret["compartment_id"] != nil || secret["secret_id"] != nil {
		requireOCID(secret["compartment_id"], "compartment", "")
		requireOCID(secret["secret_id"], "vaultsecret", text(p["region"]))
	}
	validateNetbird(p, gateway)
	if obj(ids["instances"])["controller-a"] != nil && p["seed_a_create_identity"] == nil {
		fail("manual controller-a OCID requires its preserved seed-A create identity")
	}
	if !integer(p["bucket_retention_days"]) || number(p["bucket_retention_days"]) < 1 || number(p["bucket_retention_days"]) > 3650 {
		fail("manual ledger and backup retention must be a bounded whole-day duration")
	}
	return p
}
func keysAny[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }
func LoadPlan(path string) (Object, error) {
	e := &Engine{PlanPath: path}
	return capture(func() Object { return e.loadPlan(path) })
}
