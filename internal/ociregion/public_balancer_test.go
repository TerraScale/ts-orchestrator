package ociregion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
)

const testBalancerID = "ocid1.loadbalancer.oc1.sa-saopaulo-1.aaaaaaaabalancer"

// balancerPlan is the checked-in plan, edited by edit and loaded.
func balancerPlan(t *testing.T, edit func(Object)) (Object, error) {
	t.Helper()
	wire, err := os.ReadFile(filepath.Join("..", "..", "deploy", "oci-region", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := decodeJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	edit(obj(plan))
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(canonical(plan)), 0644); err != nil {
		t.Fatal(err)
	}
	return capture(func() Object { return (&Engine{}).loadPlan(path) })
}

func TestPlanBindsTheFlexibleLoadBalancer(t *testing.T) {
	if _, err := balancerPlan(t, func(p Object) { obj(p["resource_ids"])["network_load_balancer"] = testBalancerID }); err != nil {
		t.Fatalf("rejected a load balancer OCID: %v", err)
	}
	for name, edit := range map[string]func(Object){
		"network load balancer OCID": func(p Object) {
			obj(p["resource_ids"])["network_load_balancer"] = "ocid1.networkloadbalancer.oc1.sa-saopaulo-1.aaaaaaaanlb"
		},
		"bandwidth below 10": func(p Object) { obj(p["public_api"])["min_mbps"] = 5 },
		"max below min":      func(p Object) { obj(p["public_api"])["max_mbps"] = 8 },
		"one bandwidth":      func(p Object) { delete(obj(p["public_api"]), "max_mbps") },
		"unplanned member":   func(p Object) { obj(p["public_api"])["terrabase_members"] = []any{"gru-1-db-3"} },
		"no member":          func(p Object) { obj(p["public_api"])["terrabase_members"] = []any{} },
	} {
		if _, err := balancerPlan(t, edit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEstimatePricesTheLoadBalancerAtItsCeiling(t *testing.T) {
	plan, err := balancerPlan(t, func(Object) {})
	if err != nil {
		t.Fatal(err)
	}
	if got := fixed(balancerUSD(plan), 4); got != "15.3360" || !l7Public(plan) {
		t.Fatalf("load balancer estimate %s", got)
	}
}

func TestInventoryAdmitsOnlyThePricedBalancer(t *testing.T) {
	plan, err := balancerPlan(t, func(p Object) { obj(p["resource_ids"])["network_load_balancer"] = testBalancerID })
	if err != nil {
		t.Fatal(err)
	}
	lb := func(id, shape string, mbps any) []any {
		return []any{Object{"id": id, "compartment-id": "network", "shape-name": shape, "shape-details": Object{"maximum-bandwidth-in-mbps": mbps}}}
	}
	if !pricedBalancer(plan, lb(testBalancerID, "flexible", 100), "network") {
		t.Fatal("rejected the recorded load balancer")
	}
	for name, balancers := range map[string][]any{
		"wider than priced": lb(testBalancerID, "flexible", 400),
		"fixed shape":       lb(testBalancerID, "100Mbps", nil),
		"unrecorded":        lb("ocid1.loadbalancer.oc1.sa-saopaulo-1.other", "flexible", 100),
		"two":               append(lb(testBalancerID, "flexible", 100), lb(testBalancerID, "flexible", 100)...),
	} {
		if pricedBalancer(plan, balancers, "network") {
			t.Errorf("%s: admitted", name)
		}
	}
}

// liveBalancer is the checked-in plan's load balancer as the OCI CLI lists
// it after public-api apply.
const liveBalancer = `{"id":"` + testBalancerID + `","lifecycle-state":"ACTIVE","compartment-id":"ocid1.compartment.oc1..network",
"is-private":false,"shape-name":"flexible","shape-details":{"minimum-bandwidth-in-mbps":10,"maximum-bandwidth-in-mbps":100},
"subnet-ids":["ocid1.subnet.oc1.sa-saopaulo-1.public"],"network-security-group-ids":["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.edge"],
"certificates":{"origin":{"certificate-name":"origin"},"member-ca":{"certificate-name":"member-ca"}},
"hostnames":{"terrabase":{"name":"terrabase","hostname":"gru.api.terrascale.tech"},"ts-auth":{"name":"ts-auth","hostname":"auth.terrascale.tech"}},
"listeners":{
 "http":{"port":80,"protocol":"HTTP","default-backend-set-name":"terrabase","rule-set-names":["https-redirect"]},
 "terrabase":{"port":443,"protocol":"HTTP","default-backend-set-name":"terrabase","hostname-names":["terrabase"],"rule-set-names":["security-headers"],
  "ssl-configuration":{"certificate-name":"origin","verify-peer-certificate":true},"connection-configuration":{"idle-timeout":120}},
 "ts-auth":{"port":443,"protocol":"HTTP","default-backend-set-name":"ts-auth","hostname-names":["ts-auth"],"rule-set-names":["security-headers"],
  "ssl-configuration":{"certificate-name":"origin","verify-peer-certificate":true},"connection-configuration":{"idle-timeout":120}}},
"rule-sets":{"https-redirect":{"items":[{"action":"REDIRECT","response-code":301,"conditions":[{"attribute-name":"PATH","attribute-value":"/","operator":"PREFIX_MATCH"}],"redirect-uri":{"protocol":"HTTPS","host":"{host}","port":443,"path":"{path}","query":"{query}"}}]}},
"backend-sets":{
 "terrabase":{"backends":[{"ip-address":"10.251.0.21","port":9465}],"health-checker":{"protocol":"HTTP","url-path":"/readyz","port":9465,"return-code":200},
  "ssl-configuration":{"certificate-name":"member-ca","verify-peer-certificate":true}},
 "ts-auth":{"backends":[{"ip-address":"10.251.0.11","port":8080},{"ip-address":"10.251.0.12","port":8080},{"ip-address":"10.251.0.13","port":8080}],
  "health-checker":{"protocol":"HTTP","url-path":"/readyz","port":8080,"return-code":200}}}}`

func TestLiveBalancerReadback(t *testing.T) {
	originCA, err := os.ReadFile(filepath.Join("publicapi", "testdata", "origin-pull-test-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	originServer, err := os.ReadFile(filepath.Join("publicapi", "testdata", "origin-test-server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := balancerPlan(t, func(p Object) {
		obj(p["public_api"])["origin_pull"] = Object{"ca_certificate": string(originCA), "certificate_id": "test-origin-pull"}
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := Object{"network_compartment": "ocid1.compartment.oc1..network", "vcn": "ocid1.vcn.oc1.sa-saopaulo-1.vcn",
		"public_subnet": "ocid1.subnet.oc1.sa-saopaulo-1.public", "network_load_balancer": testBalancerID}
	egress := func(port int) Object {
		return Object{"protocol": "6", "destination": "10.251.0.0/25", "destination-type": "CIDR_BLOCK", "is-stateless": false,
			"tcp-options": Object{"destination-port-range": Object{"min": port, "max": port}}}
	}
	security := Object{"ingress-security-rules": []any{}, "egress-security-rules": []any{egress(9465), egress(publicapi.AuthPort)}}
	rule := func(source string, port int) Object {
		return Object{"id": source, "direction": "INGRESS", "protocol": "6", "source": source, "source-type": "CIDR_BLOCK", "is-stateless": false,
			"tcp-options": Object{"destination-port-range": Object{"min": port, "max": port}}}
	}
	for name, c := range map[string]struct {
		edit func(lb Object, rules *[]any)
		want string
	}{
		"exact": {func(Object, *[]any) {}, ""},
		"unready TerraBase health check": {func(lb Object, _ *[]any) {
			obj(obj(obj(lb["backend-sets"])["terrabase"])["health-checker"])["return-code"] = 503
		}, "backend set terrabase"},
		"unready ts-auth health check": {func(lb Object, _ *[]any) {
			obj(obj(obj(lb["backend-sets"])["ts-auth"])["health-checker"])["return-code"] = 503
		}, "backend set ts-auth"},
		"plaintext TerraBase health check": {func(lb Object, _ *[]any) {
			obj(obj(obj(lb["backend-sets"])["terrabase"])["health-checker"])["is-force-plain-text"] = true
		}, "backend set terrabase"},
		"missing origin public certificate": {func(lb Object, _ *[]any) {
			delete(obj(obj(lb["certificates"])["origin"]), "public-certificate")
		}, "origin certificate"},
		"malformed origin public certificate": {func(lb Object, _ *[]any) {
			obj(obj(lb["certificates"])["origin"])["public-certificate"] = "not a certificate"
		}, "origin certificate"},
		"origin certificate without planned SANs": {func(lb Object, _ *[]any) {
			obj(obj(lb["certificates"])["origin"])["public-certificate"] = string(originCA)
		}, "origin certificate"},
		"missing origin-pull CA": {func(lb Object, _ *[]any) {
			delete(obj(obj(lb["certificates"])["origin"]), "ca-certificate")
		}, "origin-pull CA"},
		"replaced origin-pull CA": {func(lb Object, _ *[]any) {
			obj(obj(lb["certificates"])["origin"])["ca-certificate"] = "not Cloudflare's CA"
		}, "origin-pull CA"},
		"TerraBase routed to ts-auth": {func(lb Object, _ *[]any) {
			obj(obj(lb["listeners"])["terrabase"])["default-backend-set-name"] = "ts-auth"
		}, "listener terrabase"},
		"unselected member": {func(lb Object, _ *[]any) {
			set := obj(obj(lb["backend-sets"])["terrabase"])
			set["backends"] = append(arr(set["backends"]), Object{"ip-address": "10.251.0.22", "port": 9465})
		}, "backend set terrabase"},
		"other subnet":  {func(lb Object, _ *[]any) { lb["subnet-ids"] = []any{"ocid1.subnet.oc1.sa-saopaulo-1.private"} }, "load balancer differs"},
		"unrelated /24": {func(_ Object, rules *[]any) { *rules = append(*rules, rule("198.51.100.0/24", 443)) }, "admits more than Cloudflare"},
		"stale ranges":  {func(_ Object, rules *[]any) { *rules = (*rules)[:1] }, "origin-ips --apply"},
	} {
		t.Run(name, func(t *testing.T) {
			wire, err := decodeJSON([]byte(liveBalancer))
			if err != nil {
				t.Fatal(err)
			}
			lb := obj(wire)
			obj(obj(lb["certificates"])["origin"])["ca-certificate"] = string(originCA)
			obj(obj(lb["certificates"])["origin"])["public-certificate"] = string(originServer)
			rules := []any{rule("173.245.48.0/20", 80), rule("173.245.48.0/20", 443)}
			c.edit(lb, &rules)
			engine := &Engine{Dependency: func(name string, args []any, _ Object) (any, error) {
				if name == "cloudflare_origin_ips" {
					return []any{"173.245.48.0/20"}, nil
				}
				switch strings.Join([]string{text(args[0]), text(args[1]), text(args[2])}, " ") {
				case "lb load-balancer list":
					return []any{lb}, nil
				case "network nsg get":
					return Object{"id": "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.edge", "compartment-id": ids["network_compartment"], "vcn-id": ids["vcn"]}, nil
				case "network nsg rules":
					return rules, nil
				}
				t.Fatalf("unexpected OCI read %v", args)
				return nil, nil
			}}
			_, err = capture(func() bool { engine.livePublicBalancer(plan, ids, obj(plan["public_api"]), security); return true })
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("err=%v want %q", err, c.want)
			}
		})
	}
}
