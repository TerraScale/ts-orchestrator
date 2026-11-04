package ociregion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
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

const liveBalancer = `{"id":"` + testBalancerID + `","lifecycle-state":"ACTIVE","compartment-id":"ocid1.compartment.oc1..network",
"is-private":false,"shape-name":"flexible","shape-details":{"minimum-bandwidth-in-mbps":10,"maximum-bandwidth-in-mbps":100},
"subnet-ids":["ocid1.subnet.oc1.sa-saopaulo-1.public"],"network-security-group-ids":["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.edge"],
"certificates":{"origin":{"certificate-name":"origin"},"member-ca":{"certificate-name":"member-ca"}},
"hostnames":{"terrabase":{"name":"terrabase","hostname":"gru.api.terrascale.tech"},"ts-auth":{"name":"ts-auth","hostname":"gru.auth.terrascale.tech"}},
"listeners":{
 "http":{"port":80,"protocol":"HTTP","default-backend-set-name":"terrabase","rule-set-names":["https-redirect"]},
 "terrabase":{"port":443,"protocol":"HTTP","default-backend-set-name":"terrabase","hostname-names":["terrabase"],"rule-set-names":["security-headers"],
  "routing-policy-name":"terrabase_routes",
  "ssl-configuration":{"certificate-name":"origin","verify-peer-certificate":true},"connection-configuration":{"idle-timeout":120}},
 "ts-auth":{"port":443,"protocol":"HTTP","default-backend-set-name":"ts-auth","hostname-names":["ts-auth"],"rule-set-names":["security-headers"],
  "ssl-configuration":{"certificate-name":"origin","verify-peer-certificate":true},"connection-configuration":{"idle-timeout":120}}},
"rule-sets":{"https-redirect":{"items":[{"action":"REDIRECT","response-code":301,"conditions":[{"attribute-name":"PATH","attribute-value":"/","operator":"PREFIX_MATCH"}],"redirect-uri":{"protocol":"HTTPS","host":"{host}","port":443,"path":"{path}","query":"{query}"}}]}},
"routing-policies":{"terrabase_routes":{"name":"terrabase_routes","condition-language-version":"V1","rules":[{"name":"management_to_primary",
 "condition":"any(http.request.url.path sw '/v1/management')","actions":[{"name":"FORWARD_TO_BACKENDSET","backend-set-name":"terrabase-primary"}]}]}},
"backend-sets":{
 "terrabase":{"backends":[{"ip-address":"10.251.0.21","port":9465}],"health-checker":{"protocol":"HTTP","url-path":"/readyz","port":9465,"return-code":200},
  "ssl-configuration":{"certificate-name":"member-ca","verify-peer-certificate":true}},
 "terrabase-primary":{"backends":[{"ip-address":"10.251.0.21","port":9465}],"health-checker":{"protocol":"HTTP","url-path":"/readyz","port":9465,"return-code":200},
  "ssl-configuration":{"certificate-name":"member-ca","verify-peer-certificate":true}},
 "ts-auth":{"backends":[{"ip-address":"10.251.0.11","port":8080},{"ip-address":"10.251.0.12","port":8080},{"ip-address":"10.251.0.13","port":8080}],
  "health-checker":{"protocol":"HTTP","url-path":"/readyz","port":8080,"return-code":200}}}}`

func TestLiveBalancerReadbackServesTheMachinesAPI(t *testing.T) {
	originCA, err := os.ReadFile(filepath.Join("publicapi", "testdata", "origin-pull-test-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(15, 0, 0),
		DNSNames: []string{"gru.api.terrascale.tech", "gru.auth.terrascale.tech", "gru.orch.terrascale.tech"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := balancerPlan(t, func(p Object) {
		obj(p["public_api"])["origin_pull"] = Object{"ca_certificate": string(originCA), "certificate_id": "test-origin-pull"}
		obj(p["public_api"])["orch"] = true
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := Object{"network_compartment": "ocid1.compartment.oc1..network", "vcn": "ocid1.vcn.oc1.sa-saopaulo-1.vcn",
		"public_subnet": "ocid1.subnet.oc1.sa-saopaulo-1.public", "network_load_balancer": testBalancerID}
	wire, err := decodeJSON([]byte(liveBalancer))
	if err != nil {
		t.Fatal(err)
	}
	lb := obj(wire)
	origin := obj(obj(lb["certificates"])["origin"])
	origin["ca-certificate"], origin["public-certificate"] = string(originCA), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	obj(lb["certificates"])["cell-ca"] = Object{"certificate-name": "cell-ca"}
	obj(lb["hostnames"])["ts-orch"] = Object{"name": "ts-orch", "hostname": "gru.orch.terrascale.tech"}
	listener := Object{}
	for k, v := range obj(obj(lb["listeners"])["ts-auth"]) {
		listener[k] = v
	}
	listener["default-backend-set-name"], listener["hostname-names"] = "ts-orch", []any{"ts-orch"}
	obj(lb["listeners"])["ts-orch"] = listener
	obj(lb["backend-sets"])["ts-orch"] = Object{"backends": []any{Object{"ip-address": "10.251.0.11", "port": 8444}, Object{"ip-address": "10.251.0.12", "port": 8444},
		Object{"ip-address": "10.251.0.13", "port": 8444}}, "health-checker": Object{"protocol": "HTTP", "url-path": "/healthz", "port": 8444, "return-code": 200},
		"ssl-configuration": Object{"certificate-name": "cell-ca", "verify-peer-certificate": true}}
	egress := func(port int) Object {
		return Object{"protocol": "6", "destination": "10.251.0.0/25", "destination-type": "CIDR_BLOCK", "is-stateless": false,
			"tcp-options": Object{"destination-port-range": Object{"min": port, "max": port}}}
	}
	rules := []any{}
	for _, port := range []int{80, 443} {
		rules = append(rules, Object{"id": port, "direction": "INGRESS", "protocol": "6", "source": "173.245.48.0/20", "source-type": "CIDR_BLOCK", "is-stateless": false,
			"tcp-options": Object{"destination-port-range": Object{"min": port, "max": port}}})
	}
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
	for _, c := range []struct {
		ports []int
		want  string
	}{{[]int{9465, publicapi.AuthPort, publicapi.OrchPort}, ""}, {[]int{9465, publicapi.AuthPort}, "security-list egress"}} {
		security := Object{"ingress-security-rules": []any{}, "egress-security-rules": []any{}}
		for _, port := range c.ports {
			security["egress-security-rules"] = append(arr(security["egress-security-rules"]), egress(port))
		}
		_, err := capture(func() bool { engine.livePublicBalancer(plan, ids, obj(plan["public_api"]), security); return true })
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Fatalf("egress %v: err=%v want %q", c.ports, err, c.want)
		}
	}
}
