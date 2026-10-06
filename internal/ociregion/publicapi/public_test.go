package publicapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fakeOCI is a small stateful OCI holding the edge's resources by static
// name. It records every call.
type fakeOCI struct {
	t        *testing.T
	calls    [][]string
	network  map[string]map[string]any
	rules    map[string][]map[string]any
	balancer map[string]any
	secret   map[string]any
	// pendingShape lands on the second read after its update.
	pendingShape map[string]any
	lagged       bool
	content      string
	nextRule     int
}

func newFakeOCI(t *testing.T) *fakeOCI {
	return &fakeOCI{t: t, network: map[string]map[string]any{}, rules: map[string][]map[string]any{}}
}

func data(v any) map[string]any { return map[string]any{"data": v} }

func rowsOf(items ...map[string]any) []any {
	out := []any{}
	for _, item := range items {
		if item != nil {
			out = append(out, item)
		}
	}
	return out
}

func (f *fakeOCI) Head(context.Context, ...string) error { return errors.New("unexpected head") }

func (f *fakeOCI) Call(_ context.Context, args ...string) (map[string]any, error) {
	f.calls = append(f.calls, slices.Clone(args))
	c, err := sdkcli.Parse(args)
	if err != nil {
		f.t.Fatal(err)
	}
	words := strings.Fields(c.Path)
	switch {
	case c.Path == "network nsg rules list":
		return data(rowsOf(f.rules[c.Flags["nsg-id"]]...)), nil
	case c.Path == "network nsg rules add":
		var added []struct {
			Direction, Protocol, Source, SourceType, Description string
			TCPOptions                                           struct {
				DestinationPortRange struct{ Min, Max int } `json:"destinationPortRange"`
			} `json:"tcpOptions"`
		}
		if err := json.Unmarshal([]byte(c.Flags["security-rules"]), &added, json.MatchCaseInsensitiveNames(true)); err != nil {
			f.t.Fatal(err)
		}
		for _, r := range added {
			f.nextRule++
			f.rules[c.Flags["nsg-id"]] = append(f.rules[c.Flags["nsg-id"]], map[string]any{"id": fmt.Sprintf("rule-%d", f.nextRule),
				"direction": r.Direction, "protocol": r.Protocol, "source": r.Source, "source-type": r.SourceType, "is-stateless": false,
				"tcp-options": map[string]any{"destination-port-range": map[string]any{"min": r.TCPOptions.DestinationPortRange.Min, "max": r.TCPOptions.DestinationPortRange.Max}}})
		}
		return data([]any{}), nil
	case c.Path == "network nsg rules remove":
		var ids []string
		if err := json.Unmarshal([]byte(c.Flags["security-rule-ids"]), &ids); err != nil {
			f.t.Fatal(err)
		}
		nsg := c.Flags["nsg-id"]
		f.rules[nsg] = slices.DeleteFunc(f.rules[nsg], func(r map[string]any) bool { return slices.Contains(ids, r["id"].(string)) })
		return data(map[string]any{}), nil
	case words[0] == "network" && words[2] == "list":
		return data(rowsOf(f.network[words[1]])), nil
	case words[0] == "network" && words[2] == "create":
		r := map[string]any{}
		switch words[1] {
		case "internet-gateway":
			r["is-enabled"] = c.Flags["is-enabled"] == "true"
		case "route-table":
			var details core.CreateRouteTableDetails
			if err := jsonFlag(c, "route-rules", &details.RouteRules); err != nil {
				f.t.Fatal(err)
			}
			r = f.render(details)
		case "security-list":
			var details core.CreateSecurityListDetails
			if err := errors.Join(jsonFlag(c, "ingress-security-rules", &details.IngressSecurityRules), jsonFlag(c, "egress-security-rules", &details.EgressSecurityRules)); err != nil {
				f.t.Fatal(err)
			}
			r = f.render(details)
		case "subnet":
			var lists []string
			if err := jsonFlag(c, "security-list-ids", &lists); err != nil {
				f.t.Fatal(err)
			}
			r = map[string]any{"cidr-block": c.Flags["cidr-block"], "dns-label": c.Flags["dns-label"], "route-table-id": c.Flags["route-table-id"],
				"security-list-ids": lists, "prohibit-public-ip-on-vnic": c.Flags["prohibit-public-ip-on-vnic"] == "true", "prohibit-internet-ingress": false}
		}
		r["id"], r["display-name"], r["lifecycle-state"] = words[1], c.Flags["display-name"], "AVAILABLE"
		r["compartment-id"], r["vcn-id"] = c.Flags["compartment-id"], c.Flags["vcn-id"]
		f.network[words[1]] = r
		return data(r), nil
	case c.Path == "lb load-balancer list":
		// A shape update lands one read late, as OCI applies it asynchronously.
		if f.pendingShape != nil && f.lagged {
			f.balancer["shape-details"], f.pendingShape = f.pendingShape, nil
		}
		f.lagged = f.pendingShape != nil
		return data(rowsOf(f.balancer)), nil
	case c.Path == "lb load-balancer create":
		details, err := decodeLoadBalancer(c)
		if err != nil {
			f.t.Fatal(err)
		}
		// The reviewed network fixture supplies placeholders instead of issuing.
		certificate := details.Certificates[originCertificate]
		if certificate.PublicCertificate != nil && *certificate.PublicCertificate == "ORIGIN" {
			certificate.PublicCertificate = new(originPullFixture(f.t, "origin-test-server.pem"))
			details.Certificates[originCertificate] = certificate
		}
		f.balancer = f.render(details)
		f.balancer["id"], f.balancer["lifecycle-state"] = "ocid1.loadbalancer.oc1.sa-saopaulo-1.lb", "ACTIVE"
		f.balancer["ip-addresses"] = []any{map[string]any{"ip-address": "203.0.113.10", "is-public": true}}
		return data(map[string]any{}), nil
	case c.Path == "lb load-balancer update-shape":
		var shape loadbalancer.ShapeDetails
		if err := jsonFlag(c, "shape-details", &shape); err != nil {
			f.t.Fatal(err)
		}
		f.pendingShape = f.render(shape)
		return data(map[string]any{}), nil
	case c.Path == "lb backend-set update":
		var set loadbalancer.UpdateBackendSetDetails
		if err := jsonFlag(c, "details", &set); err != nil {
			f.t.Fatal(err)
		}
		f.balancer["backend-sets"].(map[string]any)[c.Flags["backend-set-name"]] = f.render(set)
		return data(map[string]any{}), nil
	case c.Path == "lb certificate create":
		var certificate loadbalancer.CreateCertificateDetails
		if err := jsonFlag(c, "certificate", &certificate); err != nil {
			f.t.Fatal(err)
		}
		f.balancer["certificates"].(map[string]any)[*certificate.CertificateName] = f.render(certificate)
		return data(map[string]any{}), nil
	case c.Path == "lb listener update":
		var listener loadbalancer.UpdateListenerDetails
		if err := jsonFlag(c, "details", &listener); err != nil {
			f.t.Fatal(err)
		}
		rendered := f.render(listener)
		rendered["name"] = c.Flags["listener-name"]
		f.balancer["listeners"].(map[string]any)[c.Flags["listener-name"]] = rendered
		return data(map[string]any{}), nil
	case c.Path == "lb load-balancer update":
		var tags map[string]any
		if err := jsonFlag(c, "freeform-tags", &tags); err != nil {
			f.t.Fatal(err)
		}
		f.balancer["freeform-tags"] = tags
		return data(map[string]any{}), nil
	case c.Path == "lb hostname update":
		f.balancer["hostnames"].(map[string]any)[c.Flags["name"]] = map[string]any{"name": c.Flags["name"], "hostname": c.Flags["hostname"]}
		return data(map[string]any{}), nil
	case c.Path == "vault secret update-base64":
		f.content = c.Flags["secret-content-content"]
		return data(f.secret), nil
	case c.Path == "vault secret list":
		return data(rowsOf(f.secret)), nil
	case c.Path == "vault secret create-base64":
		f.secret = map[string]any{"id": "secret", "secret-name": c.Flags["secret-name"], "lifecycle-state": "ACTIVE"}
		f.content = c.Flags["secret-content-content"]
		return data(f.secret), nil
	case c.Path == "secrets secret-bundle get":
		return data(map[string]any{"secret-bundle-content": map[string]any{"content-type": "BASE64", "content": f.content}}), nil
	}
	f.t.Fatalf("unexpected OCI call %v", args)
	return nil, nil
}

// render shapes an SDK value as the CLI lists it.
func (f *fakeOCI) render(value any) map[string]any {
	wire, err := sdkcli.Render(value)
	if err != nil {
		f.t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(wire, &out); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// mutations lists the paths of every call that changed the fake.
func (f *fakeOCI) mutations() []string {
	var out []string
	for _, args := range f.calls {
		c, _ := sdkcli.Parse(args)
		if !strings.HasSuffix(c.Path, " list") && !strings.HasSuffix(c.Path, " get") {
			out = append(out, c.Path)
		}
	}
	return out
}

const testPlan = `{"cell":"GRU","region":"sa-saopaulo-1","subnet_cidr":"10.251.0.0/25",
"hosts":[{"slot":"controller-a","private_ip":"10.251.0.11"},{"slot":"controller-b","private_ip":"10.251.0.12"},
{"slot":"member-a","private_ip":"10.251.0.21"},{"slot":"member-b","private_ip":"10.251.0.22"}],
"public_api":{"subnet_cidr":"10.251.0.128/26","listener_port":443,"client_port":9465,"min_mbps":10,"max_mbps":100,"terrabase_members":["gru-1-db-1"]},
"resource_ids":{"network_compartment":"network","control_compartment":"control","vcn":"vcn","network_security_group":"ctl-nsg","workload_network_security_group":"db-nsg","vault":"vault","key":"key"}}`

func testDesired(t *testing.T, plan string) Desired {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(plan), 0644); err != nil {
		t.Fatal(err)
	}
	d, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.OriginPull.CertificateID == "" {
		d.OriginPull = testOriginPull(t)
	}
	return d
}

func testCA(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "member-ca"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testOriginCertificate(t *testing.T, edit func(*x509.Certificate)) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST ONLY origin server"},
		DNSNames:  []string{"gru.api.terrascale.tech", "gru.auth.terrascale.tech"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
	edit(certificate)
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestPreviewMatchesGolden(t *testing.T) {
	d, err := LoadPlan(filepath.Join("..", "..", "..", "deploy", "oci-region", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := []byte(strings.Join(d.Preview(), "\n") + "\n")
	golden := filepath.Join("testdata", "preview.golden")
	if *update {
		if err := os.WriteFile(golden, got, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("preview differs from %s (go test -run Preview -update):\n%s", golden, got)
	}
}

func TestLoadPlanRejectsAnUnusableEdge(t *testing.T) {
	for name, edit := range map[string][2]string{
		"no bandwidth":      {`,"min_mbps":10,"max_mbps":100`, ``},
		"max below min":     {`"max_mbps":100`, `"max_mbps":5`},
		"public overlaps":   {`"subnet_cidr":"10.251.0.128/26"`, `"subnet_cidr":"10.251.0.0/26"`},
		"no member":         {`{"slot":"member-a","private_ip":"10.251.0.21"},{"slot":"member-b","private_ip":"10.251.0.22"}`, `{"slot":"x","private_ip":"10.251.0.30"}`},
		"unplanned member":  {`["gru-1-db-1"]`, `["gru-1-db-3"]`},
		"repeated member":   {`["gru-1-db-1"]`, `["gru-1-db-1","gru-1-db-1"]`},
		"no members":        {`["gru-1-db-1"]`, `[]`},
		"host outside cell": {`"10.251.0.21"`, `"10.9.0.21"`},
		"unknown cell":      {`"cell":"GRU"`, `"cell":"LHR"`},
	} {
		t.Run(name, func(t *testing.T) {
			plan := strings.Replace(testPlan, edit[0], edit[1], 1)
			if plan == testPlan {
				t.Fatal("edit did not apply")
			}
			path := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(path, []byte(plan), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPlan(path); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestProvisionBuildsTheEdgeThenResumes(t *testing.T) {
	d := testDesired(t, testPlan)
	_, cloudflare := newFakeCloudflare(t)
	f := newFakeOCI(t)
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	members := testCA(t)
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err == nil || !strings.Contains(err.Error(), "public-api cert --apply") {
		t.Fatalf("provisioned without the origin certificate: %v", err)
	}
	if len(f.mutations()) != 0 {
		t.Fatalf("mutated before admission: %v", f.mutations())
	}
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	f.calls = nil
	r, err := p.Provision(t.Context(), d, cloudflare, members)
	if err != nil {
		t.Fatal(err)
	}
	if r["public_ip"] != "203.0.113.10" || r["network_load_balancer"] != "ocid1.loadbalancer.oc1.sa-saopaulo-1.lb" || r["public_subnet"] != "subnet" {
		t.Fatal(r)
	}
	want := []string{"network internet-gateway create", "network route-table create", "network security-list create", "network subnet create", "network nsg create"}
	for range 6 {
		want = append(want, "network nsg rules add")
	}
	want = append(want, "lb load-balancer create")
	if got := f.mutations(); !slices.Equal(got, want) {
		t.Fatalf("mutations=%v\nwant=%v", got, want)
	}
	for _, args := range f.calls {
		c, _ := sdkcli.Parse(args)
		switch c.Path {
		case "network security-list create":
			if c.Flags["ingress-security-rules"] != "[]" || !strings.Contains(c.Flags["egress-security-rules"], `"destination":"10.251.0.0/25"`) ||
				!strings.Contains(c.Flags["egress-security-rules"], `"min":8080`) || !strings.Contains(c.Flags["egress-security-rules"], `"min":9465`) {
				t.Fatalf("security list %v", c.Flags)
			}
		case "lb load-balancer create":
			if c.Flags["shape-name"] != "flexible" || c.Flags["is-private"] != "false" || c.Flags["network-security-group-ids"] != `["nsg"]` ||
				c.Flags["shape-details"] != `{"maximumBandwidthInMbps":100,"minimumBandwidthInMbps":10}` {
				t.Fatalf("load balancer %v", c.Flags)
			}
		}
	}
	if got := f.rules["nsg"]; len(got) != 4 || got[0]["source"] != "103.21.244.0/22" || got[3]["source"] != "173.245.48.0/20" {
		t.Fatalf("NSG rules %v", got)
	}
	for nsg, port := range map[string]int{"db-nsg": 9465, "ctl-nsg": AuthPort} {
		if got := f.rules[nsg]; len(got) != 1 || got[0]["source"] != "10.251.0.128/26" || !same(field(got[0], "tcp-options", "destination-port-range", "min"), port) {
			t.Fatalf("%s rules %v", nsg, got)
		}
	}
	f.calls = nil
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("resume mutated %v: %v", f.mutations(), err)
	}
	if _, err := p.Provision(t.Context(), d, cloudflare, "not a CA"); err == nil {
		t.Fatal("accepted an invalid member CA")
	}
}

func TestApplyConvergesAnExistingLoadBalancerToThePlan(t *testing.T) {
	_, cloudflare := newFakeCloudflare(t)
	f := newFakeOCI(t)
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	d := testDesired(t, ownedPlan)
	members := testCA(t)
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil {
		t.Fatal(err)
	}
	// The plan names the owner, so the controller owns the terrabase
	// backends: it added gru-1-db-2 and drained gru-1-db-1 for a release.
	// Rerunning apply with the db-1 seed and more bandwidth changes only the
	// bandwidth.
	set := field(f.balancer, "backend-sets", "terrabase").(map[string]any)
	managed := []any{map[string]any{"ip-address": "10.251.0.21", "port": 9465, "drain": true},
		map[string]any{"ip-address": "10.251.0.22", "port": 9465}}
	set["backends"] = managed
	ownerless := testDesired(t, strings.NewReplacer(`"max_mbps":100`, `"max_mbps":200`).Replace(testPlan))
	d = testDesired(t, strings.NewReplacer(`"max_mbps":100`, `"max_mbps":200`).Replace(ownedPlan))
	f.calls = nil
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil {
		t.Fatal(err)
	}
	if got := f.mutations(); !slices.Equal(got, []string{"lb load-balancer update-shape"}) {
		t.Fatalf("mutations=%v", got)
	}
	if got := field(f.balancer, "backend-sets", "terrabase", "backends").([]any); len(got) != 2 || got[0].(map[string]any)["drain"] != true {
		t.Fatalf("apply rewrote the controller's backends: %v", got)
	}
	// A plan without an owner cannot take back a load balancer the
	// controller owns: nothing changes, not even the bandwidth.
	f.calls = nil
	if _, err := p.Provision(t.Context(), ownerless, cloudflare, members); err == nil ||
		!strings.Contains(err.Error(), "name orchestrator_owner") || len(f.mutations()) != 0 {
		t.Fatalf("ownerless apply on an owned load balancer: mutations=%v err=%v", f.mutations(), err)
	}
	// On an unclaimed load balancer nothing hands the set to the
	// controller, so apply converges it to the seed as before.
	tags := f.balancer["freeform-tags"]
	f.balancer["freeform-tags"] = map[string]any{}
	if _, err := p.Provision(t.Context(), ownerless, cloudflare, members); err != nil {
		t.Fatal(err)
	}
	f.balancer["freeform-tags"] = tags
	if got := liveBackends(f.balancer, "terrabase"); !slices.Equal(f.mutations(), []string{"lb backend-set update"}) ||
		!slices.Equal(got, []string{"10.251.0.21:9465"}) {
		t.Fatalf("ownerless apply: mutations=%v backends=%v", f.mutations(), got)
	}
	set = field(f.balancer, "backend-sets", "terrabase").(map[string]any)
	set["backends"] = managed
	f.calls = nil
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("converged load balancer mutated %v: %v", f.mutations(), err)
	}
	// A minimum-only change waits for the minimum, not just an ACTIVE state.
	d.MinMbps = 20
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil || !same(field(f.balancer, "shape-details", "minimum-bandwidth-in-mbps"), 20) {
		t.Fatalf("minimum bandwidth %v: %v", f.balancer["shape-details"], err)
	}
	if _, err := p.Provision(t.Context(), d, cloudflare, testCA(t)); err == nil || !strings.Contains(err.Error(), "different member CA") {
		t.Fatalf("ignored a rotated member CA: %v", err)
	}
	f.balancer["listeners"].(map[string]any)["terrabase"].(map[string]any)["default-backend-set-name"] = "ts-auth"
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err == nil || !strings.Contains(err.Error(), "listener terrabase") {
		t.Fatalf("accepted TerraBase traffic routed to ts-auth: %v", err)
	}
}

// ownedPlan is testPlan with the controller owner the fleet tags hosts with.
var ownedPlan = strings.Replace(testPlan, `"cell":"GRU",`, `"cell":"GRU","orchestrator_owner":"ts-470-gru-rebuild-2",`, 1)

func TestApplyStampsTheControllerOwnershipOfTheTerraBaseSet(t *testing.T) {
	d := testDesired(t, ownedPlan)
	if d.Owned.String() != "GRU/lb-backends/public-terrabase" {
		t.Fatal(d.Owned)
	}
	f := newFakeOCI(t)
	_, cloudflare := newFakeCloudflare(t)
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	members := testCA(t)
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil {
		t.Fatal(err)
	}
	owned := func() bool {
		tags := map[string]string{}
		for name, value := range f.balancer["freeform-tags"].(map[string]any) {
			tags[name] = fmt.Sprint(value)
		}
		return ociresource.Ownership{Mode: ociresource.TagModeFreeform, Owner: "ts-470-gru-rebuild-2"}.
			Owns(d.Owned, ociresource.Tags{Freeform: tags})
	}
	if !owned() || !slices.Contains(f.mutations(), "lb load-balancer update") {
		t.Fatalf("not stamped: tags=%v mutations=%v", f.balancer["freeform-tags"], f.mutations())
	}
	f.calls = nil
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("restamped an owned load balancer: %v %v", f.mutations(), err)
	}

	// An adopted load balancer keeps its other tags.
	f.balancer["freeform-tags"] = map[string]any{"CostCenter": "infra"}
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil || !owned() ||
		f.balancer["freeform-tags"].(map[string]any)["CostCenter"] != "infra" {
		t.Fatalf("adopt: tags=%v err=%v", f.balancer["freeform-tags"], err)
	}

	// Another owner's or resource's claim is never overwritten, and nothing
	// else changes first, not even a pending bandwidth change.
	wider := testDesired(t, strings.Replace(ownedPlan, `"max_mbps":100`, `"max_mbps":200`, 1))
	for _, claim := range []map[string]any{
		{"terrascale-managed-by": "ts-orchestrator", "terrascale-owner": "someone-else", "terrascale-resource-key": d.Owned.String()},
		{"terrascale-managed-by": "ts-orchestrator", "terrascale-owner": "ts-470-gru-rebuild-2", "terrascale-resource-key": "GRU/nlb-backends/public-api"},
		{"terrascale-owner": "someone-else"},
		{"terrascale-resource-key": "GRU/nlb-backends/public-api"},
	} {
		f.balancer["freeform-tags"], f.calls = claim, nil
		if _, err := p.Provision(t.Context(), wider, cloudflare, members); err == nil || !strings.Contains(err.Error(), "another ts-orchestrator ownership") ||
			len(f.mutations()) != 0 {
			t.Fatalf("claim %v: err=%v mutations=%v", claim, err, f.mutations())
		}
	}

	// Without an owner in the plan apply leaves the tags alone.
	f.balancer["freeform-tags"], f.calls = map[string]any{}, nil
	if _, err := p.Provision(t.Context(), testDesired(t, testPlan), cloudflare, members); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("stamped without an owner: %v %v", f.mutations(), err)
	}
	if _, err := ParsePlan([]byte(strings.Replace(ownedPlan, "ts-470-gru-rebuild-2", "Not A Token", 1))); err == nil {
		t.Fatal("accepted an owner that is not a token")
	}
}

func TestCheckBalancerRequiresTheExactPlan(t *testing.T) {
	d := testDesired(t, testPlan)
	f := newFakeOCI(t)
	_, cloudflare := newFakeCloudflare(t)
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	if _, err := p.Provision(t.Context(), d, cloudflare, testCA(t)); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckBalancer(f.balancer); err != nil {
		t.Fatal(err)
	}
	field(f.balancer, "certificates", originCertificate).(map[string]any)["ca-certificate"] = strings.ReplaceAll(d.OriginPull.CACertificate, "\n", "\r\n")
	if err := d.CheckBalancer(f.balancer); err != nil {
		t.Fatalf("rejected the same origin-pull CA with CRLF: %v", err)
	}
	// Once the plan names the owner, the controller may add any planned
	// member and drain one during a release while another serves. Without
	// one the set must be exactly the seed.
	owned := testDesired(t, ownedPlan)
	set := field(f.balancer, "backend-sets", "terrabase").(map[string]any)
	seed := set["backends"]
	set["backends"] = []any{map[string]any{"ip-address": "10.251.0.21", "port": 9465, "drain": true},
		map[string]any{"ip-address": "10.251.0.22", "port": 9465, "drain": false}}
	if err := owned.CheckBalancer(f.balancer); err != nil {
		t.Fatalf("rejected a controller-managed TerraBase set: %v", err)
	}
	if err := d.CheckBalancer(f.balancer); err == nil {
		t.Fatal("an ownerless plan accepted backends beyond its seed")
	}
	set["backends"] = seed
	for name, edit := range map[string]func(lb map[string]any){
		"missing origin-pull CA": func(lb map[string]any) {
			delete(field(lb, "certificates", originCertificate).(map[string]any), "ca-certificate")
		},
		"foreign origin-pull CA": func(lb map[string]any) {
			field(lb, "certificates", originCertificate).(map[string]any)["ca-certificate"] = testCA(t)
		},
		"shared Cloudflare origin-pull CA": func(lb map[string]any) {
			field(lb, "certificates", originCertificate).(map[string]any)["ca-certificate"] = originPullCA
		},
		"HTTPS path route override": func(lb map[string]any) {
			field(lb, "listeners", "terrabase").(map[string]any)["path-route-set-name"] = "override"
		},
		"HTTPS routing policy override": func(lb map[string]any) {
			field(lb, "listeners", "ts-auth").(map[string]any)["routing-policy-name"] = "override"
		},
		"HTTPS rule set override": func(lb map[string]any) {
			field(lb, "listeners", "terrabase").(map[string]any)["rule-set-names"] = []any{"https-redirect"}
		},
		"extra origin-pull CA": func(lb map[string]any) {
			field(lb, "certificates", originCertificate).(map[string]any)["ca-certificate"] = d.OriginPull.CACertificate + testCA(t)
		},
		"hostname swapped": func(lb map[string]any) { field(lb, "hostnames", "ts-auth").(map[string]any)["hostname"] = d.APIHost },
		"no client certificate": func(lb map[string]any) {
			field(lb, "listeners", "ts-auth", "ssl-configuration").(map[string]any)["verify-peer-certificate"] = false
		},
		"unplanned TerraBase backend": func(lb map[string]any) {
			set := field(lb, "backend-sets", "terrabase").(map[string]any)
			set["backends"] = append(set["backends"].([]any), map[string]any{"ip-address": "10.251.0.99", "port": 9465})
		},
		"member off the client port": func(lb map[string]any) {
			set := field(lb, "backend-sets", "terrabase").(map[string]any)
			set["backends"] = append(set["backends"].([]any), map[string]any{"ip-address": "10.251.0.22", "port": 9443})
		},
		"every TerraBase seat drained": func(lb map[string]any) {
			set := field(lb, "backend-sets", "terrabase").(map[string]any)
			set["backends"] = []any{map[string]any{"ip-address": "10.251.0.21", "port": 9465, "drain": true}}
		},
		"no TerraBase backend": func(lb map[string]any) {
			field(lb, "backend-sets", "terrabase").(map[string]any)["backends"] = []any{}
		},
		"offline TerraBase seat": func(lb map[string]any) {
			set := field(lb, "backend-sets", "terrabase").(map[string]any)
			set["backends"] = append(set["backends"].([]any), map[string]any{"ip-address": "10.251.0.22", "port": 9465, "offline": true})
		},
		"drained controller": func(lb map[string]any) {
			field(lb, "backend-sets", "ts-auth", "backends").([]any)[0].(map[string]any)["drain"] = true
		},
		"missing controller": func(lb map[string]any) {
			set := field(lb, "backend-sets", "ts-auth").(map[string]any)
			set["backends"] = set["backends"].([]any)[:1]
		},
		"plain member TLS": func(lb map[string]any) {
			delete(field(lb, "backend-sets", "terrabase").(map[string]any), "ssl-configuration")
		},
		"wider bandwidth": func(lb map[string]any) {
			field(lb, "shape-details").(map[string]any)["maximum-bandwidth-in-mbps"] = 400
		},
		"no redirect": func(lb map[string]any) { delete(lb["rule-sets"].(map[string]any), "https-redirect") },
	} {
		t.Run(name, func(t *testing.T) {
			wire, _ := json.Marshal(f.balancer)
			var lb map[string]any
			if err := json.Unmarshal(wire, &lb); err != nil {
				t.Fatal(err)
			}
			edit(lb)
			if err := owned.CheckBalancer(lb); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestOriginRulesMustBeExactlyCloudflares(t *testing.T) {
	rule := func(source string, port int, sourcePorts any) map[string]any {
		options := map[string]any{"destination-port-range": map[string]any{"min": port, "max": port}}
		if sourcePorts != nil {
			options["source-port-range"] = sourcePorts
		}
		return map[string]any{"id": source, "direction": "INGRESS", "protocol": "6", "source": source, "source-type": "CIDR_BLOCK", "tcp-options": options}
	}
	ranges := []string{"173.245.48.0/20"}
	exact := []map[string]any{rule("173.245.48.0/20", 80, nil), rule("173.245.48.0/20", 443, nil)}
	if err := CheckOriginRules(exact, ranges); err != nil {
		t.Fatal(err)
	}
	for name, rows := range map[string][]map[string]any{
		"unrelated /24":     append(slices.Clone(exact), rule("198.51.100.0/24", 443, nil)),
		"missing port":      exact[:1],
		"source port 443":   {rule("173.245.48.0/20", 80, nil), rule("173.245.48.0/20", 443, map[string]any{"min": 443, "max": 443})},
		"duplicated a rule": append(slices.Clone(exact), exact[0]),
	} {
		if err := CheckOriginRules(rows, ranges); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, ok := listed(rule("173.245.48.0/20", 443, map[string]any{"min": 443, "max": 443})); ok {
		t.Fatal("origin-ips would keep a rule restricted to one source port")
	}
}

func TestLoadBalancerRoutesByHostnameAndRequiresCloudflare(t *testing.T) {
	d := testDesired(t, testPlan)
	config := d.loadBalancer("ORIGIN", "KEY", "MEMBERS")
	var listeners map[string]struct {
		DefaultBackendSetName string   `json:"defaultBackendSetName"`
		Port                  int      `json:"port"`
		HostnameNames         []string `json:"hostnameNames"`
		RuleSetNames          []string `json:"ruleSetNames"`
		SSL                   *struct {
			CertificateName       string `json:"certificateName"`
			VerifyPeerCertificate bool   `json:"verifyPeerCertificate"`
		} `json:"sslConfiguration"`
		Connection struct {
			IdleTimeout int `json:"idleTimeout"`
		} `json:"connectionConfiguration"`
	}
	var sets map[string]struct {
		Backends []struct {
			IPAddress string `json:"ipAddress"`
			Port      int    `json:"port"`
		} `json:"backends"`
		Health struct {
			Port    int    `json:"port"`
			URLPath string `json:"urlPath"`
		} `json:"healthChecker"`
		SSL *struct {
			CertificateName       string `json:"certificateName"`
			VerifyPeerCertificate bool   `json:"verifyPeerCertificate"`
		} `json:"sslConfiguration"`
	}
	var certificates map[string]map[string]string
	var hostnames map[string]map[string]string
	for flag, target := range map[string]any{"listeners": &listeners, "backend-sets": &sets, "certificates": &certificates, "hostnames": &hostnames} {
		if err := json.Unmarshal([]byte(config[flag]), target); err != nil {
			t.Fatal(flag, err)
		}
	}
	for _, set := range []string{"terrabase", "ts-auth"} {
		l := listeners[set]
		if l.Port != 443 || l.DefaultBackendSetName != set || !slices.Equal(l.HostnameNames, []string{set}) || l.SSL == nil ||
			l.SSL.CertificateName != "origin" || !l.SSL.VerifyPeerCertificate || l.Connection.IdleTimeout != IdleTimeout || IdleTimeout <= 100 {
			t.Fatalf("listener %s: %+v", set, l)
		}
	}
	if http := listeners["http"]; http.Port != 80 || http.SSL != nil || !slices.Equal(http.RuleSetNames, []string{"https-redirect"}) {
		t.Fatalf("http listener %+v", http)
	}
	if hostnames["terrabase"]["hostname"] != "gru.api.terrascale.tech" || hostnames["ts-auth"]["hostname"] != "gru.auth.terrascale.tech" {
		t.Fatal(hostnames)
	}
	terrabase, auth := sets["terrabase"], sets["ts-auth"]
	if len(terrabase.Backends) != 1 || terrabase.Backends[0].IPAddress != "10.251.0.21" || terrabase.Backends[0].Port != 9465 ||
		terrabase.SSL == nil || terrabase.SSL.CertificateName != "member-ca" || !terrabase.SSL.VerifyPeerCertificate || terrabase.Health.URLPath != "/readyz" {
		t.Fatalf("terrabase %+v", terrabase)
	}
	if len(auth.Backends) != 2 || auth.Backends[1].IPAddress != "10.251.0.12" || auth.Backends[1].Port != AuthPort || auth.SSL != nil || auth.Health.Port != AuthPort {
		t.Fatalf("ts-auth %+v", auth)
	}
	if origin := certificates["origin"]; origin["publicCertificate"] != "ORIGIN" || origin["privateKey"] != "KEY" || origin["caCertificate"] != d.OriginPull.CACertificate ||
		certificates["member-ca"]["caCertificate"] != "MEMBERS" || certificates["member-ca"]["privateKey"] != "" {
		t.Fatal(certificates)
	}
	if !strings.Contains(config["rule-sets"], `"action":"REDIRECT"`) || !strings.Contains(config["rule-sets"], `"protocol":"HTTPS"`) {
		t.Fatal(config["rule-sets"])
	}
}

func TestOriginPullCAIsCloudflares(t *testing.T) {
	block, _ := pem.Decode([]byte(originPullCA))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || certificate.Subject.CommonName != "origin-pull.cloudflare.net" || certificate.NotAfter.Year() < 2029 {
		t.Fatalf("certificate=%v err=%v", certificate.Subject, err)
	}
}

func TestOriginIPsSyncAddsCloudflareAndRemovesEverythingElse(t *testing.T) {
	d := testDesired(t, testPlan)
	f := newFakeOCI(t)
	fc, cloudflare := newFakeCloudflare(t)
	f.network["nsg"] = map[string]any{"id": "nsg", "display-name": "gru-1-api-nsg", "lifecycle-state": "AVAILABLE"}
	p := Provisioner{Client: f}
	if err := p.ensureRules(t.Context(), "nsg", []Rule{{"0.0.0.0/0", 443}, {"173.245.48.0/20", 443}}); err != nil {
		t.Fatal(err)
	}
	fc.ranges = []string{"173.245.48.0/20", "103.21.244.0/22"}
	f.calls = nil
	steps, err := p.originSteps(t.Context(), d, cloudflare)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(t.Context(), steps, false, &out); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("dry run mutated %v: %v", f.mutations(), err)
	}
	if lines := strings.Split(out.String(), "\n"); !strings.HasPrefix(lines[0], "plan: add ") || lines[3] != "plan: remove nsg rule rule-1 from 0.0.0.0/0" ||
		lines[4] != "4 changes planned; rerun with --apply to apply them" {
		t.Fatal(out.String())
	}
	if err := run(t.Context(), steps, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, r := range f.rules["nsg"] {
		sources = append(sources, fmt.Sprintf("%v:%v", r["source"], r["tcp-options"].(map[string]any)["destination-port-range"].(map[string]any)["min"]))
	}
	slices.Sort(sources)
	if !slices.Equal(sources, []string{"103.21.244.0/22:443", "103.21.244.0/22:80", "173.245.48.0/20:443", "173.245.48.0/20:80"}) {
		t.Fatal(sources)
	}
	if steps, err := p.originSteps(t.Context(), d, cloudflare); err != nil || len(steps) != 0 {
		t.Fatalf("rerun planned %d: %v", len(steps), err)
	}
}

// ensureRules adds rules directly, for test setup.
func (p Provisioner) ensureRules(ctx context.Context, nsg string, rules []Rule) error {
	steps, err := p.syncRules(ctx, nsg, "test", rules, false)
	if err != nil {
		return err
	}
	return run(ctx, steps, true, io.Discard)
}

func TestCertIssuesIntoVaultThenInstallsOnTheLoadBalancer(t *testing.T) {
	d := testDesired(t, testPlan)
	f := newFakeOCI(t)
	fc, cloudflare := newFakeCloudflare(t)
	f.balancer = map[string]any{"id": "lb", "display-name": "gru-1-api", "lifecycle-state": "ACTIVE", "certificates": map[string]any{},
		"listeners": map[string]any{"terrabase": map[string]any{}, "ts-auth": map[string]any{}}}
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(t.Context(), steps, false, &out); err != nil || fc.issued != 0 || len(f.mutations()) != 0 {
		t.Fatalf("dry run issued %d, mutated %v: %v", fc.issued, f.mutations(), err)
	}
	want := `plan: create a Cloudflare Origin CA certificate for gru.api.terrascale.tech and gru.auth.terrascale.tech (RSA 2048, 5475 days) into vault secret gru-1-api-origin
plan: install the origin certificate on gru-1-api and serve it on both HTTPS listeners
2 changes planned; rerun with --apply to apply them
`
	if out.String() != want {
		t.Fatalf("dry run:\n%s", out.String())
	}
	if err := run(t.Context(), steps, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	wire, _ := base64.StdEncoding.DecodeString(f.content)
	certificate, key, err := p.originBundle(t.Context(), f.secret, []string{d.APIHost, "gru.auth.terrascale.tech"})
	if err != nil || !strings.Contains(string(wire), "RSA PRIVATE KEY") || certificate+key != string(wire) {
		t.Fatalf("vault bundle: %v", err)
	}
	var install []string
	for _, args := range f.calls {
		if c, _ := sdkcli.Parse(args); c.Path == "lb certificate create" {
			var installed map[string]string
			if err := json.Unmarshal([]byte(c.Flags["certificate"]), &installed); err != nil || installed["caCertificate"] != d.OriginPull.CACertificate ||
				installed["publicCertificate"] != certificate || installed["privateKey"] != key {
				t.Fatal("installed a different bundle than Vault holds")
			}
			install = append(install, installed["certificateName"])
		}
	}
	if !slices.Equal(install, []string{certificateName(certificate)}) || fc.issued != 1 {
		t.Fatalf("installed %v, issued %d", install, fc.issued)
	}
	for _, listener := range []string{"terrabase", "ts-auth"} {
		if got := field(f.balancer, "listeners", listener, "ssl-configuration", "certificate-name"); got != install[0] {
			t.Fatalf("listener %s serves %v", listener, got)
		}
	}
	if steps, err := p.certSteps(t.Context(), d, cloudflare); err != nil || len(steps) != 0 {
		t.Fatalf("rerun planned %d: %v", len(steps), err)
	}
}

func TestCertRefusesAShortOrForeignCertificate(t *testing.T) {
	d := testDesired(t, testPlan)
	f := newFakeOCI(t)
	fc, cloudflare := newFakeCloudflare(t)
	fc.validity = 365 * 24 * time.Hour
	steps, err := (Provisioner{Client: f}).certSteps(t.Context(), d, cloudflare)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), steps, true, io.Discard); err == nil || !strings.Contains(err.Error(), "origin-1") {
		t.Fatalf("stored a one-year certificate: %v", err)
	}
	if f.secret != nil {
		t.Fatal("stored a refused certificate")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := checkOrigin(testCA(t), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), nil, time.Now()); err == nil {
		t.Fatal("accepted a non-RSA key")
	}
}

func TestVaultBundleMustNameBothPlannedHostsBeforeAnyWrite(t *testing.T) {
	d := testDesired(t, testPlan)
	fc, cloudflare := newFakeCloudflare(t)
	for _, missing := range []string{d.APIHost, "gru.auth.terrascale.tech"} {
		hostnames := []string{d.APIHost, "gru.auth.terrascale.tech"}
		hostnames[slices.Index(hostnames, missing)] = "other.terrascale.tech"
		certificate, key, _, err := issueOrigin(t.Context(), cloudflare, hostnames)
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{"provision", "install"} {
			t.Run(missing+"/"+operation, func(t *testing.T) {
				f := newFakeOCI(t)
				f.secret = map[string]any{"id": "secret", "secret-name": d.Names.Secret, "lifecycle-state": "ACTIVE"}
				f.content = base64.StdEncoding.EncodeToString([]byte(certificate + key))
				fc.writes = nil
				p := Provisioner{Client: f}
				var err error
				if operation == "install" {
					// cert replaces the bundle with a new version instead of installing it.
					f.balancer = map[string]any{"id": "lb", "display-name": d.Names.LB, "lifecycle-state": "ACTIVE", "certificates": map[string]any{}}
					steps, err := p.certSteps(t.Context(), d, cloudflare)
					if err != nil || len(steps) != 2 || !strings.Contains(steps[0].what, "new version of vault secret") || len(f.mutations()) != 0 || len(fc.writes) != 0 {
						t.Fatalf("did not plan a new version for a bundle without %s: %v, %d", missing, err, len(steps))
					}
					return
				} else {
					_, err = p.Provision(t.Context(), d, cloudflare, testCA(t))
				}
				if err == nil || !strings.Contains(err.Error(), "certificate does not name "+missing) {
					t.Fatalf("accepted a Vault bundle without %s: %v", missing, err)
				}
				if len(f.mutations()) != 0 || len(fc.writes) != 0 {
					t.Fatalf("refusal mutated OCI %v or Cloudflare %v", f.mutations(), fc.writes)
				}
			})
		}
	}
}

func TestDNSUsesTheLoadBalancerAddress(t *testing.T) {
	d := testDesired(t, testPlan)
	f := newFakeOCI(t)
	_, cloudflare := newFakeCloudflare(t)
	p := Provisioner{Client: f}
	if err := p.RunDNS(t.Context(), d, cloudflare, false, io.Discard); err == nil || !strings.Contains(err.Error(), "public-api apply") {
		t.Fatalf("planned DNS without a load balancer: %v", err)
	}
	d, f, p, cloudflare, _ = reviewedEdge(t)
	f.balancer["ip-addresses"] = []any{map[string]any{"ip-address": "10.251.0.150", "is-public": false}, map[string]any{"ip-address": "203.0.113.10", "is-public": true}}
	var out bytes.Buffer
	if err := p.RunDNS(t.Context(), d, cloudflare, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "applied: create A gru.api.terrascale.tech 203.0.113.10 (proxied)") {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := p.RunDNS(t.Context(), d, cloudflare, false, &out); err != nil || out.String() != "no changes\n" {
		t.Fatalf("rerun %q: %v", out.String(), err)
	}
}

func TestSecretCommandsRefuseTheCLIBackend(t *testing.T) {
	t.Setenv(sdkcli.BackendEnv, "cli")
	if _, err := newClient("sa-saopaulo-1", true); err == nil {
		t.Fatal("handed key material to the oci CLI")
	}
	if client, err := newClient("sa-saopaulo-1", false); err != nil || client == nil {
		t.Fatalf("read-only command: %v", err)
	}
	t.Setenv(sdkcli.BackendEnv, "sdk")
	t.Setenv("OCI_GO_SDK_DEBUG", "v")
	if _, err := newClient("sa-saopaulo-1", true); err == nil || !strings.Contains(err.Error(), "OCI_GO_SDK_DEBUG") {
		t.Fatalf("handed key material to SDK debug logging: %v", err)
	}
}

var _ command.Client = (*fakeOCI)(nil)

func TestOriginTrustRequiredBeforeCertificateOrProvision(t *testing.T) {
	for _, shared := range []bool{false, true} {
		d := testDesired(t, testPlan)
		d.OriginPull = OriginPull{}
		if shared {
			d.OriginPull = OriginPull{CACertificate: originPullCA, CertificateID: "shared"}
		}
		f := newFakeOCI(t)
		fc, cloudflare := newFakeCloudflare(t)
		p := Provisioner{Client: f}
		if _, err := p.certSteps(t.Context(), d, cloudflare); err == nil {
			t.Fatal("certificate planning accepted missing or shared origin trust")
		}
		if _, err := p.Provision(t.Context(), d, cloudflare, testCA(t)); err == nil {
			t.Fatal("provisioning accepted missing or shared origin trust")
		}
		if err := d.CheckBalancer(nil); err == nil {
			t.Fatal("origin readback accepted missing or shared origin trust")
		}
		if len(f.calls) != 0 || len(fc.writes) != 0 {
			t.Fatalf("invalid origin trust reached OCI or Cloudflare: %v, %v", f.calls, fc.writes)
		}
	}
}

func TestRenamedAuthHostRotatesTheOriginInPlace(t *testing.T) {
	d := testDesired(t, testPlan)
	f := newFakeOCI(t)
	fc, cloudflare := newFakeCloudflare(t)
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	members := testCA(t)
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	if _, err := p.Provision(t.Context(), d, cloudflare, members); err != nil {
		t.Fatal(err)
	}
	renamed := d
	renamed.AuthHost = "gru.login.terrascale.tech"
	before := len(f.mutations())
	if _, err := p.Provision(t.Context(), renamed, cloudflare, members); err == nil || len(f.mutations()) != before {
		t.Fatalf("apply ran before the bundle names the new host: %v, %v", err, f.mutations()[before:])
	}
	steps, err = p.certSteps(t.Context(), renamed, cloudflare)
	if err != nil || len(steps) != 2 || !strings.Contains(steps[0].what, "new version of vault secret") {
		t.Fatalf("rotation plan: %v, %d", err, len(steps))
	}
	issued := fc.issued
	if err := run(t.Context(), steps, false, io.Discard); err != nil || fc.issued != issued || len(f.mutations()) != before {
		t.Fatalf("dry run issued or wrote: %v", err)
	}
	if err := run(t.Context(), steps, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Provision(t.Context(), renamed, cloudflare, members); err != nil {
		t.Fatal(err)
	}
	if got := field(f.balancer, "hostnames", "ts-auth", "hostname"); got != renamed.AuthHost {
		t.Fatalf("ts-auth hostname %v", got)
	}
	served := servedCertificate(f.balancer)
	if served == originCertificate || field(f.balancer, "certificates", originCertificate) == nil || renamed.CheckBalancer(f.balancer) != nil {
		t.Fatalf("serves %s; first certificate kept: %v", served, field(f.balancer, "certificates", originCertificate) != nil)
	}
	for _, path := range f.mutations()[before:] {
		if strings.Contains(path, "delete") {
			t.Fatalf("rotation deleted: %s", path)
		}
	}
	before = len(f.mutations())
	if steps, err := p.certSteps(t.Context(), renamed, cloudflare); err != nil || len(steps) != 0 {
		t.Fatalf("rerun planned %d: %v", len(steps), err)
	}
	if _, err := p.Provision(t.Context(), renamed, cloudflare, members); err != nil || len(f.mutations()) != before {
		t.Fatalf("rerun changed %v: %v", f.mutations()[before:], err)
	}
}
