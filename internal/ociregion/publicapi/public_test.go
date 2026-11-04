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
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
)

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
	sdk          *SDKClient
}

func newFakeOCI(t *testing.T) *fakeOCI {
	f := &fakeOCI{t: t, network: map[string]map[string]any{}, rules: map[string][]map[string]any{}}
	f.sdk = sdkFixture(t, f)
	return f
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

func (f *fakeOCI) Call(ctx context.Context, args ...string) (map[string]any, error) {
	f.calls = append(f.calls, slices.Clone(args))
	return f.sdk.Call(ctx, args...)
}

func (f *fakeOCI) serveCommand(_ context.Context, args ...string) (map[string]any, error) {
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
	case c.Path == "lb routing-policy create":
		policy := loadbalancer.RoutingPolicy{Name: new(c.Flags["name"]),
			ConditionLanguageVersion: loadbalancer.RoutingPolicyConditionLanguageVersionEnum(c.Flags["condition-language-version"])}
		if err := jsonFlag(c, "rules", &policy.Rules); err != nil {
			f.t.Fatal(err)
		}
		if f.balancer["routing-policies"] == nil {
			f.balancer["routing-policies"] = map[string]any{}
		}
		f.balancer["routing-policies"].(map[string]any)[*policy.Name] = f.render(policy)
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

func TestProvisionServesTheMachinesAPI(t *testing.T) {
	d := testDesired(t, strings.Replace(testPlan, `"terrabase_members":["gru-1-db-1"]}`, `"terrabase_members":["gru-1-db-1"],"orch":true}`, 1))
	_, cloudflare := newFakeCloudflare(t)
	f := newFakeOCI(t)
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	members, cell := testCA(t), testCA(t)
	if _, err := p.Provision(t.Context(), d, cloudflare, members, cell); err != nil {
		t.Fatal(err)
	}
	if got := f.rules["ctl-nsg"]; len(got) != 2 || !same(field(got[1], "tcp-options", "destination-port-range", "min"), OrchPort) {
		t.Fatalf("controller NSG rules %v", got)
	}
	f.calls = nil
	if _, err := p.Provision(t.Context(), d, cloudflare, members, cell); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("resume mutated %v: %v", f.mutations(), err)
	}
	if _, err := p.Provision(t.Context(), d, cloudflare, members, testCA(t)); err == nil || !strings.Contains(err.Error(), "cell CA") {
		t.Fatalf("accepted another cell CA: %v", err)
	}
}

func TestSFOEdgeComesUpAndRotatesItsOrigin(t *testing.T) {
	wire, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "oci-region", "sjc-1-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(wire, &plan); err != nil {
		t.Fatal(err)
	}
	plan["resource_ids"] = map[string]any{"network_compartment": "network", "control_compartment": "control", "vcn": "vcn",
		"network_security_group": "ctl-nsg", "workload_network_security_group": "db-nsg", "vault": "vault", "key": "key"}
	wire, _ = json.Marshal(plan)
	d := testDesired(t, string(wire))
	d.OriginPull = testOriginPull(t)
	f := newFakeOCI(t)
	fc, cloudflare := newFakeCloudflare(t)
	p := Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}
	steps, err := p.certSteps(t.Context(), d, cloudflare)
	if err != nil || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatal(err)
	}
	members, cell := testCA(t), testCA(t)
	if _, err := p.Provision(t.Context(), d, cloudflare, members, cell); err != nil {
		t.Fatal(err)
	}
	if err := p.RunDNS(t.Context(), d, cloudflare, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range d.hostNames() {
		if records := fc.records[name]; len(records) != 1 || records[0].Content != "203.0.113.10" || !records[0].Proxied {
			t.Fatalf("%s records %v", name, records)
		}
	}
	// A Vault bundle missing a planned name, here sjc.orch, gets a new version.
	certificate, key, _, err := issueOrigin(t.Context(), cloudflare, d.hostNames()[:2])
	if err != nil {
		t.Fatal(err)
	}
	f.content = base64.StdEncoding.EncodeToString([]byte(certificate + key))
	steps, err = p.certSteps(t.Context(), d, cloudflare)
	if err != nil || len(steps) != 2 || run(t.Context(), steps, true, io.Discard) != nil {
		t.Fatalf("rotation: %v, %d", err, len(steps))
	}
	served := servedCertificate(f.balancer)
	for _, h := range d.hosts() {
		if got := field(f.balancer, "listeners", h.set, "ssl-configuration", "certificate-name"); got == originCertificate || got != served {
			t.Fatalf("listener %s serves %v, want %s", h.set, got, served)
		}
	}
	if err := d.CheckBalancer(f.balancer); err != nil {
		t.Fatal(err)
	}
	before := len(f.mutations())
	var out bytes.Buffer
	if err := p.RunDNS(t.Context(), d, cloudflare, true, &out); err != nil || out.String() != "no changes\n" {
		t.Fatalf("dns after rotation %q: %v", out.String(), err)
	}
	if steps, err := p.certSteps(t.Context(), d, cloudflare); err != nil || len(steps) != 0 {
		t.Fatalf("cert rerun planned %d: %v", len(steps), err)
	}
	if _, err := p.Provision(t.Context(), d, cloudflare, members, cell); err != nil || len(f.mutations()) != before {
		t.Fatalf("apply rerun changed %v: %v", f.mutations()[before:], err)
	}
}

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
plan: install the origin certificate on gru-1-api and serve it on every HTTPS listener
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
		if _, err := p.Provision(t.Context(), d, cloudflare, testCA(t), ""); err == nil {
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
