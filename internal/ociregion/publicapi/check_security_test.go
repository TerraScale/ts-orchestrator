package publicapi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
)

type originCheck struct {
	edit func(*fakeOCI)
	want string
}

// unsafeOriginChecks changes only readiness or the live server certificate,
// leaving the reviewed customer origin-pull CA intact.
func unsafeOriginChecks(t *testing.T) map[string]originCheck {
	t.Helper()
	tests := map[string]originCheck{}
	for _, name := range []string{"terrabase", "ts-auth"} {
		for _, code := range []any{503, nil} {
			tests[fmt.Sprintf("%s health return-code %v", name, code)] = originCheck{func(f *fakeOCI) {
				field(f.balancer, "backend-sets", name, "health-checker").(map[string]any)["return-code"] = code
			}, "backend set " + name}
		}
	}
	tests["plaintext TerraBase health check"] = originCheck{func(f *fakeOCI) {
		field(f.balancer, "backend-sets", "terrabase", "health-checker").(map[string]any)["is-force-plain-text"] = true
	}, "backend set terrabase"}
	certificates := map[string]string{
		"missing public certificate": "",
		"malformed certificate PEM":  "not a certificate",
		"malformed certificate DER":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})),
	}
	for name, edit := range map[string]func(*x509.Certificate){
		"missing TerraBase SAN": func(c *x509.Certificate) { c.DNSNames = []string{"gru.auth.terrascale.tech"} },
		"missing ts-auth SAN":   func(c *x509.Certificate) { c.DNSNames = c.DNSNames[:1] },
		"foreign SANs":          func(c *x509.Certificate) { c.DNSNames = []string{"other.terrascale.tech"} },
		"wildcard SAN":          func(c *x509.Certificate) { c.DNSNames[0] = "*.api.terrascale.tech" },
		"expired certificate":   func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Hour) },
		"future certificate":    func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
	} {
		certificates[name] = testOriginCertificate(t, edit)
	}
	for name, certificate := range certificates {
		tests[name] = originCheck{func(f *fakeOCI) {
			origin := field(f.balancer, "certificates", originCertificate).(map[string]any)
			if certificate == "" {
				delete(origin, "public-certificate")
			} else {
				origin["public-certificate"] = certificate
			}
		}, "origin certificate"}
	}
	return tests
}

func TestCheckBalancerSecurityHealthAndOriginCertificate(t *testing.T) {
	for name, test := range unsafeOriginChecks(t) {
		t.Run(name, func(t *testing.T) {
			d, f, p, cloudflare, members := reviewedEdge(t)
			test.edit(f)
			if err := d.CheckBalancer(f.balancer); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("accepted unsafe origin %s: %v", name, err)
			}
			if _, err := p.Provision(t.Context(), d, cloudflare, members, ""); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("apply accepted unsafe origin %s: %v", name, err)
			}
			if mutations := f.mutations(); len(mutations) != 0 {
				t.Fatalf("drift reporting mutated OCI: %v", mutations)
			}
		})
	}
}

func TestCheckBalancerSecurityHealthTLSDefaults(t *testing.T) {
	d, f, _, _, _ := reviewedEdge(t)
	health := field(f.balancer, "backend-sets", "terrabase", "health-checker").(map[string]any)
	for _, forcePlaintext := range []any{nil, false} {
		health["is-force-plain-text"] = forcePlaintext
		if err := d.CheckBalancer(f.balancer); err != nil {
			t.Fatalf("rejected native TLS health-check default %v: %v", forcePlaintext, err)
		}
	}
	delete(health, "is-force-plain-text")
	if err := d.CheckBalancer(f.balancer); err != nil {
		t.Fatalf("rejected omitted TLS health-check default: %v", err)
	}
	// Readback may include a PEM chain and omits the private key.
	origin := field(f.balancer, "certificates", originCertificate).(map[string]any)
	origin["public-certificate"] = origin["public-certificate"].(string) + testCA(t)
	delete(origin, "private-key")
	if err := d.CheckBalancer(f.balancer); err != nil {
		t.Fatalf("rejected a valid leaf followed by its certificate chain without a private key: %v", err)
	}
}

func TestCheckBalancerSecurityBackendDefaults(t *testing.T) {
	d, f, _, _, _ := reviewedEdge(t)
	if err := d.CheckBalancer(f.balancer); err != nil {
		t.Fatalf("rejected SDK-rendered omitted create defaults: %v", err)
	}
	for _, name := range []string{"terrabase", "ts-auth"} {
		rows := field(f.balancer, "backend-sets", name, "backends").([]any)
		for i, row := range rows {
			// Unlike BackendDetails, a live Backend returns explicit defaults.
			rows[i] = f.render(loadbalancer.Backend{
				IpAddress: new(field(row, "ip-address").(string)), Port: new(int(field(row, "port").(float64))),
				Weight: new(1), Offline: new(false), Drain: new(false), Backup: new(false),
			})
		}
	}
	if err := d.CheckBalancer(f.balancer); err != nil {
		t.Fatalf("rejected SDK-rendered live defaults: %v", err)
	}
}

func TestCheckBalancerSecurityInactiveBackends(t *testing.T) {
	for _, backend := range []struct {
		set   string
		index int
	}{{"terrabase", 0}, {"ts-auth", 0}, {"ts-auth", 1}} {
		for _, flag := range []string{"offline", "drain", "backup"} {
			t.Run(fmt.Sprintf("%s/%d/%s", backend.set, backend.index, flag), func(t *testing.T) {
				d, f, p, cloudflare, members := reviewedEdge(t)
				rows := field(f.balancer, "backend-sets", backend.set, "backends").([]any)
				rows[backend.index].(map[string]any)[flag] = true
				want := "backend set " + backend.set
				if err := d.CheckBalancer(f.balancer); err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("accepted a %s backend at the planned IP and port: %v", flag, err)
				}
				if _, err := p.Provision(t.Context(), d, cloudflare, members, ""); err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("apply hid a %s backend behind unchanged membership: %v", flag, err)
				}
				if mutations := f.mutations(); len(mutations) != 0 {
					t.Fatalf("drift reporting mutated OCI: %v", mutations)
				}
			})
		}
	}
}

func TestCheckBalancerSecurityHTTPRedirect(t *testing.T) {
	for _, c := range []struct {
		name, object, key string
		value             any
	}{
		{"other default backend", "listener", "default-backend-set-name", "ts-auth"},
		{"hostname restricted", "listener", "hostname-names", []any{"terrabase"}},
		{"path routing", "listener", "path-route-set-name", "plaintext"},
		{"routing policy", "listener", "routing-policy-name", "plaintext"},
		{"missing redirect binding", "listener", "rule-set-names", nil},
		{"additional rule binding", "listener", "rule-set-names", []any{"https-redirect", "0000000000V4MRM46HP1SNGDYW"}},
		{"missing rule", "rule-set", "items", nil},
		{"empty rules", "rule-set", "items", []any{}},
		{"other action", "redirect", "action", "ADD_HTTP_RESPONSE_HEADER"},
		{"temporary status", "redirect", "response-code", 302},
		{"default status", "redirect", "response-code", nil},
		{"missing conditions", "redirect", "conditions", nil},
		{"empty conditions", "redirect", "conditions", []any{}},
		{"additional condition", "redirect", "conditions", []any{
			map[string]any{"attribute-name": "PATH", "attribute-value": "/", "operator": "PREFIX_MATCH"},
			map[string]any{"attribute-name": "PATH", "attribute-value": "/readyz", "operator": "EXACT_MATCH"},
		}},
		{"narrow path", "condition", "attribute-value", "/readyz"},
		{"exact root only", "condition", "operator", "EXACT_MATCH"},
		{"other attribute", "condition", "attribute-name", "HOST"},
		{"plaintext destination", "destination", "protocol", "HTTP"},
		{"foreign host", "destination", "host", "other.terrascale.tech"},
		{"missing host", "destination", "host", nil},
		{"plaintext port", "destination", "port", 80},
		{"retained plaintext port", "destination", "port", nil},
		{"replaced path", "destination", "path", "/"},
		{"missing path", "destination", "path", nil},
		{"dropped query", "destination", "query", ""},
		{"missing query", "destination", "query", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, f, _, _, _ := reviewedEdge(t)
			set := field(f.balancer, "rule-sets", "https-redirect").(map[string]any)
			redirect := set["items"].([]any)[0].(map[string]any)
			objects := map[string]map[string]any{
				"listener":    field(f.balancer, "listeners", "http").(map[string]any),
				"rule-set":    set,
				"redirect":    redirect,
				"condition":   redirect["conditions"].([]any)[0].(map[string]any),
				"destination": redirect["redirect-uri"].(map[string]any),
			}
			objects[c.object][c.key] = c.value
			want := "https-redirect rule set"
			if c.object == "listener" {
				want = "listener http"
			}
			if err := d.CheckBalancer(f.balancer); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("accepted HTTP redirect drift %s: %v", c.name, err)
			}
		})
	}
}

func TestCheckBalancerSecurityUnrestrictedHTTPDefaults(t *testing.T) {
	for _, hostnames := range []any{nil, []any{}} {
		d, f, _, _, _ := reviewedEdge(t)
		field(f.balancer, "listeners", "http").(map[string]any)["hostname-names"] = hostnames
		if err := d.CheckBalancer(f.balancer); err != nil {
			t.Fatalf("rejected unrestricted HTTP listener hostnames %v: %v", hostnames, err)
		}
	}
}
