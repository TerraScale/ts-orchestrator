package publicapi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"
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

