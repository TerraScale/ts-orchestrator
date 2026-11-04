package publicapi

import (
	"crypto/x509"
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
	return map[string]originCheck{
		"plaintext health check": {func(f *fakeOCI) {
			field(f.balancer, "backend-sets", "terrabase", "health-checker").(map[string]any)["is-force-plain-text"] = true
		}, "backend set terrabase"},
		"expired origin certificate": {func(f *fakeOCI) {
			field(f.balancer, "certificates", originCertificate).(map[string]any)["public-certificate"] = testOriginCertificate(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Hour) })
		}, "origin certificate"},
	}
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
