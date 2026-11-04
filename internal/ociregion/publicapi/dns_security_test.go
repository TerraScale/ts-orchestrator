package publicapi

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
)

type dnsTransport func(*http.Request) (*http.Response, error)

func (f dnsTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDNSSecurityPreflightRefusesUnsafeOrigin(t *testing.T) {
	tests := map[string]originCheck{
		"missing listener TLS": {func(f *fakeOCI) {
			delete(field(f.balancer, "listeners", "terrabase").(map[string]any), "ssl-configuration")
		}, "origin certificate"},
	}
	for name, test := range tests {
		for _, apply := range []bool{true} {
			t.Run(name+map[bool]string{false: "/dry-run", true: "/apply"}[apply], func(t *testing.T) {
				d, f, p, _, _ := reviewedEdge(t)
				fc, cloudflare := newFakeCloudflare(t)
				transport := cloudflare.HTTP.Transport
				cloudflare.HTTP.Transport = dnsTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path != "/ips" {
						t.Errorf("Cloudflare planning started before security refusal: %s %s", r.Method, r.URL.Path)
					}
					return transport.RoundTrip(r)
				})
				test.edit(f)
				before := command.JSON([]any{f.balancer, f.network, f.rules})
				var out bytes.Buffer
				if err := p.RunDNS(t.Context(), d, cloudflare, apply, &out); err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("unsafe DNS origin was not refused with %q: %v", test.want, err)
				}
				if got := f.mutations(); len(got) != 0 || len(fc.writes) != 0 || out.Len() != 0 ||
					command.JSON([]any{f.balancer, f.network, f.rules}) != before {
					t.Fatalf("security refusal changed OCI %v, Cloudflare %v, or planned writes %q", got, fc.writes, out.String())
				}
			})
		}
	}
}
