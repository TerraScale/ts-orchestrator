package publicapi

import (
	"bytes"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"
)

type dnsTransport func(*http.Request) (*http.Response, error)

func (f dnsTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDNSSecurityPreflightRefusesUnsafeOrigin(t *testing.T) {
	tests := map[string]originCheck{
		"minimal active load balancer": {func(f *fakeOCI) {
			f.balancer = map[string]any{"id": "lb", "display-name": "gru-1-api", "lifecycle-state": "ACTIVE",
				"ip-addresses": []any{map[string]any{"ip-address": "203.0.113.10", "is-public": true}}}
		}, "state or shape"},
		"missing listener TLS": {func(f *fakeOCI) {
			delete(field(f.balancer, "listeners", "terrabase").(map[string]any), "ssl-configuration")
		}, "origin certificate"},
		"missing listener peer auth": {func(f *fakeOCI) {
			delete(field(f.balancer, "listeners", "ts-auth", "ssl-configuration").(map[string]any), "verify-peer-certificate")
		}, "listener ts-auth"},
		"unsafe listener peer auth": {func(f *fakeOCI) {
			field(f.balancer, "listeners", "terrabase", "ssl-configuration").(map[string]any)["verify-peer-certificate"] = false
		}, "listener terrabase"},
		"missing origin-pull CA": {func(f *fakeOCI) {
			delete(field(f.balancer, "certificates", originCertificate).(map[string]any), "ca-certificate")
		}, "origin-pull CA"},
		"foreign origin-pull CA": {func(f *fakeOCI) {
			field(f.balancer, "certificates", originCertificate).(map[string]any)["ca-certificate"] = testCA(t)
		}, "origin-pull CA"},
		"missing backend TLS": {func(f *fakeOCI) {
			delete(field(f.balancer, "backend-sets", "terrabase").(map[string]any), "ssl-configuration")
		}, "backend set terrabase"},
		"unsafe backend peer auth": {func(f *fakeOCI) {
			field(f.balancer, "backend-sets", "terrabase", "ssl-configuration").(map[string]any)["verify-peer-certificate"] = false
		}, "backend set terrabase"},
		"missing NSG attachment":    {func(f *fakeOCI) { delete(f.balancer, "network-security-group-ids") }, "attachments differ"},
		"other NSG attachment":      {func(f *fakeOCI) { f.balancer["network-security-group-ids"] = []any{"other"} }, "attachments differ"},
		"extra NSG attachment":      {func(f *fakeOCI) { f.balancer["network-security-group-ids"] = []any{"nsg", "other"} }, "attachments differ"},
		"missing subnet attachment": {func(f *fakeOCI) { delete(f.balancer, "subnet-ids") }, "attachments differ"},
		"other subnet attachment":   {func(f *fakeOCI) { f.balancer["subnet-ids"] = []any{"other"} }, "attachments differ"},
		"extra subnet attachment":   {func(f *fakeOCI) { f.balancer["subnet-ids"] = []any{"subnet", "other"} }, "attachments differ"},
		"other LB compartment":      {func(f *fakeOCI) { f.balancer["compartment-id"] = "other" }, "attachments differ"},
		"missing network":           {func(f *fakeOCI) { f.network = map[string]map[string]any{} }, "does not exist"},
		"missing gateway":           {func(f *fakeOCI) { delete(f.network, "internet-gateway") }, "does not exist"},
		"missing route table":       {func(f *fakeOCI) { delete(f.network, "route-table") }, "does not exist"},
		"missing subnet":            {func(f *fakeOCI) { delete(f.network, "subnet") }, "does not exist"},
		"missing security list":     {func(f *fakeOCI) { delete(f.network, "security-list") }, "does not exist"},
		"missing NSG":               {func(f *fakeOCI) { delete(f.network, "nsg") }, "does not exist"},
		"other NSG VCN":             {func(f *fakeOCI) { f.network["nsg"]["vcn-id"] = "other" }, "reviewed network configuration"},
		"subnet extra security list": {func(f *fakeOCI) {
			f.network["subnet"]["security-list-ids"] = []any{"security-list", "default"}
		}, "reviewed network configuration"},
		"subnet other route table": {func(f *fakeOCI) {
			f.network["subnet"]["route-table-id"] = "other"
		}, "reviewed network configuration"},
		"subnet other CIDR": {func(f *fakeOCI) {
			f.network["subnet"]["cidr-block"] = "10.251.0.0/25"
		}, "reviewed network configuration"},
		"broad security-list ingress": {func(f *fakeOCI) {
			f.network["security-list"]["ingress-security-rules"] = []any{map[string]any{"source": "0.0.0.0/0", "protocol": "all"}}
		}, "reviewed network configuration"},
		"unknown security-list ingress": {func(f *fakeOCI) {
			delete(f.network["security-list"], "ingress-security-rules")
		}, "reviewed network configuration"},
		"broad security-list egress": {func(f *fakeOCI) {
			f.network["security-list"]["egress-security-rules"] = append(f.network["security-list"]["egress-security-rules"].([]any),
				map[string]any{"destination": "0.0.0.0/0", "protocol": "all"})
		}, "reviewed network configuration"},
		"public NSG ingress": {func(f *fakeOCI) { f.rules["nsg"][0]["source"] = "0.0.0.0/0" }, "more than Cloudflare"},
		"broad NSG ingress port range": {func(f *fakeOCI) {
			field(f.rules["nsg"][0], "tcp-options", "destination-port-range").(map[string]any)["max"] = 65535
		}, "more than Cloudflare"},
		"extra NSG ingress": {func(f *fakeOCI) {
			f.rules["nsg"] = append(f.rules["nsg"], map[string]any{"direction": "INGRESS", "source": "0.0.0.0/0", "protocol": "all"})
		}, "more than Cloudflare"},
		"missing Cloudflare ingress": {func(f *fakeOCI) { f.rules["nsg"] = f.rules["nsg"][:1] }, "run public-api origin-ips"},
		"duplicate Cloudflare ingress": {func(f *fakeOCI) {
			f.rules["nsg"] = append(f.rules["nsg"], f.rules["nsg"][0])
		}, "more than Cloudflare"},
	}
	maps.Copy(tests, unsafeOriginChecks(t))
	for name, test := range tests {
		for _, apply := range []bool{false, true} {
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

func TestDNSSecurityPreflightAcceptsProvisionedOriginIdempotently(t *testing.T) {
	d, f, p, _, _ := reviewedEdge(t)
	fc, cloudflare := newFakeCloudflare(t)
	// Rule ordering carries no meaning in either security boundary.
	slices.Reverse(f.network["security-list"]["egress-security-rules"].([]any))
	slices.Reverse(f.rules["nsg"])
	before := command.JSON([]any{f.balancer, f.network, f.rules})
	var out bytes.Buffer
	if err := p.RunDNS(t.Context(), d, cloudflare, false, &out); err != nil || len(fc.writes) != 0 ||
		!strings.Contains(out.String(), "plan: create A "+d.APIHost+" 203.0.113.10 (proxied)") {
		t.Fatalf("safe dry run: writes=%v output=%q err=%v", fc.writes, out.String(), err)
	}
	out.Reset()
	if err := p.RunDNS(t.Context(), d, cloudflare, true, &out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{d.APIHost, "gru.auth.terrascale.tech"} {
		records := fc.records[name]
		if len(records) != 1 || records[0].Type != "A" || records[0].Content != "203.0.113.10" || !records[0].Proxied {
			t.Fatalf("DNS did not publish the safe origin for %s: %v", name, records)
		}
	}
	writes := slices.Clone(fc.writes)
	for _, apply := range []bool{false, true} {
		out.Reset()
		if err := p.RunDNS(t.Context(), d, cloudflare, apply, &out); err != nil || out.String() != "no changes\n" || !slices.Equal(fc.writes, writes) {
			t.Fatalf("DNS rerun: writes=%v output=%q err=%v", fc.writes, out.String(), err)
		}
	}
	if got := f.mutations(); len(got) != 0 || command.JSON([]any{f.balancer, f.network, f.rules}) != before {
		t.Fatalf("DNS changed provisioned OCI resources: %v", got)
	}
}
