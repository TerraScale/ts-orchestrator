package cloudflare

import (
	"reflect"
	"strings"
	"testing"
)

func testMembers() Members {
	return Members{
		"gru": {"198.51.100.10", "198.51.100.11"},
		"sfo": {"203.0.113.10", "203.0.113.11"},
		"fra": {"192.0.2.10", "192.0.2.11"},
	}
}

func testEgress() []string {
	return []string{"100.64.0.0/10", "192.0.2.99/32"}
}

// TestDeclaredZoneMatchesD24 pins the declared DNS set to the zone apex
// plus GOAL D-24's hostnames exactly: no more, no fewer.
func TestDeclaredZoneMatchesD24(t *testing.T) {
	z, err := Production(testMembers(), testEgress())
	if err != nil {
		t.Fatalf("Production failed: %v", err)
	}
	counts := map[string]int{}
	for _, rec := range z.DNSRecords {
		counts[rec.Name]++
		if rec.Type != "A" {
			t.Errorf("%s: want type A, got %s", rec.Name, rec.Type)
		}
		if !rec.Proxied {
			t.Errorf("%s: every TerraScale record is proxied", rec.Name)
		}
	}
	if counts[ZoneName] != 1 {
		t.Errorf("the apex is one placeholder record, never member addresses: got %d", counts[ZoneName])
	}
	want := []string{
		ZoneName,
		"api.terrascale.tech",
		"sync.api.terrascale.tech",
		"gru.sync.api.terrascale.tech",
		"sfo.sync.api.terrascale.tech",
		"fra.sync.api.terrascale.tech",
		"gru.api.terrascale.tech",
		"sfo.api.terrascale.tech",
		"fra.api.terrascale.tech",
		"app.terrascale.tech",
		"docs.terrascale.tech",
		"status.terrascale.tech",
	}
	if len(counts) != len(want) {
		t.Fatalf("want exactly %d hostnames, got %d: %v", len(want), len(counts), counts)
	}
	for _, name := range want {
		if counts[name] == 0 {
			t.Errorf("D-24 hostname %s missing from the declared zone", name)
		}
	}
	// sync.api carries every member; each region hostnames its own two.
	if counts["sync.api.terrascale.tech"] != 6 {
		t.Errorf("sync.api should carry all 6 member addresses, got %d", counts["sync.api.terrascale.tech"])
	}
	for _, region := range []string{"gru", "sfo", "fra"} {
		if counts[region+".api.terrascale.tech"] != 2 {
			t.Errorf("%s.api should carry its 2 members, got %d", region, counts[region+".api.terrascale.tech"])
		}
		if counts[region+".sync.api.terrascale.tech"] != 2 {
			t.Errorf("%s.sync.api should carry its 2 members, got %d", region, counts[region+".sync.api.terrascale.tech"])
		}
	}
}

func TestProductionFollowsTheEstate(t *testing.T) {
	// A region with no members yet (add-region in flight) contributes no
	// records; a replaced member is a content change the DNS diff repairs.
	z, err := Production(Members{"gru": {"198.51.100.20"}}, testEgress())
	if err != nil {
		t.Fatalf("Production failed: %v", err)
	}
	seen := map[string]bool{}
	for _, rec := range z.DNSRecords {
		seen[rec.Name] = true
	}
	if seen["sfo.api.terrascale.tech"] || seen["fra.api.terrascale.tech"] {
		t.Error("regions without members must not declare records")
	}
	if !seen["sync.api.terrascale.tech"] || !seen["gru.api.terrascale.tech"] || !seen["gru.sync.api.terrascale.tech"] {
		t.Error("present regions must declare records")
	}
}

func TestProductionRefusesEmptyEgress(t *testing.T) {
	if _, err := Production(testMembers(), nil); err == nil {
		t.Fatal("an /admin rule with no egress CIDRs would block everyone; Production must refuse")
	}
	if _, err := Production(Members{"gru": {}}, testEgress()); err == nil {
		t.Fatal("a region with no member addresses must be refused")
	}
}

func TestProductionEncodesTheDecisions(t *testing.T) {
	z, err := Production(testMembers(), testEgress())
	if err != nil {
		t.Fatalf("Production failed: %v", err)
	}
	// D-55: the cache rule marks the reactive paths eligible, origin owns
	// the TTL.
	if len(z.CacheRules) != 4 {
		t.Fatalf("want global plus three regional cache rules, got %d", len(z.CacheRules))
	}
	if len(z.SnippetRules) != 1 || !reflect.DeepEqual(z.SnippetRules[0].Hostnames, []string{
		"sync.api.terrascale.tech", "gru.sync.api.terrascale.tech", "sfo.sync.api.terrascale.tech", "fra.sync.api.terrascale.tech",
	}) {
		t.Fatalf("gate must bind one authorization Snippet to every sync ingress: %+v", z.SnippetRules)
	}
	cr := z.CacheRules[0].rule()
	if !strings.Contains(cr.Expression, `http.host eq "sync.api.terrascale.tech"`) ||
		!strings.Contains(cr.Expression, `/api/v1/reactive/`) {
		t.Errorf("cache rule expression wrong: %s", cr.Expression)
	}
	if cr.Action != "set_cache_settings" || !strings.Contains(string(cr.ActionParameters), "respect_origin") {
		t.Errorf("cache rule must be eligible with respect-origin edge TTL: %s", cr.ActionParameters)
	}
	for _, region := range []string{"gru", "sfo", "fra"} {
		cr := z.CacheRules[0]
		for _, candidate := range z.CacheRules {
			if candidate.Hostname == region+".sync.api.terrascale.tech" {
				cr = candidate
				break
			}
		}
		if cr.Hostname != region+".sync.api.terrascale.tech" || !strings.Contains(cr.rule().Expression, `starts_with(http.request.uri.path, "/api/v1/reactive/views/")`) {
			t.Errorf("regional cache rule missing or too broad for %s: %+v", region, cr)
		}
	}
	// D-58/D-59: exactly two Worker routes, none on sync.api.
	routes := map[string]string{}
	for _, r := range z.WorkerRoutes {
		routes[r.Pattern] = r.Script
	}
	want := map[string]string{
		"api.terrascale.tech/*": ProxyWorkerScript,
		"app.terrascale.tech/*": DashboardWorkerScript,
	}
	if !reflect.DeepEqual(routes, want) {
		t.Errorf("worker routes = %v, want %v", routes, want)
	}
	// D-79: /admin blocked unless the client IP is Tailscale egress.
	fw := z.FirewallRules[0].rule()
	if !strings.Contains(fw.Expression, `http.host eq "app.terrascale.tech"`) ||
		!strings.Contains(fw.Expression, "/admin") ||
		!strings.Contains(fw.Expression, "not ip.src in {100.64.0.0/10 192.0.2.99/32}") ||
		fw.Action != "block" {
		t.Errorf("admin WAF rule wrong: %s", fw.Expression)
	}
	// D-64/D-16: one per-IP rate rule on api. and none on sync.api.
	if len(z.RateRules) != 1 || z.RateRules[0].Hostname != "api.terrascale.tech" {
		t.Fatalf("rate rules = %+v", z.RateRules)
	}
	// D-58: both KV maps are declared.
	titles := map[string]bool{}
	for _, ns := range z.KVNamespaces {
		titles[ns.Title] = true
	}
	if !titles[RegionHealthNamespace] || !titles[DBPlacementNamespace] {
		t.Errorf("KV namespaces = %v", titles)
	}
	// TLS posture and the multi-label-hostname certificate story.
	if !z.SmartTieredCache || !z.TotalTLS || z.SSL.Mode != "strict" {
		t.Errorf("tiered cache / total tls / ssl mode not declared: %+v", z)
	}
}
