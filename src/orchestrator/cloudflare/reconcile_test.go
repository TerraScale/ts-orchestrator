package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// miniCF is a stateful fake of exactly the Cloudflare surface this package
// uses. The full-zone test drives drift through it end to end: observe,
// diff, plan, apply, re-observe. No real calls.
type miniCF struct {
	mu       sync.Mutex
	dns      map[string]DNSRecord
	phases   map[string][]wireRule
	snippets map[string][]SnippetRuleWire
	routes   map[string]WorkerRoute
	kvns     map[string]KVNamespace
	kvValues map[string]string
	settings map[string]string
	totalTLS TotalTLS
	tiered   string
	nextID   int
}

func newMiniCF() *miniCF {
	return &miniCF{
		dns:      map[string]DNSRecord{},
		phases:   map[string][]wireRule{},
		snippets: map[string][]SnippetRuleWire{},
		routes:   map[string]WorkerRoute{},
		kvns:     map[string]KVNamespace{},
		kvValues: map[string]string{},
		settings: map[string]string{"brotli": "on"},
		tiered:   "off",
	}
}

func (m *miniCF) id(prefix string) string {
	m.nextID++
	return fmt.Sprintf("%s-%d", prefix, m.nextID)
}

func (m *miniCF) serve(call fakeCall) (int, string, http.Header) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path, method := call.Path, call.Method
	switch {
	// DNS records
	case method == http.MethodGet && path == "/zones/zone-1/dns_records?per_page=100":
		records := make([]DNSRecord, 0, len(m.dns))
		for _, rec := range m.dns {
			records = append(records, rec)
		}
		sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
		return okEnvelope(mustJSON(records))
	case method == http.MethodPost && path == "/zones/zone-1/dns_records":
		var rec DNSRecord
		unmarshalOr500(call.Body, &rec)
		rec.ID = m.id("dns")
		m.dns[rec.ID] = rec
		return okEnvelope(mustJSON(rec))
	case method == http.MethodPatch && strings.HasPrefix(path, "/zones/zone-1/dns_records/"):
		var patch DNSRecord
		unmarshalOr500(call.Body, &patch)
		rec, ok := m.dns[strings.TrimPrefix(path, "/zones/zone-1/dns_records/")]
		if !ok {
			return failEnvelope(http.StatusNotFound, 10004, "no record")
		}
		rec.TTL, rec.Proxied = patch.TTL, patch.Proxied
		m.dns[rec.ID] = rec
		return okEnvelope(mustJSON(rec))
	case method == http.MethodDelete && strings.HasPrefix(path, "/zones/zone-1/dns_records/"):
		delete(m.dns, strings.TrimPrefix(path, "/zones/zone-1/dns_records/"))
		return okEnvelope("null")

	// Phase rulesets (Cache Rules, WAF custom, rate limiting)
	case method == http.MethodGet && strings.HasPrefix(path, "/zones/zone-1/rulesets/phases/") && strings.HasSuffix(path, "/entrypoint"):
		phase := phaseFromPath(path)
		rules, ok := m.phases[phase]
		if !ok {
			return failEnvelope(http.StatusNotFound, 10004, "phase not configured")
		}
		return okEnvelope(`{"rules":` + mustJSON(rules) + `}`)
	case method == http.MethodPut && strings.HasPrefix(path, "/zones/zone-1/rulesets/phases/") && strings.HasSuffix(path, "/entrypoint"):
		phase := phaseFromPath(path)
		var body struct {
			Rules []wireRule `json:"rules"`
		}
		unmarshalOr500(call.Body, &body)
		for i := range body.Rules {
			if body.Rules[i].ID == "" {
				body.Rules[i].ID = m.id(phase)
			}
		}
		m.phases[phase] = body.Rules
		return okEnvelope("null")

	// Smart Tiered Cache
	case path == "/zones/zone-1/cache/tiered_cache_smart_topology_enable" && method == http.MethodGet:
		return okEnvelope(`{"value":"` + m.tiered + `"}`)
	case path == "/zones/zone-1/cache/tiered_cache_smart_topology_enable" && method == http.MethodPut:
		var body struct {
			Value string `json:"value"`
		}
		unmarshalOr500(call.Body, &body)
		m.tiered = body.Value
		return okEnvelope("null")

	// Snippets
	case method == http.MethodGet && path == "/zones/zone-1/snippets":
		out := make([]Snippet, 0, len(m.snippets))
		for name, rules := range m.snippets {
			out = append(out, Snippet{Name: name, Rules: rules})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return okEnvelope(mustJSON(out))
	case method == http.MethodGet && path == "/zones/zone-1/snippets/snippet_rules":
		names := make([]string, 0, len(m.snippets))
		for name := range m.snippets {
			names = append(names, name)
		}
		sort.Strings(names)
		rules := []zoneSnippetRule{}
		for _, name := range names {
			for _, rule := range m.snippets[name] {
				rules = append(rules, zoneSnippetRule{SnippetName: name, SnippetRuleWire: rule})
			}
		}
		return okEnvelope(mustJSON(map[string]any{"rules": rules}))
	case method == http.MethodPut && path == "/zones/zone-1/snippets/snippet_rules":
		var body struct {
			Rules []zoneSnippetRule `json:"rules"`
		}
		unmarshalOr500(call.Body, &body)
		for name := range m.snippets {
			m.snippets[name] = nil
		}
		for _, rule := range body.Rules {
			m.snippets[rule.SnippetName] = append(m.snippets[rule.SnippetName], rule.SnippetRuleWire)
		}
		return okEnvelope("null")

	// Worker routes
	case method == http.MethodGet && path == "/zones/zone-1/workers/routes":
		routes := make([]WorkerRoute, 0, len(m.routes))
		for _, r := range m.routes {
			routes = append(routes, r)
		}
		sort.Slice(routes, func(i, j int) bool { return routes[i].ID < routes[j].ID })
		return okEnvelope(mustJSON(routes))
	case method == http.MethodPost && path == "/zones/zone-1/workers/routes":
		var r WorkerRoute
		unmarshalOr500(call.Body, &r)
		r.ID = m.id("route")
		m.routes[r.ID] = r
		return okEnvelope(mustJSON(r))
	case method == http.MethodPut && strings.HasPrefix(path, "/zones/zone-1/workers/routes/"):
		var r WorkerRoute
		unmarshalOr500(call.Body, &r)
		r.ID = strings.TrimPrefix(path, "/zones/zone-1/workers/routes/")
		m.routes[r.ID] = r
		return okEnvelope(mustJSON(r))
	case method == http.MethodDelete && strings.HasPrefix(path, "/zones/zone-1/workers/routes/"):
		delete(m.routes, strings.TrimPrefix(path, "/zones/zone-1/workers/routes/"))
		return okEnvelope("null")

	// KV namespaces
	case method == http.MethodGet && strings.HasPrefix(path, "/accounts/account-1/storage/kv/namespaces"):
		out := make([]KVNamespace, 0, len(m.kvns))
		for _, ns := range m.kvns {
			out = append(out, ns)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return okEnvelope(mustJSON(out))
	case method == http.MethodPost && path == "/accounts/account-1/storage/kv/namespaces":
		var body struct {
			Title string `json:"title"`
		}
		unmarshalOr500(call.Body, &body)
		ns := KVNamespace{ID: m.id("kvn"), Title: body.Title}
		m.kvns[ns.ID] = ns
		return okEnvelope(mustJSON(ns))
	case method == http.MethodDelete && strings.HasPrefix(path, "/accounts/account-1/storage/kv/namespaces/"):
		delete(m.kvns, strings.TrimPrefix(path, "/accounts/account-1/storage/kv/namespaces/"))
		return okEnvelope("null")

	// KV values
	case (method == http.MethodPut || method == http.MethodGet || method == http.MethodDelete) &&
		strings.Contains(path, "/storage/kv/namespaces/") && strings.Contains(path, "/values/"):
		nsID := path[strings.Index(path, "/namespaces/")+len("/namespaces/") : strings.Index(path, "/values/")]
		key := path[strings.LastIndex(path, "/values/")+len("/values/"):]
		valueKey := nsID + "|" + key
		switch method {
		case http.MethodPut:
			m.kvValues[valueKey] = call.Body
			return okEnvelope("null")
		case http.MethodGet:
			if value, ok := m.kvValues[valueKey]; ok {
				return http.StatusOK, value, nil
			}
			return failEnvelope(http.StatusNotFound, 10004, "not found")
		default:
			if _, ok := m.kvValues[valueKey]; !ok {
				return failEnvelope(http.StatusNotFound, 10004, "not found")
			}
			delete(m.kvValues, valueKey)
			return okEnvelope("null")
		}

	// Zone settings and Total TLS
	case method == http.MethodGet && path == "/zones/zone-1/settings":
		out := make([]map[string]string, 0, len(m.settings))
		for id, value := range m.settings {
			out = append(out, map[string]string{"id": id, "value": value})
		}
		return okEnvelope(mustJSON(out))
	case method == http.MethodPatch && path == "/zones/zone-1/settings":
		var body struct {
			Items []settingItem `json:"items"`
		}
		unmarshalOr500(call.Body, &body)
		for _, item := range body.Items {
			m.settings[item.ID] = item.Value
		}
		return okEnvelope("null")
	case method == http.MethodGet && path == "/zones/zone-1/ssl/total_tls":
		return okEnvelope(mustJSON(m.totalTLS))
	case method == http.MethodPost && path == "/zones/zone-1/ssl/total_tls":
		unmarshalOr500(call.Body, &m.totalTLS)
		return okEnvelope(mustJSON(m.totalTLS))
	}
	return failEnvelope(http.StatusNotFound, 0, "mini cloudflare: unmatched "+call.String())
}

func phaseFromPath(path string) string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(path, "/zones/zone-1/rulesets/phases/"), "/entrypoint")
	return strings.SplitN(trimmed, "/", 2)[0]
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func unmarshalOr500(body string, out any) {
	if err := json.Unmarshal([]byte(body), out); err != nil {
		panic(fmt.Sprintf("mini cloudflare: malformed request body %q: %v", body, err))
	}
}

func miniClient(m *miniCF) *Client {
	c, _ := testClient(m.serve)
	return c
}

func driftEverywhere(m *miniCF) {
	m.dns["ns"] = DNSRecord{ID: "ns", Type: "NS", Name: "terrascale.tech", Content: "beth.ns.cloudflare.com"}
	m.dns["soa"] = DNSRecord{ID: "soa", Type: "SOA", Name: "terrascale.tech", Content: "..."}
	// app exists but DNS-only (someone flipped the cloud); it stays owned via
	// its tag, so the drift is repaired. api missing.
	m.dns["app"] = DNSRecord{ID: "app", Type: "A", Name: "app.terrascale.tech", Content: workerOrigin,
		Proxied: false, Tags: []string{DNSOwnershipTag}}
	// An untagged orphan: not ours to delete, so it is preserved with an
	// alert (D-67).
	m.dns["old"] = DNSRecord{ID: "old", Type: "A", Name: "legacy.terrascale.tech", Content: "203.0.113.99"}

	// One console-clicked cache rule, declared rule missing, tiered off.
	m.phases["http_request_cache_settings"] = []wireRule{
		{ID: "c-foreign", Expression: "true", Action: "set_cache_settings", Enabled: boolPtr(true)},
	}
	// /admin rule drifted to allow-all; rate rule missing.
	m.phases["http_request_firewall_custom"] = []wireRule{
		{ID: "f-1", Description: "terrascale:admin-tailscale-only",
			Expression: `((http.host eq "app.terrascale.tech" and starts_with(http.request.uri.path, "/admin")) and not ip.src in {0.0.0.0/0})`,
			Action:     "block", Enabled: boolPtr(true)},
	}

	// Gate snippet deployed with a stale rule expression.
	m.snippets[GateSnippetName] = []SnippetRuleWire{
		{Expression: `http.host eq "sync.api.terrascale.tech"`, Description: "terrascale:" + GateSnippetName, Enabled: true},
	}

	// api route on an old script name; app route missing; orphan present.
	m.routes["r-1"] = WorkerRoute{ID: "r-1", Pattern: "api.terrascale.tech/*", Script: "old-proxy"}
	m.routes["r-9"] = WorkerRoute{ID: "r-9", Pattern: "legacy.terrascale.tech/*", Script: "legacy"}

	// Health map exists; placement map missing; an orphan namespace lingers.
	m.kvns["k-1"] = KVNamespace{ID: "k-1", Title: RegionHealthNamespace}
	m.kvns["k-8"] = KVNamespace{ID: "k-8", Title: "old-maps"}

	m.settings = map[string]string{
		"brotli": "on", "ssl": "flexible", "min_tls_version": "1.0", "tls_1_3": "off", "always_use_https": "off",
	}
	m.totalTLS = TotalTLS{Enabled: false}
}

func boolPtr(b bool) *bool { return &b }

func TestFullZoneReconcilePass(t *testing.T) {
	m := newMiniCF()
	driftEverywhere(m)
	c := miniClient(m)
	z, err := Production(Members{
		"gru": {"198.51.100.10"},
		"sfo": {"203.0.113.10"},
		"fra": {"192.0.2.10"},
	}, []string{"100.64.0.0/10"})
	if err != nil {
		t.Fatalf("Production failed: %v", err)
	}

	plan, err := ReconcileZone(context.Background(), c, z)
	if err != nil {
		t.Fatalf("observe pass failed: %v", err)
	}
	counts := map[string]map[Action]int{}
	for _, ch := range plan.Changes {
		if counts[ch.Resource] == nil {
			counts[ch.Resource] = map[Action]int{}
		}
		counts[ch.Resource][ch.Action]++
	}
	wantCounts := map[string]map[Action]int{
		"dns-record":   {Create: 10, Update: 1, Alert: 1}, // app drifts (update); legacy is unowned (alert); apex/api/docs/status + 3 sync + 3 region creates
		"cache-rule":   {Create: 1, Alert: 1},
		"tiered-cache": {Update: 1},
		"snippet-rule": {Update: 1},
		"worker-route": {Create: 1, Update: 1, Delete: 1},
		"kv-namespace": {Create: 1, Delete: 1},
		"waf-rule":     {Update: 1},
		"rate-rule":    {Create: 1},
		"zone-setting": {Update: 4},
		"total-tls":    {Update: 1},
	}
	if !reflect.DeepEqual(counts, wantCounts) {
		t.Fatalf("plan counts = %v\nwant %v\nplan:\n%s", counts, wantCounts, plan)
	}
	if len(plan.Changes) != 28 {
		t.Fatalf("want 28 changes, got %d:\n%s", len(plan.Changes), plan)
	}

	if err := Apply(context.Background(), plan); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// The owned estate converged: a second pass plans nothing except the
	// two alerts for records this pass proved it does not own (D-67).
	again, err := ReconcileZone(context.Background(), c, z)
	if err != nil {
		t.Fatalf("second observe pass failed: %v", err)
	}
	if len(again.Changes) != 2 {
		t.Fatalf("zone should converge except the two unowned alerts:\n%s", again)
	}
	for _, ch := range again.Changes {
		if ch.Action != Alert {
			t.Fatalf("only alerts may remain, got %v:\n%s", ch.Action, again)
		}
	}
	alerts := summarize(again)
	want := []string{
		"alert dns-record preserving unowned DNS record A legacy.terrascale.tech -> 203.0.113.99",
		"alert cache-rule preserving unowned Cloudflare rule c-foreign",
	}
	if !reflect.DeepEqual(alerts, want) {
		t.Fatalf("remaining alerts = %v\nwant %v", alerts, want)
	}

	// Final DNS state is exactly the apex, D-24, the Cloudflare-managed
	// records, and the preserved unowned legacy record.
	names := map[string]int{}
	m.mu.Lock()
	for _, rec := range m.dns {
		names[rec.Name]++
	}
	kvTitles := map[string]bool{}
	for _, ns := range m.kvns {
		kvTitles[ns.Title] = true
	}
	rateRules := len(m.phases["http_ratelimit"])
	tiered := m.tiered
	m.mu.Unlock()
	for _, want := range []string{"", "api.", "sync.api.", "gru.api.", "sfo.api.", "fra.api.", "app.", "docs.", "status.", "legacy."} {
		if names[want+ZoneName] == 0 {
			t.Errorf("D-24 hostname %s missing after reconcile (dns=%v)", want+ZoneName, names)
		}
	}
	if len(names) != 10 { // the apex (A + NS + SOA) + 8 declared hostnames + preserved legacy
		t.Errorf("stray DNS names remain: %v", names)
	}
	if !kvTitles[DBPlacementNamespace] || kvTitles["old-maps"] {
		t.Errorf("kv namespaces wrong: %v", kvTitles)
	}
	if rateRules != 1 || tiered != "on" {
		t.Errorf("rate rules = %d, tiered = %q", rateRules, tiered)
	}
}

func TestRunDryRunPrintsWithoutTouching(t *testing.T) {
	m := newMiniCF()
	driftEverywhere(m)
	c := miniClient(m)
	z, err := Production(Members{"gru": {"198.51.100.10"}, "sfo": {"203.0.113.10"}, "fra": {"192.0.2.10"}}, []string{"100.64.0.0/10"})
	if err != nil {
		t.Fatalf("Production failed: %v", err)
	}
	var out strings.Builder
	if err := Run(context.Background(), c, z, true, &out); err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if !strings.Contains(out.String(), "zone terrascale.tech: 28 change(s)") {
		t.Fatalf("dry-run output wrong:\n%s", out.String())
	}
	m.mu.Lock()
	dnsCount := len(m.dns)
	m.mu.Unlock()
	if dnsCount != 4 { // NS + SOA + app + legacy, untouched
		t.Fatalf("dry run mutated the zone: %d records", dnsCount)
	}
}

func TestRunAppliesUntilConverged(t *testing.T) {
	m := newMiniCF()
	c := miniClient(m)
	z, err := Production(Members{"gru": {"198.51.100.10"}, "sfo": {"203.0.113.10"}, "fra": {"192.0.2.10"}}, []string{"100.64.0.0/10"})
	if err != nil {
		t.Fatalf("Production failed: %v", err)
	}
	var out strings.Builder
	if err := Run(context.Background(), c, z, false, &out); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	// Fresh zone: 11 DNS creates (apex, api, app, docs, status, 3 sync,
	// 3 region), 1 cache rule, tiered cache, 2 routes, 2 KV namespaces,
	// 1 WAF rule, 1 rate rule, 4 settings, total TLS, and one alert: the
	// gate snippet is not deployed yet.
	if !strings.Contains(out.String(), "zone terrascale.tech: 25 change(s)") {
		t.Fatalf("fresh zone should need 25 changes:\n%s", out.String())
	}
	again, err := ReconcileZone(context.Background(), c, z)
	if err != nil {
		t.Fatalf("second pass failed: %v", err)
	}
	// Everything converged except the one drift this package cannot repair:
	// the gate snippet's code arrives with a ts-proxy release (X-2).
	if len(again.Changes) != 1 || again.Changes[0].Action != Alert || again.Changes[0].Resource != "snippet-rule" {
		t.Fatalf("expected exactly the snippet alert to remain, got:\n%s", again)
	}
}
