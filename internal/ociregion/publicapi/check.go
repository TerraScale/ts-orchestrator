package publicapi

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
)

// field reads a nested member of a CLI-shaped OCI object.
func field(v any, path ...string) any {
	for _, key := range path {
		m, _ := v.(map[string]any)
		v = m[key]
	}
	return v
}

func same(v any, want any) bool { return fmt.Sprint(v) == fmt.Sprint(want) }

// CheckBalancer reports the first way a live, CLI-shaped load balancer
// differs from the configuration apply creates: bandwidth, hostname
// bindings, listeners and their client-certificate checks, and backend sets
// holding the planned backends: exactly every controller for ts-auth, and
// for terrabase and terrabase-primary exactly the seed, or, once the plan
// hands the sets to the controller, planned members only with at least one of
// them serving; and the routing policy sending Management to terrabase-primary.
func (d Desired) CheckBalancer(lb map[string]any) error {
	if err := d.OriginPull.Validate(); err != nil {
		return err
	}
	differs := func(what string, got any) error {
		return fmt.Errorf("load balancer %s %s differs from the plan: %v", d.Names.LB, what, got)
	}
	if lb["lifecycle-state"] != "ACTIVE" || lb["is-private"] != false || lb["shape-name"] != "flexible" ||
		!same(field(lb, "shape-details", "minimum-bandwidth-in-mbps"), d.MinMbps) || !same(field(lb, "shape-details", "maximum-bandwidth-in-mbps"), d.MaxMbps) {
		return differs("state or shape", []any{lb["lifecycle-state"], lb["is-private"], lb["shape-name"], lb["shape-details"]})
	}
	hostnames := map[string]string{}
	for _, h := range d.hosts() {
		hostnames[h.set] = h.name
	}
	live, _ := lb["hostnames"].(map[string]any)
	if !slices.Equal(slices.Sorted(maps.Keys(live)), slices.Sorted(maps.Keys(hostnames))) {
		return differs("hostnames", live)
	}
	for name, host := range hostnames {
		if field(live, name, "hostname") != host {
			return differs("hostname "+name, field(live, name, "hostname"))
		}
	}
	listeners, _ := lb["listeners"].(map[string]any)
	// Every HTTPS listener serves the first origin certificate or a rotation of it.
	served := servedCertificate(lb)
	if served != originCertificate && !strings.HasPrefix(served, originCertificate+"-") {
		return differs("origin certificate", served)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(listeners)), slices.Sorted(slices.Values(append(slices.Collect(maps.Keys(hostnames)), "http")))) {
		return differs("listeners", slices.Sorted(maps.Keys(listeners)))
	}
	for name, v := range listeners {
		l, _ := v.(map[string]any)
		ok := l["protocol"] == "HTTP"
		if name == "http" {
			ok = ok && same(l["port"], 80) && l["ssl-configuration"] == nil && same(l["rule-set-names"], []string{"https-redirect"}) &&
				l["default-backend-set-name"] == "terrabase" && (l["hostname-names"] == nil || same(l["hostname-names"], []string{})) &&
				l["path-route-set-name"] == nil && l["routing-policy-name"] == nil
		} else {
			routes := map[string]any{"terrabase": managementRoutes}[name]
			ok = ok && same(l["port"], 443) && l["default-backend-set-name"] == name && same(l["hostname-names"], []string{name}) &&
				same(l["rule-set-names"], []string{"security-headers"}) && l["path-route-set-name"] == nil && l["routing-policy-name"] == routes &&
				field(l, "ssl-configuration", "certificate-name") == served && field(l, "ssl-configuration", "verify-peer-certificate") == true &&
				same(field(l, "connection-configuration", "idle-timeout"), IdleTimeout)
		}
		if !ok {
			return differs("listener "+name, l)
		}
	}
	redirect := field(lb, "rule-sets", "https-redirect", "items")
	items, _ := redirect.([]any)
	if len(items) != 1 {
		return differs("https-redirect rule set", redirect)
	}
	rule := items[0]
	conditions, _ := field(rule, "conditions").([]any)
	uri := field(rule, "redirect-uri")
	if field(rule, "action") != "REDIRECT" || !same(field(rule, "response-code"), 301) || len(conditions) != 1 ||
		field(conditions[0], "attribute-name") != "PATH" || field(conditions[0], "attribute-value") != "/" || field(conditions[0], "operator") != "PREFIX_MATCH" ||
		field(uri, "protocol") != "HTTPS" || field(uri, "host") != "{host}" || !same(field(uri, "port"), 443) ||
		field(uri, "path") != "{path}" || field(uri, "query") != "{query}" {
		return differs("https-redirect rule set", redirect)
	}
	policies, _ := lb["routing-policies"].(map[string]any)
	policy := policies[managementRoutes]
	if len(policies) != 1 || field(policy, "condition-language-version") != "V1" || !sameRules(field(policy, "rules"), managementRules) {
		return differs("routing policies", policies)
	}
	sets, _ := lb["backend-sets"].(map[string]any)
	if !slices.Equal(slices.Sorted(maps.Keys(sets)), slices.Sorted(slices.Values(append(slices.Collect(maps.Keys(hostnames)), primarySet)))) {
		return differs("backend sets", slices.Sorted(maps.Keys(sets)))
	}
	terrabaseWant := d.TerraBase
	if d.controllerOwned() {
		terrabaseWant = d.Members
	}
	wants := map[string][]Backend{"terrabase": terrabaseWant, primarySet: terrabaseWant, "ts-auth": d.Auth}
	if d.OrchHost != "" {
		wants["ts-orch"] = d.Orch
	}
	for name, want := range wants {
		var expected []string
		for _, b := range want {
			expected = append(expected, b.Addr.String())
		}
		slices.Sort(expected)
		set := sets[name]
		port := want[0].Addr.Port()
		rows, err := command.Rows(field(set, "backends"))
		live := liveBackends(lb, name)
		path := HealthPath
		if name == "ts-orch" {
			path = OrchHealthPath
		}
		ok := err == nil && field(set, "health-checker", "protocol") == "HTTP" &&
			field(set, "health-checker", "url-path") == path && same(field(set, "health-checker", "port"), port) &&
			same(field(set, "health-checker", "return-code"), 200)
		owned := (name == "terrabase" || name == primarySet) && d.controllerOwned()
		if owned {
			// The controller owns these backends: any planned members,
			// drained during a release, with at least one serving.
			serving := false
			for _, b := range rows {
				serving = serving || b["drain"] == nil || b["drain"] == false
			}
			ok = ok && serving && !slices.ContainsFunc(live, func(addr string) bool { return !slices.Contains(expected, addr) })
		} else {
			ok = ok && slices.Equal(live, expected)
		}
		for _, b := range rows {
			// Creation leaves these optional flags at their false defaults;
			// only the controller drains a TerraBase seat.
			for _, flag := range []string{"offline", "drain", "backup"} {
				ok = ok && (b[flag] == nil || b[flag] == false || flag == "drain" && owned)
			}
		}
		if bundle := map[string]string{"terrabase": memberCA, primarySet: memberCA, "ts-orch": cellCA}[name]; bundle != "" {
			forcePlaintext := field(set, "health-checker", "is-force-plain-text")
			ok = ok && (forcePlaintext == nil || forcePlaintext == false) &&
				field(set, "ssl-configuration", "certificate-name") == bundle && field(set, "ssl-configuration", "verify-peer-certificate") == true
		} else {
			ok = ok && field(set, "ssl-configuration") == nil
		}
		if !ok {
			return differs("backend set "+name, set)
		}
	}
	bundles := []string{served, memberCA}
	if d.OrchHost != "" {
		bundles = append(bundles, cellCA)
	}
	for _, name := range bundles {
		if field(lb, "certificates", name) == nil {
			return differs("certificate "+name, "missing")
		}
	}
	if !sameCA(lb, served, d.OriginPull.CACertificate) {
		return differs("origin-pull CA", "missing or different from the reviewed customer CA")
	}
	publicCertificate, _ := field(lb, "certificates", served, "public-certificate").(string)
	if _, err := checkOriginCertificate(publicCertificate, d.hostNames(), time.Now()); err != nil {
		return fmt.Errorf("load balancer %s origin certificate: %w", d.Names.LB, err)
	}
	return nil
}

// sameRules reports whether CLI-shaped routing rules are exactly want.
func sameRules(live any, want []any) bool {
	rules, _ := live.([]any)
	if len(rules) != len(want) {
		return false
	}
	for i, rule := range rules {
		w := want[i].(map[string]any)
		actions, _ := field(rule, "actions").([]any)
		wantActions := w["actions"].([]any)
		if field(rule, "name") != w["name"] || field(rule, "condition") != w["condition"] || len(actions) != len(wantActions) {
			return false
		}
		for j, action := range actions {
			wa := wantActions[j].(map[string]any)
			if field(action, "name") != wa["name"] || field(action, "backend-set-name") != wa["backendSetName"] {
				return false
			}
		}
	}
	return true
}

// sameCA reports whether a load balancer bundle holds exactly pemCA.
func sameCA(lb map[string]any, name, pemCA string) bool {
	live, _ := field(lb, "certificates", name, "ca-certificate").(string)
	if validCA(live) != nil || validCA(pemCA) != nil {
		return false
	}
	a, _ := pem.Decode([]byte(live))
	b, _ := pem.Decode([]byte(pemCA))
	return a != nil && b != nil && bytes.Equal(a.Bytes, b.Bytes)
}

// CheckOriginRules reports whether NSG ingress rows admit exactly TCP 80 and
// 443 from each of Cloudflare's ranges, and nothing else.
func CheckOriginRules(rows []map[string]any, ranges []string) error {
	want := OriginRules(ranges)
	var have []Rule
	for _, row := range rows {
		r, ok := listed(row)
		if !ok || !slices.Contains(want, r) || slices.Contains(have, r) {
			return fmt.Errorf("load balancer NSG rule %v admits more than Cloudflare's ranges on 80 and 443", row["id"])
		}
		have = append(have, r)
	}
	if len(have) != len(want) {
		return fmt.Errorf("load balancer NSG admits %d of Cloudflare's %d range and port pairs; run public-api origin-ips --apply", len(have), len(want))
	}
	return nil
}
