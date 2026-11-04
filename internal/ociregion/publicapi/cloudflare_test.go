package publicapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeRuleset struct {
	ID    string
	Rules []configRule
}

// fakeCloudflare serves the Cloudflare API calls the edge makes and records
// every write.
type fakeCloudflare struct {
	t                 *testing.T
	ranges            []string
	ruleset           *fakeRuleset
	aop               bool
	certificates      []originPullCertificate
	hostnameOverrides map[string]any
	aopErrorPath      string
	aopErrorStatus    int
	staleAOP          bool
	staleRulePosition bool
	afterWrite        func(*http.Request)
	records           map[string][]record
	writes            []string
	validity          time.Duration
	issued            int
	fail              bool
}

func newFakeCloudflare(t *testing.T) (*fakeCloudflare, Cloudflare) {
	f := &fakeCloudflare{t: t, ranges: []string{"173.245.48.0/20", "103.21.244.0/22"}, records: map[string][]record{},
		validity: originValidityDays * 24 * time.Hour}
	f.certificates = []originPullCertificate{{ID: testOriginPull(t).CertificateID, Certificate: originPullFixture(t, "origin-pull-test-client.pem"), Status: "active"}}
	f.hostnameOverrides = map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return f, Cloudflare{BaseURL: server.URL, Token: "token", HTTP: server.Client()}
}

func (f *fakeCloudflare) reply(w http.ResponseWriter, status int, result any) {
	w.WriteHeader(status)
	if err := json.MarshalWrite(w, map[string]any{"success": status < 300, "errors": []any{}, "result": result}); err != nil {
		f.t.Error(err)
	}
}

func (f *fakeCloudflare) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ips" && r.Header.Get("Authorization") != "Bearer token" {
		f.reply(w, http.StatusForbidden, nil)
		return
	}
	if f.fail {
		f.reply(w, http.StatusForbidden, nil)
		return
	}
	if r.URL.Path == f.aopErrorPath {
		f.reply(w, f.aopErrorStatus, nil)
		return
	}
	body, _ := io.ReadAll(r.Body)
	if r.Method != http.MethodGet {
		f.writes = append(f.writes, r.Method+" "+r.URL.Path)
		defer func() {
			if f.afterWrite != nil {
				f.afterWrite(r)
			}
		}()
	}
	decode := func(v any) {
		if err := json.Unmarshal(body, v); err != nil {
			f.t.Fatalf("%s %s: %v", r.Method, r.URL.Path, err)
		}
	}
	entry := "/zones/zone/rulesets/phases/http_config_settings/entrypoint"
	switch path := r.URL.Path; {
	case path == "/ips":
		f.reply(w, 200, map[string]any{"ipv4_cidrs": f.ranges, "ipv6_cidrs": []string{"2400:cb00::/32"}})
	case path == "/zones" && r.URL.Query().Get("name") == Zone:
		f.reply(w, 200, []any{map[string]string{"id": "zone", "name": Zone}})
	case path == entry && r.Method == http.MethodGet:
		if f.ruleset == nil {
			f.reply(w, http.StatusNotFound, nil)
			return
		}
		f.reply(w, 200, map[string]any{"id": f.ruleset.ID, "rules": f.ruleset.Rules})
	case path == entry && r.Method == http.MethodPut:
		var rs struct {
			Rules []configRule `json:"rules"`
		}
		decode(&rs)
		f.ruleset = &fakeRuleset{"rs", rs.Rules}
		f.reply(w, 200, nil)
	case path == "/zones/zone/rulesets/rs/rules" && r.Method == http.MethodPost:
		var rule configRule
		decode(&rule)
		rule.ID = fmt.Sprintf("rule-%d", len(f.ruleset.Rules))
		f.ruleset.Rules = append(f.ruleset.Rules, rule)
		f.reply(w, 200, nil)
	case strings.HasPrefix(path, "/zones/zone/rulesets/rs/rules/") && r.Method == http.MethodPatch:
		var rule configRule
		decode(&rule)
		var placement struct {
			Position map[string]string `json:"position"`
		}
		decode(&placement)
		i := slices.IndexFunc(f.ruleset.Rules, func(x configRule) bool { return "/zones/zone/rulesets/rs/rules/"+x.ID == path })
		rule.ID = f.ruleset.Rules[i].ID
		f.ruleset.Rules[i] = rule
		if placement.Position != nil {
			if len(placement.Position) != 1 || placement.Position["after"] != "" {
				f.t.Fatalf("unsupported rule position: %s", body)
			}
			if !f.staleRulePosition {
				f.ruleset.Rules = append(slices.Delete(f.ruleset.Rules, i, i+1), rule)
			}
		}
		f.reply(w, 200, nil)
	case path == "/zones/zone/origin_tls_client_auth" && r.Method == http.MethodGet:
		f.reply(w, 200, f.certificates)
	case strings.HasPrefix(path, "/zones/zone/origin_tls_client_auth/hostnames/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(path, "/zones/zone/origin_tls_client_auth/hostnames/")
		association, ok := f.hostnameOverrides[name]
		if !ok {
			// Cloudflare's answer for a hostname without an association.
			w.WriteHeader(http.StatusNotFound)
			if err := json.MarshalWrite(w, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1553,
				"message": "Auth origin pull setting for this hostname not found."}}, "result": nil}); err != nil {
				f.t.Error(err)
			}
			return
		}
		f.reply(w, 200, association)
	case path == "/zones/zone/origin_tls_client_auth/settings" && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		if r.Method == http.MethodPut {
			var settings map[string]bool
			decode(&settings)
			if len(settings) != 1 || !settings["enabled"] {
				f.t.Fatalf("unsupported custom AOP settings body: %s", body)
			}
			if !f.staleAOP {
				f.aop = true
			}
		}
		f.reply(w, 200, map[string]bool{"enabled": f.aop})
	case path == "/zones/zone/dns_records" && r.Method == http.MethodGet:
		f.reply(w, 200, f.records[r.URL.Query().Get("name")])
	case strings.HasPrefix(path, "/zones/zone/dns_records/") && r.Method == http.MethodDelete:
		for name, records := range f.records {
			if records[0].ID == strings.TrimPrefix(path, "/zones/zone/dns_records/") {
				delete(f.records, name)
			}
		}
		f.reply(w, 200, map[string]string{"id": strings.TrimPrefix(path, "/zones/zone/dns_records/")})
	case strings.HasPrefix(path, "/zones/zone/dns_records"):
		var rec record
		decode(&rec)
		rec.ID = strings.TrimPrefix(strings.TrimPrefix(path, "/zones/zone/dns_records"), "/")
		if rec.ID == "" {
			rec.ID = "id-" + rec.Name
		}
		f.records[rec.Name] = []record{rec}
		f.reply(w, 200, rec)
	case path == "/certificates" && r.Method == http.MethodPost:
		var request struct {
			Hostnames []string `json:"hostnames"`
			Validity  int      `json:"requested_validity"`
			Type      string   `json:"request_type"`
			CSR       string   `json:"csr"`
		}
		decode(&request)
		f.issued++
		f.reply(w, 200, map[string]string{"id": "origin-1", "certificate": f.sign(request.CSR, request.Hostnames, request.Validity, request.Type)})
	default:
		f.t.Errorf("unexpected Cloudflare call %s %s", r.Method, r.URL)
		f.reply(w, http.StatusNotFound, nil)
	}
}

// sign plays the Origin CA: it certifies the request's key for hostnames.
func (f *fakeCloudflare) sign(csrPEM string, hostnames []string, days int, kind string) string {
	block, _ := pem.Decode([]byte(csrPEM))
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil || kind != "origin-rsa" || days != originValidityDays || !slices.Equal(request.DNSNames, hostnames) {
		f.t.Fatalf("bad origin request: %v %s %d %v", err, kind, days, request.DNSNames)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Origin CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: now, NotAfter: now.Add(f.validity), KeyUsage: x509.KeyUsageCertSign}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hostnames[0]}, DNSNames: hostnames,
		NotBefore: now, NotAfter: now.Add(f.validity)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, request.PublicKey, caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	issued := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if f.issued%2 == 1 {
		// Cloudflare may omit the final newline; the bundle must still split.
		issued = strings.TrimSuffix(issued, "\n")
	}
	return issued
}

func TestEdgeStepsSetStrictTLSAndOriginPullsBeforeProxiedRecords(t *testing.T) {
	f, cloudflare := newFakeCloudflare(t)
	names := []string{"gru.api.terrascale.tech", "gru.auth.terrascale.tech"}
	address := netip.MustParseAddr("203.0.113.10")
	var out bytes.Buffer
	steps, err := cloudflare.edgeSteps(t.Context(), names, address, "gru-1", testOriginPull(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), steps, false, &out); err != nil || len(f.writes) != 0 {
		t.Fatalf("dry run wrote %v: %v", f.writes, err)
	}
	want := `plan: set SSL Full (strict) for gru.api.terrascale.tech, gru.auth.terrascale.tech (configuration rule ts-orch-gru-1-api-ssl-strict)
plan: enable custom zone Authenticated Origin Pulls
plan: create A gru.api.terrascale.tech 203.0.113.10 (proxied)
plan: create A gru.auth.terrascale.tech 203.0.113.10 (proxied)
4 changes planned; rerun with --apply to apply them
`
	if out.String() != want {
		t.Fatalf("dry run:\n%s\nwant:\n%s", out.String(), want)
	}
	if err := run(t.Context(), steps, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.writes, []string{"PUT /zones/zone/rulesets/phases/http_config_settings/entrypoint", "PUT /zones/zone/origin_tls_client_auth/settings",
		"POST /zones/zone/dns_records", "POST /zones/zone/dns_records"}) {
		t.Fatalf("writes=%v", f.writes)
	}
	rule := f.ruleset.Rules[0]
	if rule.Action != "set_config" || rule.Parameters["ssl"] != "strict" || rule.Expression != `(http.host in {"gru.api.terrascale.tech" "gru.auth.terrascale.tech"})` || !f.aop {
		t.Fatalf("rule=%+v aop=%t", rule, f.aop)
	}
	for _, name := range names {
		if r := f.records[name][0]; r.Type != "A" || r.Content != "203.0.113.10" || !r.Proxied || r.TTL != 1 {
			t.Fatalf("record %+v", r)
		}
	}
	if steps, err := cloudflare.edgeSteps(t.Context(), names, address, "gru-1", testOriginPull(t)); err != nil || len(steps) != 0 {
		t.Fatalf("rerun planned %d steps: %v", len(steps), err)
	}
}

// Every cell's strict rule shares the zone's configuration ruleset; a later
// cell's rule, which only sets Full (strict), does not displace an earlier one.
