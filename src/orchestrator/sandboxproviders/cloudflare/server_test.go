package cloudflare

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
)

func localClient(t *testing.T, s *Server) (*httptest.Server, *cf.Client) {
	t.Helper()
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	c := cf.NewClient("sandbox", s.cfg.ZoneID, s.cfg.AccountID)
	c.BaseURL = ts.URL
	return ts, c
}

func TestEndpointMatchesReconcilerContract(t *testing.T) {
	s := NewServer(Config{ZoneID: "zone-1", AccountID: "account-1", ZoneName: "terrascale.tech"})
	_, c := localClient(t, s)
	for i := 0; i < 3; i++ {
		if err := c.CreateDNSRecord(t.Context(), cf.DNSRecord{Type: "A", Name: "sync.api.terrascale.tech", Content: "192.0.2." + strconv.Itoa(i+1), TTL: 1, Proxied: true}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := c.ListDNSRecords(t.Context())
	if err != nil || len(got) != 3 {
		t.Fatalf("list = %d, %v", len(got), err)
	}
	// A regular HTTP caller can use the result ETag for optimistic writes.
	req, _ := http.NewRequest(http.MethodGet, "http://sandbox/zones/zone-1/dns_records?per_page=2&page=2", nil)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("page status = %d", rr.Code)
	}
	var pageBody struct {
		Result []dnsRecord `json:"result"`
		Info   struct {
			TotalPages int `json:"total_pages"`
		} `json:"result_info"`
	}
	if json.Unmarshal(rr.Body.Bytes(), &pageBody) != nil || len(pageBody.Result) != 1 || pageBody.Info.TotalPages != 2 {
		t.Fatalf("bad page response: %s", rr.Body)
	}

	// Idempotency replays the exact response and does not create a duplicate.
	body := []byte(`{"type":"A","name":"idempotent.terrascale.tech","content":"192.0.2.9","ttl":1,"proxied":true}`)
	first := doRequest(s, http.MethodPost, "/zones/zone-1/dns_records", body, map[string]string{"Idempotency-Key": "dns-1"})
	second := doRequest(s, http.MethodPost, "/zones/zone-1/dns_records", body, map[string]string{"Idempotency-Key": "dns-1"})
	if first.Code != second.Code || first.Body.String() != second.Body.String() {
		t.Fatalf("idempotent replay differs: %d/%d", first.Code, second.Code)
	}
	if got, _ = c.ListDNSRecords(t.Context()); len(got) != 4 {
		t.Fatalf("replay created duplicate: %d records", len(got))
	}
	conflict := doRequest(s, http.MethodPost, "/zones/zone-1/dns_records", []byte(`{"type":"A","name":"different.terrascale.tech"}`), map[string]string{"Idempotency-Key": "dns-1"})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("idempotency conflict = %d", conflict.Code)
	}
}

func TestEndpointRulesKVWorkersAndSecrets(t *testing.T) {
	s := NewServer(Config{ZoneID: "z", AccountID: "a"})
	ts, c := localClient(t, s)
	if err := c.SetSmartTieredCache(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if on, err := c.SmartTieredCache(t.Context()); err != nil || !on {
		t.Fatalf("tiered = %v, %v", on, err)
	}
	snippetSource := []byte("export default {fetch(request){return fetch(request)}}")
	snippetDigest := sha256.Sum256(snippetSource)
	if err := c.PutSnippetCode(t.Context(), "ts-gate", "sha256:"+hex.EncodeToString(snippetDigest[:]), snippetSource); err != nil {
		t.Fatal(err)
	}
	if err := c.PutSnippetRules(t.Context(), "ts-gate", []cf.SnippetRuleWire{{Expression: "true", Description: "terrascale:ts-gate", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutPhaseRules(t.Context(), "http_request_firewall_custom", []cf.Rule{{Ref: "admin", Expression: "true", Action: "block", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateWorkerRoute(t.Context(), cf.WorkerRoute{Pattern: "api.terrascale.tech/*", Script: "ts-proxy"}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateKVNamespace(t.Context(), "ts-region-health"); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateKVNamespace(t.Context(), "ts-db-placement"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetWorkerHealth(t.Context(), cf.WorkerHealthDoc{Updated: 1000, Regions: map[string]cf.WorkerRegionHealth{"GRU": {OK: true}}, Catalog: cf.PublicRegionCatalog()}); err != nil {
		t.Fatal(err)
	}
	h, err := c.WorkerHealth(t.Context())
	if err != nil || !h.Regions["GRU"].OK {
		t.Fatalf("health = %+v, %v", h, err)
	}

	// Worker versions and deployments acknowledge synchronously. There is no
	// Cloudflare /operations endpoint in these contracts.
	source := []byte("export default {fetch(){return new Response('test')}}")
	digest := sha256.Sum256(source)
	version, err := c.UploadWorkerVersion(t.Context(), "ts-proxy", "sha256:"+hex.EncodeToString(digest[:]), source)
	if err != nil || version.ID == "" {
		t.Fatalf("upload: %+v, %v", version, err)
	}
	if _, err := c.CreateWorkerDeployment(t.Context(), "ts-proxy", []cf.WorkerDeploymentVersion{{VersionID: version.ID, Percentage: 100}}); err != nil {
		t.Fatal(err)
	}

	if err := c.CreateSecretStore(t.Context(), "secret-test"); err != nil {
		t.Fatal(err)
	}
	stores, err := c.ListSecretStores(t.Context())
	if err != nil || len(stores) != 1 {
		t.Fatalf("stores=%v err=%v", stores, err)
	}
	metadata, err := c.CreateSecret(t.Context(), stores[0].ID, cf.SecretInput{Name: "capability-current", Value: "never-return-this", Scopes: []string{"workers"}})
	if err != nil || metadata.ID == "" || metadata.Name != "capability-current" {
		t.Fatalf("secret create=%+v err=%v", metadata, err)
	}
	replacement := "replacement-private-material"
	if _, err := c.UpdateSecret(t.Context(), stores[0].ID, metadata.ID, cf.SecretUpdate{Value: &replacement}); err != nil {
		t.Fatal(err)
	}
	secrets, err := c.ListSecretMetadata(t.Context(), stores[0].ID)
	if err != nil || len(secrets) != 1 {
		t.Fatalf("secrets=%+v err=%v", secrets, err)
	}
	for _, legacy := range []string{"/secrets/capability-current", "/secrets/capability-current/versions", "/secrets/capability-current/versions/1/activate"} {
		response := doRequest(s, http.MethodPost, "/accounts/a/secrets_store/stores/"+stores[0].ID+legacy, []byte(`{"value_base64":"ignored"}`), nil)
		if response.Code < 400 {
			t.Fatal("legacy fake endpoint remains supported")
		}
	}
	if err := c.DeleteSecret(t.Context(), stores[0].ID, metadata.ID); err != nil {
		t.Fatal(err)
	}
	secrets, err = c.ListSecretMetadata(t.Context(), stores[0].ID)
	if err != nil || len(secrets) != 0 {
		t.Fatalf("secret delete=%+v err=%v", secrets, err)
	}

	_ = ts
}

func TestEndpointFaultScriptIndeterminateAndConcurrent(t *testing.T) {
	s := NewServer(Config{ZoneID: "z", AccountID: "a", Faults: []Fault{{Method: http.MethodPost, Path: "/zones/z/dns_records", Steps: []FaultStep{{Status: http.StatusGatewayTimeout, Message: "response lost", Commit: true}}}}})
	body := []byte(`{"type":"A","name":"fault.terrascale.tech","content":"192.0.2.10","ttl":1,"proxied":true}`)
	if got := doRequest(s, http.MethodPost, "/zones/z/dns_records", body, nil); got.Code != http.StatusGatewayTimeout {
		t.Fatalf("fault status = %d", got.Code)
	}
	// The mutation committed despite the lost response; a subsequent observe
	// sees one resource and does not need a blind duplicate create.
	list := doRequest(s, http.MethodGet, "/zones/z/dns_records?per_page=100", nil, nil)
	if !strings.Contains(list.Body.String(), "fault.terrascale.tech") {
		t.Fatalf("committed state missing: %s", list.Body)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = doRequest(s, http.MethodPost, "/zones/z/dns_records", []byte(`{"type":"A","name":"parallel-`+strconv.Itoa(i)+`.terrascale.tech","content":"192.0.2.11","ttl":1,"proxied":true}`), nil)
		}(i)
	}
	wg.Wait()
}

func doRequest(s *Server, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://sandbox"+path, bytes.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, r)
	return rr
}
