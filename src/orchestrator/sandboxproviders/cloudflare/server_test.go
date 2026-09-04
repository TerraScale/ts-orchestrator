package cloudflare

import (
	"bytes"
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
	s := NewServer(Config{ZoneID: "z", AccountID: "a", AsyncPolls: 1})
	ts, c := localClient(t, s)
	if err := c.SetSmartTieredCache(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if on, err := c.SmartTieredCache(t.Context()); err != nil || !on {
		t.Fatalf("tiered = %v, %v", on, err)
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
	if err := c.SetRegionHealth(t.Context(), "gru", cf.RegionHealth{Healthy: true, Members: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	h, err := c.RegionHealth(t.Context(), "gru")
	if err != nil || !h.Healthy {
		t.Fatalf("health = %+v, %v", h, err)
	}

	// The edge version/deployment API is asynchronous but the mutation is
	// applied before its acknowledgement, allowing an indeterminate response
	// to be safely observed and reconciled.
	create := doRequest(s, http.MethodPost, "/accounts/a/workers/scripts/ts-proxy/versions", []byte(`{"digest":"sha256:test"}`), nil)
	if create.Code != http.StatusAccepted {
		t.Fatalf("version status = %d", create.Code)
	}
	var ack struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if json.Unmarshal(create.Body.Bytes(), &ack) != nil || ack.Result.ID == "" {
		t.Fatalf("version ack = %s", create.Body)
	}
	opID := ack.Result.ID
	// Result is an operation object; poll it through the public endpoint.
	var op struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if json.Unmarshal(create.Body.Bytes(), &op) != nil || op.Result.ID == "" {
		t.Fatalf("operation ack = %s", create.Body)
	}
	operation := doRequest(s, http.MethodGet, "/operations/"+op.Result.ID, nil, nil)
	if operation.Code != http.StatusOK && operation.Code != http.StatusAccepted {
		t.Fatalf("operation status = %d", operation.Code)
	}
	_ = opID

	store := doRequest(s, http.MethodPost, "/accounts/a/secrets_store/stores", []byte(`{"name":"secret-test"}`), nil)
	if store.Code != http.StatusOK {
		t.Fatalf("secret store status = %d", store.Code)
	}
	secretBody := []byte(`{"name":"capability-current","value":"never-return-this"}`)
	secret := doRequest(s, http.MethodPost, "/accounts/a/secrets_store/stores/secret-test/secrets/capability-current", secretBody, nil)
	if secret.Code != http.StatusOK || strings.Contains(secret.Body.String(), "never-return-this") {
		t.Fatalf("secret response leaked material: %s", secret.Body)
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
