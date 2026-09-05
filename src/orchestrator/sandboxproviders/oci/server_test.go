package oci

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestServerComputeAsyncIdempotentAndPaginated(t *testing.T) {
	s := NewServer(Config{MaxResources: 20, WorkRequestPolls: 2})
	h := httptest.NewServer(s)
	defer h.Close()
	create := func(name string) (map[string]any, string) {
		t.Helper()
		body := []byte(`{"compartmentId":"ocid1.compartment.oc1.local.tenant","displayName":"` + name + `","shape":"VM.Standard.A1.Flex","availabilityDomain":"AD-1","freeformTags":{"terrascale-managed":"true"}}`)
		req, _ := http.NewRequest(http.MethodPost, h.URL+"/20160918/instances", bytes.NewReader(body))
		req.Header.Set("opc-retry-token", "launch/"+name)
		resp, err := h.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("create status %d", resp.StatusCode)
		}
		var got map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got, resp.Header.Get("opc-work-request-id")
	}
	one, work := create("one")
	if work == "" || one["lifecycleState"] != "CREATING" {
		t.Fatalf("create = %#v work=%q", one, work)
	}
	// The exact same token and body replays the same resource and does not
	// consume another capacity slot.
	two, _ := create("one")
	if two["id"] != one["id"] || s.ResourceCount() != 1 {
		t.Fatalf("replay = %#v count=%d", two, s.ResourceCount())
	}
	resp, err := h.Client().Get(h.URL + "/20160918/workRequests/" + work)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = h.Client().Get(h.URL + "/20160918/workRequests/" + work)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = h.Client().Get(h.URL + "/20160918/instances/" + one["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var active map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&active)
	if active["lifecycleState"] != "RUNNING" {
		t.Fatalf("work completion did not activate instance: %#v", active)
	}
	// A small page emits the OCI continuation header.
	create("two")
	resp, err = h.Client().Get(h.URL + "/20160918/instances?limit=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("opc-next-page") == "" {
		t.Fatal("missing continuation token")
	}
	var page []any
	_ = json.NewDecoder(resp.Body).Decode(&page)
	if len(page) != 1 {
		t.Fatalf("page = %#v", page)
	}
	bad, _ := http.NewRequest(http.MethodPost, h.URL+"/20160918/instances", bytes.NewReader([]byte(`{"compartmentId":"ocid1.compartment.oc1.local.tenant","displayName":"different"}`)))
	bad.Header.Set("opc-retry-token", "launch/one")
	badResp, err := h.Client().Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusConflict {
		t.Fatalf("idempotency conflict status %d", badResp.StatusCode)
	}
}

func TestServerObjectETagDigestAndLifecycle(t *testing.T) {
	s := New(Config{Namespace: "ns"})
	h := httptest.NewServer(s)
	defer h.Close()
	bucketResp, err := h.Client().Post(h.URL+"/n/ns/b/", "application/json", bytes.NewBufferString(`{"name":"bucket"}`))
	if err != nil {
		t.Fatal(err)
	}
	bucketResp.Body.Close()
	content := []byte("hello")
	// Ask the endpoint to validate its own digest metadata by first using a
	// deliberately wrong digest, then a correct value from the response model.
	req, _ := http.NewRequest(http.MethodPut, h.URL+"/n/ns/b/bucket/o/key", bytes.NewReader(content))
	req.Header.Set("opc-meta-terrascale-sha256", "bad")
	resp, err := h.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong digest status %d", resp.StatusCode)
	}
	// The server accepts an omitted metadata header and returns canonical ETag
	// and digest headers for callers that compute it themselves.
	req, _ = http.NewRequest(http.MethodPut, h.URL+"/n/ns/b/bucket/o/key", bytes.NewReader(content))
	resp, err = h.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("etag")
	resp.Body.Close()
	if etag == "" || resp.Header.Get("opc-meta-terrascale-sha256") == "" {
		t.Fatal("missing object validators")
	}
	req, _ = http.NewRequest(http.MethodHead, h.URL+"/n/ns/b/bucket/o/key", nil)
	resp, err = h.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("etag") != etag || resp.ContentLength != int64(len(content)) {
		t.Fatalf("head validators: etag=%q len=%d", resp.Header.Get("etag"), resp.ContentLength)
	}
	resp.Body.Close()
	deleteReq, _ := http.NewRequest(http.MethodDelete, h.URL+"/n/ns/b/bucket/o/key", nil)
	deleteReq.Header.Set("If-Match", `"wrong"`)
	resp, err = h.Client().Do(deleteReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("etag fence status %d", resp.StatusCode)
	}
	// lifecycle policy is persisted and read through the OCI object-storage path.
	policy := []byte(`{"items":[{"name":"archive","action":"ARCHIVE","timeAmount":30,"timeUnit":"DAYS","isEnabled":true}]}`)
	req, _ = http.NewRequest(http.MethodPut, h.URL+"/n/ns/b/bucket/lifecyclePolicy", bytes.NewReader(policy))
	resp, err = h.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = h.Client().Get(h.URL + "/n/ns/b/bucket/lifecyclePolicy")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lifecycle status %d", resp.StatusCode)
	}
}

func TestServerFaultScriptAndConcurrentAccess(t *testing.T) {
	s := NewServer(Config{})
	h := httptest.NewServer(s)
	defer h.Close()
	s.SetFaultScript([]FaultRule{{Method: http.MethodGet, Path: "/20160918/availabilityDomains", Kind: FaultResponse, Status: http.StatusTooManyRequests, Code: "TooManyRequests"}, {Method: http.MethodGet, Path: "/20160918/availabilityDomains", Kind: FaultResponse, Status: http.StatusBadGateway, Count: 2}})
	for i, want := range []int{429, 502, 502, 200} {
		resp, err := h.Client().Get(h.URL + "/20160918/availabilityDomains")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("fault %d status=%d want=%d", i, resp.StatusCode, want)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := []byte(`{"compartmentId":"ocid1.compartment.oc1.local.c","displayName":"v` + strconv.Itoa(i) + `","sizeInGBs":50,"vpusPerGB":10}`)
			resp, err := h.Client().Post(h.URL+"/20160918/volumes", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Errorf("post: %v", err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}
	wg.Wait()
	if s.ResourceCount() != 32 {
		t.Fatalf("concurrent resource count=%d", s.ResourceCount())
	}
}

func TestIndeterminateMutationIsAppliedBeforeResponseLoss(t *testing.T) {
	s := NewServer(Config{})
	h := httptest.NewServer(s)
	defer h.Close()
	s.SetFaultScript([]FaultRule{{Method: http.MethodPost, Path: "/20160918/volumes", Kind: FaultIndeterminate}})
	body := bytes.NewBufferString(`{"compartmentId":"ocid1.compartment.oc1.local.c","displayName":"uncertain","sizeInGBs":50,"vpusPerGB":10}`)
	resp, err := h.Client().Post(h.URL+"/20160918/volumes", "application/json", body)
	if err == nil {
		resp.Body.Close()
	}
	// The client should observe a lost response, but a subsequent observation
	// must find the accepted resource for safe reconciliation.
	resp, err = h.Client().Get(h.URL + "/20160918/volumes?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status %d", resp.StatusCode)
	}
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("accepted resources = %d", len(list))
	}
}

func TestServerNetworkAndVaultShapes(t *testing.T) {
	s := NewServer(Config{Region: "gru"})
	h := httptest.NewServer(s)
	defer h.Close()
	post := func(path, body string) map[string]any {
		t.Helper()
		resp, err := h.Client().Post(h.URL+path, "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			t.Fatalf("POST %s status %d", path, resp.StatusCode)
		}
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	comp := "ocid1.compartment.oc1.local.c"
	vcn := post("/20160918/vcns", `{"compartmentId":"`+comp+`","displayName":"terrascale-gru","cidrBlock":"10.0.0.0/16"}`)
	if vcn["lifecycleState"] != "CREATING" || !strings.HasPrefix(vcn["id"].(string), "ocid1.vcn.") {
		t.Fatalf("vcn shape %#v", vcn)
	}
	subnet := post("/20160918/subnets", `{"compartmentId":"`+comp+`","vcnId":"`+vcn["id"].(string)+`","displayName":"private","cidrBlock":"10.0.1.0/24"}`)
	if subnet["vcnId"] != vcn["id"] {
		t.Fatalf("subnet shape %#v", subnet)
	}
	nsg := post("/20160918/networkSecurityGroups", `{"compartmentId":"`+comp+`","vcnId":"`+vcn["id"].(string)+`","displayName":"members"}`)
	rules := `{"securityRules":[{"direction":"INGRESS","protocol":"6","source":"10.0.0.0/16","tcpOptions":{"destinationPortRange":{"min":443,"max":443}}}]}`
	post("/20160918/networkSecurityGroups/"+nsg["id"].(string)+"/securityRules", rules)
	resp, err := h.Client().Get(h.URL + "/20160918/networkSecurityGroups/" + nsg["id"].(string) + "/securityRules")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listed []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("rules %#v", listed)
	}
	vault := post("/20180608/vaults", `{"compartmentId":"`+comp+`","displayName":"terrascale-gru-vault","vaultType":"DEFAULT"}`)
	if vault["vaultType"] != "DEFAULT" || vault["managementEndpoint"] == nil {
		t.Fatalf("vault shape %#v", vault)
	}
	key := post("/20180608/keys", `{"compartmentId":"`+comp+`","displayName":"region-kek","vaultId":"`+vault["id"].(string)+`"}`)
	if !strings.HasPrefix(key["id"].(string), "ocid1.key.") || key["lifecycleState"] != "CREATING" {
		t.Fatalf("key shape %#v", key)
	}
}
