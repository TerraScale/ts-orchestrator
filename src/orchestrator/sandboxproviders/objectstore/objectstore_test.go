package objectstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEndpointObjectContract(t *testing.T) {
	root := t.TempDir()
	store, err := New(Config{Root: root, Namespace: "ns", CompartmentID: "comp", MaxBytes: 32, MaxObjectBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ts := httptest.NewServer(store)
	defer ts.Close()
	client := ts.Client()

	resp := mustRequest(t, client, http.MethodGet, ts.URL+"/n", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("namespace status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = mustRequest(t, client, http.MethodPost, ts.URL+"/n/ns/b/", strings.NewReader(`{"name":"backups","compartmentId":"comp","versioning":"Enabled"}`), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = mustRequest(t, client, http.MethodGet, ts.URL+"/n/ns/b/?limit=1", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	body := []byte("0123456789")
	digest := sha256.Sum256(body)
	headers := http.Header{"If-None-Match": []string{"*"}, "opc-meta-terrascale-sha256": []string{hex.EncodeToString(digest[:])}}
	resp = mustRequest(t, client, http.MethodPut, ts.URL+"/n/ns/b/backups/o/a%2Fb", strings.NewReader(string(body)), headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put status = %d", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("put did not return ETag")
	}
	resp.Body.Close()
	resp = mustRequest(t, client, http.MethodPut, ts.URL+"/n/ns/b/backups/o/a%2Fb", strings.NewReader("again"), http.Header{"If-None-Match": []string{"*"}})
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("duplicate put status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = mustRequest(t, client, http.MethodGet, ts.URL+"/n/ns/b/backups/o/a%2Fb", nil, http.Header{"Range": []string{"bytes=2-5"}})
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || string(got) != "2345" {
		t.Fatalf("range = %d %q", resp.StatusCode, got)
	}
	resp = mustRequest(t, client, http.MethodDelete, ts.URL+"/n/ns/b/backups/o/a%2Fb", nil, http.Header{"If-Match": []string{etag}})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	if _, err := os.Stat(filepath.Join(root, "b")); err != nil {
		t.Fatalf("store root was not persisted: %v", err)
	}
}

func TestVersioningMultipartAndPersistence(t *testing.T) {
	root := t.TempDir()
	store, err := New(Config{Root: root, Namespace: "ns", MaxBytes: 128, MaxObjectBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(store)
	client := ts.Client()
	post := mustRequest(t, client, http.MethodPost, ts.URL+"/n/ns/b/", strings.NewReader(`{"name":"b","versioning":"Enabled"}`), nil)
	post.Body.Close()
	init := mustRequest(t, client, http.MethodPost, ts.URL+"/n/ns/b/b/u/multipart", nil, nil)
	var initBody struct {
		UploadID string `json:"uploadId"`
	}
	if init.StatusCode != http.StatusOK {
		t.Fatalf("multipart initiate status = %d", init.StatusCode)
	}
	_ = json.NewDecoder(init.Body).Decode(&initBody)
	init.Body.Close()
	if initBody.UploadID == "" {
		t.Fatal("multipart upload ID is empty")
	}
	part := func(number int, value string) string {
		target := ts.URL + "/n/ns/b/b/u/multipart?uploadId=" + url.QueryEscape(initBody.UploadID) + "&partNum=" + strconv.Itoa(number)
		r := mustRequest(t, client, http.MethodPut, target, strings.NewReader(value), nil)
		etag := r.Header.Get("ETag")
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("part status = %d", r.StatusCode)
		}
		return etag
	}
	p1, p2 := part(1, "one"), part(2, "two")
	manifest := `{"partsToCommit":[{"partNum":1,"etag":` + strconv.Quote(p1) + `},{"partNum":2,"etag":` + strconv.Quote(p2) + `}]}`
	commit := mustRequest(t, client, http.MethodPost, ts.URL+"/n/ns/b/b/u/multipart?uploadId="+url.QueryEscape(initBody.UploadID), strings.NewReader(manifest), nil)
	if commit.StatusCode != http.StatusOK {
		t.Fatalf("multipart commit status = %d", commit.StatusCode)
	}
	commit.Body.Close()
	put := func(value string) string {
		r := mustRequest(t, client, http.MethodPut, ts.URL+"/n/ns/b/b/o/x", strings.NewReader(value), nil)
		id := r.Header.Get("opc-version-id")
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("put status = %d", r.StatusCode)
		}
		return id
	}
	v1, v2 := put("one"), put("two")
	if v1 == v2 || v1 == "" {
		t.Fatalf("version IDs = %q, %q", v1, v2)
	}
	r := mustRequest(t, client, http.MethodGet, ts.URL+"/n/ns/b/b/o/x?versionId="+v1, nil, nil)
	old, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(old) != "one" {
		t.Fatalf("version read = %q", old)
	}
	// A fresh process can reconstruct bucket and object metadata from the root.
	store.Close()
	store, err = New(Config{Root: root, Namespace: "ns", MaxBytes: 128, MaxObjectBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	ts.Close()
	ts = httptest.NewServer(store)
	defer ts.Close()
	r = mustRequest(t, ts.Client(), http.MethodGet, ts.URL+"/n/ns/b/b/o/x", nil, nil)
	current, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(current) != "two" {
		t.Fatalf("persisted read = %q", current)
	}
}

func TestEventualConsistencyFaultAndBounds(t *testing.T) {
	now := time.Unix(100, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	store, err := New(Config{Namespace: "ns", MaxBytes: 4, MaxObjectBytes: 4, Faults: FaultPlan{EventualConsistency: time.Minute}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ts := httptest.NewServer(store)
	defer ts.Close()
	c := ts.Client()
	r := mustRequest(t, c, http.MethodPost, ts.URL+"/n/ns/b/", strings.NewReader(`{"name":"b"}`), nil)
	r.Body.Close()
	r = mustRequest(t, c, http.MethodPut, ts.URL+"/n/ns/b/b/o/x", strings.NewReader("data"), nil)
	r.Body.Close()
	r = mustRequest(t, c, http.MethodGet, ts.URL+"/n/ns/b/b/o/x", nil, nil)
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("eventual read status = %d", r.StatusCode)
	}
	r.Body.Close()
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	r = mustRequest(t, c, http.MethodGet, ts.URL+"/n/ns/b/b/o/x", nil, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("visible read status = %d", r.StatusCode)
	}
	store.SetFaultPlan(FaultPlan{Sequence: []Outcome{OutcomeTimeout}})
	r = mustRequest(t, c, http.MethodPut, ts.URL+"/n/ns/b/b/o/y", strings.NewReader("x"), nil)
	r.Body.Close()
	if r.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("timeout status = %d", r.StatusCode)
	}
	r = mustRequest(t, c, http.MethodPut, ts.URL+"/n/ns/b/b/o/z", strings.NewReader("12345"), nil)
	r.Body.Close()
	if r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("bound status = %d", r.StatusCode)
	}
}

func mustRequest(t *testing.T, client *http.Client, method, target string, body io.Reader, headers http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
