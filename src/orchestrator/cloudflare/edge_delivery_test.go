package cloudflare_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	sandboxcf "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/cloudflare"
)

type edgeArtifactMap map[string][]byte

func (m edgeArtifactMap) EdgeArtifact(_ context.Context, service, digest string) ([]byte, error) {
	body, ok := m[service+"\x00"+digest]
	if !ok {
		return nil, errors.New("artifact not found")
	}
	return append([]byte(nil), body...), nil
}

func testEdgeDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestEdgeReleasePromoterUsesProviderVersionsDeploymentsAndSnippetRules(t *testing.T) {
	provider := sandboxcf.New(sandboxcf.Config{ZoneID: "zone", AccountID: "account"})
	server := httptest.NewServer(provider)
	t.Cleanup(server.Close)
	client := cf.NewClient("qualification", "zone", "account")
	client.BaseURL = server.URL
	zone, err := cf.Production(cf.Members{
		"gru": {"10.0.0.1"}, "sfo": {"10.0.1.1"}, "fra": {"10.0.2.1"},
	}, []string{"100.64.0.0/10"})
	if err != nil {
		t.Fatal(err)
	}
	workerPrior := []byte("export default { fetch() { return new Response('prior') } }")
	workerCandidate := []byte("export default { fetch() { return new Response('candidate') } }")
	snippetPrior := []byte("export default { async fetch(request) { return fetch(request) } }")
	snippetCandidate := []byte("export default { async fetch(request) { return fetch(request, {cf:{cacheEverything:true}}) } }")
	artifacts := edgeArtifactMap{}
	for _, item := range []struct {
		service string
		body    []byte
	}{
		{"ts-dashboard", workerPrior}, {"ts-dashboard", workerCandidate},
		{"ts-proxy-snippet", snippetPrior}, {"ts-proxy-snippet", snippetCandidate},
	} {
		digest := testEdgeDigest(item.body)
		artifacts[item.service+"\x00"+digest] = item.body
	}
	promoter, err := cf.NewEdgeReleasePromoter(cf.EdgeReleasePromoterConfig{
		Client: client, Zone: zone, Artifacts: artifacts,
		SnippetServices: map[string]string{"ts-proxy-snippet": cf.GateSnippetName},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, body := range [][]byte{workerPrior, workerCandidate, workerPrior} {
		if err := promoter.PromoteWorkerGradual(t.Context(), "ts-dashboard", testEdgeDigest(body)); err != nil {
			t.Fatal(err)
		}
	}
	active, err := client.ActiveWorkerVersion(t.Context(), "ts-dashboard")
	if err != nil || active.Digest != testEdgeDigest(workerPrior) {
		t.Fatalf("active Worker = %+v, err = %v", active, err)
	}
	deployments, err := client.ListWorkerDeployments(t.Context(), "ts-dashboard")
	if err != nil || len(deployments) != 7 {
		t.Fatalf("Worker deployments = %d, err = %v", len(deployments), err)
	}

	for index, body := range [][]byte{snippetPrior, snippetCandidate, snippetPrior} {
		digest := testEdgeDigest(body)
		if index == 1 {
			if err := promoter.CoordinateSnippetZoneRules(t.Context(), "ts-proxy-snippet", digest); err == nil {
				t.Fatal("coordinated rules for code that is not deployed")
			}
			provider.AddFault(sandboxcf.Fault{
				Method: http.MethodPut, Path: "/zones/zone/snippets/" + cf.GateSnippetName,
				Calls: 1, Steps: []sandboxcf.FaultStep{{Status: http.StatusInternalServerError, Commit: true}},
			})
		}
		promotionErr := promoter.PromoteSnippet(t.Context(), "ts-proxy-snippet", digest)
		if index == 1 {
			if promotionErr == nil {
				t.Fatal("committed candidate with failed response reported success")
			}
			observed, err := client.SnippetCode(t.Context(), cf.GateSnippetName)
			if err != nil || observed.Digest != digest {
				t.Fatalf("failed-response candidate was not committed: %+v, err = %v", observed, err)
			}
		} else if promotionErr != nil {
			t.Fatal(promotionErr)
		}
		if err := promoter.CoordinateSnippetZoneRules(t.Context(), "ts-proxy-snippet", digest); err != nil {
			t.Fatal(err)
		}
	}
	snippet, err := client.SnippetCode(t.Context(), cf.GateSnippetName)
	if err != nil || snippet.Digest != testEdgeDigest(snippetPrior) {
		t.Fatalf("active Snippet = %+v, err = %v", snippet, err)
	}
	live, err := client.ListSnippets(t.Context())
	if err != nil || len(live) != 1 || len(live[0].Rules) != 1 || !live[0].Rules[0].Enabled {
		t.Fatalf("Snippet rules = %+v, err = %v", live, err)
	}
	if events := promoter.Events(); len(events) != 13 {
		t.Fatalf("provider promotion events = %d, want 13", len(events))
	}
}

// These fixtures follow Cloudflare's multipart metadata documentation and
// Wrangler 4.20.0 packages/wrangler/src/versions/{api,types}.ts. They do not
// share the sandbox's encoders or response types.
func TestEdgeUploadsUseCloudflareMultipartContracts(t *testing.T) {
	source := []byte("export default {fetch(){return new Response('verified')}}")
	digest := testEdgeDigest(source)
	var workerUploads, snippetUploads int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer scoped-token" {
			t.Error("missing authorization")
		}
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/versions"):
			workerUploads++
			assertEdgeUpload(t, r, "worker.js", "worker.js", source, digest)
			// Upload response alone is insufficient: version detail is read separately.
			fmt.Fprint(w, `{"success":true,"result":{"id":"version-immutable"}}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/versions/version-immutable"):
			fmt.Fprintf(w, `{"success":true,"result":{"id":"version-immutable","annotations":{"workers/message":"terrascale-artifact:%s"}}}`, digest)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/snippets/gate"):
			snippetUploads++
			assertEdgeUpload(t, r, "files", "snippet.js", source, "")
			fmt.Fprint(w, `{"success":true,"result":{"snippet_name":"gate"}}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/snippets/gate/content"):
			if r.Header.Get("Accept") != "multipart/form-data" {
				t.Errorf("content Accept = %q", r.Header.Get("Accept"))
			}
			w.Header().Set("Content-Type", "multipart/form-data; boundary=readback")
			fmt.Fprintf(w, "--readback\r\nContent-Disposition: form-data; name=\"files\"; filename=\"snippet.js\"\r\nContent-Type: application/javascript+module\r\n\r\n%s\r\n--readback--\r\n", source)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := cf.NewClient("scoped-token", "zone", "account")
	client.BaseURL = server.URL
	version, err := client.UploadWorkerVersion(t.Context(), "worker", digest, source)
	if err != nil || version.Digest != digest || version.ID != "version-immutable" {
		t.Fatalf("version = %+v, %v", version, err)
	}
	if err := client.PutSnippetCode(t.Context(), "gate", digest, source); err != nil {
		t.Fatal(err)
	}
	observed, err := client.SnippetCode(t.Context(), "gate")
	if err != nil || observed.Digest != digest {
		t.Fatalf("snippet = %+v, %v", observed, err)
	}
	if workerUploads != 1 || snippetUploads != 1 {
		t.Fatalf("upload counts %d, %d", workerUploads, snippetUploads)
	}
}

func assertEdgeUpload(t *testing.T, r *http.Request, field, filename string, source []byte, digest string) {
	t.Helper()
	reader, err := r.MultipartReader()
	if err != nil {
		t.Errorf("multipart upload: %v", err)
		return
	}
	metadata, err := reader.NextPart()
	if err != nil {
		t.Errorf("metadata: %v", err)
		return
	}
	if metadata.FormName() != "metadata" || metadata.Header.Get("Content-Type") != "application/json" {
		t.Errorf("metadata headers: %v", metadata.Header)
	}
	var value map[string]json.RawMessage
	if err := json.NewDecoder(metadata).Decode(&value); err != nil {
		t.Error(err)
	}
	var main string
	if err := json.Unmarshal(value["main_module"], &main); err != nil || main != filename {
		t.Errorf("main_module = %s", value["main_module"])
	}
	delete(value, "main_module")
	if digest != "" {
		var annotations map[string]string
		if err := json.Unmarshal(value["annotations"], &annotations); err != nil || annotations["workers/message"] != "terrascale-artifact:"+digest {
			t.Errorf("annotations = %s", value["annotations"])
		}
		delete(value, "annotations")
	}
	if len(value) != 0 {
		t.Errorf("unexpected metadata keys: %v", value)
	}
	module, err := reader.NextPart()
	if err != nil {
		t.Errorf("module: %v", err)
		return
	}
	if module.FormName() != field || module.FileName() != filename || module.Header.Get("Content-Type") != "application/javascript+module" {
		t.Errorf("module headers = %v", module.Header)
	}
	body, err := io.ReadAll(module)
	if err != nil || !bytes.Equal(body, source) {
		t.Error("uploaded source differs from verified artifact")
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Errorf("unexpected extra part: %v", err)
	}
}

func TestWorkerReadbackUsesLatestDeploymentAndRejectsPartialTraffic(t *testing.T) {
	source := []byte("source")
	digest := testEdgeDigest(source)
	partial := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/account/workers/scripts/worker/versions":
			if r.URL.Query().Get("page") == "1" {
				fmt.Fprintf(w, `{"success":true,"result":{"items":[{"id":"new","annotations":{"workers/message":"terrascale-artifact:%s"}}]},"result_info":{"page":1,"total_pages":2}}`, digest)
			} else {
				fmt.Fprint(w, `{"success":true,"result":{"items":[{"id":"old","digest":"fabricated-digest"}]},"result_info":{"page":2,"total_pages":2}}`)
			}
		case "/accounts/account/workers/scripts/worker/deployments":
			if partial {
				fmt.Fprint(w, `{"success":true,"result":{"deployments":[{"id":"a-latest","versions":[{"version_id":"new","percentage":50},{"version_id":"old","percentage":50}]}]}}`)
			} else {
				fmt.Fprint(w, `{"success":true,"result":{"deployments":[{"id":"a-latest","versions":[{"version_id":"new","percentage":100}]},{"id":"z-old","versions":[{"version_id":"old","percentage":100}]}]}}`)
			}
		case "/accounts/account/workers/scripts/worker/versions/new":
			fmt.Fprintf(w, `{"success":true,"result":{"id":"new","annotations":{"workers/message":"terrascale-artifact:%s"}}}`, digest)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := cf.NewClient("token", "zone", "account")
	client.BaseURL = server.URL
	versions, err := client.ListWorkerVersions(t.Context(), "worker")
	if err != nil || len(versions) != 2 || versions[0].Digest != digest || versions[1].Digest != "" {
		t.Fatalf("versions = %+v, %v", versions, err)
	}
	active, err := client.ActiveWorkerVersion(t.Context(), "worker")
	if err != nil || active.ID != "new" || active.Digest != digest {
		t.Fatalf("active = %+v, %v", active, err)
	}
	partial = true
	if _, err := client.ActiveWorkerVersion(t.Context(), "worker"); err == nil {
		t.Fatal("partial traffic reported as a fully active version")
	}
}

func TestWorkerRollbackRecoversCommittedPartialDeployment(t *testing.T) {
	provider := sandboxcf.New(sandboxcf.Config{ZoneID: "zone", AccountID: "account"})
	server := httptest.NewServer(provider)
	defer server.Close()
	client := cf.NewClient("token", "zone", "account")
	client.BaseURL = server.URL
	zone, err := cf.Production(cf.Members{"gru": {"10.0.0.1"}, "sfo": {"10.0.1.1"}, "fra": {"10.0.2.1"}}, []string{"100.64.0.0/10"})
	if err != nil {
		t.Fatal(err)
	}
	prior, candidate := []byte("prior module"), []byte("candidate module")
	priorDigest, candidateDigest := testEdgeDigest(prior), testEdgeDigest(candidate)
	promoter, err := cf.NewEdgeReleasePromoter(cf.EdgeReleasePromoterConfig{Client: client, Zone: zone, Artifacts: edgeArtifactMap{"ts-dashboard\x00" + priorDigest: prior, "ts-dashboard\x00" + candidateDigest: candidate}})
	if err != nil {
		t.Fatal(err)
	}
	if err := promoter.PromoteWorkerGradual(t.Context(), "ts-dashboard", priorDigest); err != nil {
		t.Fatal(err)
	}
	provider.AddFault(sandboxcf.Fault{Method: http.MethodPost, Path: "/accounts/account/workers/scripts/ts-dashboard/deployments", Calls: 1, Steps: []sandboxcf.FaultStep{{Status: http.StatusInternalServerError, Commit: true}}})
	if err := promoter.PromoteWorkerGradual(t.Context(), "ts-dashboard", candidateDigest); err == nil {
		t.Fatal("committed failed-response deployment reported success")
	}
	if _, err := client.ActiveWorkerVersion(t.Context(), "ts-dashboard"); err == nil {
		t.Fatal("partial deployment accepted as fully active")
	}
	if err := promoter.PromoteWorkerGradual(t.Context(), "ts-dashboard", priorDigest); err != nil {
		t.Fatal(err)
	}
	active, err := client.ActiveWorkerVersion(t.Context(), "ts-dashboard")
	if err != nil || active.Digest != priorDigest {
		t.Fatalf("rollback = %+v, %v", active, err)
	}
}
