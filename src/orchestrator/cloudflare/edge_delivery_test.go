package cloudflare_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
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
	provider := sandboxcf.New(sandboxcf.Config{ZoneID: "zone", AccountID: "account", AsyncPolls: 1})
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
