package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

type globalDeliveryHTTPRecorder struct{ calls int }

func (r *globalDeliveryHTTPRecorder) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}
func TestGlobalDeliveryTransportRechecksBothAuthorities(t *testing.T) {
	recorder := &globalDeliveryHTTPRecorder{}
	authorityCalls := 0
	lost := errors.New("lease changed")
	transport := globalDeliveryTransport{inner: recorder, authorize: func(context.Context) error { authorityCalls++; return nil }}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPut, "https://api.cloudflare.com/client/v4/test", nil)
	if _, err := transport.RoundTrip(req); err == nil || recorder.calls != 0 || authorityCalls != 0 {
		t.Fatal("missing durable fence reached authority/provider")
	}
	fence := delivery.OperationFence{OperationID: "operation", RequestDigest: "digest", OwnerID: "owner", Generation: 1}
	fenceCalls := 0
	ctx, err := delivery.WithExecutionFence(t.Context(), fence, func(delivery.OperationFence) error { fenceCalls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(ctx)
	if _, err = transport.RoundTrip(req); err != nil || recorder.calls != 1 || authorityCalls != 1 || fenceCalls != 1 {
		t.Fatalf("fenced call failed: %v", err)
	}
	transport.authorize = func(context.Context) error { return lost }
	if _, err = transport.RoundTrip(req); !errors.Is(err, lost) || recorder.calls != 1 || fenceCalls != 2 {
		t.Fatal("lost global authority reached provider")
	}
}
func TestRegionalDeliveryEdgeRefusesProviderEffects(t *testing.T) {
	edge := regionalDeliveryEdge{}
	if err := edge.PromoteWorker(t.Context(), "ts-proxy", "digest"); err == nil {
		t.Fatal("regional Worker mutation accepted")
	}
	if err := edge.PromoteSnippet(t.Context(), "ts-capability", "digest"); err == nil {
		t.Fatal("regional Snippet mutation accepted")
	}
}

type partialWorkerDeploymentTransport struct{ calls int }

func (p *partialWorkerDeploymentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p.calls++
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"success":true,"result":{"deployments":[{"id":"partial","versions":[{"version_id":"old","percentage":50},{"version_id":"new","percentage":50}]}]}}`))}, nil
}
func TestGlobalDeliveryObservesPartialWorkerAsRecoverable(t *testing.T) {
	recorder := &partialWorkerDeploymentTransport{}
	client := cloudflare.NewClient("fixture", "zone", "account")
	client.HTTP = recorder
	edge := &productionGlobalDeliveryEdge{client: client, authorize: func(context.Context) error { return nil }}
	body := []byte("source")
	digest := delivery.SHA256Digest(body)
	request := &delivery.Request{OperationID: "operation", Target: &delivery.Target{Service: "ts-proxy"}, Artifact: &delivery.Artifact{Kind: "site", Digest: digest}}
	artifact := &delivery.ReleaseArtifact{Service: "ts-proxy", Digest: digest, Body: body}
	fence := delivery.OperationFence{OperationID: "operation", RequestDigest: "digest", OwnerID: "owner", Generation: 1}
	reached, err := edge.Observe(t.Context(), request, artifact, fence, func(delivery.OperationFence) error { return nil })
	if err != nil || reached || recorder.calls != 1 {
		t.Fatalf("partial deployment must permit recovery: reached=%v calls=%d err=%v", reached, recorder.calls, err)
	}
}

func TestGlobalDeliverySnippetRejectsArtifactDigestMismatchBeforeProvider(t *testing.T) {
	recorder := &globalDeliveryHTTPRecorder{}
	edge := &productionGlobalDeliveryEdge{
		client:    cloudflare.NewClient("fixture", "zone", "account"),
		authorize: func(context.Context) error { return nil },
	}
	edge.client.HTTP = recorder
	body := []byte("verified source")
	request := &delivery.Request{
		OperationID: "operation",
		Target:      &delivery.Target{Service: "ts-proxy-snippet"},
		Artifact:    &delivery.Artifact{Kind: "package", Digest: delivery.SHA256Digest([]byte("declared source"))},
	}
	artifact := &delivery.ReleaseArtifact{Service: "ts-proxy-snippet", Digest: request.Artifact.Digest, Body: body}
	fence := delivery.OperationFence{OperationID: "operation", RequestDigest: "request", OwnerID: "owner", Generation: 1}
	if _, err := edge.Observe(t.Context(), request, artifact, fence, func(delivery.OperationFence) error { return nil }); err == nil {
		t.Fatal("accepted Snippet artifact whose bytes do not match its declared digest")
	}
	if recorder.calls != 0 {
		t.Fatalf("provider received mismatched Snippet artifact: %d calls", recorder.calls)
	}
}

func TestGlobalDeliverySnippetFailsClosedWithoutCapabilityPromoter(t *testing.T) {
	edge := &productionGlobalDeliveryEdge{authorize: func(context.Context) error { return nil }}
	if err := edge.PromoteSnippet(t.Context(), "ts-proxy-snippet", "sha256:bad"); err == nil {
		t.Fatal("Snippet promotion succeeded without its runtime promoter")
	}
	if err := edge.CoordinateSnippetZoneRules(t.Context(), "ts-proxy-snippet", "sha256:bad"); err == nil {
		t.Fatal("Snippet rule coordination succeeded without its runtime promoter")
	}
}
