package vmqual

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	sandboxcf "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/cloudflare"
)

type deliveryProviderArtifactSource struct {
	mu    sync.Mutex
	items map[string][]byte
}

func newDeliveryProviderArtifactSource() *deliveryProviderArtifactSource {
	return &deliveryProviderArtifactSource{items: make(map[string][]byte)}
}

func (s *deliveryProviderArtifactSource) put(service, digest string, body []byte) {
	s.mu.Lock()
	s.items[service+"\x00"+strings.ToLower(digest)] = append([]byte(nil), body...)
	s.mu.Unlock()
}

func (s *deliveryProviderArtifactSource) EdgeArtifact(_ context.Context, service, digest string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, ok := s.items[service+"\x00"+strings.ToLower(digest)]
	if !ok {
		return nil, errors.New("vmqual: edge artifact is absent from the verified delivery set")
	}
	return append([]byte(nil), body...), nil
}

func newDeliveryProviderEdge(ctx context.Context, endpoints *LocalProviderEndpoints, client *http.Client, artifacts *deliveryProviderArtifactSource) (*cf.EdgeReleasePromoter, *cf.Client, error) {
	if endpoints == nil || endpoints.Cloudflare == nil || endpoints.CloudflareURL == "" || artifacts == nil {
		return nil, nil, errors.New("vmqual: provider-backed edge delivery requires local Cloudflare")
	}
	providerClient := cf.NewClient("vmqual-edge-delivery", endpoints.ZoneID, endpoints.AccountID)
	providerClient.BaseURL = endpoints.CloudflareURL
	if client != nil && client.Transport != nil {
		providerClient.HTTP = client.Transport
	}
	zone, err := cf.Production(cf.Members{
		"gru": {"10.77.0.10", "10.77.0.11"},
		"sfo": {"10.77.1.10", "10.77.1.11"},
		"fra": {"10.77.2.10", "10.77.2.11"},
	}, []string{"100.64.0.0/10"})
	if err != nil {
		return nil, nil, err
	}
	// Run the public production reconciler first. The missing Snippet code is
	// an expected alert until its first verified package delivery below.
	if err := cf.Run(ctx, providerClient, zone, false, io.Discard); err != nil {
		return nil, nil, fmt.Errorf("vmqual: reconcile production edge declaration: %w", err)
	}
	promoter, err := cf.NewEdgeReleasePromoter(cf.EdgeReleasePromoterConfig{
		Client: providerClient, Zone: zone, Artifacts: artifacts,
		SnippetServices: map[string]string{"ts-proxy-snippet": cf.GateSnippetName},
	})
	if err != nil {
		return nil, nil, err
	}
	return promoter, providerClient, nil
}

func injectDeliveryWorkerFailure(endpoints *LocalProviderEndpoints, service string) {
	endpoints.Cloudflare.AddFault(sandboxcf.Fault{
		Method: http.MethodPost,
		Path:   "/accounts/" + endpoints.AccountID + "/workers/scripts/" + service + "/deployments",
		Calls:  1,
		Steps: []sandboxcf.FaultStep{{
			Status: http.StatusInternalServerError, Message: "qualification Worker gate failed", Commit: true,
		}},
	})
}

func injectDeliverySnippetCodeFailure(endpoints *LocalProviderEndpoints, snippet string) {
	endpoints.Cloudflare.AddFault(sandboxcf.Fault{
		Method: http.MethodPut,
		Path:   "/zones/" + endpoints.ZoneID + "/snippets/" + snippet,
		Calls:  1,
		Steps: []sandboxcf.FaultStep{{
			Status: http.StatusInternalServerError, Message: "qualification Snippet code response lost after commit", Commit: true,
		}},
	})
}

func observeDeliveryProviderEdge(ctx context.Context, client *cf.Client, promoter *cf.EdgeReleasePromoter, workerPrior, workerCandidate, snippetPrior, snippetCandidate string) (deliveryContractEdgeState, error) {
	var result deliveryContractEdgeState
	if client == nil || promoter == nil {
		return result, errors.New("vmqual: provider-backed edge observation is unavailable")
	}
	activeWorker, err := client.ActiveWorkerVersion(ctx, "ts-dashboard")
	if err != nil {
		return result, err
	}
	activeSnippet, err := client.SnippetCode(ctx, cf.GateSnippetName)
	if err != nil {
		return result, err
	}
	if !delivery.SameDigest(activeWorker.Digest, workerPrior) || !delivery.SameDigest(activeSnippet.Digest, snippetPrior) {
		return result, errors.New("vmqual: provider edge rollback did not restore exact prior digests")
	}
	versions, err := client.ListWorkerVersions(ctx, "ts-dashboard")
	if err != nil {
		return result, err
	}
	digestByVersion := make(map[string]string, len(versions))
	for _, version := range versions {
		digestByVersion[version.ID] = version.Digest
	}
	deployments, err := client.ListWorkerDeployments(ctx, "ts-dashboard")
	if err != nil {
		return result, err
	}
	providerSawCandidate, providerSawPriorOnly := false, false
	for _, deployment := range deployments {
		if len(deployment.Versions) == 1 && deployment.Versions[0].Percentage == 100 && delivery.SameDigest(digestByVersion[deployment.Versions[0].VersionID], workerPrior) {
			providerSawPriorOnly = true
		}
		for _, version := range deployment.Versions {
			if version.Percentage > 0 && delivery.SameDigest(digestByVersion[version.VersionID], workerCandidate) {
				providerSawCandidate = true
			}
		}
	}
	if len(deployments) == 0 {
		return result, errors.New("vmqual: Worker provider recorded no deployments")
	}
	if !providerSawCandidate || !providerSawPriorOnly {
		return result, errors.New("vmqual: Worker provider history lacks candidate traffic and final prior-only rollback")
	}
	seenWorkerCandidate, seenWorkerRollback := false, false
	seenSnippetCandidate, seenSnippetRollback := false, false
	for _, event := range promoter.Events() {
		text := fmt.Sprintf("%s:%s:%s:%d:error=%t", event.Kind, event.Service, event.Digest, event.Percentage, event.Err)
		switch event.Kind {
		case "worker":
			result.workerEvents = append(result.workerEvents, text)
			if delivery.SameDigest(event.Digest, workerCandidate) {
				seenWorkerCandidate = true
			}
			if seenWorkerCandidate && delivery.SameDigest(event.Digest, workerPrior) && !event.Err && event.Percentage == 100 {
				seenWorkerRollback = true
			}
		case "snippet-code", "snippet-rules":
			result.snippetEvents = append(result.snippetEvents, text)
			if delivery.SameDigest(event.Digest, snippetCandidate) {
				seenSnippetCandidate = true
			}
			if seenSnippetCandidate && delivery.SameDigest(event.Digest, snippetPrior) && !event.Err {
				seenSnippetRollback = true
			}
		}
	}
	if !seenWorkerCandidate || !seenWorkerRollback || !seenSnippetCandidate || !seenSnippetRollback {
		return result, errors.New("vmqual: provider edge trace lacks candidate mutation and exact rollback")
	}
	result.workerDigest = activeWorker.Digest
	result.snippetDigest = activeSnippet.Digest
	result.snippetRuleDigest = activeSnippet.Digest
	return result, nil
}

func probeProviderReactivePath(ctx context.Context, endpoints *LocalProviderEndpoints, edgeClient *cf.Client, client *http.Client) (deliveryReactiveObservation, error) {
	var result deliveryReactiveObservation
	if endpoints == nil || edgeClient == nil {
		return result, errors.New("vmqual: reactive provider observation is unavailable")
	}
	routes, err := edgeClient.ListWorkerRoutes(ctx)
	if err != nil {
		return result, err
	}
	workerFree := true
	for _, route := range routes {
		if deliveryRouteCoversHost(route.Pattern, "sync.api.terrascale.tech") {
			workerFree = false
			break
		}
	}
	snippets, err := edgeClient.ListSnippets(ctx)
	if err != nil {
		return result, err
	}
	hasLiveGate := false
	for _, snippet := range snippets {
		if snippet.Name != cf.GateSnippetName || snippet.Digest == "" {
			continue
		}
		for _, rule := range snippet.Rules {
			if rule.Enabled && strings.Contains(rule.Expression, `http.host eq "sync.api.terrascale.tech"`) {
				hasLiveGate = true
			}
		}
	}
	if !workerFree || !hasLiveGate {
		return result, errors.New("vmqual: live provider routing does not keep the reactive path on the Snippet gate")
	}
	observed, err := probeDeliveryReactivePath(ctx, endpoints, client)
	if err != nil {
		return result, err
	}
	observed.workerFree = workerFree
	return observed, nil
}

func deliveryRouteCoversHost(pattern, host string) bool {
	hostPattern := pattern
	if slash := strings.IndexByte(hostPattern, '/'); slash >= 0 {
		hostPattern = hostPattern[:slash]
	}
	switch {
	case strings.HasPrefix(hostPattern, "*") && strings.HasSuffix(hostPattern, "*"):
		return strings.Contains(host, strings.Trim(hostPattern, "*"))
	case strings.HasPrefix(hostPattern, "*"):
		return strings.HasSuffix(host, strings.TrimPrefix(hostPattern, "*"))
	case strings.HasSuffix(hostPattern, "*"):
		return strings.HasPrefix(host, strings.TrimSuffix(hostPattern, "*"))
	default:
		return hostPattern == host
	}
}
