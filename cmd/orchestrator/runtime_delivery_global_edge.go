package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// Regional host delivery never owns Cloudflare account mutations. The global
// master completes edge releases once under its durable operation and lease.
type regionalDeliveryEdge struct{}

func (regionalDeliveryEdge) PromoteWorker(context.Context, string, string) error {
	return errors.New("delivery: edge release must execute under global master authority")
}
func (regionalDeliveryEdge) PromoteSnippet(context.Context, string, string) error {
	return errors.New("delivery: edge release must execute under global master authority")
}
func (regionalDeliveryEdge) ObserveEdge(context.Context, string, string) (delivery.EdgeReleaseState, error) {
	return delivery.EdgeReleaseState{}, errors.New("delivery: edge observation must execute under global master authority")
}
func (regionalDeliveryEdge) RestoreEdge(context.Context, string, string, delivery.EdgeReleaseState) error {
	return errors.New("delivery: edge restoration must execute under global master authority")
}
func (regionalDeliveryEdge) CheckEdge(context.Context, string, string, string) error {
	return errors.New("delivery: edge health must execute under global master authority")
}

type productionGlobalDeliveryEdge struct {
	workers      *cloudflare.EdgeReleasePromoter
	client       *cloudflare.Client
	capabilities *cloudflare.SnippetCapabilityStore
	authorize    func(context.Context) error
}

func (r *constructedProductionDelivery) GlobalEdge(mirror *delivery.ArtifactMirror, capabilities *cloudflare.SnippetCapabilityStore, authorize func(context.Context) error) (control.GlobalEdgeDelivery, error) {
	if r == nil || r.plan == nil || r.plan.cell != "gru" || mirror == nil || capabilities == nil || authorize == nil {
		return nil, errors.New("delivery: global edge requires GRU mirror, shared capability store and live authority")
	}
	f := r.plan.file.Cloudflare
	token, err := readProductionDeliveryToken(f.TokenFile)
	if err != nil {
		return nil, err
	}
	zone, err := cloudflare.Production(nil, f.TailscaleEgressCIDRs)
	if err != nil {
		return nil, err
	}
	client := cloudflare.NewClient(token, f.ZoneID, f.AccountID)
	client.HTTP = globalDeliveryTransport{inner: client.HTTP, authorize: authorize}
	canary, err := productionCanaryProbe(f, client)
	if err != nil {
		return nil, err
	}
	health := cloudflare.EdgeHealthRouter{Site: canary, Package: capabilities}
	workers, err := cloudflare.NewEdgeReleasePromoter(cloudflare.EdgeReleasePromoterConfig{Client: client, Zone: zone, Artifacts: productionDeliveryMirrorSource{mirror: mirror, region: "gru"}, Health: health, SnippetServices: f.SnippetServices, WorkerStages: f.WorkerStages})
	if err != nil {
		return nil, err
	}
	return &productionGlobalDeliveryEdge{workers: workers, client: client, capabilities: capabilities, authorize: authorize}, nil
}

func productionCanaryProbe(config productionDeliveryCloudflareFile, client *cloudflare.Client) (cloudflare.CanaryEdgeHealthProbe, error) {
	if client == nil || strings.TrimSpace(config.CanaryRouteURL) == "" || strings.TrimSpace(config.CanaryProjectID) == "" || strings.TrimSpace(config.CanaryDatabaseID) == "" || strings.TrimSpace(config.CanaryExpectedMarker) == "" || config.CanaryMinimumRevision <= 0 || strings.TrimSpace(config.CanaryDownstreamService) == "" {
		return cloudflare.CanaryEdgeHealthProbe{}, errors.New("delivery: authenticated Worker canary configuration is incomplete")
	}
	route, err := url.Parse(config.CanaryRouteURL)
	expectedPath := "/api/v1/projects/" + url.PathEscape(config.CanaryProjectID) + "/databases/" + url.PathEscape(config.CanaryDatabaseID)
	if err != nil || route.Scheme != "https" || route.Host == "" || route.User != nil || route.RawQuery != "" || route.Fragment != "" || route.EscapedPath() != expectedPath {
		return cloudflare.CanaryEdgeHealthProbe{}, errors.New("delivery: authenticated Worker canary route must be an explicit HTTPS URL")
	}
	canaryToken, err := readProductionDeliveryToken(config.CanaryTokenFile)
	if err != nil {
		return cloudflare.CanaryEdgeHealthProbe{}, err
	}
	foreignToken, err := readProductionDeliveryToken(config.CanaryForeignTokenFile)
	if err != nil {
		return cloudflare.CanaryEdgeHealthProbe{}, err
	}
	return cloudflare.CanaryEdgeHealthProbe{Client: client, HTTPClient: &http.Client{Timeout: 10 * time.Second}, RouteURL: config.CanaryRouteURL, ProjectID: config.CanaryProjectID, DatabaseID: config.CanaryDatabaseID, CanaryToken: canaryToken, ForeignToken: foreignToken, ExpectedMarker: config.CanaryExpectedMarker, MinimumRevision: config.CanaryMinimumRevision, DownstreamService: config.CanaryDownstreamService}, nil
}
func (e *productionGlobalDeliveryEdge) check(ctx context.Context) error {
	if err := delivery.CheckExecutionFence(ctx); err != nil {
		return err
	}
	return e.authorize(ctx)
}
func (e *productionGlobalDeliveryEdge) PromoteWorker(ctx context.Context, service, digest string) error {
	return e.PromoteWorkerGradual(ctx, service, digest)
}
func (e *productionGlobalDeliveryEdge) PromoteWorkerGradual(ctx context.Context, service, digest string) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.workers.PromoteWorkerGradual(ctx, service, digest); err != nil {
		return err
	}
	return e.check(ctx)
}
func (e *productionGlobalDeliveryEdge) PromoteSnippet(ctx context.Context, service, digest string) error {
	if e == nil || e.capabilities == nil {
		return errors.New("delivery: global Snippet promoter is unavailable")
	}
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.capabilities.PromoteTemplate(ctx, service, digest); err != nil {
		return err
	}
	return e.check(ctx)
}
func (e *productionGlobalDeliveryEdge) CoordinateSnippetZoneRules(ctx context.Context, service, digest string) error {
	if e == nil || e.capabilities == nil {
		return errors.New("delivery: global Snippet rule coordinator is unavailable")
	}
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.capabilities.CoordinateTemplateRules(ctx, service, digest); err != nil {
		return err
	}
	return e.check(ctx)
}

func (e *productionGlobalDeliveryEdge) ObserveEdge(ctx context.Context, kind, service string) (delivery.EdgeReleaseState, error) {
	if e == nil || e.workers == nil {
		return delivery.EdgeReleaseState{}, errors.New("delivery: global edge observer is unavailable")
	}
	if err := e.check(ctx); err != nil {
		return delivery.EdgeReleaseState{}, err
	}
	state, err := e.workers.ObserveEdge(ctx, kind, service)
	if err != nil {
		return delivery.EdgeReleaseState{}, err
	}
	if err := e.check(ctx); err != nil {
		return delivery.EdgeReleaseState{}, err
	}
	return state, nil
}

func (e *productionGlobalDeliveryEdge) RestoreEdge(ctx context.Context, kind, service string, prior delivery.EdgeReleaseState) error {
	if e == nil || e.workers == nil {
		return errors.New("delivery: global edge restorer is unavailable")
	}
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.workers.RestoreEdge(ctx, kind, service, prior); err != nil {
		return err
	}
	return e.check(ctx)
}

func (e *productionGlobalDeliveryEdge) CheckEdge(ctx context.Context, kind, service, digest string) error {
	if e == nil || e.workers == nil {
		return errors.New("delivery: global edge health is unavailable")
	}
	if err := e.check(ctx); err != nil {
		return err
	}
	if err := e.workers.CheckEdge(ctx, kind, service, digest); err != nil {
		return err
	}
	return e.check(ctx)
}

type globalDeliveryTransport struct {
	inner     http.RoundTripper
	authorize func(context.Context) error
}

func (t globalDeliveryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := delivery.CheckExecutionFence(request.Context()); err != nil {
		return nil, err
	}
	if err := t.authorize(request.Context()); err != nil {
		return nil, err
	}
	return t.inner.RoundTrip(request)
}
func (e *productionGlobalDeliveryEdge) bound(ctx context.Context, request *delivery.Request, artifact *delivery.ReleaseArtifact, fence delivery.OperationFence, check func(delivery.OperationFence) error) (context.Context, error) {
	if request == nil || request.Target == nil || request.Artifact == nil || artifact == nil || fence.OperationID != request.OperationID || artifact.Service != request.Target.Service || !delivery.SameDigest(artifact.Digest, request.Artifact.Digest) || len(artifact.Body) == 0 || !delivery.SameDigest(delivery.SHA256Digest(artifact.Body), artifact.Digest) || (request.Artifact.Kind != "site" && request.Artifact.Kind != "package") {
		return nil, errors.New("delivery: global edge intent and verified artifact differ")
	}
	bound, err := delivery.WithExecutionFence(ctx, fence, check)
	if err != nil {
		return nil, err
	}
	if err = e.check(bound); err != nil {
		return nil, err
	}
	return bound, nil
}
func (e *productionGlobalDeliveryEdge) Observe(ctx context.Context, request *delivery.Request, artifact *delivery.ReleaseArtifact, fence delivery.OperationFence, check func(delivery.OperationFence) error) (bool, error) {
	bound, err := e.bound(ctx, request, artifact, fence, check)
	if err != nil {
		return false, err
	}
	if request.Artifact.Kind == "package" {
		return e.capabilities.ObserveTemplate(bound, artifact.Service, artifact.Digest)
	}
	deployments, err := e.client.ListWorkerDeployments(bound, artifact.Service)
	if err != nil {
		return false, err
	}
	if len(deployments) == 0 || len(deployments[0].Versions) != 1 || deployments[0].Versions[0].Percentage != 100 {
		return false, nil
	}
	version, err := e.client.ActiveWorkerVersion(bound, artifact.Service)
	if errors.Is(err, cloudflare.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = e.check(bound); err != nil {
		return false, err
	}
	return delivery.SameDigest(version.Digest, artifact.Digest), nil
}
func (e *productionGlobalDeliveryEdge) Apply(ctx context.Context, request *delivery.Request, artifact *delivery.ReleaseArtifact, fence delivery.OperationFence, check func(delivery.OperationFence) error) error {
	bound, err := e.bound(ctx, request, artifact, fence, check)
	if err != nil {
		return err
	}
	if request.Artifact.Kind == "site" {
		return e.PromoteWorkerGradual(bound, artifact.Service, artifact.Digest)
	}
	if err = e.PromoteSnippet(bound, artifact.Service, artifact.Digest); err != nil {
		return err
	}
	return e.CoordinateSnippetZoneRules(bound, artifact.Service, artifact.Digest)
}
