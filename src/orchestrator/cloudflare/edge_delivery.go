package cloudflare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

const workerDigestAnnotationPrefix = "terrascale-artifact:"

// EdgeArtifactSource retrieves the already verified bytes named by an edge
// delivery digest. Production wires this to the durable regional artifact
// mirror. The promoter verifies the bytes again before a provider mutation.
type EdgeArtifactSource interface {
	EdgeArtifact(context.Context, string, string) ([]byte, error)
}

// EdgeHealthProbe is the authenticated application-level edge health check.
// Provider allocation readback is identity evidence only and never satisfies
// this contract.
type EdgeHealthProbe interface {
	CheckEdge(context.Context, string, string, string) error
}

// WorkerVersion is the provider identity of one uploaded Worker candidate.
type WorkerVersion struct {
	ID string `json:"id"`
	// Digest is derived from our uploaded version annotation, not a provider hash.
	Digest      string            `json:"-"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Metadata    json.RawMessage   `json:"metadata,omitempty"`
}

func (v *WorkerVersion) UnmarshalJSON(raw []byte) error {
	type wire WorkerVersion
	var value wire
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*v = WorkerVersion(value)
	message := v.Annotations["workers/message"]
	if strings.HasPrefix(message, workerDigestAnnotationPrefix) {
		digest := strings.TrimPrefix(message, workerDigestAnnotationPrefix)
		decoded, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
		if err == nil && strings.HasPrefix(digest, "sha256:") && len(decoded) == sha256.Size {
			v.Digest = digest
		}
	}
	return nil
}

// WorkerDeploymentVersion assigns one version a percentage of traffic.
type WorkerDeploymentVersion struct {
	VersionID  string `json:"version_id"`
	Percentage int    `json:"percentage"`
}

// WorkerDeployment is one provider-observed gradual deployment.
type WorkerDeployment struct {
	ID       string                    `json:"id"`
	Versions []WorkerDeploymentVersion `json:"versions"`
}

// SnippetCode is the provider-observed identity of deployed Snippet source.
// Digest is computed from the source bytes returned by the content endpoint.
type SnippetCode struct {
	Name   string `json:"snippet_name"`
	Digest string `json:"-"`
}

// EdgePromotionEvent records completed provider calls for bounded delivery
// evidence. The promoter never consults this trace when making a decision.
type EdgePromotionEvent struct {
	Kind       string
	Service    string
	Digest     string
	Percentage int
	Err        bool
}

// EdgeReleasePromoterConfig binds delivery to one declared zone and one
// verified artifact source. SnippetServices maps delivery service names to
// declared Cloudflare Snippet names.
type EdgeReleasePromoterConfig struct {
	Client          *Client
	Zone            *Zone
	Artifacts       EdgeArtifactSource
	Health          EdgeHealthProbe
	SnippetServices map[string]string
	WorkerStages    []int
}

// EdgeReleasePromoter implements delivery's Worker and Snippet promotion
// ports through Cloudflare's HTTP API. Provider reads, not local active-state
// fields, select versions and verify the final serving identity.
type EdgeReleasePromoter struct {
	client    *Client
	zone      *Zone
	artifacts EdgeArtifactSource
	health    EdgeHealthProbe
	snippets  map[string]string
	stages    []int

	mu     sync.Mutex
	events []EdgePromotionEvent
}

func NewEdgeReleasePromoter(config EdgeReleasePromoterConfig) (*EdgeReleasePromoter, error) {
	if config.Client == nil || config.Zone == nil || config.Artifacts == nil {
		return nil, errors.New("cloudflare: edge release promoter requires client, zone, and artifact source")
	}
	if err := config.Zone.validateGateDeclaration(); err != nil {
		return nil, err
	}
	snippets := make(map[string]string, len(config.SnippetServices))
	declared := make(map[string]struct{}, len(config.Zone.SnippetRules))
	for _, rule := range config.Zone.SnippetRules {
		declared[rule.SnippetName] = struct{}{}
	}
	for service, snippet := range config.SnippetServices {
		service, snippet = strings.TrimSpace(service), strings.TrimSpace(snippet)
		if service == "" || snippet == "" {
			return nil, errors.New("cloudflare: edge Snippet mapping is incomplete")
		}
		if _, ok := declared[snippet]; !ok {
			return nil, fmt.Errorf("cloudflare: edge Snippet %q is not declared", snippet)
		}
		snippets[service] = snippet
	}
	stages := append([]int(nil), config.WorkerStages...)
	if len(stages) == 0 {
		stages = []int{10, 50, 100}
	}
	prior := 0
	for _, stage := range stages {
		if stage <= prior || stage > 100 {
			return nil, errors.New("cloudflare: Worker stages must increase to 100")
		}
		prior = stage
	}
	if prior != 100 {
		return nil, errors.New("cloudflare: Worker stages must end at 100")
	}
	return &EdgeReleasePromoter{
		client: config.Client, zone: config.Zone, artifacts: config.Artifacts,
		health: config.Health, snippets: snippets, stages: stages,
	}, nil
}

func (p *EdgeReleasePromoter) PromoteWorker(ctx context.Context, service, digest string) error {
	return p.PromoteWorkerGradual(ctx, service, digest)
}

func (p *EdgeReleasePromoter) CheckEdge(ctx context.Context, kind, service, digest string) error {
	if p == nil || ctx == nil || p.health == nil {
		return errors.New("cloudflare: edge health requires an authenticated probe")
	}
	return p.health.CheckEdge(ctx, kind, service, digest)
}

// ObserveEdge provides delivery recovery with provider readback. A partial
// Worker allocation is intentionally reported as an error: its predecessor
// must come from durable rollout state, never from an inferred version.
func (p *EdgeReleasePromoter) ObserveEdge(ctx context.Context, kind, service string) (delivery.EdgeReleaseState, error) {
	if p == nil || ctx == nil {
		return delivery.EdgeReleaseState{}, errors.New("cloudflare: edge observation requires a promoter and context")
	}
	switch kind {
	case "site":
		if !p.workerDeclared(service) {
			return delivery.EdgeReleaseState{}, fmt.Errorf("cloudflare: Worker service %q has no declared route", service)
		}
		deployments, err := p.client.ListWorkerDeployments(ctx, service)
		if err != nil {
			return delivery.EdgeReleaseState{}, err
		}
		if len(deployments) == 0 {
			return delivery.EdgeReleaseState{}, nil
		}
		allocation, err := encodeWorkerAllocation(deployments[0].Versions)
		if err != nil {
			return delivery.EdgeReleaseState{}, err
		}
		state := delivery.EdgeReleaseState{Allocation: allocation}
		if len(deployments[0].Versions) == 1 && deployments[0].Versions[0].Percentage == 100 {
			version, err := p.client.ActiveWorkerVersion(ctx, service)
			if err != nil {
				return delivery.EdgeReleaseState{}, err
			}
			state.Digest = version.Digest
		}
		return state, nil
	case "package":
		snippet, ok := p.snippets[service]
		if !ok {
			return delivery.EdgeReleaseState{}, fmt.Errorf("cloudflare: Snippet service %q is not mapped", service)
		}
		code, err := p.client.SnippetCode(ctx, snippet)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return delivery.EdgeReleaseState{}, nil
			}
			return delivery.EdgeReleaseState{}, err
		}
		allocation, _ := json.Marshal(map[string]string{"snippet": snippet})
		return delivery.EdgeReleaseState{Digest: code.Digest, Allocation: string(allocation)}, nil
	default:
		return delivery.EdgeReleaseState{}, fmt.Errorf("cloudflare: edge observation kind %q is unsupported", kind)
	}
}

// RestoreEdge applies the exact allocation captured by ObserveEdge. It never
// reconstructs a predecessor from version history.
func (p *EdgeReleasePromoter) RestoreEdge(ctx context.Context, kind, service string, prior delivery.EdgeReleaseState) error {
	if p == nil || ctx == nil {
		return errors.New("cloudflare: edge restoration requires a promoter and context")
	}
	switch kind {
	case "site":
		if !p.workerDeclared(service) {
			return fmt.Errorf("cloudflare: Worker service %q has no declared route", service)
		}
		allocation, err := decodeWorkerAllocation(prior.Allocation)
		if err != nil {
			return err
		}
		versions, err := p.client.ListWorkerVersions(ctx, service)
		if err != nil {
			return err
		}
		known := make(map[string]struct{}, len(versions))
		for _, version := range versions {
			known[version.ID] = struct{}{}
			if version.Digest == prior.Digest && len(allocation) == 1 && allocation[0].VersionID != version.ID {
				return errors.New("cloudflare: edge predecessor allocation does not identify the requested digest")
			}
		}
		for _, item := range allocation {
			if _, ok := known[item.VersionID]; !ok {
				return errors.New("cloudflare: edge predecessor allocation references an unknown version")
			}
		}
		if _, err := p.client.CreateWorkerDeployment(ctx, service, allocation); err != nil {
			return err
		}
		observed, err := p.ObserveEdge(ctx, kind, service)
		if err != nil || observed.Allocation != prior.Allocation || (prior.Digest != "" && observed.Digest != prior.Digest) {
			return errors.New("cloudflare: edge predecessor allocation readback did not match")
		}
		return nil
	case "package":
		if prior.Digest == "" {
			return errors.New("cloudflare: Snippet restoration requires a digest")
		}
		snippet, ok := p.snippets[service]
		if !ok {
			return fmt.Errorf("cloudflare: Snippet service %q is not mapped", service)
		}
		var expected map[string]string
		if err := json.Unmarshal([]byte(prior.Allocation), &expected); err != nil || expected["snippet"] != snippet {
			return errors.New("cloudflare: Snippet predecessor allocation is invalid")
		}
		body, err := p.artifact(ctx, service, prior.Digest)
		if err != nil {
			return err
		}
		if err := p.client.PutSnippetCode(ctx, snippet, prior.Digest, body); err != nil {
			return err
		}
		observed, err := p.ObserveEdge(ctx, kind, service)
		if err != nil || observed.Digest != prior.Digest || observed.Allocation != prior.Allocation {
			return errors.New("cloudflare: Snippet predecessor readback did not match")
		}
		return nil
	default:
		return fmt.Errorf("cloudflare: edge restoration kind %q is unsupported", kind)
	}
}

func encodeWorkerAllocation(versions []WorkerDeploymentVersion) (string, error) {
	if !validWorkerAllocation(versions) {
		return "", errors.New("cloudflare: Worker allocation is invalid")
	}
	raw, err := json.Marshal(versions)
	return string(raw), err
}

func decodeWorkerAllocation(encoded string) ([]WorkerDeploymentVersion, error) {
	var versions []WorkerDeploymentVersion
	if err := json.Unmarshal([]byte(encoded), &versions); err != nil || !validWorkerAllocation(versions) {
		return nil, errors.New("cloudflare: Worker predecessor allocation is invalid")
	}
	return versions, nil
}

func validWorkerAllocation(versions []WorkerDeploymentVersion) bool {
	if len(versions) == 0 {
		return false
	}
	total := 0
	seen := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		if version.VersionID == "" || version.Percentage <= 0 || version.Percentage > 100 {
			return false
		}
		if _, ok := seen[version.VersionID]; ok {
			return false
		}
		seen[version.VersionID] = struct{}{}
		total += version.Percentage
	}
	return total == 100
}

func (p *EdgeReleasePromoter) PromoteWorkerGradual(ctx context.Context, service, digest string) error {
	if p == nil || ctx == nil {
		return errors.New("cloudflare: Worker promotion requires a promoter and context")
	}
	if p.health == nil {
		return errors.New("cloudflare: Worker promotion requires an authenticated edge health probe")
	}
	if !p.workerDeclared(service) {
		return fmt.Errorf("cloudflare: Worker service %q has no declared route", service)
	}
	body, err := p.artifact(ctx, service, digest)
	if err != nil {
		return err
	}
	target, err := p.ensureWorkerVersion(ctx, service, digest, body)
	if err != nil {
		return err
	}
	active, activeErr := p.client.workerPromotionBaseline(ctx, service)
	if activeErr != nil && !errors.Is(activeErr, ErrNotFound) {
		return activeErr
	}
	stages := p.stages
	if activeErr != nil || active.ID == target.ID {
		// A single 100% deployment creates the initial release and also clears
		// any partial deployment left by an indeterminate prior attempt.
		stages = []int{100}
	}
	for _, percentage := range stages {
		versions := []WorkerDeploymentVersion{{VersionID: target.ID, Percentage: 100}}
		if percentage < 100 && activeErr == nil && active.ID != target.ID {
			versions = []WorkerDeploymentVersion{
				{VersionID: active.ID, Percentage: 100 - percentage},
				{VersionID: target.ID, Percentage: percentage},
			}
		}
		_, deployErr := p.client.CreateWorkerDeployment(ctx, service, versions)
		p.record(EdgePromotionEvent{Kind: "worker", Service: service, Digest: digest, Percentage: percentage, Err: deployErr != nil})
		if deployErr != nil {
			return deployErr
		}
		if err := p.CheckEdge(ctx, "site", service, digest); err != nil {
			return fmt.Errorf("cloudflare: Worker stage %d health check: %w", percentage, err)
		}
	}
	observed, err := p.client.ActiveWorkerVersion(ctx, service)
	if err != nil {
		return err
	}
	if !sameEdgeDigest(observed.Digest, digest) {
		return fmt.Errorf("cloudflare: Worker provider readback digest %q did not reach %q", observed.Digest, digest)
	}
	return nil
}

func (p *EdgeReleasePromoter) PromoteSnippet(ctx context.Context, service, digest string) error {
	if p == nil || ctx == nil {
		return errors.New("cloudflare: Snippet promotion requires a promoter and context")
	}
	if p.health == nil {
		return errors.New("cloudflare: Snippet promotion requires an authenticated edge health probe")
	}
	snippet, ok := p.snippets[service]
	if !ok {
		return fmt.Errorf("cloudflare: Snippet service %q is not mapped", service)
	}
	body, err := p.artifact(ctx, service, digest)
	if err != nil {
		return err
	}
	putErr := p.client.PutSnippetCode(ctx, snippet, digest, body)
	p.record(EdgePromotionEvent{Kind: "snippet-code", Service: service, Digest: digest, Percentage: 100, Err: putErr != nil})
	if putErr != nil {
		return putErr
	}
	if err := p.CheckEdge(ctx, "package", service, digest); err != nil {
		return fmt.Errorf("cloudflare: Snippet health check: %w", err)
	}
	observed, err := p.client.SnippetCode(ctx, snippet)
	if err != nil {
		return err
	}
	if !sameEdgeDigest(observed.Digest, digest) {
		return errors.New("cloudflare: Snippet provider readback did not reach the requested digest")
	}
	return nil
}

func (p *EdgeReleasePromoter) CoordinateSnippetZoneRules(ctx context.Context, service, digest string) error {
	if p == nil || ctx == nil {
		return errors.New("cloudflare: Snippet rule coordination requires a promoter and context")
	}
	snippet, ok := p.snippets[service]
	if !ok {
		return fmt.Errorf("cloudflare: Snippet service %q is not mapped", service)
	}
	observed, err := p.client.SnippetCode(ctx, snippet)
	if err != nil {
		return err
	}
	if !sameEdgeDigest(observed.Digest, digest) {
		return errors.New("cloudflare: Snippet rule coordination requires the requested code digest")
	}
	err = ReconcileSnippetRules(ctx, p.client, p.zone, snippet)
	p.record(EdgePromotionEvent{Kind: "snippet-rules", Service: service, Digest: digest, Percentage: 100, Err: err != nil})
	return err
}

func (p *EdgeReleasePromoter) Events() []EdgePromotionEvent {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]EdgePromotionEvent(nil), p.events...)
}

func (p *EdgeReleasePromoter) record(event EdgePromotionEvent) {
	p.mu.Lock()
	p.events = append(p.events, event)
	p.mu.Unlock()
}

func (p *EdgeReleasePromoter) workerDeclared(service string) bool {
	for _, route := range p.zone.WorkerRoutes {
		if route.Script == service {
			return true
		}
	}
	return false
}

func (p *EdgeReleasePromoter) artifact(ctx context.Context, service, digest string) ([]byte, error) {
	body, err := p.artifacts.EdgeArtifact(ctx, service, digest)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || !sameEdgeDigest(edgeDigest(body), digest) {
		return nil, errors.New("cloudflare: edge artifact bytes do not match the requested digest")
	}
	return body, nil
}

func (p *EdgeReleasePromoter) ensureWorkerVersion(ctx context.Context, service, digest string, body []byte) (WorkerVersion, error) {
	versions, err := p.client.ListWorkerVersions(ctx, service)
	if err != nil {
		return WorkerVersion{}, err
	}
	for _, version := range versions {
		if sameEdgeDigest(version.Digest, digest) {
			return version, nil
		}
	}
	return p.client.UploadWorkerVersion(ctx, service, digest, body)
}

// The wire contracts follow Cloudflare's Workers versions API and Wrangler's
// ApiVersion type. Cloudflare returns release annotations, not source digests.
func (c *Client) ListWorkerVersions(ctx context.Context, script string) ([]WorkerVersion, error) {
	if c == nil || strings.TrimSpace(script) == "" {
		return nil, errors.New("cloudflare: Worker script is required")
	}
	var result []WorkerVersion
	for page := 1; ; page++ {
		var batch struct {
			Items []WorkerVersion `json:"items"`
		}
		path := c.accountPath("/workers/scripts/" + url.PathEscape(script) + "/versions?per_page=100&page=" + fmt.Sprint(page))
		info, err := c.doPage(ctx, "list Worker versions", http.MethodGet, path, nil, &batch)
		if isCloudflareNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		result = append(result, batch.Items...)
		if info == nil || info.TotalPages <= page {
			break
		}
	}
	return result, nil
}

func (c *Client) UploadWorkerVersion(ctx context.Context, script, digest string, source []byte) (WorkerVersion, error) {
	if c == nil || strings.TrimSpace(script) == "" || len(source) == 0 || !sameEdgeDigest(edgeDigest(source), digest) {
		return WorkerVersion{}, errors.New("cloudflare: Worker version identity is invalid")
	}
	metadata := map[string]any{"main_module": "worker.js", "annotations": map[string]string{"workers/message": workerDigestAnnotationPrefix + edgeDigest(source)}}
	payload, contentType, err := edgeMultipart("worker.js", "worker.js", metadata, source)
	if err != nil {
		return WorkerVersion{}, err
	}
	path := c.accountPath("/workers/scripts/" + url.PathEscape(script) + "/versions")
	var version WorkerVersion
	if err := c.doEdgeMultipart(ctx, "upload Worker version", http.MethodPost, path, payload, contentType, &version); err != nil {
		return WorkerVersion{}, err
	}
	if version.ID == "" {
		return WorkerVersion{}, errors.New("cloudflare: Worker upload response identity is invalid")
	}
	// Read the immutable version independently before making it eligible for traffic.
	uploadedID := version.ID
	if err := c.do(ctx, "read Worker version", http.MethodGet, path+"/"+url.PathEscape(uploadedID), nil, &version); err != nil {
		return WorkerVersion{}, err
	}
	if version.ID != uploadedID {
		return WorkerVersion{}, errors.New("cloudflare: Worker detail returned a different version")
	}
	if !sameEdgeDigest(version.Digest, digest) {
		return WorkerVersion{}, errors.New("cloudflare: Worker version annotation does not match artifact")
	}
	return version, nil
}

func (c *Client) ActiveWorkerVersion(ctx context.Context, script string) (WorkerVersion, error) {
	deployments, err := c.ListWorkerDeployments(ctx, script)
	if err != nil {
		return WorkerVersion{}, err
	}
	if len(deployments) == 0 {
		return WorkerVersion{}, ErrNotFound
	}
	if len(deployments[0].Versions) != 1 || deployments[0].Versions[0].Percentage != 100 {
		return WorkerVersion{}, errors.New("cloudflare: Worker has a partial deployment")
	}
	var version WorkerVersion
	err = c.do(ctx, "read deployed Worker version", http.MethodGet, c.accountPath("/workers/scripts/"+url.PathEscape(script)+"/versions/"+url.PathEscape(deployments[0].Versions[0].VersionID)), nil, &version)
	if err == nil && version.ID != deployments[0].Versions[0].VersionID {
		return WorkerVersion{}, errors.New("cloudflare: Worker detail returned a different version")
	}
	return version, err
}

// A failed response can leave a partial deployment serving. The most recent
// full deployment is the durable predecessor. An unknown
// partial deployment fails closed until the durable rollout state identifies
// the exact prior allocation.
func (c *Client) workerPromotionBaseline(ctx context.Context, script string) (WorkerVersion, error) {
	deployments, err := c.ListWorkerDeployments(ctx, script)
	if err != nil {
		return WorkerVersion{}, err
	}
	for _, deployment := range deployments {
		if len(deployment.Versions) != 1 || deployment.Versions[0].Percentage != 100 {
			continue
		}
		var version WorkerVersion
		err := c.do(ctx, "read Worker promotion baseline", http.MethodGet, c.accountPath("/workers/scripts/"+url.PathEscape(script)+"/versions/"+url.PathEscape(deployment.Versions[0].VersionID)), nil, &version)
		if err == nil && version.ID != deployment.Versions[0].VersionID {
			return WorkerVersion{}, errors.New("cloudflare: Worker detail returned a different version")
		}
		return version, err
	}
	if len(deployments) != 0 {
		return WorkerVersion{}, errors.New("cloudflare: partial deployment has no full predecessor")
	}
	return WorkerVersion{}, ErrNotFound
}

func (c *Client) CreateWorkerDeployment(ctx context.Context, script string, versions []WorkerDeploymentVersion) (WorkerDeployment, error) {
	if c == nil || strings.TrimSpace(script) == "" || len(versions) == 0 {
		return WorkerDeployment{}, errors.New("cloudflare: Worker deployment is incomplete")
	}
	total := 0
	seen := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		if version.VersionID == "" || version.Percentage <= 0 || version.Percentage > 100 {
			return WorkerDeployment{}, errors.New("cloudflare: Worker deployment percentage is invalid")
		}
		if _, ok := seen[version.VersionID]; ok {
			return WorkerDeployment{}, errors.New("cloudflare: Worker deployment repeats a version")
		}
		seen[version.VersionID] = struct{}{}
		total += version.Percentage
	}
	if total != 100 {
		return WorkerDeployment{}, errors.New("cloudflare: Worker deployment percentages must total 100")
	}
	// Include the observed predecessor in the logical mutation identity. A
	// later rollback may legitimately submit the same 100% target as an old
	// deployment; it must not replay that historical response and leave the
	// newer deployment serving.
	predecessor := "initial"
	deployments, err := c.ListWorkerDeployments(ctx, script)
	if err != nil {
		return WorkerDeployment{}, err
	}
	if len(deployments) != 0 {
		predecessor = deployments[0].ID
	}
	path := c.accountPath("/workers/scripts/" + url.PathEscape(script) + "/deployments")
	var deployment WorkerDeployment
	body := map[string]any{"strategy": "percentage", "versions": versions, "annotations": map[string]string{"workers/message": "terrascale-after-" + predecessor}}
	if err := c.do(ctx, "create Worker deployment", http.MethodPost, path, body, &deployment); err != nil {
		return WorkerDeployment{}, err
	}
	if deployment.ID == "" || !sameWorkerAllocation(deployment.Versions, versions) {
		return WorkerDeployment{}, errors.New("cloudflare: Worker deployment response is invalid")
	}
	// A response is not proof that the requested allocation is serving.
	observed, err := c.ListWorkerDeployments(ctx, script)
	if err != nil {
		return WorkerDeployment{}, err
	}
	if len(observed) == 0 || observed[0].ID != deployment.ID || !sameWorkerAllocation(observed[0].Versions, versions) {
		return WorkerDeployment{}, errors.New("cloudflare: Worker deployment readback does not match requested traffic")
	}
	return deployment, nil
}

func sameWorkerAllocation(left, right []WorkerDeploymentVersion) bool {
	if len(left) != len(right) {
		return false
	}
	allocations := make(map[string]int, len(left))
	for _, item := range left {
		if _, ok := allocations[item.VersionID]; ok {
			return false
		}
		allocations[item.VersionID] = item.Percentage
	}
	for _, item := range right {
		if allocations[item.VersionID] != item.Percentage {
			return false
		}
	}
	return true
}

func (c *Client) ListWorkerDeployments(ctx context.Context, script string) ([]WorkerDeployment, error) {
	if c == nil || strings.TrimSpace(script) == "" {
		return nil, errors.New("cloudflare: Worker script is required")
	}
	var result struct {
		Deployments []WorkerDeployment `json:"deployments"`
	}
	err := c.do(ctx, "list Worker deployments", http.MethodGet, c.accountPath("/workers/scripts/"+url.PathEscape(script)+"/deployments"), nil, &result)
	if isCloudflareNotFound(err) {
		return nil, nil
	}
	// The provider returns newest first. UUID lexical order is not chronology.
	return result.Deployments, err
}

func (c *Client) PutSnippetCode(ctx context.Context, snippet, digest string, source []byte) error {
	if c == nil || strings.TrimSpace(snippet) == "" || len(source) == 0 || !sameEdgeDigest(edgeDigest(source), digest) {
		return errors.New("cloudflare: Snippet code identity is invalid")
	}
	payload, contentType, err := edgeMultipart("files", "snippet.js", map[string]string{"main_module": "snippet.js"}, source)
	if err != nil {
		return err
	}
	return c.doEdgeMultipart(ctx, "deploy Snippet code", http.MethodPut, c.zonePath("/snippets/"+url.PathEscape(snippet)), payload, contentType, nil)
}

func (c *Client) SnippetCode(ctx context.Context, snippet string) (SnippetCode, error) {
	if c == nil || strings.TrimSpace(snippet) == "" {
		return SnippetCode{}, errors.New("cloudflare: Snippet name is required")
	}
	status, headers, raw, err := c.roundtripContent(ctx, "read Snippet content", http.MethodGet, c.zonePath("/snippets/"+url.PathEscape(snippet)+"/content"), nil, "", "multipart/form-data")
	if err != nil {
		return SnippetCode{}, err
	}
	if status == http.StatusNotFound {
		return SnippetCode{}, ErrNotFound
	}
	if status < 200 || status >= 300 {
		return SnippetCode{}, apiErrorFromEnvelope("read Snippet content", status, raw)
	}
	source, err := singleEdgeModule(headers.Get("Content-Type"), raw, "snippet.js")
	if err != nil {
		return SnippetCode{}, err
	}
	return SnippetCode{Name: snippet, Digest: edgeDigest(source)}, nil
}

func edgeMultipart(field, filename string, metadata any, source []byte) ([]byte, string, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, "", err
	}
	header := textproto.MIMEHeader{"Content-Disposition": {`form-data; name="metadata"`}, "Content-Type": {"application/json"}}
	part, err := writer.CreatePart(header)
	if err != nil {
		return nil, "", err
	}
	if _, err = part.Write(encoded); err != nil {
		return nil, "", err
	}
	header = textproto.MIMEHeader{"Content-Disposition": {fmt.Sprintf(`form-data; name="%s"; filename="%s"`, field, filename)}, "Content-Type": {"application/javascript+module"}}
	part, err = writer.CreatePart(header)
	if err != nil {
		return nil, "", err
	}
	if _, err = part.Write(source); err != nil {
		return nil, "", err
	}
	if err = writer.Close(); err != nil {
		return nil, "", err
	}
	return buffer.Bytes(), writer.FormDataContentType(), nil
}

func singleEdgeModule(contentType string, raw []byte, filename string) ([]byte, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return nil, errors.New("cloudflare: expected multipart code content")
	}
	reader := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
	var source []byte
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("cloudflare: malformed multipart code content")
		}
		body, err := io.ReadAll(part)
		if err != nil {
			return nil, errors.New("cloudflare: unreadable code module")
		}
		if part.FormName() == "metadata" && part.FileName() == "" {
			continue
		}
		if part.FileName() != filename || source != nil {
			return nil, errors.New("cloudflare: unexpected code module")
		}
		source = body
	}
	if len(source) == 0 {
		return nil, errors.New("cloudflare: code module is missing")
	}
	return source, nil
}

func (c *Client) doEdgeMultipart(ctx context.Context, op, method, path string, payload []byte, contentType string, out any) error {
	status, _, raw, err := c.roundtripContent(ctx, op, method, path, payload, contentType, "application/json")
	if err != nil {
		return err
	}
	var env envelope
	if json.Unmarshal(raw, &env) != nil {
		return &APIError{Op: op, Status: status, Message: "malformed response envelope"}
	}
	if status < 200 || status >= 300 || !env.Success {
		return apiErrorFromEnvelope(op, status, raw)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// ReconcileSnippetRules runs the production Snippet rule planner and applies
// only the named declared Snippet. It exists so delivery can coordinate code
// activation with its rule without reconciling unrelated zone resources.
func ReconcileSnippetRules(ctx context.Context, client *Client, zone *Zone, snippet string) error {
	if client == nil || zone == nil || strings.TrimSpace(snippet) == "" {
		return errors.New("cloudflare: Snippet rule reconciliation is incomplete")
	}
	if err := zone.validateGateDeclaration(); err != nil {
		return err
	}
	filtered := *zone
	filtered.SnippetRules = nil
	for _, rule := range zone.SnippetRules {
		if rule.SnippetName == snippet {
			filtered.SnippetRules = append(filtered.SnippetRules, rule)
		}
	}
	if len(filtered.SnippetRules) != 1 {
		return errors.New("cloudflare: requested Snippet has no unique declared rule")
	}
	plan := &Plan{Zone: zone.ZoneName}
	if err := filtered.reconcileSnippets(ctx, client, plan); err != nil {
		return err
	}
	return Apply(ctx, plan)
}

func edgeDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sameEdgeDigest(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func isCloudflareNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}
