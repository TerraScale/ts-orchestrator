package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const edgeOperationPollInterval = 250 * time.Millisecond

// EdgeArtifactSource retrieves the already verified bytes named by an edge
// delivery digest. Production wires this to the durable regional artifact
// mirror. The promoter verifies the bytes again before a provider mutation.
type EdgeArtifactSource interface {
	EdgeArtifact(context.Context, string, string) ([]byte, error)
}

// WorkerVersion is the provider identity of one uploaded Worker candidate.
type WorkerVersion struct {
	ID        string          `json:"id"`
	Digest    string          `json:"digest"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at,omitempty"`
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
	Status   string                    `json:"status"`
}

// SnippetCode is the provider-observed identity of deployed Snippet source.
// Source bytes are accepted by PutSnippetCode but are never returned.
type SnippetCode struct {
	Name   string `json:"snippet_name"`
	Digest string `json:"digest"`
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
		snippets: snippets, stages: stages,
	}, nil
}

func (p *EdgeReleasePromoter) PromoteWorker(ctx context.Context, service, digest string) error {
	return p.PromoteWorkerGradual(ctx, service, digest)
}

func (p *EdgeReleasePromoter) PromoteWorkerGradual(ctx context.Context, service, digest string) error {
	if p == nil || ctx == nil {
		return errors.New("cloudflare: Worker promotion requires a promoter and context")
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
	active, activeErr := p.client.ActiveWorkerVersion(ctx, service)
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
	}
	active, err = p.client.ActiveWorkerVersion(ctx, service)
	if err != nil {
		return err
	}
	if !sameEdgeDigest(active.Digest, digest) {
		return fmt.Errorf("cloudflare: Worker provider readback digest %q did not reach %q", active.Digest, digest)
	}
	return nil
}

func (p *EdgeReleasePromoter) PromoteSnippet(ctx context.Context, service, digest string) error {
	if p == nil || ctx == nil {
		return errors.New("cloudflare: Snippet promotion requires a promoter and context")
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

func (c *Client) ListWorkerVersions(ctx context.Context, script string) ([]WorkerVersion, error) {
	if c == nil || strings.TrimSpace(script) == "" {
		return nil, errors.New("cloudflare: Worker script is required")
	}
	var result []WorkerVersion
	for page := 1; ; page++ {
		var batch []WorkerVersion
		path := c.accountPath("/workers/scripts/" + url.PathEscape(script) + "/versions?per_page=100&page=" + fmt.Sprint(page))
		info, err := c.doPage(ctx, "list Worker versions", http.MethodGet, path, nil, &batch)
		if err != nil {
			return nil, err
		}
		result = append(result, batch...)
		if info == nil || info.TotalPages <= page {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (c *Client) UploadWorkerVersion(ctx context.Context, script, digest string, source []byte) (WorkerVersion, error) {
	if c == nil || strings.TrimSpace(script) == "" || len(source) == 0 || !sameEdgeDigest(edgeDigest(source), digest) {
		return WorkerVersion{}, errors.New("cloudflare: Worker version identity is invalid")
	}
	body := map[string]any{
		"digest":   digest,
		"metadata": map[string]any{"main_module": "worker.js", "source_base64": base64.StdEncoding.EncodeToString(source)},
	}
	path := c.accountPath("/workers/scripts/" + url.PathEscape(script) + "/versions")
	var version WorkerVersion
	if err := c.doAsync(ctx, "upload Worker version", http.MethodPost, path, body, &version); err != nil {
		return WorkerVersion{}, err
	}
	if version.ID == "" || !sameEdgeDigest(version.Digest, digest) {
		return WorkerVersion{}, errors.New("cloudflare: Worker upload response identity is invalid")
	}
	return version, nil
}

func (c *Client) ActiveWorkerVersion(ctx context.Context, script string) (WorkerVersion, error) {
	if c == nil || strings.TrimSpace(script) == "" {
		return WorkerVersion{}, errors.New("cloudflare: Worker script is required")
	}
	var result WorkerVersion
	err := c.do(ctx, "read active Worker version", http.MethodGet, c.accountPath("/workers/scripts/"+url.PathEscape(script)), nil, &result)
	if isCloudflareNotFound(err) {
		return WorkerVersion{}, ErrNotFound
	}
	return result, err
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
		predecessor = deployments[len(deployments)-1].ID
	}
	path := c.accountPath("/workers/scripts/" + url.PathEscape(script) + "/deployments")
	var deployment WorkerDeployment
	body := map[string]any{"versions": versions, "annotations": map[string]string{"message": "terrascale-after-" + predecessor}}
	if err := c.doAsync(ctx, "create Worker deployment", http.MethodPost, path, body, &deployment); err != nil {
		return WorkerDeployment{}, err
	}
	if deployment.ID == "" || len(deployment.Versions) != len(versions) {
		return WorkerDeployment{}, errors.New("cloudflare: Worker deployment response is invalid")
	}
	return deployment, nil
}

func (c *Client) ListWorkerDeployments(ctx context.Context, script string) ([]WorkerDeployment, error) {
	if c == nil || strings.TrimSpace(script) == "" {
		return nil, errors.New("cloudflare: Worker script is required")
	}
	var result []WorkerDeployment
	for page := 1; ; page++ {
		var batch []WorkerDeployment
		path := c.accountPath("/workers/scripts/" + url.PathEscape(script) + "/deployments?per_page=100&page=" + fmt.Sprint(page))
		info, err := c.doPage(ctx, "list Worker deployments", http.MethodGet, path, nil, &batch)
		if err != nil {
			return nil, err
		}
		result = append(result, batch...)
		if info == nil || info.TotalPages <= page {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (c *Client) PutSnippetCode(ctx context.Context, snippet, digest string, source []byte) error {
	if c == nil || strings.TrimSpace(snippet) == "" || len(source) == 0 || !sameEdgeDigest(edgeDigest(source), digest) {
		return errors.New("cloudflare: Snippet code identity is invalid")
	}
	predecessor := "initial"
	current, err := c.SnippetCode(ctx, snippet)
	if err == nil {
		predecessor = current.Digest
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	path := c.zonePath("/snippets/" + url.PathEscape(snippet))
	return c.do(ctx, "deploy Snippet code", http.MethodPut, path, map[string]string{
		"digest": digest, "source_base64": base64.StdEncoding.EncodeToString(source), "previous_digest": predecessor,
	}, nil)
}

func (c *Client) SnippetCode(ctx context.Context, snippet string) (SnippetCode, error) {
	if c == nil || strings.TrimSpace(snippet) == "" {
		return SnippetCode{}, errors.New("cloudflare: Snippet name is required")
	}
	var result SnippetCode
	err := c.do(ctx, "read Snippet code", http.MethodGet, c.zonePath("/snippets/"+url.PathEscape(snippet)), nil, &result)
	if isCloudflareNotFound(err) {
		return SnippetCode{}, ErrNotFound
	}
	return result, err
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

type asyncEdgeResult struct {
	ID        string                    `json:"id"`
	Status    string                    `json:"status"`
	Digest    string                    `json:"digest,omitempty"`
	Metadata  json.RawMessage           `json:"metadata,omitempty"`
	CreatedAt time.Time                 `json:"created_at,omitempty"`
	Versions  []WorkerDeploymentVersion `json:"versions,omitempty"`
	Result    json.RawMessage           `json:"result,omitempty"`
}

func (c *Client) doAsync(ctx context.Context, op, method, path string, body, out any) error {
	var result asyncEdgeResult
	if err := c.do(ctx, op, method, path, body, &result); err != nil {
		return err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("cloudflare %s: encode result: %w", op, err)
	}
	if result.Status == "pending" {
		raw, err = c.pollEdgeOperation(ctx, result.ID)
		if err != nil {
			return fmt.Errorf("cloudflare %s: %w", op, err)
		}
	} else if len(result.Result) != 0 && string(result.Result) != "null" {
		raw = result.Result
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("cloudflare %s: decode result: %w", op, err)
		}
	}
	return nil
}

func (c *Client) pollEdgeOperation(ctx context.Context, operation string) (json.RawMessage, error) {
	if operation == "" {
		return nil, errors.New("asynchronous operation identity is missing")
	}
	for {
		if err := c.sleep(ctx, edgeOperationPollInterval); err != nil {
			return nil, err
		}
		var result asyncEdgeResult
		if err := c.do(ctx, "poll edge operation", http.MethodGet, "/operations/"+url.PathEscape(operation), nil, &result); err != nil {
			return nil, err
		}
		switch result.Status {
		case "complete":
			if len(result.Result) == 0 || string(result.Result) == "null" {
				return nil, errors.New("asynchronous operation result is missing")
			}
			return result.Result, nil
		case "pending":
		default:
			return nil, errors.New("asynchronous operation status is invalid")
		}
	}
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
