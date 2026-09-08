package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	workerVersionOverrideHeader = "Cloudflare-Workers-Version-Overrides"
	defaultEdgeProbeBodyLimit   = int64(64 << 10)
)

// CanaryEdgeHealthProbe proves the public application route with a
// pre-provisioned tenant-scoped fixture. It performs no mutations.
type CanaryEdgeHealthProbe struct {
	Client          *Client
	HTTPClient      *http.Client
	RouteURL        string
	ProjectID       string
	DatabaseID      string
	CanaryToken     string
	ForeignToken    string
	ExpectedMarker  string
	MinimumRevision int64
	BodyLimit       int64
	// DownstreamService is resolved from the provider deployment at every
	// stage. IDs are never inferred from the primary Worker: Cloudflare version
	// IDs are scoped to each Worker.
	DownstreamService string
}

// EdgeHealthRouter keeps Worker application checks separate from the existing
// Snippet capability-generation check used by package releases.
type EdgeHealthRouter struct {
	Site    EdgeHealthProbe
	Package EdgeHealthProbe
}

func (r EdgeHealthRouter) CheckEdge(ctx context.Context, kind, service, digest string) error {
	var probe EdgeHealthProbe
	switch kind {
	case "site":
		probe = r.Site
	case "package":
		probe = r.Package
	default:
		return errors.New("cloudflare: unsupported edge health kind")
	}
	if probe == nil {
		return errors.New("cloudflare: edge health probe is not configured")
	}
	return probe.CheckEdge(ctx, kind, service, digest)
}

func (p CanaryEdgeHealthProbe) CheckEdge(ctx context.Context, kind, service, digest string) error {
	if kind != "site" {
		return errors.New("cloudflare: canary probe only supports site releases")
	}
	if p.Client == nil || strings.TrimSpace(service) == "" || strings.TrimSpace(digest) == "" || p.CanaryToken == "" || p.ForeignToken == "" || p.ExpectedMarker == "" || p.ProjectID == "" || p.DatabaseID == "" {
		return errors.New("cloudflare: canary probe configuration is incomplete")
	}
	route, err := validateCanaryRoute(p.RouteURL)
	if err != nil {
		return err
	}
	versions, err := p.Client.ListWorkerVersions(ctx, service)
	if err != nil {
		return err
	}
	versionID := ""
	for _, version := range versions {
		if version.Digest == digest {
			versionID = version.ID
			break
		}
	}
	if versionID == "" {
		return errors.New("cloudflare: canary candidate version is not present")
	}
	deployments, err := p.Client.ListWorkerDeployments(ctx, service)
	if err != nil || len(deployments) == 0 {
		return errors.New("cloudflare: canary candidate deployment is unavailable")
	}
	current := deployments[0]
	if !deploymentContains(current, versionID) {
		return errors.New("cloudflare: canary candidate is not in the current deployment")
	}
	candidatePercentage := 0
	candidateEntries := 0
	totalPercentage := 0
	previous := ""
	previousPercentage := 0
	for _, version := range current.Versions {
		totalPercentage += version.Percentage
		if version.VersionID == versionID {
			candidateEntries++
			candidatePercentage = version.Percentage
		} else if version.Percentage > 0 {
			if previous != "" {
				return errors.New("cloudflare: canary deployment has multiple predecessor versions")
			}
			previous = version.VersionID
			previousPercentage = version.Percentage
		}
	}
	if candidateEntries != 1 || totalPercentage != 100 {
		return errors.New("cloudflare: canary deployment allocation is invalid")
	}
	switch candidatePercentage {
	case 10, 50:
		if previous == "" || previousPercentage != 100-candidatePercentage {
			return errors.New("cloudflare: canary deployment allocation is invalid")
		}
	case 100:
		if previous != "" {
			return errors.New("cloudflare: canary deployment allocation is invalid")
		}
	default:
		return errors.New("cloudflare: canary deployment allocation is invalid")
	}
	ids := []string{versionID}
	downstream := map[string]string{}
	if strings.TrimSpace(p.DownstreamService) != "" {
		if !workerName(p.DownstreamService) {
			return errors.New("cloudflare: downstream Worker binding configuration is incomplete")
		}
		bound, err := p.Client.ListWorkerDeployments(ctx, p.DownstreamService)
		if err != nil || len(bound) == 0 {
			return errors.New("cloudflare: downstream Worker deployment is unavailable")
		}
		boundVersions, err := p.Client.ListWorkerVersions(ctx, p.DownstreamService)
		if err != nil {
			return errors.New("cloudflare: downstream Worker versions are unavailable")
		}
		downstreamCandidateID, downstreamPreviousID, ok := resolveDownstreamAllocation(bound[0], boundVersions, digest, candidatePercentage, previousPercentage)
		if !ok {
			return errors.New("cloudflare: downstream Worker allocation does not match the current edge stage")
		}
		downstream[versionID] = downstreamCandidateID
		if previous != "" {
			downstream[previous] = downstreamPreviousID
		}
	}
	if previous != "" {
		ids = append(ids, previous)
	}
	for _, id := range ids {
		if err := p.checkVersion(ctx, route, id, downstream[id], p.CanaryToken, true); err != nil {
			return err
		}
		if err := p.checkVersion(ctx, route, id, downstream[id], p.ForeignToken, false); err != nil {
			return err
		}
	}
	return nil
}

func (p CanaryEdgeHealthProbe) checkVersion(ctx context.Context, route, versionID, downstreamID, token string, allowed bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, route, nil)
	if err != nil {
		return errors.New("cloudflare: canary probe request is invalid")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	override := `ts-proxy="` + versionID + `"`
	if downstreamID != "" {
		override += `, ` + p.DownstreamService + `="` + downstreamID + `"`
	}
	req.Header.Set(workerVersionOverrideHeader, override)
	req.Header.Set("Cache-Control", "no-store")
	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	copy := *client
	if copy.Timeout <= 0 {
		copy.Timeout = 10 * time.Second
	}
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copy.Do(req)
	if err != nil {
		return errors.New("cloudflare: canary probe request failed")
	}
	defer response.Body.Close()
	limit := p.BodyLimit
	if limit <= 0 {
		limit = defaultEdgeProbeBodyLimit
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if readErr != nil || int64(len(body)) > limit {
		return errors.New("cloudflare: canary probe response exceeded its bound")
	}
	if !allowed {
		if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
			return errors.New("cloudflare: foreign canary credential was accepted")
		}
		if strings.Contains(string(body), p.ProjectID) || strings.Contains(string(body), p.DatabaseID) || strings.Contains(string(body), p.ExpectedMarker) {
			return errors.New("cloudflare: foreign canary response disclosed fixture data")
		}
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflare: canary probe returned status %s", response.Status)
	}
	var result struct {
		ProjectID  string `json:"projectId"`
		DatabaseID string `json:"databaseId"`
		Marker     string `json:"marker"`
		Revision   int64  `json:"revision"`
	}
	if json.Unmarshal(body, &result) != nil || result.ProjectID != p.ProjectID || result.DatabaseID != p.DatabaseID || result.Marker != p.ExpectedMarker || result.Revision < p.MinimumRevision {
		return errors.New("cloudflare: canary probe response did not match the fixture")
	}
	return nil
}

func validateCanaryRoute(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("cloudflare: canary probe route must be an authenticated HTTPS URL without query state")
	}
	return parsed.String(), nil
}

func deploymentContains(deployment WorkerDeployment, versionID string) bool {
	for _, version := range deployment.Versions {
		if version.VersionID == versionID && version.Percentage > 0 {
			return true
		}
	}
	return false
}

func resolveDownstreamAllocation(deployment WorkerDeployment, versions []WorkerVersion, digest string, candidatePercentage, previousPercentage int) (string, string, bool) {
	digests := make(map[string]string, len(versions))
	for _, version := range versions {
		digests[version.ID] = version.Digest
	}
	var candidateID, previousID string
	total := 0
	for _, version := range deployment.Versions {
		if version.Percentage <= 0 {
			continue
		}
		total += version.Percentage
		if version.Percentage != candidatePercentage && version.Percentage != previousPercentage {
			return "", "", false
		}
		if digests[version.VersionID] == digest {
			if candidateID != "" || version.Percentage != candidatePercentage {
				return "", "", false
			}
			candidateID = version.VersionID
		} else {
			if previousID != "" || version.Percentage != previousPercentage {
				return "", "", false
			}
			previousID = version.VersionID
		}
	}
	if total != 100 || candidateID == "" {
		return "", "", false
	}
	if candidatePercentage == 100 {
		return candidateID, "", previousID == ""
	}
	return candidateID, previousID, previousID != ""
}

func workerName(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (index > 0 && char >= '0' && char <= '9') || (index > 0 && char == '-') {
			continue
		}
		return false
	}
	return true
}
