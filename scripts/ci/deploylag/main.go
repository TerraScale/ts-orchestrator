// The scheduled deployment guard compares qualified main builds with live fleet proofs.
package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/atlas"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
)

const forge = "https://git.terrascale.tech/api/v1/repos/TerraScale/"
const qualifiedContext = "deployment/qualified"
const alertTitle = "TS-768: Deployment lag exceeds 30 minutes"
const lagLimit = 30 * time.Minute
const collectionBudget = 7 * time.Minute
const notificationBudget = 90 * time.Second

var services = []string{"ts-orchestrator", "terrabase", "ts-auth", "ts-atlas", "ts-status", "ts-dashboard"}

type commit struct {
	SHA     string    `json:"sha"`
	GreenAt time.Time `json:"-"`
}

type observation struct {
	Service    string    `json:"service"`
	Region     string    `json:"region"`
	Target     string    `json:"target"`
	Version    string    `json:"version"`
	Status     int       `json:"status"`
	ObservedAt time.Time `json:"observedAt"`
}

type api struct {
	client                *http.Client
	readToken, writeToken string
}

func (a api) request(ctx context.Context, method, url, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		wire, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(wire)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	response, err := a.client.Do(req)
	if err != nil {
		return errors.New("deployment guard HTTP request did not complete")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("deployment guard HTTP status %d", response.StatusCode)
	}
	if output == nil {
		return nil
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(wire, output)
}

// Main ancestry, rather than workflow outcome, survives a failed deployment.
// Bound API work; an exhausted history fails visibly instead of assuming green.
func (a api) history(ctx context.Context, service string) ([]commit, error) {
	var commits []commit
	if err := a.request(ctx, "GET", forge+service+"/commits?sha=main&limit=50", a.readToken, nil, &commits); err != nil {
		return nil, err
	}
	found := false
	for i := range commits {
		for page := 1; ; page++ {
			var statuses []struct {
				Context   string    `json:"context"`
				State     string    `json:"status"`
				CreatedAt time.Time `json:"created_at"`
			}
			url := fmt.Sprintf("%s%s/commits/%s/statuses?limit=50&page=%d", forge, service, commits[i].SHA, page)
			if err := a.request(ctx, "GET", url, a.readToken, nil, &statuses); err != nil {
				return nil, err
			}
			for _, status := range statuses {
				if status.Context == qualifiedContext && status.State == "success" &&
					!status.CreatedAt.IsZero() && (commits[i].GreenAt.IsZero() || status.CreatedAt.Before(commits[i].GreenAt)) {
					commits[i].GreenAt = status.CreatedAt
					found = true
				}
			}
			if len(statuses) < 50 {
				break
			}
		}
	}
	if !found {
		return nil, errors.New("no qualified-main marker in the latest 50 commits; verify pipeline markers")
	}
	return commits, nil
}

// Do not reset the clock when another green build overtakes a pending build.
func pending(history []commit, version string, now time.Time) (commit, time.Duration, error) {
	var newest commit
	var oldest time.Time
	found := false
	for _, entry := range history {
		if entry.SHA == version {
			found = true
			break
		}
		if entry.GreenAt.IsZero() {
			continue
		}
		if entry.GreenAt.After(now.Add(30 * time.Second)) {
			return commit{}, 0, errors.New("qualified-main timestamp is ahead of the clock")
		}
		if newest.SHA == "" {
			newest = entry
		}
		if oldest.IsZero() || entry.GreenAt.Before(oldest) {
			oldest = entry.GreenAt
		}
	}
	if !found {
		return commit{}, 0, errors.New("incomplete qualified-main history: deployed revision is outside the checked ancestry")
	}
	if oldest.IsZero() {
		return newest, 0, nil
	}
	return newest, now.Sub(oldest), nil
}

func native(ctx context.Context, service, region string) (observation, error) {
	result := observation{Service: service, Region: region, Target: "fleet"}
	factory, err := ociclient.OperatorConfig(catalog.OCIRegion(region))
	if err != nil {
		return result, errors.New("OCI guard credentials are unavailable")
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		return result, errors.New("OCI object client is unavailable")
	}
	bucket, err := releasechannel.BucketName(region)
	if err != nil {
		return result, err
	}
	location := releasechannel.Location{Client: client, Namespace: os.Getenv("TS_OBJECT_NAMESPACE"), Bucket: bucket}
	var revision, cell, schema string
	var state releasechannel.State
	var updated time.Time
	var found bool
	if service == "ts-orchestrator" {
		var status releasechannel.Status
		status, found, err = releasechannel.ReadStatus(ctx, location)
		revision, cell, schema, state, updated = status.SourceRevision, status.Cell, status.Schema, status.State, status.UpdatedAt
		if schema != releasechannel.StatusSchema {
			found = false
		}
	} else {
		var status releasechannel.ServiceStatus
		status, found, err = releasechannel.ReadServiceStatus(ctx, location, service)
		revision, cell, schema, state, updated = status.SourceRevision, status.Cell, status.Schema, status.State, status.UpdatedAt
		if schema != releasechannel.ServiceStatusSchema || status.Role != service {
			found = false
		}
	}
	if err != nil {
		return result, errors.New("regional fleet proof could not be read")
	}
	result.ObservedAt = updated
	if found && cell == region && state == releasechannel.StateComplete {
		result.Version, result.Status = revision, 200
	}
	return result, nil
}

func proofError(proof observation, now time.Time) error {
	if proof.Status != http.StatusOK || !release.ValidSourceRevision(proof.Version) {
		return errors.New("live deployment proof is missing or invalid")
	}
	if age := now.Sub(proof.ObservedAt); age < -30*time.Second || age > releasechannel.MaxPinAge {
		return errors.New("live deployment proof timestamp is stale or ahead of the clock")
	}
	return nil
}

func (a api) alert(ctx context.Context, findings []string) error {
	base := forge + "ts-orchestrator/issues"
	slices.Sort(findings)
	body := "@mariogk Automatic deployment guard: a qualified main build has not reached every region within 30 minutes, or its live proof is unavailable.\n\n"
	body += strings.Join(findings, "\n") + "\n\nPart of TS-768. See docs/deploy-pipeline.md and the scheduled deploy-lag.yml run."
	for page := 1; ; page++ {
		var issues []struct {
			Number int    `json:"number"`
			Title  string `json:"title"`
			Body   string `json:"body"`
		}
		if err := a.request(ctx, "GET", fmt.Sprintf("%s?state=open&type=issues&limit=50&page=%d", base, page),
			a.writeToken, nil, &issues); err != nil {
			return err
		}
		for _, issue := range issues {
			if issue.Title != alertTitle {
				continue
			}
			if len(findings) == 0 {
				return a.request(ctx, "PATCH", fmt.Sprintf("%s/%d", base, issue.Number), a.writeToken, map[string]string{"state": "closed"}, nil)
			}
			if issue.Body == body {
				return nil
			}
			return a.request(ctx, "PATCH", fmt.Sprintf("%s/%d", base, issue.Number), a.writeToken, map[string]string{"body": body}, nil)
		}
		if len(issues) == 0 {
			break
		}
	}
	if len(findings) == 0 {
		return nil
	}
	return a.request(ctx, "POST", base, a.writeToken, map[string]any{
		"title": alertTitle, "body": body, "assignees": []string{"mariogk"},
	}, nil)
}

func run(ctx context.Context, a api, now func() time.Time,
	readNative func(context.Context, string, string) (observation, error), notify bool) error {
	collectCtx, cancelCollection := context.WithTimeout(ctx, collectionBudget)
	defer cancelCollection()
	regions, discoveryErr := atlas.DiscoverServingCells(collectCtx, a.client)
	histories := make(map[string][]commit)
	var findings []string
	if discoveryErr != nil {
		findings = append(findings, "- Serving-region discovery unavailable: "+discoveryErr.Error())
	}
	var lock sync.Mutex
	var workers sync.WaitGroup
	for _, service := range services {
		workers.Go(func() {
			history, err := a.history(collectCtx, service)
			lock.Lock()
			defer lock.Unlock()
			if err != nil {
				findings = append(findings, "- "+service+": qualified-main history unavailable")
				return
			}
			histories[service] = history
		})
	}
	workers.Wait()
	var observed []observation
	for _, service := range services[:3] {
		for _, region := range regions {
			workers.Go(func() {
				proof, err := readNative(collectCtx, service, region)
				lock.Lock()
				defer lock.Unlock()
				if err != nil {
					findings = append(findings, "- "+service+" "+region+": live fleet proof unavailable")
					return
				}
				observed = append(observed, proof)
			})
		}
	}
	var edge []observation
	err := a.request(collectCtx, "GET", "https://status.terrascale.tech/api/v1/deployments", "", nil, &edge)
	workers.Wait()
	cancelCollection()
	if err != nil {
		findings = append(findings, "- Edge deployment observations unavailable from ts-status")
	}
	// Require every discovered region, including its Status vantage build.
	for _, service := range services[3:] {
		for _, region := range regions {
			targets := []string{"service"}
			if service == "ts-status" {
				targets = append(targets, "vantage")
			}
			for _, target := range targets {
				proof := observation{Service: service, Region: region, Target: target}
				for _, row := range edge {
					if row.Service == service && row.Region == region && row.Target == target {
						proof = row
						break
					}
				}
				observed = append(observed, proof)
			}
		}
	}
	for _, proof := range observed {
		checkedAt := now()
		if err := proofError(proof, checkedAt); err != nil {
			findings = append(findings, "- "+proof.Service+" "+proof.Region+" "+proof.Target+": "+err.Error())
			continue
		}
		history, ok := histories[proof.Service]
		if !ok {
			continue
		}
		target, lag, err := pending(history, proof.Version, checkedAt)
		if err != nil {
			findings = append(findings, "- "+proof.Service+" "+proof.Region+": "+err.Error())
			continue
		}
		fmt.Printf("%s %s %s deployed=%s target=%s oldest-pending=%s\n",
			proof.Service, proof.Region, proof.Target, proof.Version, target.SHA, lag.Round(time.Second))
		if lag >= lagLimit {
			findings = append(findings, fmt.Sprintf("- %s %s %s: target `%s`; deployed `%s`; qualified build overdue.",
				proof.Service, proof.Region, proof.Target, target.SHA, proof.Version))
		}
	}
	if notify {
		// Collection failure still gets a bounded opportunity to deliver its alert.
		alertCtx, cancelAlert := context.WithTimeout(context.WithoutCancel(ctx), notificationBudget)
		defer cancelAlert()
		if err := a.alert(alertCtx, findings); err != nil {
			return fmt.Errorf("deployment alert could not be delivered: %w", err)
		}
	}
	if len(findings) > 0 {
		return fmt.Errorf("deployment guard found %d lag/proof failures", len(findings))
	}
	return nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	a := api{client: &http.Client{Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		readToken: os.Getenv("FORGEJO_READ_TOKEN"), writeToken: os.Getenv("FORGEJO_WRITE_TOKEN")}
	if a.readToken == "" || (os.Getenv("TS_DEPLOY_GUARD_DRY_RUN") != "1" && a.writeToken == "") {
		fmt.Fprintln(os.Stderr, "deployment guard requires Forgejo read and alert-write credentials")
		os.Exit(1)
	}
	if err := run(ctx, a, time.Now, native, os.Getenv("TS_DEPLOY_GUARD_DRY_RUN") != "1"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
