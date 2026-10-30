// The scheduled deployment guard fails when a main build was published but has
// not been released to the regions within 30 minutes (TS-768, TS-764).
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

const forge = "https://api.github.com/repos/TerraScale/"
const alertTitle = "TS-768: Deployment lag exceeds 30 minutes"
const lagLimit = 30 * time.Minute

// app is a service ts-orch releases from the image job of a repository's main
// push: the job's "Release to every region" step is its deployment.
type app struct{ service, repo, workflow, job string }

var apps = []app{
	{"terrabase", "terrascale", "ci.yml", "main (terrabase)"},
	{"ts-auth", "terrascale", "ci.yml", "main (auth)"},
	{"ts-dashboard", "terrascale", "images-ghcr.yml", "Publish and release"},
}

// held services are released by hand for now: reported, never a failure.
var held = map[string]string{
	"terrabase": "released by hand until the TerraBase batch-2 wipe (terrascale #408, #398)",
}

type api struct {
	client                *http.Client
	readToken, writeToken string
}

// Reads are idempotent: a transient GitHub failure must not turn readable
// deployment history into a missing-proof alert. Writes are never retried.
func (a api) request(ctx context.Context, method, url, token string, input, output any) error {
	for attempt := 0; ; attempt++ {
		err := a.requestOnce(ctx, method, url, token, input, output)
		var transient *transientReadError
		if method != http.MethodGet || !errors.As(err, &transient) || attempt == 2 {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type transientReadError struct{ error }

func (a api) requestOnce(ctx context.Context, method, url, token string, input, output any) error {
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
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	response, err := a.client.Do(req)
	if err != nil {
		return &transientReadError{errors.New("deployment guard HTTP request did not complete")}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := fmt.Errorf("deployment guard HTTP status %d", response.StatusCode)
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return &transientReadError{err}
		}
		return err
	}
	if output == nil {
		return nil
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return &transientReadError{errors.New("deployment guard response could not be read")}
	}
	return json.Unmarshal(wire, output)
}

// orch reports ts-orchestrator main commits older than lagLimit that no
// deploy/release-push has delivered: walking from the newest commit, a
// successful release-push delivers it and everything older; a skipped one
// with a green test check had nothing to publish.
func (a api) orch(ctx context.Context, now time.Time) ([]string, error) {
	var commits []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := a.request(ctx, "GET", forge+"ts-orchestrator/commits?sha=main&per_page=30", a.readToken, nil, &commits); err != nil {
		return nil, err
	}
	var oldest string
	for _, c := range commits {
		conclusion := func(name string) (string, error) {
			var runs struct {
				CheckRuns []struct {
					Status     string `json:"status"`
					Conclusion string `json:"conclusion"`
				} `json:"check_runs"`
			}
			err := a.request(ctx, "GET", forge+"ts-orchestrator/commits/"+c.SHA+"/check-runs?check_name="+name, a.readToken, nil, &runs)
			if err != nil || len(runs.CheckRuns) == 0 {
				return "", err
			}
			return cmp.Or(runs.CheckRuns[0].Conclusion, runs.CheckRuns[0].Status), nil
		}
		release, err := conclusion("deploy/release-push")
		if err != nil {
			return nil, err
		}
		if release == "success" {
			break
		}
		if release == "skipped" {
			if test, err := conclusion("test"); err != nil {
				return nil, err
			} else if test == "success" {
				continue
			}
		}
		if now.Sub(c.Commit.Committer.Date) >= lagLimit {
			oldest = fmt.Sprintf("- ts-orchestrator: main `%s` (%s ago) is not released to the regions; release-push: %s",
				c.SHA, now.Sub(c.Commit.Committer.Date).Round(time.Minute), cmp.Or(release, "missing"))
		}
	}
	if oldest == "" {
		return nil, nil
	}
	return []string{oldest}, nil
}

// release reports an app whose oldest main image published since its last
// release has waited lagLimit or longer: a newer build never resets the clock.
func (a api) release(ctx context.Context, x app, now time.Time) ([]string, error) {
	var runs struct {
		WorkflowRuns []struct {
			ID      int64  `json:"id"`
			HeadSHA string `json:"head_sha"`
		} `json:"workflow_runs"`
	}
	// Dashboard releases also originate from qualified manual and CI-completion
	// runs. Their successful publication step proves an image exists to release.
	query := "?branch=main&event=push&per_page=20"
	if x.service == "ts-dashboard" {
		query = "?branch=main&per_page=20"
	}
	url := fmt.Sprintf("%s%s/actions/workflows/%s/runs%s", forge, x.repo, x.workflow, query)
	if err := a.request(ctx, "GET", url, a.readToken, nil, &runs); err != nil {
		return nil, err
	}
	var finding string
	for _, run := range runs.WorkflowRuns {
		var jobs struct {
			Jobs []struct {
				Name  string `json:"name"`
				Steps []struct {
					Name        string    `json:"name"`
					Status      string    `json:"status"`
					Conclusion  string    `json:"conclusion"`
					CompletedAt time.Time `json:"completed_at"`
				} `json:"steps"`
			} `json:"jobs"`
		}
		if err := a.request(ctx, "GET", fmt.Sprintf("%s%s/actions/runs/%d/jobs?per_page=50", forge, x.repo, run.ID), a.readToken, nil, &jobs); err != nil {
			return nil, err
		}
		for _, job := range jobs.Jobs {
			if job.Name != x.job {
				continue
			}
			var published time.Time
			released := "missing"
			for _, step := range job.Steps {
				// The last build-push step publishes; earlier ones only build.
				if strings.HasPrefix(step.Name, "Run docker/build-push-action") && step.Conclusion == "success" {
					published = step.CompletedAt
				}
				if step.Name == "Release to every region" {
					released = cmp.Or(step.Conclusion, step.Status)
				}
			}
			switch {
			case published.IsZero():
				// This run published no image for the service.
			case released == "success":
				return report(x, finding), nil
			case now.Sub(published) >= lagLimit:
				finding = fmt.Sprintf("- %s: image of %s main `%s` published %s ago, release: %s",
					x.service, x.repo, run.HeadSHA, now.Sub(published).Round(time.Minute), released)
			}
		}
	}
	return report(x, finding), nil
}

// report turns a held service's finding into a log line.
func report(x app, finding string) []string {
	if finding == "" {
		return nil
	}
	if reason, ok := held[x.service]; ok {
		fmt.Println("held:", finding[2:], "-", reason)
		return nil
	}
	return []string{finding}
}

func (a api) alert(ctx context.Context, findings []string) error {
	base := forge + "ts-orchestrator/issues"
	slices.Sort(findings)
	body := "@mariogk Automatic deployment guard: a main build was published but not released to the regions within 30 minutes, or its release history is unreadable.\n\n"
	body += strings.Join(findings, "\n") + "\n\nPart of TS-768. See docs/deploy-pipeline.md and the scheduled deploy-lag.yml run."
	for page := 1; ; page++ {
		var issues []struct {
			Number      int       `json:"number"`
			Title       string    `json:"title"`
			Body        string    `json:"body"`
			PullRequest *struct{} `json:"pull_request"`
		}
		if err := a.request(ctx, "GET", fmt.Sprintf("%s?state=open&per_page=50&page=%d", base, page),
			a.writeToken, nil, &issues); err != nil {
			return err
		}
		for _, issue := range issues {
			if issue.PullRequest != nil || issue.Title != alertTitle {
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

func run(ctx context.Context, a api, now func() time.Time, notify bool) error {
	findings, err := a.orch(ctx, now())
	if err != nil {
		findings = append(findings, "- ts-orchestrator: main release history unavailable: "+err.Error())
	}
	for _, x := range apps {
		found, err := a.release(ctx, x, now())
		if err != nil {
			found = []string{"- " + x.service + ": " + x.repo + " image job history unavailable: " + err.Error()}
		}
		findings = append(findings, found...)
	}
	for _, finding := range findings {
		fmt.Println(finding)
	}
	if notify {
		// Collection failure still gets a bounded opportunity to deliver its alert.
		alertCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
		defer cancel()
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
		readToken:  cmp.Or(os.Getenv("GH_READ_TOKEN"), os.Getenv("GH_TOKEN")),
		writeToken: cmp.Or(os.Getenv("GH_WRITE_TOKEN"), os.Getenv("GH_TOKEN"))}
	if a.readToken == "" || (os.Getenv("TS_DEPLOY_GUARD_DRY_RUN") != "1" && a.writeToken == "") {
		fmt.Fprintln(os.Stderr, "deployment guard requires GitHub read and alert-write credentials")
		os.Exit(1)
	}
	if err := run(ctx, a, time.Now, os.Getenv("TS_DEPLOY_GUARD_DRY_RUN") != "1"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
