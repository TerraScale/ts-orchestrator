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
const publishStep = "Build or reuse the target image and publish its main tag"
const releaseStep = "Release to every region"

type app struct {
	service, repo, workflow, jobID, jobName string
}

var apps = []app{
	{"ts-auth", "terrascale", "ci.yml", "main-auth", "main-auth"},
	{"ts-dashboard", "terrascale", "images-ghcr.yml", "image", "Publish and release"},
}

type workflowRun struct {
	ID         int64     `json:"id"`
	HeadSHA    string    `json:"head_sha"`
	HTMLURL    string    `json:"html_url"`
	Conclusion string    `json:"conclusion"`
	CreatedAt  time.Time `json:"created_at"`
}

type step struct {
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Conclusion  string    `json:"conclusion"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

type job struct {
	JobID      string `json:"job_id"`
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"`
	Steps      []step `json:"steps"`
}

func (a api) jobs(ctx context.Context, repo string, run workflowRun) ([]job, error) {
	var result struct {
		TotalCount int   `json:"total_count"`
		Jobs       []job `json:"jobs"`
	}
	err := a.request(ctx, "GET", fmt.Sprintf("%s%s/actions/runs/%d/jobs?per_page=100", forge, repo, run.ID), a.readToken, nil, &result)
	if err == nil && result.TotalCount > len(result.Jobs) {
		err = fmt.Errorf("run %s is unreadable: it has %d jobs, %d read", run.HTMLURL, result.TotalCount, len(result.Jobs))
	}
	return result.Jobs, err
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
			if test, err := conclusion("all-green"); err != nil {
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

func (a api) release(ctx context.Context, x app, now time.Time) ([]string, error) {
	var runs struct {
		WorkflowRuns []workflowRun `json:"workflow_runs"`
	}
	url := fmt.Sprintf("%s%s/actions/workflows/%s/runs?branch=main&event=workflow_dispatch&per_page=20", forge, x.repo, x.workflow)
	if err := a.request(ctx, "GET", url, a.readToken, nil, &runs); err != nil {
		return nil, err
	}
	var finding, unread string
	seen := false
walk:
	for _, run := range runs.WorkflowRuns {
		jobs, err := a.jobs(ctx, x.repo, run)
		if err != nil {
			return nil, err
		}
		for _, job := range jobs {
			matches := job.JobID == x.jobID
			if job.JobID == "" {
				matches = job.Name == x.jobName || slices.ContainsFunc(job.Steps, func(s step) bool { return s.Name == publishStep })
			}
			if !matches {
				continue
			}
			seen = true
			var published time.Time
			var publishes bool
			released := "missing"
			for _, step := range job.Steps {
				if step.Name == publishStep {
					publishes = true
					if step.Conclusion == "success" {
						published = step.CompletedAt
					}
				}
				if step.Name == releaseStep {
					released = cmp.Or(step.Conclusion, step.Status)
				}
			}
			if released == "success" {
				fmt.Printf("%s: successful release boundary (%s)\n", x.service, run.HTMLURL)
				break walk
			}
			var missing string
			switch {
			case !publishes:
				missing = publishStep
			case released == "missing":
				missing = releaseStep
			}
			if job.Conclusion == "success" && missing != "" && unread == "" {
				unread = fmt.Sprintf("- %s: job `%s` of %s %s run %s succeeded without a `%s` step", x.service, job.Name, x.repo, x.workflow, run.HTMLURL, missing)
			}
			switch {
			case published.IsZero():
			case now.Sub(published) >= lagLimit:
				finding = fmt.Sprintf("- %s: image of %s main run %s published %s ago, release: %s",
					x.service, x.repo, run.HTMLURL, now.Sub(published).Round(time.Minute), released)
			}
		}
	}

	if !seen {
		return []string{fmt.Sprintf("- %s: no run in the last %d runs has job `%s`; the guard's job contract is stale", x.service, len(runs.WorkflowRuns), x.jobID)}, nil
	}
	return slices.DeleteFunc([]string{unread, finding}, func(s string) bool { return s == "" }), nil
}

func (a api) terrabase(ctx context.Context) ([]string, error) {
	for page := 1; ; page++ {
		var runs struct {
			WorkflowRuns []workflowRun `json:"workflow_runs"`
		}
		url := fmt.Sprintf("%sterrascale/actions/workflows/ci.yml/runs?branch=main&event=workflow_dispatch&per_page=100&page=%d", forge, page)
		if err := a.request(ctx, "GET", url, a.readToken, nil, &runs); err != nil {
			return nil, err
		}
		for _, run := range runs.WorkflowRuns {
			jobs, err := a.jobs(ctx, "terrascale", run)
			if err != nil {
				return nil, err
			}
			for _, job := range jobs {
				if job.Name != "release-only" || job.Conclusion == "skipped" {
					continue
				}
				var findings []string
				releasedAt := run.CreatedAt
				for _, step := range job.Steps {
					if step.Name != "Release the pinned arm64 digest to each region" {
						continue
					}
					if !step.StartedAt.IsZero() {
						releasedAt = step.StartedAt
					}
					if !step.CompletedAt.IsZero() {
						releasedAt = step.CompletedAt
					}
					if !step.StartedAt.IsZero() && (step.Conclusion == "failure" || step.Conclusion == "cancelled") {
						findings = []string{fmt.Sprintf("- terrabase: manual release `%s` %s after starting: %s", run.HeadSHA, step.Conclusion, run.HTMLURL)}
					}
				}
				var comparison struct {
					AheadBy int `json:"ahead_by"`
				}
				err := a.request(ctx, "GET", forge+"terrascale/compare/"+run.HeadSHA+"...main", a.readToken, nil, &comparison)
				if err != nil {
					fmt.Println("terrabase held: main comparison unavailable:", err)
				} else {
					fmt.Printf("terrabase held: last manual release %s at %s, main is %d commits ahead\n", run.HeadSHA, releasedAt.UTC().Format(time.RFC3339), comparison.AheadBy)
				}
				return findings, nil
			}
		}
		if len(runs.WorkflowRuns) < 100 {
			fmt.Println("terrabase held: no manual release-only run found")
			return nil, nil
		}
	}
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
	held, err := a.terrabase(ctx)
	if err != nil {
		held = []string{"- terrabase: manual release history unavailable: " + err.Error()}
	}
	findings = append(findings, held...)
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
