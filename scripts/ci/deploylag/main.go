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
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

const forge = "https://api.github.com/repos/TerraScale/"

type artifact struct {
	name, repo string
	budget     time.Duration
}

var artifacts = []artifact{
	{"ts-orchestrator", "ts-orchestrator", 15 * time.Minute},
	{"terrabase", "terrascale", 15 * time.Minute},
	{"ts-auth", "terrascale", 15 * time.Minute},
	{"ts-dashboard", "terrascale", 15 * time.Minute},
}

type commit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Committer struct {
			Date time.Time `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

type api struct {
	client                                  *http.Client
	readToken, writeToken, observationToken string
	commits                                 map[string]commit
	relations                               map[string]string
	publications                            map[string]time.Time
}

func (a *api) request(ctx context.Context, method, url, token string, input, output any) error {
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
		return errors.New("HTTP request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if output == nil {
		return nil
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		return errors.New("HTTP response unreadable")
	}
	if len(wire) > 4<<20 {
		return errors.New("HTTP response exceeds 4 MiB")
	}
	return json.Unmarshal(wire, output)
}

func (a *api) mainCommit(ctx context.Context, repo string) (commit, error) {
	if c, ok := a.commits[repo]; ok {
		return c, nil
	}
	var c commit
	if err := a.request(ctx, "GET", forge+repo+"/commits/main", a.readToken, nil, &c); err != nil {
		return c, err
	}
	if len(c.SHA) != 40 || c.Commit.Committer.Date.IsZero() {
		return c, errors.New("main commit unavailable")
	}
	a.commits[repo] = c
	return c, nil
}

func (a *api) lag(ctx context.Context, repo, running string, main commit, now time.Time) (time.Duration, error) {
	if len(running) != 40 {
		return 0, errors.New("running revision is unavailable")
	}
	if running == main.SHA {
		return 0, nil
	}
	key := repo + "/" + running + "/" + main.SHA
	status, ok := a.relations[key]
	var comparison struct {
		Status string `json:"status"`
	}
	if !ok {
		if err := a.request(ctx, "GET", forge+repo+"/compare/"+running+"..."+main.SHA+"?per_page=1", a.readToken, nil, &comparison); err != nil {
			return 0, err
		}
		status = comparison.Status
		a.relations[key] = status
	}
	var lag time.Duration
	switch status {
	case "identical", "behind":
	case "ahead":
		if main.Commit.Committer.Date.IsZero() {
			return 0, errors.New("selected release publication timestamp is unavailable")
		}
		lag = max(0, now.Sub(main.Commit.Committer.Date))
	default:
		return 0, errors.New("running commit and main have diverged")
	}
	return lag, nil
}

func (a *api) region(ctx context.Context, region string) (releasepush.DeploymentObservation, error) {
	var report releasepush.DeploymentObservation
	request, err := http.NewRequestWithContext(ctx, "GET", "https://"+region+".mesh.terrascale.tech"+releasepush.ObservationPath+"?view=deployments", nil)
	if err != nil {
		return report, errors.New("observation request invalid")
	}
	request.Header.Set("Authorization", "Bearer "+a.observationToken)
	response, err := a.client.Do(request)
	if err != nil {
		return report, errors.New("regional HTTPS request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusServiceUnavailable {
		return report, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	err = json.UnmarshalRead(io.LimitReader(response.Body, 4<<20), &report)
	if err != nil {
		return report, fmt.Errorf("HTTP %d: invalid regional deployment JSON", response.StatusCode)
	}
	if report.Error != "" {
		return report, errors.New(report.Error)
	}
	if response.StatusCode != http.StatusOK {
		return report, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if err == nil && (report.Region != region || report.Host == "" || report.Apps == nil || len(report.Hosts) == 0) {
		err = errors.New("incomplete regional deployment observation")
	}
	return report, err
}

func (a *api) publication(ctx context.Context, x artifact, target releasepush.DeploymentTarget) (time.Time, error) {
	if !target.PublishedAt.IsZero() {
		return target.PublishedAt, nil
	}
	key := x.name + "/" + target.RunID
	if published, ok := a.publications[key]; ok {
		return published, nil
	}
	var result struct {
		Total int `json:"total_count"`
		Jobs  []struct {
			Name  string `json:"name"`
			Steps []struct {
				Name        string    `json:"name"`
				Conclusion  string    `json:"conclusion"`
				CompletedAt time.Time `json:"completed_at"`
				StartedAt   time.Time `json:"started_at"`
			} `json:"steps"`
		} `json:"jobs"`
	}
	if err := a.request(ctx, "GET", forge+x.repo+"/actions/runs/"+target.RunID+"/jobs?per_page=100", a.readToken, nil, &result); err != nil {
		return time.Time{}, err
	}
	if result.Total > len(result.Jobs) {
		return time.Time{}, errors.New("release publication jobs are incomplete")
	}
	for _, job := range result.Jobs {
		matches := x.name == "terrabase" && slices.Contains([]string{"main", "native-release", "release-only"}, job.Name) || x.name == "ts-auth" && slices.Contains([]string{"main-auth", "main-auth-ordered"}, job.Name) || x.name == "ts-dashboard" && job.Name == "Publish and release"
		if !matches {
			continue
		}
		for _, step := range job.Steps {
			if step.Name == "Publish and verify the same image and bundles in every OCIR region" && step.Conclusion == "success" && !step.CompletedAt.IsZero() {
				a.publications[key] = step.CompletedAt
				return step.CompletedAt, nil
			}
			if step.Name == "Release the pinned arm64 digest to each region" && !step.StartedAt.IsZero() {
				a.publications[key] = step.StartedAt
				return step.StartedAt, nil
			}
		}
	}
	return time.Time{}, errors.New("selected release publication timestamp is unavailable")
}

func (a *api) verdict(ctx context.Context, x artifact, region string, report releasepush.DeploymentObservation, now time.Time) (string, bool) {
	main, err := a.mainCommit(ctx, x.repo)
	if err != nil {
		return fmt.Sprintf("%s %s: cannot observe main: %s", x.name, region, err), true
	}
	target, ok := report.Targets[x.name]
	if !ok || target.Error != "" || len(target.Revision) != 40 {
		return fmt.Sprintf("%s %s: main=%s cannot observe %s: %s", x.name, region, main.SHA, region, cmp.Or(target.Error, "selected release revision unavailable")), true
	}
	if _, err := a.lag(ctx, x.repo, target.Revision, main, now); err != nil {
		return fmt.Sprintf("%s %s: cannot observe %s: selected release ancestry: %s", x.name, region, region, err), true
	}
	release := commit{SHA: target.Revision}
	var tasks []releasepush.DeploymentTask
	var reasons []string
	failed := false
	pending := false
	if x.name == "ts-orchestrator" {
		for _, host := range report.Hosts {
			tasks = append(tasks, releasepush.DeploymentTask{Host: host.Host, Revision: host.Version, State: "RUNNING"})
			if host.State != "" && host.State != "current" && host.State != "newer" {
				pending = true
				reasons = append(reasons, host.Host+": "+host.State)
			}
			if host.Error != "" || host.Down || host.Refusal != nil || host.RolledBack != "" {
				failed = true
				reason := cmp.Or(host.Error, host.State, "host down or release rolled back")
				if host.Refusal != nil {
					reason = host.Refusal.Reason
				}
				reasons = append(reasons, host.Host+": "+reason)
			}
		}
		var pull struct {
			Target *struct {
				SHA string `json:"sha"`
			} `json:"target"`
			Phase  string `json:"phase"`
			Reason string `json:"reason"`
			Hosts  []struct {
				Host  string `json:"host"`
				Error string `json:"error"`
			} `json:"hosts"`
		}
		if err := json.Unmarshal(report.Pull, &pull); err != nil {
			return fmt.Sprintf("%s %s: cannot observe %s: pull rollout unreadable", x.name, region, region), true
		}
		if pull.Target != nil && pull.Target.SHA == target.Revision && !slices.Contains([]string{"idle", "complete", "newer"}, pull.Phase) {
			pending = true
		}
		if (pull.Target == nil || pull.Target.SHA == target.Revision) && slices.Contains([]string{"refused", "rolled_back", "rollback_stalled"}, pull.Phase) {
			failed = true
		}
		if (pull.Target == nil || pull.Target.SHA == target.Revision) && pull.Reason != "" {
			reasons = append(reasons, report.Host+": "+pull.Reason)
		}
		for _, host := range pull.Hosts {
			if (pull.Target == nil || pull.Target.SHA == target.Revision) && host.Error != "" {
				reasons = append(reasons, host.Host+": "+host.Error)
			}
		}
	} else {
		app, ok := report.Apps[x.name]
		if !ok || app.Error != "" {
			return fmt.Sprintf("%s %s: cannot observe %s: %s", x.name, region, region, cmp.Or(app.Error, "application deployment inventory missing")), true
		}
		tasks, failed = app.Tasks, app.Failed
		if app.Reason != "" {
			reasons = append(reasons, app.Host+": "+app.Reason)
		}
	}
	var running []string
	var lag time.Duration
	if x.name != "ts-orchestrator" {
		pending = !report.Apps[x.name].Complete || uint64(len(tasks)) < report.Apps[x.name].Replicas
	}
	for _, task := range tasks {
		if task.Reason != "" {
			reasons = append(reasons, task.Host+": "+task.Reason)
		}
		if task.State != "RUNNING" {
			pending = true
			reasons = append(reasons, task.Host+": "+task.State)
			continue
		}
		running = append(running, task.Host+"="+task.Revision)
		differentImage := x.name != "ts-orchestrator" && !appregistry.SameDigest(task.Image, target.Image)
		if (task.Revision != target.Revision || differentImage) && release.Commit.Committer.Date.IsZero() {
			published, err := a.publication(ctx, x, target)
			if err != nil {
				return fmt.Sprintf("%s %s: cannot observe %s: %s", x.name, region, region, err), true
			}
			release.Commit.Committer.Date = published
		}
		behind, err := a.lag(ctx, x.repo, task.Revision, release, now)
		if err != nil {
			return fmt.Sprintf("%s %s: main=%s running=%s cannot observe %s: %s", x.name, region, main.SHA, strings.Join(running, ","), region, err), true
		}
		lag = max(lag, behind)
		if differentImage && task.Revision == target.Revision {
			lag = max(lag, now.Sub(release.Commit.Committer.Date))
		}
	}
	if len(running) == 0 {
		running = []string{"none"}
		pending = true
	}
	if pending {
		published, err := a.publication(ctx, x, target)
		if err != nil {
			return fmt.Sprintf("%s %s: cannot observe %s: %s", x.name, region, region, err), true
		}
		lag = max(lag, now.Sub(published))
	}
	red := failed || lag > x.budget
	state := "ok"
	if red {
		state = "red"
	}
	slices.Sort(reasons)
	reasons = slices.Compact(reasons)
	return fmt.Sprintf("%s %s: main=%s release=%s running=%s lag=%.1fm budget=%.0fm state=%s %s", x.name, region, main.SHA, target.Revision, strings.Join(running, ","), lag.Minutes(), x.budget.Minutes(), state, strings.Join(reasons, "; ")), red
}

func (a *api) issues(ctx context.Context, rows map[string][]string, red map[string]bool) error {
	type issue struct {
		Number      int    `json:"number"`
		Title       string `json:"title"`
		PullRequest any    `json:"pull_request"`
	}
	open := map[string][]int{}
	base := forge + "ts-orchestrator/issues"
	for page := 1; ; page++ {
		var issues []issue
		if err := a.request(ctx, "GET", fmt.Sprintf("%s?state=open&per_page=100&page=%d", base, page), a.writeToken, nil, &issues); err != nil {
			return err
		}
		for _, issue := range issues {
			if issue.PullRequest == nil {
				open[issue.Title] = append(open[issue.Title], issue.Number)
			}
		}
		if len(issues) < 100 {
			break
		}
	}
	for _, x := range artifacts {
		title := "Deploy lag: " + x.name
		body := "@mariogk Deployment guard is red.\n\n```text\n" + strings.Join(rows[x.name], "\n") + "\n```\n\nhttps://github.com/" + os.Getenv("GITHUB_REPOSITORY") + "/actions/runs/" + os.Getenv("GITHUB_RUN_ID")
		for i, number := range open[title] {
			patch := map[string]string{"state": "closed"}
			if red[x.name] && i == 0 {
				patch = map[string]string{"body": body}
			}
			if err := a.request(ctx, "PATCH", fmt.Sprintf("%s/%d", base, number), a.writeToken, patch, nil); err != nil {
				return err
			}
		}
		if red[x.name] && len(open[title]) == 0 {
			if err := a.request(ctx, "POST", base, a.writeToken, map[string]any{"title": title, "body": body, "assignees": []string{"mariogk"}}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *api) page(ctx context.Context, affected []string) error {
	topic := os.Getenv("TS_ALERTS_NTFY_TOPIC")
	if topic == "" || strings.ContainsAny(topic, "/?# \t\r\n") {
		return errors.New("existing paging topic unavailable")
	}
	message := "Deployment guard red: " + strings.Join(affected, ", ") + ". Check Deploy lag issues in TerraScale/ts-orchestrator."
	request, err := http.NewRequestWithContext(ctx, "POST", "https://ntfy.sh/"+topic, strings.NewReader(message))
	if err != nil {
		return errors.New("page request invalid")
	}
	request.Header.Set("Title", "TerraScale deployment lag")
	request.Header.Set("Priority", "urgent")
	response, err := a.client.Do(request)
	if err != nil {
		return errors.New("page delivery transport failed")
	}
	defer response.Body.Close()
	var result struct {
		ID      string `json:"id"`
		Event   string `json:"event"`
		Topic   string `json:"topic"`
		Message string `json:"message"`
	}
	if response.StatusCode != http.StatusOK || json.UnmarshalRead(io.LimitReader(response.Body, 64<<10), &result) != nil || result.ID == "" || result.Event != "message" || result.Topic != topic || result.Message != message {
		return errors.New("page delivery was not accepted")
	}
	return nil
}

func run(ctx context.Context, a *api, now time.Time) bool {
	regions, err := releasepush.LoadRegions("deploy/m1/regions.json")
	rows, red := map[string][]string{}, map[string]bool{}
	if err != nil {
		fmt.Println("cannot observe regions:", err)
	}
	reports := map[string]releasepush.DeploymentObservation{}
	observationErrors := map[string]error{}
	targets := map[string]releasepush.DeploymentTarget{}
	for _, region := range regions {
		report, observeErr := a.region(ctx, region.Region)
		reports[region.Region], observationErrors[region.Region] = report, observeErr
		if observeErr != nil {
			continue
		}
		for _, x := range artifacts {
			target := report.Targets[x.name]
			candidate, parseErr := strconv.ParseUint(target.RunID, 10, 64)
			selected, _ := strconv.ParseUint(targets[x.name].RunID, 10, 64)
			if x.name == "ts-orchestrator" {
				candidate, selected = target.Seq, targets[x.name].Seq
			}
			if _, exists := targets[x.name]; !exists {
				targets[x.name] = target
			}
			if target.Error == "" && parseErr == nil && (candidate > selected || candidate == selected && target.Attempt > targets[x.name].Attempt) {
				targets[x.name] = target
			}
			current := targets[x.name]
			if target.Error == "" && parseErr == nil && candidate == selected && target.Attempt == current.Attempt && (target.Revision != current.Revision || target.Image != current.Image) {
				current.Error = "regions report conflicting signed release selections"
				targets[x.name] = current
			}
		}
	}
	for _, region := range regions {
		report, observeErr := reports[region.Region], observationErrors[region.Region]
		report.Targets = targets
		for _, x := range artifacts {
			var line string
			var bad bool
			if observeErr != nil {
				line, bad = fmt.Sprintf("%s: cannot observe %s: %s", x.name, region.Region, observeErr), true
			} else {
				line, bad = a.verdict(ctx, x, region.Region, report, now)
			}
			fmt.Println(line)
			rows[x.name] = append(rows[x.name], line)
			red[x.name] = red[x.name] || bad
		}
	}
	var affected []string
	for _, x := range artifacts {
		red[x.name] = red[x.name] || err != nil
		if red[x.name] {
			affected = append(affected, x.name)
		}
	}
	if os.Getenv("GITHUB_REF") == "refs/heads/main" {
		if err := a.issues(ctx, rows, red); err != nil {
			fmt.Println("issue delivery failed:", err)
			if len(affected) == 0 {
				for _, x := range artifacts {
					affected = append(affected, x.name)
				}
			}
		}
		if len(affected) > 0 {
			if err := a.page(ctx, affected); err != nil {
				fmt.Println("paging failed:", err)
			}
		}
	}
	if len(affected) > 0 {
		fmt.Println("DEPLOY red", strings.Join(affected, ","))
		return false
	}
	var names []string
	for _, x := range artifacts {
		names = append(names, x.name)
	}
	fmt.Println("DEPLOY ok", strings.Join(names, ","))
	return true
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	token, err := releasepush.MintToken(ctx)
	if err != nil {
		fmt.Println("observation identity unavailable:", err)
	}
	a := &api{client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, readToken: cmp.Or(os.Getenv("GH_READ_TOKEN"), os.Getenv("GH_TOKEN")), writeToken: cmp.Or(os.Getenv("GH_WRITE_TOKEN"), os.Getenv("GH_TOKEN")), observationToken: token, commits: map[string]commit{}, relations: map[string]string{}, publications: map[string]time.Time{}}
	if !run(ctx, a, time.Now()) {
		os.Exit(1)
	}
}
