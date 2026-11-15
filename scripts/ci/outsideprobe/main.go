package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	domain       = "terrascale.tech"
	regionsFile  = "deploy/m1/regions.json"
	pushEndpoint = "https://ntfy.sh/"
	probeLabel   = "terrascale-alert-delivery-probe-v1"
	deadmanLimit = 10 * time.Minute
	repageLimit  = 30 * time.Minute
	workflowFile = "outside-probe.yml"
)

var (
	regionName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	pushTopic  = regexp.MustCompile(`^[A-Za-z0-9_-]{43,64}$`)
	fleetHost  = regexp.MustCompile(`^ts-[a-z0-9]+-[0-9]+$`)
	repoPart   = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	stateKey   = regexp.MustCompile(`^(?:deadman|[a-z0-9](?:[a-z0-9.-]{0,200}[a-z0-9])?)$`)
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	os.Exit(run(ctx, os.Stdout))
}

func run(ctx context.Context, w io.Writer) int {
	host, err := os.Hostname()
	if err != nil || fleetHost.MatchString(host) {
		fmt.Fprintln(w, "refusing fleet host")
		return 1
	}
	regions, err := loadRegions(regionsFile)
	if err != nil {
		fmt.Fprintln(w, "regions unreadable")
		return 1
	}
	secret := os.Getenv("TS_ALERTS_NTFY_TOPIC")
	configured := pushTopic.MatchString(secret) && probeTopic(secret) != secret
	client := newClient()
	outcomes := client.endpoints(ctx, regions)
	slices.SortFunc(outcomes, func(a, b outcome) int { return strings.Compare(a.name, b.name) })
	var incidents []incident
	for _, item := range outcomes {
		if item.reason == "" {
			fmt.Fprintf(w, "endpoint ok %s\n", item.name)
			continue
		}
		fmt.Fprintf(w, "endpoint down %s %s\n", item.name, item.reason)
		incidents = append(incidents, incident{key: item.name, detail: item.name + " " + item.reason})
	}
	if !configured {
		for _, line := range client.scheduleLines(ctx, time.Now()) {
			fmt.Fprintln(w, line)
		}
		fmt.Fprintln(w, "deadman down unconfigured")
		fmt.Fprintln(w, "NEED GitHub Actions secret TS_ALERTS_NTFY_TOPIC (vault ref gru-1-ts-alerts-ntfy-topic)")
		return 1
	}
	age, newest, reason := client.heartbeat(ctx, secret)
	observed := time.Now()
	switch reason {
	case "":
		fmt.Fprintf(w, "deadman ok age_s=%d\n", int(age.Seconds()))
		fmt.Fprintf(w, "heartbeat_unix=%d observed_unix=%d\n", newest, observed.Unix())
	case "missing":
		fmt.Fprintln(w, "deadman down missing")
		incidents = append(incidents, incident{key: "deadman", detail: "monitoring heartbeat missing"})
	case "stale":
		fmt.Fprintf(w, "deadman down stale age_s=%d\n", int(age.Seconds()))
		fmt.Fprintf(w, "heartbeat_unix=%d observed_unix=%d\n", newest, observed.Unix())
		incidents = append(incidents, incident{key: "deadman", detail: "monitoring heartbeat stale"})
	default:
		fmt.Fprintln(w, "deadman down unread")
		incidents = append(incidents, incident{key: "deadman", detail: "monitoring heartbeat unread"})
	}
	for _, line := range client.scheduleLines(ctx, observed) {
		fmt.Fprintln(w, line)
	}
	prior, kind, prevAt := client.previousState(ctx)
	fmt.Fprintf(w, "prior=%s\n", kind)
	if kind == "ok" {
		fmt.Fprintf(w, "prior_observed_unix=%d prior_open=%d\n", prior.Observed, len(prior.Open))
	}
	now := time.Now()
	page, recover, next := decide(prior, kind == "ok", incidents, now)
	if kind == "blind" {
		page = forcePage(page, &next, incidents, now)
	}
	if staleAcrossRuns(newest, reason, observed, prevAt) {
		var dead []incident
		for _, item := range incidents {
			if item.key == "deadman" {
				dead = append(dead, item)
			}
		}
		page = forcePage(page, &next, dead, now)
	}
	for _, item := range page {
		fmt.Fprintf(w, "paging %s\n", item.key)
	}
	for _, item := range next.Open {
		if slices.ContainsFunc(page, func(candidate incident) bool { return candidate.key == item.Key }) {
			continue
		}
		if item.Paged == 0 {
			fmt.Fprintf(w, "holding %s\n", item.Key)
			continue
		}
		fmt.Fprintf(w, "quiet %s\n", item.Key)
	}
	for _, item := range recover {
		fmt.Fprintf(w, "recovering %s\n", label(item.Key))
	}
	pageErr := error(nil)
	if len(page) > 0 {
		details := make([]string, len(page))
		for i, item := range page {
			details[i] = item.detail
		}
		detected := time.Now()
		pageErr = client.publish(ctx, secret, "TerraScale outside probe", "urgent", pageBody(details))
		if pageErr != nil {
			fmt.Fprintln(w, "page failed")
			restorePaged(&next, prior, page)
		} else {
			fmt.Fprintf(w, "time_to_page_ms=%d\n", time.Since(detected).Milliseconds())
		}
	}
	recoverErr := error(nil)
	if pageErr == nil && len(recover) > 0 {
		names := make([]string, len(recover))
		for i, item := range recover {
			names[i] = label(item.Key)
		}
		slices.Sort(names)
		recoverErr = client.publish(ctx, secret, "TerraScale outside probe recovered", "default", recoveredBody(names))
		if recoverErr != nil {
			fmt.Fprintln(w, "recover failed")
			next.Recovery = recover
		}
	} else if pageErr != nil && len(recover) > 0 {
		next.Recovery = recover
	}
	if len(next.Open) == 0 {
		next.Open = []tracked{}
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		fmt.Fprintln(w, "probe_state unreadable")
		return 1
	}
	fmt.Fprintf(w, "probe_state %s\n", encoded)
	if len(incidents) > 0 || pageErr != nil || recoverErr != nil || kind == "unreadable" || kind == "blind" {
		fmt.Fprintln(w, "down")
		return 1
	}
	fmt.Fprintln(w, "up")
	return 0
}

func pageBody(failed []string) string {
	lines := append([]string{}, failed...)
	id, repo, server := os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_SERVER_URL")
	if id != "" && repo != "" && server != "" {
		lines = append(lines, server+"/"+repo+"/actions/runs/"+id)
	}
	return strings.Join(lines, "\n")
}

func probeTopic(secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(probeLabel))
	return "ts-probe-" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func loadRegions(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return nil, errors.New("regions unreadable")
	}
	var rows []struct {
		Region string `json:"region"`
	}
	if json.Unmarshal(data, &rows) != nil || len(rows) == 0 {
		return nil, errors.New("regions invalid")
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		if !regionName.MatchString(row.Region) || slices.Contains(names, row.Region) {
			return nil, errors.New("regions invalid")
		}
		names = append(names, row.Region)
	}
	return names, nil
}

type outcome struct {
	name, reason string
}

type target struct {
	name, kind, region string
}

func endpointTargets(regions []string) []target {
	list := []target{
		{name: "api." + domain, kind: "api"},
		{name: "dash." + domain, kind: "dash"},
		{name: "auth." + domain, kind: "auth"},
		{name: "pg." + domain, kind: "pg"},
	}
	for _, region := range regions {
		list = append(list,
			target{name: region + ".api." + domain, kind: "api", region: region},
			target{name: region + ".pg." + domain, kind: "pg", region: region},
		)
	}
	return list
}

type client struct {
	web, push, api *http.Client
}

func newClient() client {
	web := http.DefaultTransport.(*http.Transport).Clone()
	web.Proxy = nil
	return client{
		web:  &http.Client{Transport: web, Timeout: 3 * time.Second, CheckRedirect: refuseRedirect},
		push: &http.Client{Transport: web.Clone(), Timeout: 20 * time.Second, CheckRedirect: refuseRedirect},
		api: &http.Client{Transport: web.Clone(), Timeout: 10 * time.Second, CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("github redirect")
			}
			host := request.URL.Hostname()
			if request.URL.Scheme == "https" || (request.URL.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
				return nil
			}
			return errors.New("github redirect")
		}},
	}
}

func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (c client) endpoints(ctx context.Context, regions []string) []outcome {
	list := endpointTargets(regions)
	outcomes := make([]outcome, len(list))
	var wg sync.WaitGroup
	for i, item := range list {
		wg.Go(func() {
			outcomes[i] = outcome{name: item.name, reason: c.one(ctx, item, regions)}
		})
	}
	wg.Wait()
	return outcomes
}

func (c client) one(ctx context.Context, item target, regions []string) string {
	if item.kind == "pg" {
		return pgReady(ctx, item.name)
	}
	return c.httpReady(ctx, item, regions)
}

func (c client) httpReady(ctx context.Context, item target, regions []string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+item.name+"/readyz", nil)
	if err != nil {
		return "request"
	}
	response, err := c.web.Do(request)
	if err != nil {
		return classify(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Sprintf("status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10+1))
	if err != nil || len(body) > 16<<10 {
		return "body"
	}
	var result struct {
		Status       string            `json:"status"`
		Region       string            `json:"region"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if json.Unmarshal(body, &result) != nil {
		return "body"
	}
	switch item.kind {
	case "dash":
		if result.Status != "ok" || result.Dependencies["ts-auth"] != "ok" || result.Dependencies["terrabase"] != "ok" {
			return "not ready"
		}
	case "auth":
		if result.Status != "ready" {
			return "not ready"
		}
	default:
		if result.Status != "ready" || !slices.Contains(regions, result.Region) {
			return "not ready"
		}
		if item.region != "" && result.Region != item.region {
			return "region mismatch"
		}
	}
	return ""
}

func pgReady(ctx context.Context, host string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "5432"))
	if err != nil {
		return classify(err)
	}
	defer conn.Close()
	if len(conn.(*tls.Conn).ConnectionState().VerifiedChains) == 0 {
		return "certificate"
	}
	return ""
}

func classify(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "unreachable"
}

type ntfyMessage struct {
	ID      string `json:"id"`
	Time    int64  `json:"time"`
	Event   string `json:"event"`
	Topic   string `json:"topic"`
	Message string `json:"message"`
}

func (c client) heartbeat(ctx context.Context, secret string) (time.Duration, int64, string) {
	topic := probeTopic(secret)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pushEndpoint+topic+"/json?poll=1&since=latest", nil)
	if err != nil {
		return 0, 0, "unread"
	}
	response, err := c.push.Do(request)
	if err != nil {
		return 0, 0, "unread"
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if response.StatusCode != http.StatusOK || err != nil || len(body) > 64<<10 {
		return 0, 0, "unread"
	}
	var newest int64
	for line := range strings.SplitSeq(string(body), "\n") {
		if line == "" {
			continue
		}
		var message ntfyMessage
		if json.Unmarshal([]byte(line), &message) != nil || message.Event != "message" || message.Topic != topic || message.Time <= 0 {
			continue
		}
		if message.Time > newest {
			newest = message.Time
		}
	}
	if newest == 0 {
		return 0, 0, "missing"
	}
	age := time.Since(time.Unix(newest, 0))
	if age >= deadmanLimit {
		return age, newest, "stale"
	}
	return age, newest, ""
}

func (c client) publish(ctx context.Context, topic, title, priority, text string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, pushEndpoint+topic, strings.NewReader(text))
	if err != nil {
		return errors.New("push request")
	}
	request.Header.Set("Title", title)
	request.Header.Set("Priority", priority)
	response, err := c.push.Do(request)
	if err != nil {
		return errors.New("push transport")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	var published ntfyMessage
	if response.StatusCode != http.StatusOK || err != nil || len(body) > 64<<10 || json.Unmarshal(body, &published) != nil || published.ID == "" || published.Event != "message" || published.Topic != topic || published.Message != text {
		return errors.New("push rejected")
	}
	return nil
}

func recoveredBody(names []string) string {
	lines := append([]string{"recovered"}, names...)
	id, repo, server := os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_SERVER_URL")
	if id != "" && repo != "" && server != "" {
		lines = append(lines, server+"/"+repo+"/actions/runs/"+id)
	}
	return strings.Join(lines, "\n")
}

func label(key string) string {
	if key == "deadman" {
		return "monitoring heartbeat"
	}
	return key
}

type incident struct {
	key, detail string
}

type tracked struct {
	Key   string `json:"key"`
	Paged int64  `json:"paged"`
}

type probeState struct {
	Open     []tracked `json:"open"`
	Recovery []tracked `json:"recovery,omitempty"`
	Observed int64     `json:"observed"`
}

func decide(prior probeState, havePrior bool, current []incident, now time.Time) ([]incident, []tracked, probeState) {
	known := map[string]tracked{}
	if havePrior {
		for _, item := range prior.Open {
			known[item.Key] = item
		}
		for _, item := range prior.Recovery {
			if _, ok := known[item.Key]; !ok {
				known[item.Key] = item
			}
		}
	}
	var page []incident
	var open []tracked
	seen := map[string]bool{}
	for _, item := range current {
		if seen[item.key] {
			continue
		}
		seen[item.key] = true
		entry := tracked{Key: item.key}
		if prev, ok := known[item.key]; ok {
			if prev.Paged == 0 || now.Sub(time.Unix(prev.Paged, 0)) >= repageLimit {
				entry.Paged = now.Unix()
				page = append(page, item)
			} else {
				entry.Paged = prev.Paged
			}
		}
		open = append(open, entry)
	}
	var recover []tracked
	if havePrior {
		for _, item := range prior.Open {
			if !seen[item.Key] && item.Paged > 0 {
				recover = append(recover, item)
			}
		}
		for _, item := range prior.Recovery {
			if !seen[item.Key] && !slices.ContainsFunc(recover, func(candidate tracked) bool { return candidate.Key == item.Key }) {
				recover = append(recover, item)
			}
		}
	}
	next := probeState{Open: open, Observed: now.Unix()}
	return page, recover, next
}

func forcePage(page []incident, next *probeState, items []incident, now time.Time) []incident {
	for _, item := range items {
		if slices.ContainsFunc(page, func(candidate incident) bool { return candidate.key == item.key }) {
			continue
		}
		page = append(page, item)
		stamped := false
		for i := range next.Open {
			if next.Open[i].Key == item.key {
				next.Open[i].Paged = now.Unix()
				stamped = true
			}
		}
		if !stamped {
			next.Open = append(next.Open, tracked{Key: item.key, Paged: now.Unix()})
		}
	}
	return page
}

func staleAcrossRuns(newest int64, reason string, observed, prevAt time.Time) bool {
	if reason != "stale" || newest <= 0 {
		return false
	}
	heartbeat := time.Unix(newest, 0)
	if !prevAt.IsZero() {
		return prevAt.Sub(heartbeat) >= deadmanLimit
	}
	return observed.Sub(heartbeat) >= deadmanLimit+5*time.Minute
}

func restorePaged(next *probeState, prior probeState, page []incident) {
	prev := map[string]int64{}
	for _, item := range prior.Open {
		prev[item.Key] = item.Paged
	}
	for _, item := range prior.Recovery {
		if _, ok := prev[item.Key]; !ok {
			prev[item.Key] = item.Paged
		}
	}
	paging := map[string]bool{}
	for _, item := range page {
		paging[item.key] = true
	}
	for i := range next.Open {
		if paging[next.Open[i].Key] {
			next.Open[i].Paged = prev[next.Open[i].Key]
		}
	}
}

func (c client) scheduleLines(ctx context.Context, observed time.Time) []string {
	event := os.Getenv("GITHUB_EVENT_NAME")
	if event == "" {
		event = "local"
	}
	lines := []string{"schedule_event=" + event}
	if event != "schedule" {
		return append(lines, "schedule_delay_s=na", "schedule_gap_s=na")
	}
	owner, repo, runID, ok := actionsIdentity()
	if !ok {
		return append(lines, "schedule_delay_s=unreadable", "schedule_gap_s=na")
	}
	gctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	current, err := c.githubRun(gctx, owner, repo, runID)
	if err != nil {
		return append(lines, "schedule_delay_s=unreadable", "schedule_gap_s=na")
	}
	nominal, ok := nominalSchedule(current.CreatedAt)
	if !ok {
		lines = append(lines, "schedule_delay_s=unreadable")
	} else {
		started := current.RunStartedAt
		if started.IsZero() {
			started = observed
		}
		lines = append(lines,
			"schedule_nominal="+nominal.UTC().Format(time.RFC3339),
			"schedule_started="+started.UTC().Format(time.RFC3339),
			fmt.Sprintf("schedule_delay_s=%d", int(started.Sub(nominal).Seconds())),
		)
	}
	prev, err := c.previousScheduled(gctx, owner, repo, runID)
	if err != nil {
		return append(lines, "schedule_gap_s=unreadable")
	}
	if current.CreatedAt.IsZero() || prev.CreatedAt.IsZero() {
		return append(lines, "schedule_gap_s=na")
	}
	return append(lines, fmt.Sprintf("schedule_gap_s=%d", int(current.CreatedAt.Sub(prev.CreatedAt).Seconds())))
}

func (c client) previousState(ctx context.Context) (probeState, string, time.Time) {
	owner, repo, runID, ok := actionsIdentity()
	if !ok {
		return probeState{}, "none", time.Time{}
	}
	gctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	runs, err := c.scheduledRuns(gctx, owner, repo)
	if err != nil {
		return probeState{}, "unreadable", time.Time{}
	}
	misses := 0
	seen := 0
	var prevAt time.Time
	for _, run := range runs {
		if run.ID == runID || run.Status != "completed" || run.Event != "schedule" {
			continue
		}
		seen++
		if seen > 5 {
			break
		}
		if prevAt.IsZero() {
			prevAt = runTime(run)
		}
		state, kind := c.stateFromRun(gctx, owner, repo, run.ID)
		switch kind {
		case "ok":
			if misses == 0 {
				return state, "ok", runTime(run)
			}
			return probeState{}, "unreadable", prevAt
		case "none":
			if misses > 0 {
				return probeState{}, "unreadable", prevAt
			}
		default:
			misses++
			if misses >= 2 {
				return probeState{}, "blind", prevAt
			}
		}
	}
	if misses > 0 {
		return probeState{}, "unreadable", prevAt
	}
	return probeState{}, "none", time.Time{}
}

func runTime(run ghRun) time.Time {
	if !run.RunStartedAt.IsZero() {
		return run.RunStartedAt
	}
	return run.CreatedAt
}

func actionsIdentity() (owner, repo string, runID int64, ok bool) {
	if os.Getenv("GITHUB_TOKEN") == "" {
		return "", "", 0, false
	}
	owner, repo, found := strings.Cut(os.Getenv("GITHUB_REPOSITORY"), "/")
	if !found || !repoPart.MatchString(owner) || !repoPart.MatchString(repo) || strings.Contains(repo, "/") {
		return "", "", 0, false
	}
	id, err := strconv.ParseInt(os.Getenv("GITHUB_RUN_ID"), 10, 64)
	if err != nil || id <= 0 {
		return "", "", 0, false
	}
	return owner, repo, id, true
}

type ghRun struct {
	ID           int64     `json:"id"`
	Event        string    `json:"event"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	RunStartedAt time.Time `json:"run_started_at"`
}

func (c client) githubRun(ctx context.Context, owner, repo string, id int64) (ghRun, error) {
	body, err := c.githubGet(ctx, fmt.Sprintf("/repos/%s/%s/actions/runs/%d", url.PathEscape(owner), url.PathEscape(repo), id))
	if err != nil {
		return ghRun{}, err
	}
	var run ghRun
	if json.Unmarshal(body, &run) != nil || run.ID != id {
		return ghRun{}, errors.New("github run")
	}
	return run, nil
}

func (c client) scheduledRuns(ctx context.Context, owner, repo string) ([]ghRun, error) {
	body, err := c.githubGet(ctx, fmt.Sprintf("/repos/%s/%s/actions/workflows/%s/runs?event=schedule&status=completed&per_page=5", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(workflowFile)))
	if err != nil {
		return nil, err
	}
	var page struct {
		Runs []ghRun `json:"workflow_runs"`
	}
	if json.Unmarshal(body, &page) != nil {
		return nil, errors.New("github runs")
	}
	return page.Runs, nil
}

func (c client) previousScheduled(ctx context.Context, owner, repo string, current int64) (ghRun, error) {
	runs, err := c.scheduledRuns(ctx, owner, repo)
	if err != nil {
		return ghRun{}, err
	}
	for _, run := range runs {
		if run.ID != current && run.Status == "completed" && run.Event == "schedule" {
			return run, nil
		}
	}
	return ghRun{}, nil
}

func (c client) stateFromRun(ctx context.Context, owner, repo string, id int64) (probeState, string) {
	body, err := c.githubGet(ctx, fmt.Sprintf("/repos/%s/%s/actions/runs/%d/jobs?per_page=100", url.PathEscape(owner), url.PathEscape(repo), id))
	if err != nil {
		return probeState{}, "unreadable"
	}
	var jobs struct {
		Total int `json:"total_count"`
		Jobs  []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"jobs"`
	}
	if json.Unmarshal(body, &jobs) != nil || jobs.Total > len(jobs.Jobs) {
		return probeState{}, "unreadable"
	}
	var jobID int64
	for _, job := range jobs.Jobs {
		if job.Name == "outside-probe" && job.ID > 0 {
			jobID = job.ID
			break
		}
	}
	if jobID == 0 {
		return probeState{}, "unreadable"
	}
	logBody, err := c.githubGet(ctx, fmt.Sprintf("/repos/%s/%s/actions/jobs/%d/logs", url.PathEscape(owner), url.PathEscape(repo), jobID))
	if err != nil {
		return probeState{}, "unreadable"
	}
	return extractState(logBody)
}

func extractState(log []byte) (probeState, string) {
	last := ""
	for line := range strings.SplitSeq(string(log), "\n") {
		idx := strings.LastIndex(line, "probe_state ")
		if idx >= 0 {
			last = strings.TrimSpace(line[idx+len("probe_state "):])
		}
	}
	if last == "" {
		return probeState{}, "none"
	}
	var state probeState
	if json.Unmarshal([]byte(last), &state) != nil || !validState(state) {
		return probeState{}, "invalid"
	}
	return state, "ok"
}

func validState(state probeState) bool {
	if state.Observed <= 0 || len(state.Open) > 64 || len(state.Recovery) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, list := range [][]tracked{state.Open, state.Recovery} {
		for _, item := range list {
			if !stateKey.MatchString(item.Key) || item.Paged < 0 || seen[item.Key] {
				return false
			}
			seen[item.Key] = true
		}
	}
	return true
}

func (c client) githubGet(ctx context.Context, path string) ([]byte, error) {
	base, err := githubBase()
	if err != nil || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return nil, errors.New("github path")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, errors.New("github request")
	}
	request.Header.Set("Authorization", "Bearer "+os.Getenv("GITHUB_TOKEN"))
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := c.api.Do(request)
	if err != nil {
		return nil, errors.New("github transport")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
	if response.StatusCode != http.StatusOK || err != nil || len(body) > 4<<20 {
		return nil, errors.New("github status")
	}
	return body, nil
}

func githubBase() (string, error) {
	base := strings.TrimRight(os.Getenv("GITHUB_API_URL"), "/")
	if base == "" {
		base = "https://api.github.com"
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("github api")
	}
	host := parsed.Hostname()
	if parsed.Scheme == "https" || (parsed.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.EscapedPath(), "/"), nil
	}
	return "", errors.New("github api")
}

func nominalSchedule(created time.Time) (time.Time, bool) {
	if created.IsZero() {
		return time.Time{}, false
	}
	minutes, ok := cronMinutes()
	if !ok {
		return time.Time{}, false
	}
	created = created.UTC()
	for back := 0; back <= 60; back++ {
		slot := created.Add(-time.Duration(back) * time.Minute).Truncate(time.Minute)
		if slices.Contains(minutes, slot.Minute()) {
			return slot, true
		}
	}
	return time.Time{}, false
}

func cronMinutes() ([]int, bool) {
	path := os.Getenv("GITHUB_EVENT_PATH")
	if path == "" || strings.Contains(path, "..") {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 2<<20 {
		return nil, false
	}
	var event struct {
		Schedule string `json:"schedule"`
	}
	if json.Unmarshal(data, &event) != nil {
		return nil, false
	}
	fields := strings.Fields(event.Schedule)
	if len(fields) != 5 || fields[1] != "*" || fields[2] != "*" || fields[3] != "*" || fields[4] != "*" || fields[0] == "" {
		return nil, false
	}
	parts := strings.Split(fields[0], ",")
	minutes := make([]int, 0, len(parts))
	for _, part := range parts {
		minute, err := strconv.Atoi(part)
		if err != nil || minute < 0 || minute > 59 || slices.Contains(minutes, minute) {
			return nil, false
		}
		minutes = append(minutes, minute)
	}
	return minutes, len(minutes) > 0
}
