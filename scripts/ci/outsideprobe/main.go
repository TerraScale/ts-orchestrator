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
	"os"
	"regexp"
	"slices"
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
)

var (
	regionName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	pushTopic  = regexp.MustCompile(`^[A-Za-z0-9_-]{43,64}$`)
	fleetHost  = regexp.MustCompile(`^ts-[a-z0-9]+-[0-9]+$`)
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
	var failed []string
	for _, item := range outcomes {
		if item.reason == "" {
			fmt.Fprintf(w, "endpoint ok %s\n", item.name)
			continue
		}
		fmt.Fprintf(w, "endpoint down %s %s\n", item.name, item.reason)
		failed = append(failed, item.name+" "+item.reason)
	}
	if !configured {
		fmt.Fprintln(w, "deadman down unconfigured")
		fmt.Fprintln(w, "NEED GitHub Actions secret TS_ALERTS_NTFY_TOPIC (vault ref gru-1-ts-alerts-ntfy-topic)")
		return 1
	}
	age, reason := client.heartbeat(ctx, secret)
	switch reason {
	case "":
		fmt.Fprintf(w, "deadman ok age_s=%d\n", int(age.Seconds()))
	case "missing":
		fmt.Fprintln(w, "deadman down missing")
		failed = append(failed, "monitoring heartbeat missing")
	case "stale":
		fmt.Fprintf(w, "deadman down stale age_s=%d\n", int(age.Seconds()))
		failed = append(failed, "monitoring heartbeat stale")
	default:
		fmt.Fprintln(w, "deadman down unread")
		failed = append(failed, "monitoring heartbeat unread")
	}
	if len(failed) == 0 {
		fmt.Fprintln(w, "up")
		return 0
	}
	detected := time.Now()
	if err := client.publish(ctx, secret, pageBody(failed)); err != nil {
		fmt.Fprintln(w, "page failed")
		return 1
	}
	fmt.Fprintf(w, "time_to_page_ms=%d\n", time.Since(detected).Milliseconds())
	return 1
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
	web, push *http.Client
}

func newClient() client {
	web := http.DefaultTransport.(*http.Transport).Clone()
	web.Proxy = nil
	return client{
		web:  &http.Client{Transport: web, Timeout: 3 * time.Second, CheckRedirect: refuseRedirect},
		push: &http.Client{Transport: web.Clone(), Timeout: 20 * time.Second, CheckRedirect: refuseRedirect},
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

func (c client) heartbeat(ctx context.Context, secret string) (time.Duration, string) {
	topic := probeTopic(secret)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pushEndpoint+topic+"/json?poll=1&since=latest", nil)
	if err != nil {
		return 0, "unread"
	}
	response, err := c.push.Do(request)
	if err != nil {
		return 0, "unread"
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if response.StatusCode != http.StatusOK || err != nil || len(body) > 64<<10 {
		return 0, "unread"
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
		return 0, "missing"
	}
	age := time.Since(time.Unix(newest, 0))
	if age >= deadmanLimit {
		return age, "stale"
	}
	return age, ""
}

func (c client) publish(ctx context.Context, topic, text string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, pushEndpoint+topic, strings.NewReader(text))
	if err != nil {
		return errors.New("push request")
	}
	request.Header.Set("Title", "TerraScale outside probe")
	request.Header.Set("Priority", "urgent")
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
