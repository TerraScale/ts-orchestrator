package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

type budget struct {
	Name    string     `json:"name"`
	Kind    string     `json:"kind"`
	Fresh   [3]float64 `json:"fresh"`
	Kept    [3]float64 `json:"kept"`
	EdgeP95 float64    `json:"edge_p95"`
}

type target struct {
	Name   string `json:"name"`
	Host   string `json:"host"`
	Region string `json:"region"`
}

type manifest struct {
	Revision string   `json:"revision"`
	Targets  []target `json:"targets"`
}

type sample struct {
	DNS, Connect, TLS, FirstByte, Total float64
}

type result struct {
	Name      string                `json:"name"`
	Region    string                `json:"region"`
	Path      string                `json:"path"`
	Samples   int                   `json:"samples"`
	Quantiles map[string][3]float64 `json:"seconds_p50_p95_p99"`
	Budget    [3]float64            `json:"budget_seconds_p50_p95_p99"`
	Passed    bool                  `json:"passed"`
}

func read(path string, value any) error {
	data, err := os.Open(path)
	if err != nil {
		return err
	}
	defer data.Close()
	decoder := json.NewDecoder(data)
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: latency budgets.json staging-manifest.json")
	}
	var budgets []budget
	var staging manifest
	if err := read(os.Args[1], &budgets); err != nil {
		return err
	}
	if err := read(os.Args[2], &staging); err != nil {
		return err
	}
	if len(staging.Revision) != 40 || staging.Revision != os.Getenv("GITHUB_SHA") {
		return fmt.Errorf("staging revision must match the release GITHUB_SHA")
	}
	if len(staging.Targets) != len(budgets) || len(budgets) == 0 {
		return fmt.Errorf("staging inventory must cover every budgeted public name")
	}
	byName := make(map[string]budget, len(budgets))
	for _, b := range budgets {
		byName[b.Name] = b
	}
	seen := map[string]bool{}
	for _, t := range staging.Targets {
		_, exists := byName[t.Name]
		labels := strings.Split(t.Host, ".")
		if !exists || seen[t.Name] || !slices.Contains(labels, "staging") || !strings.HasSuffix(t.Host, ".terrascale.tech") || strings.ContainsAny(t.Host, "/:@ ") || !slices.Contains([]string{"gru", "sjc", "fra"}, t.Region) {
			return fmt.Errorf("invalid or duplicate staging target %q", t.Name)
		}
		seen[t.Name] = true
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	var results []result
	passed := true
	for _, t := range staging.Targets {
		b := byName[t.Name]
		paths := []string{"fresh", "kept"}
		if b.Kind == "postgres" {
			paths = []string{"connect"}
		}
		for _, path := range paths {
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			var samples []sample
			count := 1000
			if path == "kept" {
				count++
			}
			for range count {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				var s sample
				var err error
				if b.Kind == "postgres" {
					s, err = postgres(ctx, t.Host)
				} else {
					s, err = measureHTTP(ctx, client, t, path == "kept" && len(samples) > 0)
				}
				cancel()
				if err != nil {
					transport.CloseIdleConnections()
					return fmt.Errorf("%s %s: %w", t.Name, path, err)
				}
				samples = append(samples, s)
				if path == "fresh" {
					transport.CloseIdleConnections()
				}
			}
			transport.CloseIdleConnections()
			limit := b.Fresh
			if path == "kept" {
				limit = b.Kept
				samples = samples[1:]
			} else {
				samples = samples[:1000]
			}
			r := summarize(t, path, samples, limit)
			results = append(results, r)
			passed = passed && r.Passed
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"revision": staging.Revision, "vantage": host, "completed": time.Now().UTC(), "results": results, "passed": passed}); err != nil {
		return err
	}
	if !passed {
		return fmt.Errorf("staging latency exceeds the release budget")
	}
	return nil
}

func measureHTTP(ctx context.Context, client *http.Client, t target, reused bool) (sample, error) {
	start := time.Now()
	var s sample
	var dns, connect, handshake time.Time
	var actualReuse bool
	var lock sync.Mutex
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { lock.Lock(); defer lock.Unlock(); dns = time.Now() },
		DNSDone:  func(httptrace.DNSDoneInfo) { lock.Lock(); defer lock.Unlock(); s.DNS = time.Since(dns).Seconds() },
		ConnectStart: func(string, string) {
			lock.Lock()
			defer lock.Unlock()
			if connect.IsZero() {
				connect = time.Now()
			}
		},
		ConnectDone: func(_, _ string, err error) {
			lock.Lock()
			defer lock.Unlock()
			if err == nil {
				s.Connect = time.Since(connect).Seconds()
			}
		},
		TLSHandshakeStart: func() { lock.Lock(); defer lock.Unlock(); handshake = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			lock.Lock()
			defer lock.Unlock()
			s.TLS = time.Since(handshake).Seconds()
		},
		GotConn:              func(info httptrace.GotConnInfo) { lock.Lock(); defer lock.Unlock(); actualReuse = info.Reused },
		GotFirstResponseByte: func() { lock.Lock(); defer lock.Unlock(); s.FirstByte = time.Since(start).Seconds() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "https://"+t.Host+"/readyz", nil)
	if err != nil {
		return s, err
	}
	response, err := client.Do(req)
	lock.Lock()
	defer lock.Unlock()
	if err != nil {
		return s, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	n := len(body)
	s.Total = time.Since(start).Seconds()
	if err != nil {
		return s, err
	}
	if response.StatusCode != http.StatusOK || n > 65536 || reused != actualReuse {
		return s, fmt.Errorf("status=%d body_bytes=%d connection_reused=%t expected=%t", response.StatusCode, n, actualReuse, reused)
	}
	var ready struct {
		Status       string            `json:"status"`
		Region       string            `json:"region"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(body, &ready); err != nil {
		return s, err
	}
	valid := ready.Status == "ready"
	if t.Name == "dash.terrascale.tech" {
		valid = ready.Status == "ok" && ready.Dependencies["ts-auth"] == "ok" && ready.Dependencies["terrabase"] == "ok"
	} else if t.Name != "auth.terrascale.tech" {
		valid = valid && ready.Region == t.Region
	}
	if !valid {
		return s, fmt.Errorf("staging readiness or region mismatch")
	}
	return s, nil
}

func postgres(ctx context.Context, host string) (sample, error) {
	start := time.Now()
	var s sample
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	s.DNS = time.Since(start).Seconds()
	if err != nil {
		return s, err
	}
	if len(addresses) == 0 {
		return s, fmt.Errorf("no PostgreSQL address")
	}
	tcp := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(addresses[0].IP.String(), "5432"))
	s.Connect = time.Since(tcp).Seconds()
	if err != nil {
		return s, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return s, err
	}
	handshake := time.Now()
	secure := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	err = secure.HandshakeContext(ctx)
	s.TLS = time.Since(handshake).Seconds()
	s.Total = time.Since(start).Seconds()
	s.FirstByte = s.Total
	return s, err
}

func summarize(t target, path string, samples []sample, limit [3]float64) result {
	r := result{t.Name, t.Region, path, len(samples), map[string][3]float64{}, limit, true}
	for name, field := range map[string]func(sample) float64{
		"dns": func(s sample) float64 { return s.DNS }, "connect": func(s sample) float64 { return s.Connect },
		"tls": func(s sample) float64 { return s.TLS }, "first_byte": func(s sample) float64 { return s.FirstByte }, "total": func(s sample) float64 { return s.Total },
	} {
		values := make([]float64, len(samples))
		for i, s := range samples {
			values[i] = field(s)
		}
		slices.Sort(values)
		var quantiles [3]float64
		for i, q := range []float64{.5, .95, .99} {
			quantiles[i] = values[int(math.Ceil(q*float64(len(values))))-1]
			if (name == "total" || name == "first_byte") && quantiles[i] > limit[i] {
				r.Passed = false
			}
		}
		r.Quantiles[name] = quantiles
	}
	return r
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
