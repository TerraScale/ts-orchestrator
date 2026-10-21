package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

const hostWANMetrics = `terrabase_wan_lag{region="sjc-1"} 0
terrabase_wan_staleness_seconds{region="sjc-1"} 2.5
terrabase_wan_members{region="sjc-1"} 3
terrabase_wan_unregistered{region="sjc-1"} 0
terrabase_wan_conflicts{region="sjc-1"} 0
`

func hostWANFixture(at time.Time, receiverRegion string) *terrabase.WANObservation {
	return &terrabase.WANObservation{ObservedAt: at, ReceiverRegion: receiverRegion, Sources: []terrabase.WANSource{{
		SourceRegion: "sjc-1", LagGroups: new(0.0), StalenessSeconds: new(2.5),
		Members: new(3.0), Unregistered: new(0.0), Conflicts: new(0.0),
	}}}
}

func TestLoadOperationValidatesWANAgainstCurrentSignedNativeRegion(t *testing.T) {
	c, key, session, _ := reportedTestHost(t)
	desired, _, _, err := c.readDesired(t.Context(), "node-a", terrabase.Role)
	if err != nil {
		t.Fatal(err)
	}
	desired.Env = map[string]string{terrabase.EnvRegion: "gru-native-region"}
	replaceLoadTestDesired(t, c, desired)
	var got hostload.Report
	var origin hostload.Origin
	c.SetLoadSink(func(o hostload.Origin, r hostload.Report) error { origin, got = o, r; return nil })
	for _, test := range []struct {
		name           string
		at             time.Time
		receiverRegion string
		accepted       bool
	}{
		{"fresh native receiver region", time.Now().UTC().Add(-time.Minute), "gru-native-region", true},
		{"display identity", time.Now().UTC(), "gru", false},
		{"different native region", time.Now().UTC(), "gru-1", false},
		{"stale", time.Now().UTC().Add(-terrabase.WANFreshFor - time.Second), "gru-native-region", false},
		{"future", time.Now().UTC().Add(time.Minute), "gru-native-region", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := hostload.Report{SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: terrabase.Role,
				CPUCores: new(0.5), WAN: hostWANFixture(test.at, test.receiverRegion)}}}
			if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, key, "load", session.SessionID, session.Epoch, report)); err != nil {
				t.Fatal(err)
			}
			if origin != (hostload.Origin{Cell: "gru", Environment: "production", Node: "node-a"}) || len(got.Roles) != 1 ||
				got.Roles[0].CPUCores == nil || (got.Roles[0].WAN != nil) != test.accepted {
				t.Fatalf("WAN admission = origin %+v report %+v", origin, got)
			}
			if test.accepted && !got.Roles[0].WAN.ObservedAt.Equal(test.at) {
				t.Fatal("delivery replaced original scrape time")
			}
		})
	}
	// A changed native receiver identity cannot carry the old deployment's observations.
	desired.Env = nil
	replaceLoadTestDesired(t, c, desired)
	report := hostload.Report{SchemaVersion: 1, Roles: []hostload.RoleUsage{{Role: terrabase.Role,
		WAN: hostWANFixture(time.Now().UTC(), "gru-native-region")}}}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, key, "load", session.SessionID, session.Epoch, report)); err != nil || got.Roles[0].WAN != nil {
		t.Fatalf("missing receiver identity accepted: %+v, %v", got, err)
	}
	desired.Withdrawn = true
	replaceLoadTestDesired(t, c, desired)
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, key, "load", session.SessionID, session.Epoch, report)); err != nil || len(got.Roles) != 0 {
		t.Fatalf("withdrawn role accepted: %+v, %v", got, err)
	}
}

func TestNativeWANCollectionRequiresTheSameRunningProcess(t *testing.T) {
	runner := &memoryRunner{observed: make(map[string]Observation)}
	var scrapes atomic.Int32
	var changeProcess atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scrapes.Add(1)
		if changeProcess.Load() {
			runner.mu.Lock()
			process := runner.observed[terrabase.Role]
			process.PID++
			runner.observed[terrabase.Role] = process
			runner.mu.Unlock()
		}
		fmt.Fprint(w, `terrabase_wan_lag{region="sjc-1"} 0
terrabase_wan_staleness_seconds{region="sjc-1"} 2.5
terrabase_wan_members{region="sjc-1"} 3
terrabase_wan_unregistered{region="sjc-1"} 0
terrabase_wan_conflicts{region="sjc-1"} 0
`)
	}))
	defer server.Close()
	address, _ := url.Parse(server.URL)
	desired := Desired{Role: terrabase.Role, Digest: "digest", Env: map[string]string{
		terrabase.EnvAdminPort: address.Port(), terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "node-a=127.0.0.1:9443",
		terrabase.EnvRegion: "gru-native-region"}}
	fingerprint, err := desiredFingerprint(desired)
	if err != nil {
		t.Fatal(err)
	}
	process := Observation{Role: terrabase.Role, Digest: desired.Digest, Fingerprint: fingerprint, Running: true, PID: 42}
	agent := &Agent{cfg: AgentConfig{TerraBaseRoot: t.TempDir()}, runner: runner}
	// A running unrelated/replaced process is not the signed Desired's member.
	for _, wrong := range []Observation{{}, {Running: true, Digest: "other", Fingerprint: fingerprint},
		{Running: true, Digest: desired.Digest, Fingerprint: "other"}} {
		runner.observed[terrabase.Role] = wrong
		agent.collectTerraBaseWAN(t.Context(), desired)
		if agent.terraBaseWAN != nil || scrapes.Load() != 0 {
			t.Fatal("scraped a process outside the current desired")
		}
	}
	runner.observed[terrabase.Role] = process
	agent.collectTerraBaseWAN(t.Context(), desired)
	if agent.terraBaseWAN == nil || scrapes.Load() != 1 {
		t.Fatal("verified running native member was not scraped")
	}
	at := agent.terraBaseWAN.wan.ObservedAt
	for _, roles := range [][]hostload.RoleUsage{nil, {{Role: terrabase.Role, CPUCores: new(0.5)}}} {
		report := hostload.Report{SchemaVersion: 1, Roles: roles}
		agent.addTerraBaseWAN(t.Context(), &report)
		if len(report.Roles) != 1 || report.Roles[0].WAN == nil || !report.Roles[0].WAN.ObservedAt.Equal(at) {
			t.Fatalf("native WAN missing from sampler report: %+v", report)
		}
	}
	for name, change := range map[string]func(){
		"stale": func() {
			agent.terraBaseWAN.wan = hostWANFixture(time.Now().UTC().Add(-terrabase.WANFreshFor-time.Second), "gru-native-region")
		},
		"stopped":             func() { runner.observed[terrabase.Role] = Observation{} },
		"replaced":            func() { replaced := process; replaced.PID++; runner.observed[terrabase.Role] = replaced },
		"digest changed":      func() { changed := process; changed.Digest = "other"; runner.observed[terrabase.Role] = changed },
		"fingerprint changed": func() { changed := process; changed.Fingerprint = "other"; runner.observed[terrabase.Role] = changed },
	} {
		t.Run(name, func(t *testing.T) {
			agent.terraBaseWAN = &terraBaseWAN{process: process, wan: hostWANFixture(at, "gru-native-region")}
			runner.observed[terrabase.Role] = process
			change()
			var report hostload.Report
			agent.addTerraBaseWAN(t.Context(), &report)
			if len(report.Roles) != 0 {
				t.Fatalf("published stale or invalid process evidence: %+v", report)
			}
		})
	}
	agent.terraBaseWAN = nil
	runner.observed[terrabase.Role] = process
	changeProcess.Store(true)
	agent.collectTerraBaseWAN(t.Context(), desired)
	if agent.terraBaseWAN != nil {
		t.Fatal("process changed during scrape but observation was accepted")
	}
}

func TestNativeWANPublicationRechecksEvidenceAfterObservation(t *testing.T) {
	for _, invalidation := range []string{"freshness expired", "desired unverified"} {
		t.Run(invalidation, func(t *testing.T) {
			process := Observation{Role: terrabase.Role, Digest: "digest", Fingerprint: "fingerprint", Running: true, PID: 42}
			entry := &terraBaseWAN{process: process, wan: hostWANFixture(time.Now().UTC(), "gru-native-region")}
			agent := &Agent{terraBaseWAN: entry}
			agent.runner = &wanObserveRunner{observe: func(ctx context.Context, _ string) (Observation, error) {
				if invalidation == "freshness expired" {
					entry.wan.ObservedAt = time.Now().UTC().Add(-terrabase.WANFreshFor - time.Second)
				} else {
					agent.collectTerraBaseWAN(ctx, Desired{Role: terrabase.Role, Withdrawn: true})
				}
				return process, nil
			}}
			var report hostload.Report
			agent.addTerraBaseWAN(t.Context(), &report)
			if len(report.Roles) != 0 {
				t.Fatal("published evidence invalidated during process verification")
			}
		})
	}
}

func TestNativeWANRetainsVerifiedObservationDuringRunningReport(t *testing.T) {
	for _, outcome := range []string{"http failure", "missing metrics", "success"} {
		t.Run(outcome, func(t *testing.T) {
			healthEntered, scrapeEntered := make(chan struct{}), make(chan struct{})
			releaseHealth, releaseScrape := make(chan struct{}), make(chan struct{})
			var polling atomic.Bool
			agent, desired, _ := newNativeWANTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/healthz" {
					close(healthEntered)
					select {
					case <-releaseHealth:
					case <-r.Context().Done():
						return
					}
					fmt.Fprint(w, `{"status":"ok"}`)
					return
				}
				if polling.Load() {
					close(scrapeEntered)
					select {
					case <-releaseScrape:
					case <-r.Context().Done():
						return
					}
					switch outcome {
					case "http failure":
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					case "missing metrics":
						fmt.Fprint(w, "other_metric 1\n")
						return
					}
				}
				fmt.Fprint(w, hostWANMetrics)
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			agent.collectTerraBaseWAN(ctx, desired)
			if agent.terraBaseWAN == nil {
				t.Fatal("initial verified scrape missing")
			}
			at := agent.terraBaseWAN.wan.ObservedAt
			polling.Store(true)
			done := make(chan Report, 1)
			go func() { done <- agent.terraBaseRunningReport(ctx, desired) }()
			assertCached := func() {
				t.Helper()
				var report hostload.Report
				agent.addTerraBaseWAN(ctx, &report)
				if len(report.Roles) != 1 || report.Roles[0].WAN == nil || !report.Roles[0].WAN.ObservedAt.Equal(at) {
					t.Fatalf("last verified observation was lost or retimed: %+v", report)
				}
			}
			waitFor := func(entered <-chan struct{}) {
				t.Helper()
				select {
				case <-entered:
				case report := <-done:
					t.Fatalf("poll ended before expected endpoint: %+v", report)
				case <-time.After(5 * time.Second):
					t.Fatal("poll did not reach expected endpoint")
				}
			}
			waitFor(healthEntered)
			assertCached()
			close(releaseHealth)
			waitFor(scrapeEntered)
			assertCached()
			close(releaseScrape)
			select {
			case report := <-done:
				if report.State != "running" || report.Error != "" {
					t.Fatalf("verified poll failed: %+v", report)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("poll did not complete")
			}
			if outcome != "success" {
				assertCached()
			}
			if outcome == "success" && !agent.terraBaseWAN.wan.ObservedAt.After(at) {
				t.Fatal("successful scrape did not replace the observation")
			}
			// A failed/nil scrape cannot extend the original freshness window.
			agent.terraBaseWAN.wan.ObservedAt = time.Now().UTC().Add(-terrabase.WANFreshFor - time.Second)
			var report hostload.Report
			agent.addTerraBaseWAN(ctx, &report)
			if len(report.Roles) != 0 {
				t.Fatal("stale cached observation was published")
			}
		})
	}
}

func TestNativeWANLogsChangedOutcomesAndRecovery(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, outcome := range []string{"desired_unverified", "before_verification_failed", "after_verification_failed",
		"not_running", "process_replaced", "metrics_unavailable", "metrics_http_failed", "metrics_invalid"} {
		t.Run(outcome, func(t *testing.T) {
			var failing atomic.Bool
			var processChange func()
			agent, desired, runner := newNativeWANTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
				if failing.Load() {
					switch outcome {
					case "metrics_unavailable":
						fmt.Fprint(w, "other_metric 1\n")
						return
					case "metrics_http_failed":
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					case "metrics_invalid":
						fmt.Fprint(w, `terrabase_wan_lag{region="sjc-1"} invalid`)
						return
					case "process_replaced":
						processChange()
					}
				}
				fmt.Fprint(w, hostWANMetrics)
			})
			process := runner.observed[terrabase.Role]
			processChange = func() {
				runner.mu.Lock()
				defer runner.mu.Unlock()
				replaced := process
				replaced.PID++
				runner.observed[terrabase.Role] = replaced
			}
			var calls int
			agent.runner = &wanObserveRunner{Runner: runner, observe: func(ctx context.Context, role string) (Observation, error) {
				calls++
				if failing.Load() && ((outcome == "before_verification_failed" && calls == 1) ||
					(outcome == "after_verification_failed" && calls == 2)) {
					return Observation{}, errors.New("runner verification unavailable")
				}
				return runner.Observe(ctx, role)
			}}
			agent.collectTerraBaseWAN(t.Context(), desired)
			at := agent.terraBaseWAN.wan.ObservedAt
			logs.Reset()
			failing.Store(true)
			badDesired := desired
			if outcome == "desired_unverified" {
				badDesired.Withdrawn = true
			}
			for range 2 {
				runner.mu.Lock()
				runner.observed[terrabase.Role] = process
				if outcome == "not_running" {
					runner.observed[terrabase.Role] = Observation{}
				}
				runner.mu.Unlock()
				calls = 0
				agent.collectTerraBaseWAN(t.Context(), badDesired)
			}
			output := logs.String()
			if strings.Count(output, "outcome="+outcome) != 1 || !strings.Contains(output, "component=host") {
				t.Fatalf("missing or repeated failure outcome: %s", output)
			}
			switch outcome {
			case "desired_unverified", "not_running", "process_replaced":
				if agent.terraBaseWAN != nil {
					t.Fatal("known-invalid evidence retained")
				}
			default:
				if agent.terraBaseWAN == nil || !agent.terraBaseWAN.wan.ObservedAt.Equal(at) {
					t.Fatal("transient failure cleared or retimed verified evidence")
				}
				var report hostload.Report
				agent.addTerraBaseWAN(t.Context(), &report)
				if len(report.Roles) != 1 || report.Roles[0].WAN == nil || !report.Roles[0].WAN.ObservedAt.Equal(at) {
					t.Fatal("verified evidence unavailable after a transient failure")
				}
			}
			if outcome == "metrics_http_failed" && !strings.Contains(output, "HTTP status 503") {
				t.Fatalf("HTTP failure detail missing: %s", output)
			}
			if outcome == "metrics_invalid" && !strings.Contains(output, "invalid WAN metric value") {
				t.Fatalf("parser failure detail missing: %s", output)
			}
			runner.mu.Lock()
			runner.observed[terrabase.Role] = process
			runner.mu.Unlock()
			failing.Store(false)
			for range 2 {
				agent.collectTerraBaseWAN(t.Context(), desired)
			}
			output = logs.String()
			if strings.Count(output, "terrabase WAN collection recovered") != 1 || strings.Contains(output, "credential-sentinel") {
				t.Fatalf("recovery repeated/missing or environment disclosed: %s", output)
			}
		})
	}
}

type wanObserveRunner struct {
	Runner
	observe func(context.Context, string) (Observation, error)
}

func (r *wanObserveRunner) Observe(ctx context.Context, role string) (Observation, error) {
	return r.observe(ctx, role)
}

func newNativeWANTestAgent(t *testing.T, handler http.HandlerFunc) (*Agent, Desired, *memoryRunner) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	desired := Desired{Role: terrabase.Role, Digest: strings.Repeat("a", 64), Env: map[string]string{
		terrabase.EnvAdminPort: address.Port(), terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "node-a=127.0.0.1:9443",
		terrabase.EnvRegion: "gru-native-region", "SECRET_TEST": "credential-sentinel"}}
	fingerprint, err := desiredFingerprint(desired)
	if err != nil {
		t.Fatal(err)
	}
	runner := &memoryRunner{observed: map[string]Observation{terrabase.Role: {
		Role: terrabase.Role, Digest: desired.Digest, Fingerprint: fingerprint, Running: true, PID: 42}}}
	dir := t.TempDir()
	root := filepath.Join(dir, "terrabase")
	agent := &Agent{runner: runner, terraBase: make(map[string]terraBaseMember), cfg: AgentConfig{Node: "node-a", TerraBaseRoot: root,
		WorkloadIdentity: WorkloadIdentity{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}}}
	now := time.Now()
	caPEM, caKey, err := terrabase.NewCA("gru", now)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"ca.pem": caPEM, "ca.key": caKey} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ca, err := terrabase.LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := terrabase.NewMemberKey()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := terrabase.ParseProfile(desired.Env)
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := profile.Peer("node-a")
	certificate, err := ca.Issue(csr, peer, now)
	if err != nil {
		t.Fatal(err)
	}
	layout := terrabase.Layout(root)
	if err := os.MkdirAll(layout.TLS(), 0o750); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{layout.CA(): caPEM, layout.Key(): key, layout.Certificate(): certificate} {
		if err := os.WriteFile(path, data, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	return agent, desired, runner
}
