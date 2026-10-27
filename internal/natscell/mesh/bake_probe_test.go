package mesh

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type bakeRoundTrip func(*http.Request) (*http.Response, error)

func (f bakeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBakeDependencyBodies(t *testing.T) {
	for _, tc := range []struct {
		service, body, want string
		code                int
	}{
		{"ts-auth", `{"status":"ready"}`, "ok", 200},
		{"ts-auth", `{"status":"ready"}`, "HTTP 503", 503},
		{"ts-auth", `{"status":"ok"}`, "dependency-unavailable-or-missing", 200},
		{"ts-dashboard", `{"status":"ok","dependencies":{"ts-auth":"ok","terrabase":"ok"}}`, "ok", 200},
		{"ts-dashboard", `{"status":"ok","dependencies":{"terrabase":"ok"}}`, "dependency-unavailable-or-missing", 200},
		{"ts-dashboard", `ok`, "invalid-readiness-body", 200},
		{"ts-auth", strings.Repeat("s", (16<<10)+1), "invalid-readiness-body", 200},
	} {
		client := &http.Client{Transport: bakeRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme != "https" || r.URL.Path != "/readyz" || r.Method != "GET" {
				t.Fatalf("unexpected probe: %s %s", r.Method, r.URL)
			}
			return &http.Response{StatusCode: tc.code, Body: io.NopCloser(strings.NewReader(tc.body)), Header: http.Header{}}, nil
		})}
		if got := bakeDependency(t.Context(), client, tc.service); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.service, got, tc.want)
		}
	}
}

// The batch-10 gru swap made TerraBase ready before auth recovered. Exercise
// the production HTTP classification and bake policy together, not a generic
// fake error: one initial auth 503 must restart the full healthy window.
func TestBakeTerraBaseSwapAuth503Recovery(t *testing.T) {
	for _, mode := range []string{"brief", "persistent", "invalid-dashboard", "dashboard-roll", "persistent-dashboard-roll", "variable-latency-dashboard-roll"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				auth, dashboard := 0, 0
				crossService := strings.Contains(mode, "dashboard-roll")
				client := &http.Client{Transport: bakeRoundTrip(func(r *http.Request) (*http.Response, error) {
					code, body := http.StatusOK, `{"status":"ready"}`
					if r.URL.Host == "auth.terrascale.tech" {
						auth++
						if mode == "persistent" || auth == 1 && !crossService {
							code = http.StatusServiceUnavailable
						}
					} else if r.URL.Host == "dash.terrascale.tech" {
						dashboard++
						body = `{"status":"ok","dependencies":{"ts-auth":"ok","terrabase":"ok"}}`
						if mode == "invalid-dashboard" {
							body = "invalid"
						}
						// Batch 11: gru's dashboard rolls 170 seconds into
						// fra's otherwise healthy TerraBase bake.
						if crossService && dashboard >= 18 && (dashboard == 18 || mode != "dashboard-roll") {
							if dashboard == 18 || mode != "variable-latency-dashboard-roll" {
								time.Sleep(3 * time.Second)
							}
							return nil, errors.New("connection interrupted by dashboard rollout")
						}
					} else {
						t.Fatalf("unexpected dependency host: %s", r.URL.Host)
					}
					return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				v, err := rollout.RunBake(t.Context(), func(ctx context.Context) (map[string]string, error) {
					checks := map[string]string{"candidate": "ok", "terrabase-logs": "ok"}
					return checks, bakeDependencies(ctx, client, checks)
				})
				if auth != v.Samples || dashboard != v.Samples {
					t.Fatalf("lost dependency checks/evidence: auth=%d dashboard=%d verdict=%+v", auth, dashboard, v)
				}
				if mode == "invalid-dashboard" {
					if err == nil || v.Samples != 1 || v.RecoverySamples != 0 || v.Checks["ts-dashboard"] != "invalid-readiness-body" {
						t.Fatalf("auth recovery masked malformed dashboard response: %+v %v", v, err)
					}
					return
				}
				if crossService {
					if v.RecoveryChecks["ts-dashboard"] != "request-failed" || v.RecoveryChecks["candidate"] != "ok" || v.RecoveryChecks["terrabase-logs"] != "ok" {
						t.Fatalf("lost cross-service rollover evidence: %+v", v)
					}
					if mode != "dashboard-roll" {
						if err == nil || v.Samples != 21 || v.Finished.Sub(v.Started) != 203*time.Second {
							t.Fatalf("persistent mid-bake failure did not hold after 30 seconds: %+v %v", v, err)
						}
					} else if err != nil || v.Samples != 49 || v.RecoverySamples != 1 || v.Finished.Sub(v.Started) != 480*time.Second || v.Finished.Sub(v.HealthySince) != rollout.BakeWindow {
						t.Fatalf("dashboard roll interrupted fra bake instead of restarting healthy window: %+v %v", v, err)
					}
					return
				}
				if v.RecoveryChecks["ts-auth"] != "HTTP 503" {
					t.Fatalf("lost tolerated auth failure: %+v", v)
				}
				if mode == "persistent" {
					if err == nil || v.Reason != "bake ts-auth readiness: HTTP 503" || v.Samples != 3 || v.Finished.Sub(v.Started) != rollout.DependencyRecoveryWindow {
						t.Fatalf("persistent auth failure did not hold: %+v %v", v, err)
					}
				} else if err != nil || v.Samples != 32 || v.RecoverySamples != 1 || v.Finished.Sub(v.Started) != rollout.BakeWindow+10*time.Second || v.Finished.Sub(v.HealthySince) != rollout.BakeWindow || v.Checks["ts-auth"] != "ok" {
					t.Fatalf("normal swap did not recover into a full healthy bake: %+v %v", v, err)
				}
			})
		})
	}
}

func TestBakeLogsOnlyNewFaultsAndCoverage(t *testing.T) {
	anchor := `{"msg":"This machine's catalog anchor could not be written; it is tried again","Error":"private-marker"}` + "\n"
	writer := `{"msg":"Waited 5 s for a database's writer and took it: write queued behind holder"}` + "\n"
	for _, scenario := range []string{"healthy", "anchor", "writer", "split", "truncated", "replaced", "missing", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stdout")
			if err := os.WriteFile(path, []byte(anchor), 0600); err != nil {
				t.Fatal(err)
			}
			log := &bakeLog{path: path}
			if err := log.check(); err != nil {
				t.Fatalf("old warning counted: %v", err)
			}
			appendLog := func(s string) {
				t.Helper()
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString(s)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "healthy":
				appendLog("{\"msg\":\"healthy\"}\n")
			case "anchor":
				appendLog(anchor)
			case "writer":
				appendLog(writer)
			case "split":
				appendLog(writer[:15])
				if err := log.check(); err != nil {
					t.Fatal(err)
				}
				appendLog(writer[15:])
			case "truncated":
				if err := os.WriteFile(path, []byte(strings.Repeat("x", len(anchor))), 0600); err != nil {
					t.Fatal(err)
				}
			case "replaced":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(anchor), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				appendLog(strings.Repeat("x", (1<<20)+1))
			}
			err := log.check()
			if (err == nil) != (scenario == "healthy") || err != nil && strings.Contains(err.Error(), "private-marker") {
				t.Fatalf("%s: %v", scenario, err)
			}
		})
	}
}

func TestBakeRejectsReplacedAndAbsentTasks(t *testing.T) {
	a := []swarmruntime.ServiceTaskEvidence{{TaskID: "one"}, {TaskID: "two"}}
	if !bakeSameTasks(a, []swarmruntime.ServiceTaskEvidence{a[1], a[0]}) || bakeSameTasks(a, []swarmruntime.ServiceTaskEvidence{{TaskID: "one"}, {TaskID: "new"}}) || bakeSameTasks(nil, nil) || bakeSameTasks(a, []swarmruntime.ServiceTaskEvidence{a[0], a[0]}) {
		t.Fatal("task replacement or missing runtime identity passed")
	}
}

// 2026-10-27 14:57Z: one unready sample of the dashboard candidate (its
// readiness includes a flapping ts-auth) failed the d5b0e7b release at once.
func TestBakeCandidateReadinessRecovers(t *testing.T) {
	if candidateUnready("ts-dashboard", errors.New("running task does not match the requested artifact and generation")) != nil {
		t.Fatal("a replaced candidate must stay fatal")
	}
	for _, mode := range []string{"brief-503", "persistent-503", "http-500"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				samples := 0
				v, err := rollout.RunBake(t.Context(), func(context.Context) (map[string]string, error) {
					samples++
					checks := map[string]string{}
					var probe error
					switch {
					case mode == "http-500":
						probe = &swarmruntime.TaskReadinessError{Status: "HTTP 500"}
					case mode == "persistent-503" || samples == 1:
						probe = &swarmruntime.TaskReadinessError{Status: "HTTP 503"}
					}
					if failure := candidateUnready("ts-dashboard", probe); failure != nil {
						checks["candidate"] = failure.Status
						return checks, failure
					}
					checks["candidate"] = "ok"
					return checks, nil
				})
				switch mode {
				case "brief-503":
					if err != nil || v.RecoverySamples != 1 || v.RecoveryChecks["candidate"] != "HTTP 503" || v.Finished.Sub(v.HealthySince) != rollout.BakeWindow {
						t.Fatalf("brief candidate 503 did not recover into a full bake: %+v %v", v, err)
					}
				case "persistent-503":
					if err == nil || v.Finished.Sub(v.Started) != rollout.DependencyRecoveryWindow {
						t.Fatalf("persistent candidate 503 did not fail after the recovery window: %+v %v", v, err)
					}
				case "http-500":
					if err == nil || v.Samples != 1 {
						t.Fatalf("candidate HTTP 500 must fail at once: %+v %v", v, err)
					}
				}
			})
		})
	}
}
