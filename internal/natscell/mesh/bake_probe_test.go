package mesh

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
)

type bakeRoundTrip func(*http.Request) (*http.Response, error)

func (f bakeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The batch-10 gru swap made TerraBase ready before auth recovered. Exercise
// the production HTTP classification and bake policy together, not a generic
// fake error: one initial auth 503 must restart the full healthy window.
func TestBakeTerraBaseSwapAuth503Recovery(t *testing.T) {
	for _, mode := range []string{"brief"} {
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
						// Batch 11: gru's dashboard rolls 10 seconds into
						// fra's otherwise healthy TerraBase bake.
						if crossService && dashboard >= 6 && (dashboard == 6 || mode != "dashboard-roll") {
							if dashboard == 6 || mode != "variable-latency-dashboard-roll" {
								time.Sleep(time.Second)
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
					return checks, bakeDependencies(ctx, client, checks, "gru", []string{"ts-auth", "ts-dashboard"})
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
						if err == nil || v.Samples != 21 || v.Finished.Sub(v.Started) != 41*time.Second {
							t.Fatalf("persistent mid-bake failure did not hold after 30 seconds: %+v %v", v, err)
						}
					} else if err != nil || v.Samples != 22 || v.RecoverySamples != 1 || v.Finished.Sub(v.Started) != 42*time.Second || v.Finished.Sub(v.HealthySince) != rollout.BakeWindow {
						t.Fatalf("dashboard roll interrupted fra bake instead of restarting healthy window: %+v %v", v, err)
					}
					return
				}
				if v.RecoveryChecks["ts-auth"] != "HTTP 503" {
					t.Fatalf("lost tolerated auth failure: %+v", v)
				}
				if mode == "persistent" {
					if err == nil || v.Reason != "bake ts-auth readiness: HTTP 503" || v.Samples != 15 || v.Finished.Sub(v.Started) != rollout.DependencyRecoveryWindow {
						t.Fatalf("persistent auth failure did not hold: %+v %v", v, err)
					}
				} else if err != nil || v.Samples != 17 || v.RecoverySamples != 1 || v.Finished.Sub(v.Started) != rollout.BakeWindow+2*time.Second || v.Finished.Sub(v.HealthySince) != rollout.BakeWindow || v.Checks["ts-auth"] != "ok" {
					t.Fatalf("normal swap did not recover into a full healthy bake: %+v %v", v, err)
				}
			})
		})
	}
}
