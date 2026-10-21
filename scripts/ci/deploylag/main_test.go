package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHistoryKeepsFirstQualificationAcrossFailedDeploymentAndRerun(t *testing.T) {
	a := api{readToken: "read", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.github.com" || r.URL.Query().Get("per_page") != "50" || r.URL.Query().Has("limit") {
			t.Fatalf("incorrect GitHub history URL: %s", r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer read" {
			t.Fatal("missing authenticated history request")
		}
		body := `[{"sha":"abc","GreenAt":"2000-01-01T00:00:00Z"}]`
		if strings.Contains(r.URL.Path, "statuses") {
			body = `[
				{"context":"deploy","state":"failure","created_at":"2026-10-09T15:00:00Z"},
				{"context":"deployment/qualified","state":"success","created_at":"2026-10-09T14:59:00Z"},
				{"context":"deployment/qualified","state":"success","created_at":"2026-10-09T14:00:00Z"}
			]`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	history, err := a.history(context.Background(), "ts-auth")
	if err != nil || len(history) != 1 || history[0].GreenAt.Format(time.RFC3339) != "2026-10-09T14:00:00Z" {
		t.Fatalf("qualification changed after failed deployment: %+v %v", history, err)
	}
}

func TestHistoryPaginatesQualificationStatusesAndFailsOnUnreadablePage(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(fmt.Sprint(unreadable), func(t *testing.T) {
			var pages []string
			a := api{readToken: "read", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
				body, status := `[{"sha":"abc"}]`, http.StatusOK
				if strings.HasSuffix(r.URL.Path, "/statuses") {
					page := r.URL.Query().Get("page")
					pages = append(pages, page)
					switch page {
					case "1":
						entry := `{"context":"deployment/qualified","state":"success","created_at":"2026-10-09T14:59:00Z"}`
						body = "[" + strings.Repeat(entry+",", 49) + entry + "]"
					case "2":
						body = `[{"context":"deployment/qualified","state":"success","created_at":"2026-10-09T14:00:00Z"}]`
						if unreadable {
							status = http.StatusServiceUnavailable
						}
					default:
						t.Fatalf("unexpected page %s", page)
					}
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			history, err := a.history(t.Context(), "ts-auth")
			if (err != nil) != unreadable || strings.Join(pages, ",") != "1,2" {
				t.Fatalf("pages=%v history=%+v err=%v", pages, history, err)
			}
			if !unreadable && history[0].GreenAt.Format(time.RFC3339) != "2026-10-09T14:00:00Z" {
				t.Fatalf("pagination reset the qualification clock: %+v", history)
			}
		})
	}
}

func TestRunDeliversAlertAfterCollectionContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	delivered := false
	a := api{readToken: "read", writeToken: "write", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/discovery" {
			body := fmt.Sprintf(`{"v":1,"updated":%d,"regions":[{"id":"gru-1"},{"id":"sjc-1"}]}`, time.Now().Unix())
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		if r.URL.Path == "/api/v1/deployments" {
			cancel()
			return nil, context.Canceled
		}
		if strings.HasSuffix(r.URL.Path, "/issues") {
			deadline, bounded := r.Context().Deadline()
			if r.Context().Err() != nil || !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > notificationBudget {
				t.Fatal("alert reused the expired collection context or lacks its own bounded budget")
			}
			if r.Method == "POST" {
				wire, _ := io.ReadAll(r.Body)
				delivered = strings.Contains(string(wire), "live fleet proof unavailable")
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("[]"))}, nil
	})}}
	readNative := func(ctx context.Context, _, _ string) (observation, error) {
		<-ctx.Done()
		return observation{}, ctx.Err()
	}
	if err := run(ctx, a, time.Now, readNative, true); err == nil || !delivered {
		t.Fatalf("expired collection did not deliver its failure alert: delivered=%v err=%v", delivered, err)
	}
}

func TestAlertCreatesAssignedIncidentAndClosesItAfterRecovery(t *testing.T) {
	var methods []string
	a := api{writeToken: "write", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer write" {
			t.Fatal("alert lacks write credential")
		}
		methods = append(methods, r.Method)
		body := "[]"
		if r.Method == "POST" {
			wire, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(wire), `"assignees":["mariogk"]`) {
				t.Fatal("alert is not assigned")
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	if err := a.alert(context.Background(), []string{"- ts-auth GRU overdue"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(methods, ",") != "GET,POST" {
		t.Fatal(methods)
	}
	methods = nil
	a.client.Transport = testTransport(func(r *http.Request) (*http.Response, error) {
		methods = append(methods, r.Method)
		body := `[{"number":1,"title":"TS-768: Deployment lag exceeds 30 minutes"}]`
		if r.Method == "PATCH" {
			wire, _ := io.ReadAll(r.Body)
			if string(wire) != `{"state":"closed"}` {
				t.Fatal(string(wire))
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	if err := a.alert(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(methods, ",") != "GET,PATCH" {
		t.Fatal(methods)
	}
}

func TestPendingDoesNotResetThirtyMinuteClockForContinuousBuilds(t *testing.T) {
	now := time.Date(2026, 10, 9, 15, 0, 0, 0, time.UTC)
	history := []commit{
		{SHA: "new", GreenAt: now.Add(-time.Minute)},
		{SHA: "red"},
		{SHA: "pending", GreenAt: now.Add(-31 * time.Minute)},
		{SHA: "live", GreenAt: now.Add(-time.Hour)},
	}
	target, lag, err := pending(history, "live", now)
	if err != nil || target.SHA != "new" || lag != 31*time.Minute {
		t.Fatalf("target=%+v lag=%s err=%v", target, lag, err)
	}
	for _, tc := range []struct {
		version string
		lag     time.Duration
	}{
		{"new", 0}, {"pending", time.Minute},
	} {
		_, lag, err := pending(history, tc.version, now)
		if err != nil || lag != tc.lag {
			t.Fatalf("%s lag=%s err=%v", tc.version, lag, err)
		}
	}
	if _, _, err := pending(history, "unknown", now); err == nil {
		t.Fatal("treated incomplete ancestry as a recent deployment")
	}
	history[0].GreenAt = now.Add(time.Minute)
	if _, _, err := pending(history, "live", now); err == nil {
		t.Fatal("accepted future qualification")
	}
}

func TestPendingRefusesAnExhaustedHistoryWindow(t *testing.T) {
	now := time.Date(2026, 10, 9, 15, 0, 0, 0, time.UTC)
	history := make([]commit, 50)
	for i := range history {
		history[i] = commit{SHA: fmt.Sprint(i), GreenAt: now.Add(-time.Minute)}
	}
	if _, _, err := pending(history, "older-deployed-revision", now); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("stalled deployment reset its lag clock: %v", err)
	}
}

func TestAlertFindsAndRecoversAnIncidentBeyondTheFirstPage(t *testing.T) {
	for _, findings := range [][]string{nil, {"- ts-auth GRU overdue"}} {
		t.Run(fmt.Sprint(len(findings)), func(t *testing.T) {
			var methods []string
			a := api{writeToken: "write", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
				methods = append(methods, r.Method)
				body := "[]"
				if r.Method == "GET" {
					if r.URL.Query().Get("per_page") != "50" || r.URL.Query().Has("type") {
						t.Fatalf("incorrect GitHub issues URL: %s", r.URL)
					}
					switch r.URL.Query().Get("page") {
					case "1":
						body = "[" + strings.Repeat(`{"number":1,"title":"unrelated"},`, 49) + `{"number":50,"title":"unrelated"}]`
					case "2":
						body = `[{"number":41,"title":"TS-768: Deployment lag exceeds 30 minutes","pull_request":{}},{"number":42,"title":"TS-768: Deployment lag exceeds 30 minutes"}]`
					default:
						t.Fatalf("unexpected page: %s", r.URL)
					}
				} else if r.Method == "PATCH" {
					wire, _ := io.ReadAll(r.Body)
					if !strings.HasSuffix(r.URL.Path, "/42") || (strings.Contains(string(wire), `"state":"closed"`) != (len(findings) == 0)) {
						t.Fatalf("wrong incident update: %s %s", r.URL, wire)
					}
				} else {
					t.Fatalf("duplicate incident: %s", r.Method)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			if err := a.alert(context.Background(), findings); err != nil {
				t.Fatal(err)
			}
			if strings.Join(methods, ",") != "GET,GET,PATCH" {
				t.Fatal(methods)
			}
		})
	}
}

func TestRunValidatesCurrentProofsBeforeClosingAnIncident(t *testing.T) {
	baseNow := time.Date(2026, 10, 9, 15, 0, 0, 0, time.UTC)
	latest, deployed := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for _, broken := range []string{"", "new region", "discovery missing", "native missing", "native stale", "edge missing", "edge stale", "edge non-200", "edge invalid revision"} {
		t.Run(broken, func(t *testing.T) {
			regions := []string{"GRU", "SJC"}
			if broken == "new region" {
				regions = append(regions, "FRA")
			}
			var elapsed atomic.Int64
			var nativeReads atomic.Int64
			now := func() time.Time { return baseNow.Add(time.Duration(elapsed.Load()) * time.Second) }
			closed, updated := false, false
			a := api{readToken: "read", writeToken: "write", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
				body := "[]"
				switch {
				case r.URL.Path == "/v1/discovery":
					var entries []string
					for _, region := range regions {
						entries = append(entries, fmt.Sprintf(`{"id":%q,"health":"unknown"}`, strings.ToLower(region)+"-1"))
					}
					if broken == "discovery missing" {
						entries = nil
					}
					body = fmt.Sprintf(`{"v":1,"updated":%d,"regions":[%s]}`, time.Now().Unix(), strings.Join(entries, ","))
				case strings.HasSuffix(r.URL.Path, "/statuses"):
					// History retrieval crosses the old 30-second future tolerance.
					elapsed.Store(45)
					greenAt := baseNow.Add(-time.Hour)
					if strings.Contains(r.URL.Path, latest) {
						greenAt = now()
					}
					body = fmt.Sprintf(`[{"context":"deployment/qualified","state":"success","created_at":%q}]`, greenAt.Format(time.RFC3339))
				case strings.HasSuffix(r.URL.Path, "/commits"):
					body = fmt.Sprintf(`[{"sha":%q},{"sha":%q}]`, latest, deployed)
				case r.URL.Path == "/api/v1/deployments":
					var rows []string
					for _, service := range services[3:] {
						for _, region := range regions {
							targets := []string{"service"}
							if service == "ts-status" {
								targets = append(targets, "vantage")
							}
							for _, target := range targets {
								status, version, observedAt := 200, deployed, now()
								if service == "ts-atlas" && region == "SJC" {
									switch broken {
									case "edge missing":
										continue
									case "edge stale":
										observedAt = now().Add(-3 * time.Minute)
									case "edge non-200":
										status = 503
									case "edge invalid revision":
										version = ""
									}
								}
								rows = append(rows, fmt.Sprintf(`{"service":%q,"region":%q,"target":%q,"version":%q,"status":%d,"observedAt":%q}`,
									service, region, target, version, status, observedAt.Format(time.RFC3339)))
							}
						}
					}
					body = "[" + strings.Join(rows, ",") + "]"
				case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/issues"):
					body = `[{"number":42,"title":"TS-768: Deployment lag exceeds 30 minutes"}]`
				case r.Method == "PATCH":
					wire, _ := io.ReadAll(r.Body)
					closed = string(wire) == `{"state":"closed"}`
					updated = strings.Contains(string(wire), "live deployment proof") || strings.Contains(string(wire), "Serving-region discovery unavailable")
				default:
					t.Fatalf("unexpected guard request: %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			readNative := func(_ context.Context, service, region string) (observation, error) {
				nativeReads.Add(1)
				proof := observation{Service: service, Region: region, Target: "fleet", Version: deployed, Status: 200, ObservedAt: now()}
				if service == "ts-auth" && region == "GRU" {
					switch broken {
					case "native missing":
						proof.Version, proof.Status = "", 0
					case "native stale":
						proof.ObservedAt = now().Add(-3 * time.Minute)
					}
				}
				return proof, nil
			}
			err := run(context.Background(), a, now, readNative, true)
			wantNative := int64(len(regions) * 3)
			if broken == "discovery missing" {
				wantNative = 0
			}
			if nativeReads.Load() != wantNative {
				t.Fatalf("discovered native regions omitted: reads=%d want=%d", nativeReads.Load(), wantNative)
			}
			if broken == "" || broken == "new region" {
				if err != nil || !closed {
					t.Fatalf("fresh proofs/qualifications after slow history failed: closed=%v err=%v", closed, err)
				}
			} else if err == nil || closed || !updated {
				t.Fatalf("invalid proof closed the alert before 30 minutes: updated=%v closed=%v err=%v", updated, closed, err)
			}
		})
	}
}
