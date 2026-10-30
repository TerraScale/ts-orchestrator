package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// serve answers GitHub API paths from routes (path?query -> JSON body).
func serve(t *testing.T, routes map[string]string) api {
	return api{readToken: "read", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		key := strings.TrimPrefix(r.URL.Path, "/repos/TerraScale/")
		if r.URL.RawQuery != "" {
			key += "?" + r.URL.RawQuery
		}
		body, ok := routes[key]
		if !ok {
			t.Fatalf("unexpected request %s", key)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
}

func TestOrchReportsOnlyUndeliveredCommitsOlderThanTheLimit(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	commit := func(sha string, age time.Duration) string {
		return fmt.Sprintf(`{"sha":%q,"commit":{"committer":{"date":%q}}}`, sha, now.Add(-age).Format(time.RFC3339))
	}
	check := func(conclusion string) string {
		if conclusion == "" {
			return `{"check_runs":[]}`
		}
		return `{"check_runs":[{"status":"completed","conclusion":"` + conclusion + `"}]}`
	}
	routes := func(commits []string, checks map[string]string) map[string]string {
		r := map[string]string{"ts-orchestrator/commits?sha=main&per_page=30": "[" + strings.Join(commits, ",") + "]"}
		for key, conclusion := range checks {
			sha, name, _ := strings.Cut(key, " ")
			r["ts-orchestrator/commits/"+sha+"/check-runs?check_name="+name] = check(conclusion)
		}
		return r
	}
	for name, c := range map[string]struct {
		commits []string
		checks  map[string]string
		want    string
	}{
		"newest released": {[]string{commit("c", time.Hour), commit("b", 2*time.Hour)},
			map[string]string{"c deploy/release-push": "success"}, ""},
		"docs commit on top": {[]string{commit("c", time.Hour), commit("b", 2*time.Hour)},
			map[string]string{"c deploy/release-push": "skipped", "c test": "success", "b deploy/release-push": "success"}, ""},
		"young failure": {[]string{commit("c", time.Minute), commit("b", 2*time.Hour)},
			map[string]string{"c deploy/release-push": "failure", "b deploy/release-push": "success"}, ""},
		"red main blocks release": {[]string{commit("c", 40*time.Minute), commit("b", 2*time.Hour)},
			map[string]string{"c deploy/release-push": "skipped", "c test": "failure", "b deploy/release-push": "success"}, "main `c`"},
		"reports the oldest": {[]string{commit("c", 40*time.Minute), commit("b", 50*time.Minute), commit("a", 2*time.Hour)},
			map[string]string{"c deploy/release-push": "cancelled", "b deploy/release-push": "", "a deploy/release-push": "success"}, "main `b`"},
	} {
		t.Run(name, func(t *testing.T) {
			findings, err := serve(t, routes(c.commits, c.checks)).orch(context.Background(), now)
			if err != nil || (c.want == "") != (len(findings) == 0) || c.want != "" && !strings.Contains(findings[0], c.want) {
				t.Fatalf("findings = %q, %v; want %q", findings, err, c.want)
			}
		})
	}
}

func TestReleaseReportsAnUnreleasedImageAfterTheLimitUnlessHeld(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	routes := func(service, job, published, release, oldRelease string, age time.Duration) map[string]string {
		x := apps[0]
		for _, candidate := range apps {
			if candidate.service == service {
				x = candidate
			}
		}
		steps := `{"name":"Run docker/build-push-action@x","status":"completed","conclusion":"` + published + `","completed_at":"` + now.Add(-age).Format(time.RFC3339) + `"}`
		if release != "" {
			steps += `,{"name":"Release to every region","status":"completed","conclusion":"` + release + `"}`
		}
		return map[string]string{
			x.repo + "/actions/workflows/" + x.workflow + "/runs?branch=main&event=push&per_page=20": `{"workflow_runs":[{"id":2,"head_sha":"new"},{"id":1,"head_sha":"old"}]}`,
			x.repo + "/actions/runs/2/jobs?per_page=50":                                              `{"jobs":[{"name":"` + job + `","steps":[` + steps + `]}]}`,
			x.repo + "/actions/runs/1/jobs?per_page=50":                                              `{"jobs":[{"name":"` + x.job + `","steps":[{"name":"Run docker/build-push-action@x","conclusion":"success","completed_at":"` + now.Add(-3*time.Hour).Format(time.RFC3339) + `"},{"name":"Release to every region","conclusion":"` + oldRelease + `"}]}]}`,
		}
	}
	for name, c := range map[string]struct {
		service, job, published, release string
		age                              time.Duration
		want                             bool
		oldRelease                       string
	}{
		"released":                {"ts-auth", "main (auth)", "success", "success", time.Hour, false, "success"},
		"young":                   {"ts-auth", "main (auth)", "success", "failure", time.Minute, false, "success"},
		"young on an old backlog": {"ts-auth", "main (auth)", "success", "failure", time.Minute, true, "failure"},
		"overdue":                 {"ts-auth", "main (auth)", "success", "failure", time.Hour, true, "success"},
		"no release step":         {"ts-dashboard", "test", "success", "", time.Hour, true, "success"},
		"held":                    {"terrabase", "main (terrabase)", "success", "", time.Hour, false, "success"},
		"newest built no image":   {"ts-auth", "main (auth)", "skipped", "", time.Hour, false, "success"},
		"newest skipped the area": {"ts-auth", "main (terrabase)", "success", "", time.Hour, false, "success"},
	} {
		t.Run(name, func(t *testing.T) {
			x := apps[0]
			for _, candidate := range apps {
				if candidate.service == c.service {
					x = candidate
				}
			}
			findings, err := serve(t, routes(c.service, c.job, c.published, c.release, c.oldRelease, c.age)).release(context.Background(), x, now)
			if err != nil || (len(findings) == 1) != c.want {
				t.Fatalf("findings = %q, %v; want finding %t", findings, err, c.want)
			}
		})
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

func TestHistoryReadsRetryTransientFailuresWithoutHidingPermanentErrors(t *testing.T) {
	for _, status := range []int{502, 503, 429, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			a := api{client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				code := status
				if calls > 1 {
					code = 200
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(`{"workflow_runs":[]}`))}, nil
			})}}
			_, err := a.release(t.Context(), apps[1], time.Now())
			if status == 403 {
				if err == nil || calls != 1 {
					t.Fatalf("permanent failure: calls=%d err=%v", calls, err)
				}
			} else if err != nil || calls != 2 {
				t.Fatalf("transient read: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestHistoryReadRetriesAreBoundedAndWritesAreNotRepeated(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			calls := 0
			a := api{client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("private response"))}, nil
			})}}
			err := a.request(t.Context(), method, forge+"ts-orchestrator/issues", "secret", nil, nil)
			want := 1
			if method == http.MethodGet {
				want = 3
			}
			if err == nil || calls != want || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("calls=%d want=%d err=%v", calls, want, err)
			}
		})
	}
}
