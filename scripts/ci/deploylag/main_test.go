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
