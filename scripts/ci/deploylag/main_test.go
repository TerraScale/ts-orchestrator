package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHistoryKeepsFirstQualificationAcrossFailedDeploymentAndRerun(t *testing.T) {
	a := api{readToken: "read", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "token read" {
			t.Fatal("missing authenticated history request")
		}
		body := `[{"sha":"abc","GreenAt":"2000-01-01T00:00:00Z"}]`
		if strings.Contains(r.URL.Path, "statuses") {
			body = `[
				{"context":"deploy","status":"failure","created_at":"2026-10-09T15:00:00Z"},
				{"context":"deployment/qualified","status":"success","created_at":"2026-10-09T14:59:00Z"},
				{"context":"deployment/qualified","status":"success","created_at":"2026-10-09T14:00:00Z"}
			]`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	history, err := a.history(context.Background(), "ts-auth")
	if err != nil || len(history) != 1 || history[0].GreenAt.Format(time.RFC3339) != "2026-10-09T14:00:00Z" {
		t.Fatalf("qualification changed after failed deployment: %+v %v", history, err)
	}
}

func TestAlertCreatesAssignedIncidentAndClosesItAfterRecovery(t *testing.T) {
	var methods []string
	a := api{writeToken: "write", client: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "token write" {
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
		{"new", 0}, {"pending", time.Minute}, {"unknown", time.Hour},
	} {
		_, lag, err := pending(history, tc.version, now)
		if err != nil || lag != tc.lag {
			t.Fatalf("%s lag=%s err=%v", tc.version, lag, err)
		}
	}
	history[0].GreenAt = now.Add(time.Minute)
	if _, _, err := pending(history, "live", now); err == nil {
		t.Fatal("accepted future qualification")
	}
}
