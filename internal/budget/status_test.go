package budget

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testStatusToken = "tok-status-operator-secret"
const testIncidentID = "0b6f3f2e-7a4d-4c1e-9f0a-2d8e6b1c7a90"

// statusServer answers every request with status and reply, and records each request's method, path, auth and body.
func statusServer(t *testing.T, status int, reply string) (StatusPage, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, strings.Join([]string{r.Method, r.URL.Path, r.Header.Get("Authorization"), string(body)}, "\n"))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	page := StatusPage{URL: srv.URL + "/api/operator", HTTP: &http.Client{Timeout: 10 * time.Second},
		Token: func(context.Context) (string, error) { return testStatusToken, nil }}
	return page, &seen
}

func TestStatusPageOpenWarningPostsFixedWarning(t *testing.T) {
	page, seen := statusServer(t, http.StatusCreated, `{"id":"`+testIncidentID+`","url":"/incidents/x"}`)
	id, err := page.OpenWarning(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if id != testIncidentID {
		t.Fatalf("incident id = %q, want %q", id, testIncidentID)
	}
	if len(*seen) != 1 {
		t.Fatalf("made %d requests, want 1", len(*seen))
	}
	parts := strings.SplitN((*seen)[0], "\n", 4)
	if parts[0] != http.MethodPost || parts[1] != "/api/operator/incidents" || parts[2] != "Bearer "+testStatusToken {
		t.Fatalf("request = %q, want POST /api/operator/incidents with the bearer token", parts[:3])
	}
	for _, want := range []string{`"kind":"warning"`, `"impact":"none"`, `"components":[]`,
		`"title":"Capacity growth may be limited"`, `"message":"TerraScale's capacity budget for this month is nearly used.`} {
		if !strings.Contains(parts[3], want) {
			t.Fatalf("body %s lacks %s", parts[3], want)
		}
	}
}

func TestStatusPageResolveWarningPostsResolvedUpdate(t *testing.T) {
	page, seen := statusServer(t, http.StatusCreated, `{"id":"`+testIncidentID+`"}`)
	if err := page.ResolveWarning(t.Context(), testIncidentID); err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN((*seen)[0], "\n", 4)
	if parts[1] != "/api/operator/incidents/"+testIncidentID+"/updates" {
		t.Fatalf("path = %s, want the incident's updates", parts[1])
	}
	if parts[3] != `{"status":"resolved","message":"Capacity growth is back to normal."}` {
		t.Fatalf("body = %s, want the resolved update", parts[3])
	}
}

func TestStatusPageRejectsBadIncidentIDs(t *testing.T) {
	page, seen := statusServer(t, http.StatusCreated, `{"id":"../../secret","url":"/x"}`)
	if _, err := page.OpenWarning(t.Context()); err == nil {
		t.Fatal("OpenWarning accepted a non-UUID incident id")
	}
	if err := page.ResolveWarning(t.Context(), "../../secret"); err == nil {
		t.Fatal("ResolveWarning accepted a path-traversing incident id")
	}
	if len(*seen) != 1 {
		t.Fatalf("made %d requests, want only the open call", len(*seen))
	}
}

func TestStatusPageErrorsOmitTheToken(t *testing.T) {
	page, _ := statusServer(t, http.StatusUnauthorized, `{"error":{"code":"unauthorized"}}`)
	_, err := page.OpenWarning(t.Context())
	if err == nil {
		t.Fatal("non-2xx reply succeeded")
	}
	if strings.Contains(err.Error(), testStatusToken) {
		t.Fatalf("error %q contains the token", err)
	}
}

func TestStatusPageMissingTokenIsReported(t *testing.T) {
	page := StatusPage{URL: "http://127.0.0.1:1", HTTP: &http.Client{Timeout: time.Second},
		Token: func(context.Context) (string, error) { return "", ErrNoStatusToken }}
	if _, err := page.OpenWarning(t.Context()); !errors.Is(err, ErrNoStatusToken) {
		t.Fatalf("error = %v, want ErrNoStatusToken", err)
	}
}
