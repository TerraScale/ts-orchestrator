package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// With the dashboard enabled on a token-protected listener a browser signs
// in with the bearer token, and the pages render the providers the
// controller attaches later.
func TestControllerDashboardRequiresSignIn(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	nats, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nats.Close() })
	tokenFile := filepath.Join(t.TempDir(), "token")
	token := strings.Repeat("d", 40)
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	address := freeLoopbackAddress(t)
	cfg := Config{NATS: natscell.Config{Cell: "lab", Instance: "one"},
		Observability: observability.Config{ListenAddress: address, BearerTokenFile: tokenFile,
			ClusterAggregation: true, Dashboard: true}}
	telemetry, err := startRuntimeObservability(ctx, cfg, "controller", "one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(telemetry.close)
	if telemetry.server == nil {
		t.Skipf("loopback port %s was taken before the listener bound", address)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	browse := func(path string) (int, string, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept", "text/html")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, response.Header.Get("Location"), string(data)
	}
	if status, location, _ := browse("/members"); status != http.StatusSeeOther || location != "/login?next=%2Fmembers" {
		t.Fatalf("unauthenticated /members = %d %q", status, location)
	}
	if status, _, page := browse("/login"); status != http.StatusOK || !strings.Contains(page, `name="token"`) {
		t.Fatalf("/login = %d", status)
	}
	store, err := observability.OpenSessionStore(ctx, nats.JetStream(), 1, "local."+telemetry.member)
	if err != nil {
		t.Fatal(err)
	}
	if err := telemetry.server.SetSessionStore(ctx, store); err != nil {
		t.Fatal(err)
	}
	login, err := client.PostForm("http://"+address+"/login", url.Values{"token": {token}, "next": {"/members"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	if login.StatusCode != http.StatusSeeOther || login.Header.Get("Location") != "/members" {
		t.Fatalf("login = %d %q", login.StatusCode, login.Header.Get("Location"))
	}
	if status, _, page := browse("/members"); status != http.StatusOK || !strings.Contains(page, "still starting") {
		t.Fatalf("/members before attach = %d", status)
	}
	lease := observedAuthority{snapshot: authority.Snapshot{Leader: true, Ready: true, OwnerID: "0000000000DV8998ZCQW1J2V2R", Epoch: 3,
		ExpiresAt: time.Now().Add(time.Minute)}}
	if err := telemetry.attachController(ctx, controllerObservation{nats: nats, replicas: 1,
		brokerIDs: []string{"one", "two"}, authority: lease}, nil); err != nil {
		t.Fatal(err)
	}
	telemetry.markStarted()
	status, _, page := browse("/members")
	if !strings.Contains(page, ">one</a></td>") || !strings.Contains(page, "<td>two</td>") ||
		!strings.Contains(page, "did not answer") {
		t.Fatalf("/members after attach = %d, lacks the cell view:\n%s", status, page)
	}
	if _, _, page := browse("/"); !strings.Contains(page, "epoch 3") {
		t.Fatalf("overview lacks the authority lease:\n%s", page)
	}
	// The bearer header still works for scrapers alongside sessions.
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("/metrics with bearer = %d", response.StatusCode)
	}
}

func TestHostDashboardKeepsLocalBrowserLoginWithoutJetStream(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	token := strings.Repeat("h", 48)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	telemetry, err := startRuntimeObservability(t.Context(), Config{Observability: observability.Config{
		ListenAddress: freeLoopbackAddress(t), BearerTokenFile: tokenFile, Dashboard: true}}, "host", "host-one")
	if err != nil || telemetry.server == nil {
		t.Fatalf("host listener: %v", err)
	}
	defer telemetry.close()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"token": {token}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	telemetry.server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || len(recorder.Result().Cookies()) != 1 {
		t.Fatalf("host login = %d", recorder.Code)
	}
	cookie := recorder.Result().Cookies()[0]
	request = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	telemetry.server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("host dashboard = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	telemetry.server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("host logout = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	telemetry.server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatal("host logout did not revoke the copied cookie")
	}
}

func TestDashboardSessionAttachmentRetriesAndStops(t *testing.T) {
	var logs bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var attempts atomic.Int32
	done := make(chan struct{})
	go func() {
		retryDashboardSessionAttachment(ctx, func(attempt context.Context) error {
			if _, ok := attempt.Deadline(); !ok {
				t.Error("attachment attempt is unbounded")
			}
			switch attempts.Add(1) {
			case 1, 2:
				return errors.New("opening bucket temporarily unavailable")
			case 3:
				return errors.New("binding token temporarily unavailable")
			default:
				return nil
			}
		})
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("attachment never retried to success")
	}
	if attempts.Load() != 4 {
		t.Fatal("failed open and bind were not retried")
	}
	if strings.Count(logs.String(), "dashboard session storage unavailable; retrying") != 2 ||
		!strings.Contains(logs.String(), "opening bucket temporarily unavailable") || !strings.Contains(logs.String(), "binding token temporarily unavailable") {
		t.Fatal("attachment hid a changed failure or repeated an unchanged warning")
	}
	stopped, cancelStopped := context.WithCancel(t.Context())
	cancelStopped()
	retryDashboardSessionAttachment(stopped, func(context.Context) error { t.Fatal("canceled runtime attempted attachment"); return nil })
}
