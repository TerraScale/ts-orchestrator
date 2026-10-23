package alertdelivery

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const fixtureTopic = "fixture-only-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func fixtureReadTopic(context.Context) (string, error) { return fixtureTopic, nil }

func TestDeliveryOnlyAcknowledgesProviderAcceptanceAndOmitsPrivateLabels(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
		status   int
		want     int
	}{
		{"accepted", `{"success":true,"result":{"delivered":["mariogk@terrascale.tech"],"permanent_bounces":[]}}`, 200, 202},
		{"queued", `{"success":true,"result":{"queued":["mariogk@terrascale.tech"]}}`, 200, 202},
		{"suppressed", `{"success":true,"result":{"suppressed_recipients":["mariogk@terrascale.tech"]}}`, 200, 502},
		{"no recipient", `{"success":true,"result":{}}`, 200, 502},
		{"bounce", `{"success":true,"result":{"permanent_bounces":["recipient"]}}`, 200, 502},
		{"provider failure", `{"success":false}`, 200, 502},
		{"unavailable", `{"success":false,"errors":[{"message":"private value"}]}`, 503, 502},
		{"malformed", `not json`, 200, 502},
	} {
		t.Run(test.name, func(t *testing.T) {
			var pushed atomic.Bool
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				if r.URL.Path == "/"+fixtureTopic {
					pushed.Store(true)
					if r.Header.Get("Authorization") != "" || strings.Contains(string(data), "TerraBaseBackupLag") || strings.Contains(string(data), "private value") {
						t.Error("push exposed operational details or credentials")
					}
					_, _ = io.WriteString(w, `{"id":"test-id","event":"message","topic":"`+fixtureTopic+`"}`)
					return
				}
				var payload map[string]any
				if err := json.Unmarshal(data, &payload); err != nil || payload["to"] != "mariogk@terrascale.tech" || !strings.Contains(string(data), "TerraBaseBackupLag") || strings.Contains(string(data), "private value") {
					t.Errorf("unexpected delivery payload")
				}
				if r.Header.Get("Authorization") != "Bearer test-token" || r.URL.Path != "/account/email/sending/send" {
					t.Errorf("unexpected provider authentication or path")
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.response)
			}))
			defer provider.Close()
			r := relay{client: provider.Client(), endpoint: provider.URL + "/", pushEndpoint: provider.URL + "/", readTopic: fixtureReadTopic, read: func(context.Context) (credentials, error) { return credentials{"account", "test-token"}, nil }}
			request := httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(`{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"TerraBaseBackupLag","service":"terrabase","tenant":"private value"},"annotations":{"secret":"private value"}}]}`))
			response := httptest.NewRecorder()
			r.deliver(response, request)
			if !pushed.Load() {
				t.Fatal("independent push was skipped")
			}
			if response.Code != test.want || strings.Contains(response.Body.String(), "private value") {
				t.Fatalf("status=%d want=%d; response=%s", response.Code, test.want, response.Body)
			}
		})
	}
}

func TestInvalidNotificationsNeverReadCredentials(t *testing.T) {
	r := relay{read: func(context.Context) (credentials, error) {
		t.Fatal("read credentials for invalid input")
		return credentials{}, nil
	}}
	for _, body := range []string{`{`, `{}`, `{"status":"firing","alerts":[{"status":"firing","labels":{}}]}`, strings.Repeat("x", 64<<10+1)} {
		response := httptest.NewRecorder()
		r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid input returned %d", response.Code)
		}
	}
}

func TestPushFailureRemainsRetryable(t *testing.T) {
	for _, test := range []struct {
		name   string
		body   string
		status int
	}{
		{"unavailable", `provider private error`, 503},
		{"malformed", `{`, 200},
		{"missing receipt", `{}`, 200},
		{"wrong event", `{"id":"id","event":"keepalive","topic":"` + fixtureTopic + `"}`, 200},
		{"wrong topic", `{"id":"id","event":"message","topic":"other"}`, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/"+fixtureTopic {
					w.WriteHeader(test.status)
					_, _ = io.WriteString(w, test.body)
					return
				}
				_, _ = io.WriteString(w, `{"success":true,"result":{"delivered":["mariogk@terrascale.tech"]}}`)
			}))
			defer provider.Close()
			r := relay{client: provider.Client(), endpoint: provider.URL + "/", pushEndpoint: provider.URL + "/", readTopic: fixtureReadTopic, read: func(context.Context) (credentials, error) { return credentials{"account", "test-token"}, nil }}
			response := httptest.NewRecorder()
			r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(`{"status":"resolved","alerts":[{"status":"resolved","labels":{"alertname":"Test"}}]}`)))
			if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private") {
				t.Fatalf("push failure was acknowledged or leaked provider body: %d", response.Code)
			}
		})
	}
}

func TestVaultFailureStillAttemptsPush(t *testing.T) {
	var pushed atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed.Store(true)
		_, _ = io.WriteString(w, `{"id":"test-id","event":"message","topic":"`+fixtureTopic+`"}`)
	}))
	defer provider.Close()
	r := relay{client: provider.Client(), pushEndpoint: provider.URL + "/", readTopic: fixtureReadTopic, read: func(context.Context) (credentials, error) {
		return credentials{}, errors.New("private Vault error")
	}}
	response := httptest.NewRecorder()
	r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(`{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Test"}}]}`)))
	if !pushed.Load() || response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("Vault failure skipped push, was acknowledged, or leaked an error: %d", response.Code)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPushTopicFailureStillAttemptsEmail(t *testing.T) {
	for _, value := range []string{"", "short", fixtureTopic + "/escape", fixtureTopic + "\n", fixtureTopic + "?query", fixtureTopic} {
		t.Run("invalid topic", func(t *testing.T) {
			var emailed atomic.Bool
			r := relay{endpoint: "https://email.invalid/", read: func(context.Context) (credentials, error) { return credentials{"account", "test-token"}, nil },
				readTopic: func(context.Context) (string, error) {
					if value == fixtureTopic {
						return "", errors.New("private Vault failure")
					}
					return value, nil
				},
				client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.URL.Host != "email.invalid" {
						t.Error("invalid topic reached transport")
					}
					emailed.Store(true)
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true,"result":{"queued":["mariogk@terrascale.tech"]}}`))}, nil
				})}}
			response := httptest.NewRecorder()
			r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(`{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Test"}}]}`)))
			if !emailed.Load() || response.Code != http.StatusBadGateway {
				t.Fatal("topic failure skipped email or was acknowledged")
			}
		})
	}
}

func TestDeliveryNeverLogsTopicOrProviderErrors(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	for _, failure := range []string{"none", "email vault", "push transport"} {
		r := relay{endpoint: "https://email.invalid/", pushEndpoint: "https://push.invalid/", readTopic: fixtureReadTopic,
			read: func(context.Context) (credentials, error) {
				if failure == "email vault" {
					return credentials{}, errors.New(fixtureTopic)
				}
				return credentials{"account", "test-token"}, nil
			},
			client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host == "email.invalid" {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true,"result":{"queued":["mariogk@terrascale.tech"]}}`))}, nil
				}
				if failure == "push transport" {
					return nil, errors.New(request.URL.String())
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"` + fixtureTopic + `","event":"message","topic":"` + fixtureTopic + `"}`))}, nil
			})}}
		response := httptest.NewRecorder()
		r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(`{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Test"}}]}`)))
		want := http.StatusBadGateway
		if failure == "none" {
			want = http.StatusAccepted
		}
		if response.Code != want || strings.Contains(response.Body.String()+logs.String(), fixtureTopic) || strings.Contains(logs.String(), "https://") {
			t.Fatal("topic or transport URL escaped in output")
		}
	}
}
