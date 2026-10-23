package alertdelivery

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

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
				if r.URL.Path == "/push" {
					pushed.Store(true)
					if r.Header.Get("Authorization") != "" || strings.Contains(string(data), "TerraBaseBackupLag") || strings.Contains(string(data), "private value") {
						t.Error("push exposed operational details or credentials")
					}
					_, _ = io.WriteString(w, `{"id":"test-id","event":"message","topic":"`+pushTopic+`"}`)
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
			r := relay{client: provider.Client(), endpoint: provider.URL + "/", pushEndpoint: provider.URL + "/push", read: func(context.Context) (credentials, error) { return credentials{"account", "test-token"}, nil }}
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
		{"wrong event", `{"id":"id","event":"keepalive","topic":"` + pushTopic + `"}`, 200},
		{"wrong topic", `{"id":"id","event":"message","topic":"other"}`, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/push" {
					w.WriteHeader(test.status)
					_, _ = io.WriteString(w, test.body)
					return
				}
				_, _ = io.WriteString(w, `{"success":true,"result":{"delivered":["mariogk@terrascale.tech"]}}`)
			}))
			defer provider.Close()
			r := relay{client: provider.Client(), endpoint: provider.URL + "/", pushEndpoint: provider.URL + "/push", read: func(context.Context) (credentials, error) { return credentials{"account", "test-token"}, nil }}
			response := httptest.NewRecorder()
			r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(`{"status":"resolved","alerts":[{"status":"resolved","labels":{"alertname":"Test"}}]}`)))
			if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private") {
				t.Fatalf("push failure was acknowledged or leaked provider body: %d", response.Code)
			}
		})
	}
}
