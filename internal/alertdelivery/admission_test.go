package alertdelivery

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

// Existing provider fixtures also admit through this test-only transport;
// production always uses the fixed HTTPS endpoint, with no configuration knob.
func admittingClient(original *http.Client) *http.Client {
	client := http.Client{}
	if original != nil {
		client = *original
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == admissionEndpoint {
			body := fmt.Sprintf(`{"status":"admitted","sendBy":%q}`, time.Now().UTC().Add(5*time.Second).Format(time.RFC3339Nano))
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}
		return transport.RoundTrip(request)
	})
	return &client
}

func TestAdmissionControlsProviderDeliveryAndPreservesPush(t *testing.T) {
	for _, scenario := range []string{"admitted", "denied", "unavailable", "malformed", "oversized", "missing deadline", "expired", "too long", "wrong status", "redirect", "timeout", "provider deadline"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			var admissions, emails, pushes atomic.Int32
			providerCanceled := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/v1/terrascale/email/admission":
					admissions.Add(1)
					// Independent known vector for the synthetic test-token credential.
					if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer b8e7059bbb335fb8b207455348cb0e4a921a406e36cde606e1f0111864e86bd0" || request.Header.Get("Content-Type") != "application/json" {
						t.Error("invalid admission method or authentication")
					}
					var body map[string]string
					data, _ := io.ReadAll(request.Body)
					if json.Unmarshal(data, &body) != nil || len(body) != 1 {
						t.Error("invalid admission body")
					}
					if _, err := ulid.ParseStrict(body["attemptId"]); err != nil {
						t.Error("attempt ID is not a ULID")
					}
					sendBy, status := time.Now().UTC().Add(5*time.Second), "admitted"
					switch scenario {
					case "denied":
						w.WriteHeader(http.StatusTooManyRequests)
					case "unavailable":
						w.WriteHeader(http.StatusServiceUnavailable)
					case "malformed":
						_, _ = io.WriteString(w, "private provider error")
						return
					case "oversized":
						_, _ = io.WriteString(w, strings.Repeat("x", 4097))
						return
					case "missing deadline":
						sendBy = time.Time{}
					case "expired":
						sendBy = time.Now().UTC().Add(-time.Second)
					case "too long":
						sendBy = time.Now().UTC().Add(time.Hour)
					case "wrong status":
						status = "denied"
					case "redirect":
						http.Redirect(w, request, "/account/email/sending/send", http.StatusTemporaryRedirect)
						return
					case "timeout":
						select {
						case <-request.Context().Done():
						case <-t.Context().Done():
						}
						return
					case "provider deadline":
						sendBy = time.Now().UTC().Add(time.Second)
					}
					_, _ = fmt.Fprintf(w, `{"status":%q,"sendBy":%q}`, status, sendBy.Format(time.RFC3339Nano))
				case "/account/email/sending/send":
					emails.Add(1)
					if request.Header.Get("Authorization") != "Bearer test-token" {
						t.Error("provider did not receive its own authentication")
					}
					if scenario == "provider deadline" {
						_, _ = io.Copy(io.Discard, request.Body)
						select {
						case <-request.Context().Done():
							close(providerCanceled)
						case <-t.Context().Done():
						}
						return
					}
					_, _ = io.WriteString(w, `{"success":true,"result":{"queued":["mariogk@terrascale.tech"]}}`)
				case "/" + fixtureTopic:
					pushes.Add(1)
					_, _ = io.WriteString(w, `{"id":"fixture","event":"message","topic":"`+fixtureTopic+`"}`)
				default:
					t.Error("unexpected provider route")
				}
			}))
			defer server.Close()
			origin, _ := url.Parse(server.URL)
			transport := server.Client().Transport
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				// Route the fixed production admission URL to this test's server.
				copy := request.Clone(request.Context())
				copy.URL.Scheme, copy.URL.Host = origin.Scheme, origin.Host
				return transport.RoundTrip(copy)
			})}
			if scenario == "timeout" {
				client.Timeout = 100 * time.Millisecond
			}
			r := relay{client: client, endpoint: server.URL + "/", pushEndpoint: server.URL + "/", ledgerPath: filepath.Join(t.TempDir(), "ledger.json"), readTopic: fixtureReadTopic,
				read: func(context.Context) (credentials, error) { return credentials{"account", "test-token"}, nil }}
			for i := range 3 {
				response := httptest.NewRecorder()
				r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(`{"groupKey":"same","status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Test"}}]}`)))
				want := http.StatusAccepted
				if scenario == "provider deadline" && i == 0 {
					want = http.StatusBadGateway
				}
				if response.Code != want || strings.Contains(response.Body.String(), "private") {
					t.Errorf("relay status=%d want=%d", response.Code, want)
				}
			}
			wantEmails := int32(0)
			if scenario == "admitted" || scenario == "provider deadline" {
				wantEmails = 1
			}
			if admissions.Load() != 1 || emails.Load() != wantEmails || pushes.Load() != 3 {
				t.Fatalf("admissions=%d emails=%d pushes=%d", admissions.Load(), emails.Load(), pushes.Load())
			}
			if scenario == "provider deadline" {
				select {
				case <-providerCanceled:
				case <-time.After(2 * time.Second):
					t.Fatal("provider request continued beyond admission deadline")
				}
			}
		})
	}
}
