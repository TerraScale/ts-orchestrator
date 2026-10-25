package alertdelivery

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentRetryStormAndGlobalCap(t *testing.T) {
	for _, distinct := range []bool{false, true} {
		t.Run(fmt.Sprintf("distinct groups=%t", distinct), func(t *testing.T) {
			var emails, pushes atomic.Int32
			r := relay{ledgerPath: filepath.Join(t.TempDir(), "ledger.json"), endpoint: "https://email.invalid/", pushEndpoint: "https://push.invalid/", readTopic: fixtureReadTopic,
				read: func(context.Context) (credentials, error) { return credentials{"account", "test"}, nil },
				client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.Host == "email.invalid" {
						emails.Add(1)
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true,"result":{"queued":["mariogk@terrascale.tech"]}}`))}, nil
					}
					pushes.Add(1)
					return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("private"))}, nil
				})}}
			var requests sync.WaitGroup
			for i := range 64 {
				requests.Go(func() {
					group := "same"
					if distinct {
						group = fmt.Sprint(i)
					}
					body := fmt.Sprintf(`{"groupKey":%q,"status":"firing","alerts":[{"status":"firing","fingerprint":%q,"labels":{"alertname":"Test"}}]}`, group, fmt.Sprint(i))
					response := httptest.NewRecorder()
					r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(body)))
					if response.Code != http.StatusAccepted {
						t.Errorf("status=%d", response.Code)
					}
				})
			}
			requests.Wait()
			want := int32(1)
			if distinct {
				want = emailHourlyLimit
			}
			if emails.Load() != want || pushes.Load() != 64 {
				t.Fatalf("emails=%d want=%d, pushes=%d want=64", emails.Load(), want, pushes.Load())
			}
		})
	}
}

func TestEmailLedgerSurvivesRestartAndHonorsRollingWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	now := time.Now().UTC()
	reserve := func(key string, at time.Time, want string) {
		t.Helper()
		// A fresh relay on every attempt also exercises independent processes'
		// shared ledger, rather than relying on process-local deduplication.
		r := relay{ledgerPath: path}
		if got := r.reserveEmail(t.Context(), key, at); got != want {
			t.Fatalf("reserve %s at %v: %q, want %q", key, at.Sub(now), got, want)
		}
	}
	for i := range emailHourlyLimit {
		reserve(fmt.Sprint(i), now.Add(time.Duration(i)*time.Minute), "")
	}
	reserve("overflow", now.Add(59*time.Minute), "hourly cap")
	reserve("overflow", now.Add(time.Hour-time.Nanosecond), "hourly cap")
	reserve("overflow", now.Add(time.Hour), "")
	reserve("0", now.Add(emailRepeatInterval-time.Nanosecond), "duplicate")
	reserve("0", now.Add(emailRepeatInterval), "")
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	reserve("corrupt must not reset the budget", now.Add(5*time.Hour), "ledger unavailable")
}

func TestEmailIdentitySeparatesStatusAndIgnoresAlertOrder(t *testing.T) {
	var n notification
	if err := json.Unmarshal([]byte(`{"status":"firing","alerts":[{"fingerprint":"b"},{"fingerprint":"a"}]}`), &n); err != nil {
		t.Fatal(err)
	}
	key := n.emailKey()
	n.Alerts[0], n.Alerts[1] = n.Alerts[1], n.Alerts[0]
	if n.emailKey() != key {
		t.Fatal("alert order changed deduplication identity")
	}
	n.Status = "resolved"
	if n.emailKey() == key {
		t.Fatal("resolved notification suppressed by firing notification")
	}
}

func TestLedgerFailureSuppressesEmailButStillPushes(t *testing.T) {
	var pushes atomic.Int32
	r := relay{ledgerPath: filepath.Join(t.TempDir(), "missing", "ledger.json"), pushEndpoint: "https://push.invalid/", readTopic: fixtureReadTopic,
		read: func(context.Context) (credentials, error) {
			t.Fatal("email attempted without durable budget")
			return credentials{}, nil
		},
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			pushes.Add(1)
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("private"))}, nil
		})}}
	response := httptest.NewRecorder()
	r.deliver(response, httptest.NewRequest(http.MethodPost, "/alerts", strings.NewReader(`{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Test"}}]}`)))
	if response.Code != http.StatusAccepted || pushes.Load() != 1 {
		t.Fatalf("ledger failure: status=%d pushes=%d", response.Code, pushes.Load())
	}
}

func TestDelayedSendCannotShortenQuotaOrRepeatWindows(t *testing.T) {
	r := relay{ledgerPath: filepath.Join(t.TempDir(), "ledger.json")}
	now := time.Now().UTC()
	sendBy := now.Add(50 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), sendBy)
	defer cancel()
	for i := range emailHourlyLimit {
		if got := r.reserveEmail(ctx, fmt.Sprint(i), now); got != "" {
			t.Fatal(got)
		}
	}
	for _, test := range []struct {
		key, want string
		at        time.Time
	}{
		{"new", "hourly cap", now.Add(time.Hour)},
		{"new", "", sendBy.Add(time.Hour)},
		{"0", "duplicate", now.Add(emailRepeatInterval)},
		{"0", "", sendBy.Add(emailRepeatInterval)},
	} {
		if got := r.reserveEmail(t.Context(), test.key, test.at); got != test.want {
			t.Fatalf("delayed send boundary %s: got=%q want=%q", test.key, got, test.want)
		}
	}
}
