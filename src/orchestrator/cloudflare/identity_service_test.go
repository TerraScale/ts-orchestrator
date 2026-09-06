package cloudflare

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type identityTransport func(*http.Request) (*http.Response, error)

func (f identityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestIdentityServiceAtomicMergePatch(t *testing.T) {
	c := NewClient("token", "zone", "account")
	calls := 0
	c.HTTP = identityTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "PATCH" || r.URL.Path != "/client/v4/accounts/account/workers/scripts/dashboard/secrets-bulk" {
			t.Fatalf("unexpected provider operation %s %s", r.Method, r.URL.Path)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Secrets map[string]*struct {
				Name string `json:"name"`
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"secrets"`
		}
		if json.Unmarshal(raw, &body) != nil || len(body.Secrets) != 3 {
			t.Fatal("expected three named merge-patch secrets")
		}
		for name, secret := range body.Secrets {
			if secret != nil && (secret.Name != name || secret.Type != "secret_text") {
				t.Fatal("invalid provider secret object")
			}
		}
		if calls == 1 && body.Secrets["TERRASCALE_IDENTITY_SERVICE_PREVIOUS_KEY"] == nil {
			t.Fatal("missing overlap")
		}
		if calls == 2 && (body.Secrets["TERRASCALE_IDENTITY_SERVICE_PREVIOUS_KEY"] != nil || body.Secrets["TERRASCALE_IDENTITY_SERVICE_PREVIOUS_KEY_EXPIRES_AT"] != nil) {
			t.Fatal("previous pair not deleted atomically")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":true}`)), Header: http.Header{}}, nil
	})
	if err := c.SetIdentityServiceKeys(t.Context(), "dashboard", []byte(strings.Repeat("n", 43)), []byte(strings.Repeat("o", 43)), time.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetIdentityServiceKeys(t.Context(), "dashboard", []byte(strings.Repeat("n", 43)), nil, time.Time{}); err != nil {
		t.Fatal(err)
	}
}
func TestIdentityServiceRejectsUnboundedOverlap(t *testing.T) {
	c := NewClient("token", "zone", "account")
	if c.SetIdentityServiceKeys(t.Context(), "dashboard", []byte(strings.Repeat("n", 43)), []byte(strings.Repeat("o", 43)), time.Now().Add(301*time.Second)) == nil {
		t.Fatal("accepted excessive overlap")
	}
}
