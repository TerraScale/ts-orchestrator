package reaper

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type mailTestTransport struct{ target string }

func (rt mailTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.URL.Scheme = "http"
	copy.URL.Host = rt.target
	return http.DefaultTransport.RoundTrip(copy)
}

func TestOCIMailSubmissionContract(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/20220926/actions/submitEmail" {
			t.Errorf("unexpected route: %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(raw)
		if r.Header.Get("X-Content-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
			t.Error("body digest mismatch")
		}
		canonical := fmt.Sprintf("date: %s\n(request-target): post %s\nhost: %s\ncontent-length: %d\ncontent-type: application/json\nx-content-sha256: %s", r.Header.Get("Date"), r.URL.Path, r.Host, len(raw), r.Header.Get("X-Content-Sha256"))
		hash := sha256.Sum256([]byte(canonical))
		_, signature, _ := strings.Cut(r.Header.Get("Authorization"), `signature="`)
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(signature, `"`))
		if err != nil || rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], sig) != nil {
			t.Error("invalid OCI signature")
		}
		var payload struct {
			Sender struct {
				Compartment string `json:"compartmentId"`
				Address     struct {
					Email string `json:"email"`
				} `json:"senderAddress"`
			} `json:"sender"`
			Recipients struct {
				To []struct {
					Email string `json:"email"`
				} `json:"to"`
			} `json:"recipients"`
			Subject string `json:"subject"`
			Body    string `json:"bodyText"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Error(err)
		}
		if payload.Sender.Compartment != "ocid1.compartment.test" || payload.Sender.Address.Email != "notice@example.com" || len(payload.Recipients.To) != 1 || payload.Recipients.To[0].Email != "owner@example.com" || !strings.Contains(payload.Body, "db-1") || payload.Subject == "" {
			t.Errorf("wrong payload: %s", raw)
		}
		if r.Header.Get("opc-request-id") == "" {
			t.Error("missing operation correlation")
		}
		if r.Header.Get("opc-retry-token") != "" {
			t.Error("invented retry-token contract")
		}
		_, _ = io.WriteString(w, `{"messageId":"message-1","envelopeId":"envelope-1","suppressedRecipients":[]}`)
	}))
	defer server.Close()
	adapter, err := NewOCIMailAdapter(OCIMailConfig{Endpoint: "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com", CompartmentID: "ocid1.compartment.test", Sender: "notice@example.com", KeyID: "tenancy/user/fingerprint", PrivateKey: key, Transport: mailTestTransport{strings.TrimPrefix(server.URL, "http://")}, CheckEffectAuthority: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, template := range []string{"free-tier-paused", "free-tier-reminder-1", "free-tier-final"} {
		if err := adapter.Send(t.Context(), Email{To: "owner@example.com", Template: template, DatabaseID: "db-1", OperationKey: "notice/1"}); err != nil {
			t.Fatal(err)
		}
	}
	fence := errors.New("authority lost")
	adapter.check = func(context.Context) error { return fence }
	if err := adapter.SendMessage(t.Context(), OCIEmailMessage{To: "owner@example.com", Subject: "notice", Body: "metadata", OperationKey: "op"}); !errors.Is(err, fence) {
		t.Fatalf("fence error: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("fence made external call: %d", calls.Load())
	}
}

func TestOCIMailRejectsUnacknowledgedResponses(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"missing message", 200, `{"envelopeId":"e"}`},
		{"missing envelope", 200, `{"messageId":"m"}`},
		{"suppressed", 200, `{"messageId":"m","envelopeId":"e","suppressedRecipients":[{"email":"owner@example.com"}]}`},
		{"malformed suppression", 200, `{"messageId":"m","envelopeId":"e","suppressedRecipients":{}}`},
		{"malformed json", 200, `{`},
		{"duplicate fields", 200, `{"messageId":"m","messageId":"other","envelopeId":"e"}`},
		{"oversized", 200, strings.Repeat(" ", 65<<10)},
		{"rejected", 400, `{"secret":"must not escape"}`},
		{"redirect", 307, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			a, err := NewOCIMailAdapter(OCIMailConfig{Endpoint: "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com", CompartmentID: "compartment", Sender: "notice@example.com", KeyID: "id", PrivateKey: key, Transport: mailTestTransport{strings.TrimPrefix(s.URL, "http://")}, CheckEffectAuthority: func(context.Context) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.SendMessage(t.Context(), OCIEmailMessage{To: "owner@example.com", Subject: "notice", Body: "metadata", OperationKey: "op"}); !errors.Is(err, ErrOCIEmail) {
				t.Fatalf("unexpected error: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("redirect/retry followed: %d", calls.Load())
			}
		})
	}
}

func TestOCIMailConfigurationAndInputFailClosed(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	baseline := OCIMailConfig{Endpoint: "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com", CompartmentID: "compartment", Sender: "notice@example.com", KeyID: "id", PrivateKey: key, CheckEffectAuthority: func(context.Context) error { return nil }}
	for _, endpoint := range []string{"http://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com", "https://attacker.example", "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com:443", "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com/path", "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com/?", "https://user@cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com"} {
		c := baseline
		c.Endpoint = endpoint
		if _, err := NewOCIMailAdapter(c); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	for _, mutate := range []func(*OCIMailConfig){func(c *OCIMailConfig) { c.CheckEffectAuthority = nil }, func(c *OCIMailConfig) { c.PrivateKey = nil }, func(c *OCIMailConfig) { c.Sender = "notice@example.com\r\nInjected: yes" }, func(c *OCIMailConfig) { c.KeyID = "id\"" }} {
		c := baseline
		mutate(&c)
		if _, err := NewOCIMailAdapter(c); err == nil {
			t.Fatal("accepted incomplete or unsafe configuration")
		}
	}
	a, err := NewOCIMailAdapter(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(t.Context(), Email{To: "owner@example.com", Template: "unknown", DatabaseID: "db", OperationKey: "op"}); err == nil {
		t.Fatal("accepted unknown template")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.SendMessage(ctx, OCIEmailMessage{To: "owner@example.com", Subject: "notice", Body: "metadata", OperationKey: "op"}); err == nil {
		t.Fatal("accepted canceled call")
	}
}
