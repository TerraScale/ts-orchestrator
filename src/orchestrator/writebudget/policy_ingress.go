package writebudget

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"
)

const PolicyPath = "/internal/v1/billing/write-budget/policy"

var ErrPolicyTransport = errors.New("writebudget: policy transport failure")

// PolicyEnvelope is the Dashboard's post-CAS document. Policy is retained as
// JSON so billing can add fields without making regional writers billing
// customers or collaborators.
type PolicyEnvelope struct {
	SchemaVersion    int            `json:"schemaVersion"`
	OrganizationID   string         `json:"organizationId"`
	CycleID          string         `json:"cycleId"`
	AccountRevision  string         `json:"accountRevision"`
	PolicyGeneration int            `json:"policyGeneration"`
	Policy           map[string]any `json:"policy"`
	Checksum         string         `json:"checksum"`
}

type PolicyResult struct {
	Status           string `json:"status"`
	AccountRevision  string `json:"accountRevision"`
	CycleID          string `json:"cycleId"`
	PolicyGeneration int    `json:"policyGeneration"`
	Checksum         string `json:"checksum"`
	Deadline         string `json:"deadline,omitempty"`
}

// PolicyReceiver is implemented by the GRU authority owner, which must apply
// the envelope through its fenced durable journal and reconcile duplicate
// deliveries. The HTTP layer never keeps policy state in memory.
type PolicyReceiver interface {
	ApplyPolicy(context.Context, PolicyEnvelope) (PolicyResult, error)
}

func NewPolicyHandler(receiver PolicyReceiver, serviceKey string) (http.Handler, error) {
	if receiver == nil || len(serviceKey) < 32 || strings.TrimSpace(serviceKey) != serviceKey {
		return nil, ErrInvalid
	}
	expectedKey := sha256.Sum256([]byte(serviceKey))
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PolicyPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 {
			http.Error(w, "HTTPS required", http.StatusBadRequest)
			return
		}
		providedKey := sha256.Sum256([]byte(r.Header.Get("x-terrascale-billing-key")))
		if len(r.Header.Values("x-terrascale-billing-key")) != 1 || subtle.ConstantTimeCompare(expectedKey[:], providedKey[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		providedSignature := r.Header.Get("x-terrascale-policy-signature")
		mac := hmac.New(sha256.New, []byte(serviceKey))
		_, _ = mac.Write(body)
		expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if len(r.Header.Values("x-terrascale-policy-signature")) != 1 || !hmac.Equal([]byte(expectedSignature), []byte(providedSignature)) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var policy PolicyEnvelope
		if json.Unmarshal(body, &policy, json.RejectUnknownMembers(true)) != nil || policy.SchemaVersion != 1 || policy.OrganizationID == "" || policy.CycleID == "" || policy.AccountRevision == "" || policy.PolicyGeneration <= 0 || policy.Checksum == "" || policy.Policy == nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		if policy.Checksum != r.Header.Get("x-terrascale-policy-checksum") || len(r.Header.Values("x-terrascale-policy-checksum")) != 1 {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		result, err := receiver.ApplyPolicy(r.Context(), policy)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if result.Status != "accepted" && result.Status != "pending" || result.AccountRevision != policy.AccountRevision || result.PolicyGeneration != policy.PolicyGeneration || result.CycleID != policy.CycleID || result.Checksum != policy.Checksum {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		encoded, err := json.Marshal(result)
		if err != nil {
			return
		}
		_, _ = w.Write(encoded)
	})
	return mux, nil
}
