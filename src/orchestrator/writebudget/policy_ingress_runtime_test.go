package writebudget

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type policyReceiverFixture struct {
	accepted []PolicyEnvelope
}

func (r *policyReceiverFixture) ApplyPolicy(_ context.Context, envelope PolicyEnvelope) (PolicyResult, error) {
	for _, prior := range r.accepted {
		if prior.AccountRevision == envelope.AccountRevision && prior.Checksum == envelope.Checksum {
			return PolicyResult{Status: "accepted", AccountRevision: envelope.AccountRevision, PolicyGeneration: envelope.PolicyGeneration, CycleID: envelope.CycleID, Checksum: envelope.Checksum}, nil
		}
		if prior.OrganizationID == envelope.OrganizationID && prior.PolicyGeneration >= envelope.PolicyGeneration && prior.Checksum != envelope.Checksum {
			return PolicyResult{}, ErrConflict
		}
	}
	r.accepted = append(r.accepted, envelope)
	return PolicyResult{Status: "accepted", AccountRevision: envelope.AccountRevision, PolicyGeneration: envelope.PolicyGeneration, CycleID: envelope.CycleID, Checksum: envelope.Checksum}, nil
}

func TestPolicyIngressAcceptsCanonicalSerializedEnvelopeAndReplaysExactRevision(t *testing.T) {
	const key = "policy-ingress-test-key-012345678901234567890123"
	receiver := new(policyReceiverFixture)
	handler, err := NewPolicyHandler(receiver, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	envelope := PolicyEnvelope{SchemaVersion: 1, OrganizationID: "org-uuid", CycleID: "cycle-1", AccountRevision: "01JUUIDREVISION", PolicyGeneration: 4, Policy: map[string]any{"organizationId": "org-uuid", "includedWriteUnits": "1000000", "paidExcessEnabled": true, "organizationSpendNano": nil, "databaseSpendCapsCents": map[string]int64{"db": 0}}, Checksum: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(body)
	request := func() *http.Response {
		req, err := http.NewRequest(http.MethodPost, server.URL+PolicyPath, io.NopCloser(bytes.NewReader(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("x-terrascale-billing-key", key)
		req.Header.Set("x-terrascale-policy-signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		req.Header.Set("x-terrascale-policy-checksum", envelope.Checksum)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	for range 2 {
		response := request()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", response.StatusCode)
		}
		response.Body.Close()
	}
	if len(receiver.accepted) != 1 || receiver.accepted[0].AccountRevision != "01JUUIDREVISION" {
		t.Fatalf("accepted=%+v", receiver.accepted)
	}
}
