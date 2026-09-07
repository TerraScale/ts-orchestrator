package cloudflare_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cf "terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestMembershipPublisherAuthenticatedRetryAndNoResurrection(t *testing.T) {
	f := newRotationFixture(t)
	if err := f.store.Distribute(t.Context(), security.CredentialSet{Capability: f.material(1), OriginProof: f.originMaterial(1)}, "stage"); err != nil {
		t.Fatal(err)
	}
	entry := cf.CapabilityRevocation{Scope: fmt.Sprintf("scope-%064x", 7), ExpiresAt: f.now.Add(1320 * time.Second).Unix()}
	digest := sha256.Sum256(fmt.Appendf(nil, "%s.%d\n", entry.Scope, entry.ExpiresAt))
	snapshot := cf.MembershipRevocationSnapshot{Revision: hex.EncodeToString(digest[:]), ValidUntil: f.now.Add(30 * time.Second).Unix(), Entries: []cf.CapabilityRevocation{entry}}
	status := http.StatusOK
	serviceKey := "issuer-secret"
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/api/internal/identity/introspect" || r.Header.Get("x-terrascale-identity-service-key") != serviceKey {
			t.Error("unauthenticated snapshot request")
			w.WriteHeader(401)
			return
		}
		var request struct {
			Kind     string `json:"kind"`
			Audience string `json:"audience"`
		}
		if json.UnmarshalRead(r.Body, &request) != nil || request.Kind != "revocations" || request.Audience != "https://api.terrascale.tech" {
			t.Error("wrong authority request")
		}
		w.WriteHeader(status)
		_ = json.MarshalWrite(w, struct {
			Active   bool                            `json:"active"`
			Snapshot cf.MembershipRevocationSnapshot `json:"membershipRevocations"`
		}{false, snapshot})
	}))
	defer server.Close()
	publisher, err := cf.NewMembershipRevocationPublisher(cf.MembershipRevocationPublisherConfig{Endpoint: server.URL + "/api/internal/identity/introspect", Audience: "https://api.terrascale.tech", ServiceKey: func() (string, error) { return serviceKey, nil }, HTTPClient: server.Client(), Store: f.store, Authorize: f.config.Authorize})
	if err != nil {
		t.Fatal(err)
	}
	if err = publisher.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}

	f.forged.Store(true)
	if publisher.Tick(t.Context()) == nil {
		t.Fatal("forged ingress acknowledgement accepted")
	}
	f.forged.Store(false)
	serviceKey = "rotated-secret"
	puts := f.puts.Load()
	if err = publisher.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.puts.Load() != puts {
		t.Fatal("duplicate snapshot republished")
	}
	status = 503
	if publisher.Tick(t.Context()) == nil {
		t.Fatal("failed authority accepted")
	}
	receipt, _, _ := f.journal.Load(t.Context())
	if receipt.MembershipRevocations.ValidUntil != snapshot.ValidUntil {
		t.Fatal("failure extended lease")
	}
	status = 200
	snapshot.ValidUntil++ // a new source lease, not a local extension
	if publisher.Tick(t.Context()) == nil {
		t.Fatal("lease beyond maximum accepted")
	}
	f.now = f.now.Add(time.Second)
	if err = publisher.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot.Entries = nil
	empty := sha256.Sum256(nil)
	snapshot.Revision = hex.EncodeToString(empty[:])
	if publisher.Tick(t.Context()) == nil {
		t.Fatal("missing live tombstone resurrected membership")
	}
	if calls != 7 {
		t.Fatalf("poll calls=%d", calls)
	}
	f.now = f.now.Add(30 * time.Second)
	if publisher.Tick(t.Context()) == nil {
		t.Fatal("stale source accepted")
	}
}
