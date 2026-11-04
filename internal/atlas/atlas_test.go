package atlas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	sdkatlas "terrascale.tech/sdk/atlas"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func fakeAtlas(t *testing.T, publishKeys string, status *atomic.Int32, got *sdkatlas.Topology) *httptest.Server {
	var jwks struct {
		Keys []struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(publishKeys), &jwks); err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("PUBLISH_KEYS %s: %v", publishKeys, err)
	}
	x, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].X)
	y, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].Y)
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.WriteHeader(int(status.Load()))
			return
		}
		if r.URL.Path != "/v1/publish" {
			http.Error(w, `{"error":{"code":"store_unavailable"}}`, http.StatusBadGateway)
			return
		}
		body, _ := io.ReadAll(r.Body)
		timestamp, signature := r.Header.Get("x-atlas-timestamp"), r.Header.Get("x-atlas-signature")
		raw, err := base64.RawURLEncoding.DecodeString(signature)
		digest := sha256.Sum256([]byte("atlas-publish-v1\n" + timestamp + "\n" + string(body)))
		if len(signature) != 86 || err != nil ||
			!ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
			http.Error(w, `{"error":{"code":"invalid_signature"}}`, http.StatusUnauthorized)
			return
		}
		var request struct {
			Topology sdkatlas.Topology `json:"topology"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
		}
		*got = request.Topology
		_, _ = io.WriteString(w, `{"topology":"updated","placements":[]}`)
	}))
}

func testConfig(t *testing.T) Config {
	data, err := os.ReadFile("../../deploy/oci-region/atlas-gru-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := protocol.DecodeStrict(data, &config, 64<<10); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestPublishSignsAMonotonicTopologyWithProbedHealth(t *testing.T) {
	pem, err := NewKey(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	publishKeys, err := JWKS(key)
	if err != nil {
		t.Fatal(err)
	}
	status := new(atomic.Int32)
	status.Store(http.StatusOK)
	var got sdkatlas.Topology
	server := fakeAtlas(t, publishKeys, status, &got)
	defer server.Close()
	config := testConfig(t)
	config.URL = server.URL + "/"
	for i := range config.Regions {
		config.Regions[i].API = server.URL
	}
	publisher := Publisher{HTTP: server.Client(), Key: key}
	now := time.Unix(1_791_159_807, 0)
	if err := publisher.Publish(t.Context(), config, now, nil); err != nil {
		t.Fatal(err)
	}
	if got.V != 1 || got.Updated != now.Unix() || len(got.Regions) != 2 || !got.Regions[0].OK || !got.Regions[1].OK ||
		got.Regions[0].ID != "gru-1" || got.Regions[1].ID != "sjc-1" || len(got.Services) != len(config.Services) {
		t.Fatalf("published %+v", got)
	}
	// A second publish within the same second still moves updated on, and a
	// region whose readyz fails is published down.
	status.Store(http.StatusServiceUnavailable)
	if err := publisher.Publish(t.Context(), config, now, nil); err != nil {
		t.Fatal(err)
	}
	if got.Updated != now.Unix()+1 || got.Regions[0].OK {
		t.Fatalf("republished %+v", got)
	}
	other, _ := NewKey(t.Context())
	publisher.Key, _ = ParseKey(other)
	if err := publisher.Publish(t.Context(), config, now, nil); err != ErrUnauthorized {
		t.Fatalf("a key outside PUBLISH_KEYS: %v", err)
	}
}
