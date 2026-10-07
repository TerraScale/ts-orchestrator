package atlas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
	sdkatlas "terrascale.tech/sdk/atlas"
)

// fakeAtlas checks a publish the way the ts-atlas Worker does (pin.ts
// publishSigned) against the PUBLISH_KEYS JWKS, and records the topology.
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
	config.URL, config.Regions[0].API = server.URL+"/", server.URL
	publisher := Publisher{HTTP: server.Client(), Key: key}
	now := time.Unix(1_791_159_807, 0)
	if err := publisher.Publish(t.Context(), config, now, nil); err != nil {
		t.Fatal(err)
	}
	if got.V != 1 || got.Updated != now.Unix() || len(got.Regions) != 1 || !got.Regions[0].OK ||
		got.Regions[0].ID != "gru-1" || len(got.Services) != len(config.Services) {
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

func TestLoopAlertsOnceAtlasIsStaleAndRecovers(t *testing.T) {
	pem, _ := NewKey(t.Context())
	key, _ := ParseKey(pem)
	publishKeys, _ := JWKS(key)
	status := new(atomic.Int32)
	status.Store(http.StatusOK)
	var got sdkatlas.Topology
	server := fakeAtlas(t, publishKeys, status, &got)
	defer server.Close()
	config := testConfig(t)
	config.URL, config.Regions[0].API = server.URL, server.URL
	control, loads := &fakeAuthority{leader: true}, 0
	loop := Loop{Publisher: Publisher{HTTP: server.Client()},
		Config: func() *Config { return &config }, Authority: control,
		LoadKey: func(ctx context.Context, _ vaultsecret.Ref) (*ecdsa.PrivateKey, error) {
			if _, bounded := ctx.Deadline(); !bounded {
				t.Error("the key read has no deadline")
			}
			loads++
			return key, nil
		}}
	start := time.Unix(1_791_159_807, 0)
	loop.tick(t.Context(), start)
	if got.Updated != start.Unix() || loop.alerted || loads != 1 {
		t.Fatalf("first tick: updated %d alerted %v loads %d", got.Updated, loop.alerted, loads)
	}
	config.URL = server.URL + "/down" // every publish now fails
	loop.tick(t.Context(), start.Add(30*time.Second))
	if loop.alerted {
		t.Fatal("alerted before Atlas could go stale")
	}
	loop.tick(t.Context(), start.Add(StaleAfter))
	if !loop.alerted || loop.Key == nil {
		t.Fatal("no alert once no publish succeeded for StaleAfter")
	}
	config.URL = server.URL
	loop.tick(t.Context(), start.Add(StaleAfter+Interval))
	if loop.alerted || got.Updated != start.Add(StaleAfter+Interval).Unix() || loads != 1 {
		t.Fatalf("recovery: alerted %v updated %d loads %d", loop.alerted, got.Updated, loads)
	}
	// Authority lost after the probes: the guard stops the POST, and the
	// controller drops the job without an alert.
	control.guard = authority.ErrFenced
	loop.tick(t.Context(), start.Add(time.Hour))
	if !loop.since.IsZero() || loop.alerted || got.Updated != start.Add(StaleAfter+Interval).Unix() {
		t.Fatal("a fenced controller published")
	}
	// A follower publishes nothing.
	control.guard, control.leader = nil, false
	loop.tick(t.Context(), start.Add(2*time.Hour))
	if !loop.since.IsZero() || got.Updated != start.Add(StaleAfter+Interval).Unix() {
		t.Fatal("a follower published")
	}
}

func TestLoopKeepsOneHungKeyReadInFlight(t *testing.T) {
	config := testConfig(t)
	hung, reads := make(chan struct{}), new(atomic.Int32)
	loop := Loop{Config: func() *Config { return &config }, Authority: &fakeAuthority{leader: true},
		LoadKey: func(context.Context, vaultsecret.Ref) (*ecdsa.PrivateKey, error) {
			reads.Add(1)
			<-hung
			return nil, errors.New("metadata service unavailable")
		}}
	tick := func() time.Duration {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		loop.tick(ctx, start)
		return time.Since(start)
	}
	if took := tick() + tick(); took > 5*time.Second || reads.Load() != 1 {
		t.Fatalf("two ticks over a hung read took %v and started %d reads", took, reads.Load())
	}
	close(hung)
	tick() // collects the failed read
	tick() // starts the next one
	if reads.Load() != 2 {
		t.Fatalf("%d reads after the hung one finished", reads.Load())
	}
}

type fakeAuthority struct {
	leader bool
	guard  error
}

func (f *fakeAuthority) Current() authority.Snapshot {
	return authority.Snapshot{Leader: f.leader, Ready: true, Epoch: 7, Revision: 1, ExpiresAt: time.Now().Add(time.Minute)}
}

func (f *fakeAuthority) Guard(_ context.Context, epoch uint64) error {
	if epoch != 7 {
		return authority.ErrFenced
	}
	return f.guard
}

func TestConfigValidate(t *testing.T) {
	if err := testConfig(t).Validate("gru"); err != nil {
		t.Fatalf("deploy/oci-region/atlas-gru-1.json: %v", err)
	}
	for name, edit := range map[string]func(*Config){
		"plain http":      func(c *Config) { c.URL = "http://atlas.terrascale.tech" },
		"url with a path": func(c *Config) { c.URL = "https://atlas.terrascale.tech/v1" },
		"foreign secret":  func(c *Config) { c.PublishKey.Name = "gru-1-ts-auth-master-key" },
		"no regions":      func(c *Config) { c.Regions = nil },
		"repeated region": func(c *Config) { c.Regions = append(c.Regions, c.Regions[0]) },
		"bad region id":   func(c *Config) { c.Regions[0].ID = "GRU" },
		"no docs":         func(c *Config) { c.Services = c.Services[:4] },
	} {
		config := testConfig(t)
		edit(&config)
		if err := config.Validate("gru"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
