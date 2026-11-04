package machinesapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIssuer   = "https://gru.auth.terrascale.tech/terrascale"
	testAudience = "https://gru.orch.terrascale.tech"
)

// issuer is a fake ts-auth: an ES256 key ring published as a JWKS.
type issuer struct {
	t       *testing.T
	mu      sync.Mutex
	keys    map[string]*ecdsa.PrivateKey
	down    bool
	fetches atomic.Int32
	server  *httptest.Server
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	i := &issuer{t: t, keys: map[string]*ecdsa.PrivateKey{}}
	i.addKey("skey_one")
	i.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i.fetches.Add(1)
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.down {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		var keys []map[string]string
		for kid, key := range i.keys {
			public, _ := key.PublicKey.Bytes()
			keys = append(keys, map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
				"x": base64.RawURLEncoding.EncodeToString(public[1:33]), "y": base64.RawURLEncoding.EncodeToString(public[33:])})
		}
		// A key the verifier cannot use is skipped.
		keys = append(keys, map[string]string{"kty": "RSA", "kid": "rsa", "n": "AQAB", "e": "AQAB"})
		data, _ := json.Marshal(map[string]any{"keys": keys})
		_, _ = w.Write(data)
	}))
	t.Cleanup(i.server.Close)
	return i
}

func (i *issuer) addKey(kid string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		i.t.Fatal(err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys[kid] = key
}

func (i *issuer) removeKey(kid string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.keys, kid)
}

func (i *issuer) setDown(down bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.down = down
}

// sign returns a token with claims merged over valid defaults; a nil claim
// value removes the claim.
func (i *issuer) sign(kid string, header, claims map[string]any) string {
	i.mu.Lock()
	key := i.keys[kid]
	i.mu.Unlock()
	if key == nil {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return signWith(key, kid, header, claims)
}

func signWith(key *ecdsa.PrivateKey, kid string, header, claims map[string]any) string {
	now := time.Now().Unix()
	h := map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": kid}
	c := map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "0000000000MKRT6SVZW2P1SRPH", "client_id": "00000000006HEQR9ARBF6BV9X9",
		"scope": "openid orch:read", "iat": now, "exp": now + 3600, "jti": "j"}
	merge := func(into, from map[string]any) {
		for name, value := range from {
			if value == nil {
				delete(into, name)
			} else {
				into[name] = value
			}
		}
	}
	merge(h, header)
	merge(c, claims)
	encode := func(value any) string {
		data, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signed := encode(h) + "." + encode(c)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (i *issuer) verifier(urls ...string) *Verifier {
	v := NewVerifier(testIssuer, testAudience, append(urls, i.server.URL))
	v.client = i.server.Client()
	return v
}

func TestVerifierAcceptsAccessToken(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier()
	principal, err := v.Verify(t.Context(), i.sign("skey_one", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "0000000000MKRT6SVZW2P1SRPH" || principal.ClientID != "00000000006HEQR9ARBF6BV9X9" || !principal.HasScope(ScopeRead) || principal.HasScope("orch:write") {
		t.Fatalf("principal = %+v", principal)
	}
	// ts-auth sends an array when it has several audiences.
	token := i.sign("skey_one", nil, map[string]any{"aud": []string{"https://gru.api.terrascale.tech", testAudience}})
	if _, err := v.Verify(t.Context(), token); err != nil {
		t.Fatalf("array audience: %v", err)
	}
	// typ is case-insensitive and may carry the media type prefix.
	if _, err := v.Verify(t.Context(), i.sign("skey_one", map[string]any{"typ": "application/AT+JWT"}, nil)); err != nil {
		t.Fatalf("typ: %v", err)
	}
}

func TestVerifierRejectsTokens(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier()
	parts := strings.Split(i.sign("skey_one", nil, nil), ".")
	claims, _ := json.Marshal(map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "0000000000FT4JKN5QV2BGQ38B", "scope": "orch:write", "exp": time.Now().Unix() + 3600})
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + parts[2]
	if _, err := v.Verify(t.Context(), forged); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("forged token: %v", err)
	}
}
