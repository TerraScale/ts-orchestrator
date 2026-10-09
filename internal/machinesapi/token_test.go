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
	now := time.Now().Unix()
	valid := i.sign("skey_one", nil, nil)
	parts := strings.Split(valid, ".")
	forgedClaims, _ := json.Marshal(map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "0000000000FT4JKN5QV2BGQ38B",
		"scope": "orch:write", "exp": now + 3600})
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]string{
		"payload swapped":    parts[0] + "." + base64.RawURLEncoding.EncodeToString(forgedClaims) + "." + parts[2],
		"signature flipped":  parts[0] + "." + parts[1] + "." + flipLast(parts[2]),
		"no signature":       parts[0] + "." + parts[1] + ".",
		"alg none":           i.sign("skey_one", map[string]any{"alg": "none"}, nil),
		"alg HS256":          i.sign("skey_one", map[string]any{"alg": "HS256"}, nil),
		"id token typ":       i.sign("skey_one", map[string]any{"typ": "JWT"}, nil),
		"no typ":             i.sign("skey_one", map[string]any{"typ": nil}, nil),
		"no kid":             i.sign("skey_one", map[string]any{"kid": nil}, nil),
		"other key same kid": signWith(otherKey, "skey_one", nil, nil),
		"unknown kid":        i.sign("skey_unknown", nil, nil),
		"wrong issuer":       i.sign("skey_one", nil, map[string]any{"iss": "https://evil.example/terrascale"}),
		"issuer suffix":      i.sign("skey_one", nil, map[string]any{"iss": testIssuer + "/"}),
		"wrong audience":     i.sign("skey_one", nil, map[string]any{"aud": "https://gru.api.terrascale.tech"}),
		"audience prefix":    i.sign("skey_one", nil, map[string]any{"aud": testAudience + "/"}),
		"no audience":        i.sign("skey_one", nil, map[string]any{"aud": nil}),
		"expired":            i.sign("skey_one", nil, map[string]any{"exp": now - 120}),
		"no exp":             i.sign("skey_one", nil, map[string]any{"exp": nil}),
		"not yet valid":      i.sign("skey_one", nil, map[string]any{"nbf": now + 600}),
		"issued in future":   i.sign("skey_one", nil, map[string]any{"iat": now + 600}),
		"no subject":         i.sign("skey_one", nil, map[string]any{"sub": nil}),
		"two segments":       parts[0] + "." + parts[1],
		"oversized":          strings.Repeat("a", maxTokenBytes+1),
		"garbage header":     "!!!." + parts[1] + "." + parts[2],
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(t.Context(), token)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Verify = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func flipLast(segment string) string {
	data, _ := base64.RawURLEncoding.DecodeString(segment)
	data[len(data)-1] ^= 1
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestVerifierKeyRotationAndOutage(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier()
	clock := time.Now()
	v.now = func() time.Time { return clock }
	if _, err := v.Verify(t.Context(), i.sign("skey_one", nil, nil)); err != nil {
		t.Fatal(err)
	}
	// Forged key IDs refetch the set at most once per refreshEvery.
	i.fetches.Store(0)
	clock = clock.Add(refreshEvery)
	for range 20 {
		if _, err := v.Verify(t.Context(), i.sign("skey_forged", nil, nil)); err == nil {
			t.Fatal("forged key ID verified")
		}
	}
	if got := i.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
	// A key ts-auth adds verifies once the rate limit allows a refetch.
	i.addKey("skey_two")
	clock = clock.Add(refreshEvery)
	if _, err := v.Verify(t.Context(), i.sign("skey_two", nil, nil)); err != nil {
		t.Fatalf("rotated-in key: %v", err)
	}
	// While ts-auth is down, fetched keys keep verifying, even stale ones.
	i.setDown(true)
	clock = clock.Add(keysFresh + time.Second)
	if _, err := v.Verify(t.Context(), i.sign("skey_one", nil, nil)); err != nil {
		t.Fatalf("known key during outage: %v", err)
	}
	// A key ts-auth withdrew stops verifying at the next refresh.
	i.setDown(false)
	i.mu.Lock()
	withdrawn := i.keys["skey_one"]
	i.mu.Unlock()
	i.removeKey("skey_one")
	clock = clock.Add(refreshEvery)
	if _, err := v.Verify(t.Context(), i.sign("skey_two", nil, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(t.Context(), signWith(withdrawn, "skey_one", nil, nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("withdrawn key verified: %v", err)
	}
}

func TestVerifierRejectsUnusableKeySet(t *testing.T) {
	for name, body := range map[string]string{
		"empty":     `{"keys":[]}`,
		"wrong use": `{"keys":[{"kty":"EC","crv":"P-256","use":"enc","kid":"k","x":"AA","y":"AA"}]}`,
		"not json":  `<html>`,
		"too large": `{"keys":[],"pad":"` + strings.Repeat("a", maxJWKSBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			v := NewVerifier(testIssuer, testAudience, []string{server.URL})
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if _, err := v.Verify(t.Context(), signWith(key, "k", nil, nil)); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Verify = %v", err)
			}
		})
	}
}

// The first key set URL that answers is used: a controller without a local
// ts-auth replica falls back to another controller's.
func TestVerifierFallsBackToTheNextKeySetURL(t *testing.T) {
	i := newIssuer(t)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no replica", http.StatusBadGateway)
	}))
	defer down.Close()
	if _, err := i.verifier(down.URL).Verify(t.Context(), i.sign("skey_one", nil, nil)); err != nil {
		t.Fatal(err)
	}
}

// Once every token signed before the last fetch has expired, keys of that
// set are no longer trusted while ts-auth stays unreachable: it may have
// withdrawn one.
func TestVerifierDistrustsAnOldKeySet(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier()
	clock := time.Now()
	v.now = func() time.Time { return clock }
	if _, err := v.Verify(t.Context(), i.sign("skey_one", nil, nil)); err != nil {
		t.Fatal(err)
	}
	i.setDown(true)
	clock = clock.Add(maxKeyAge + time.Second)
	token := i.sign("skey_one", nil, map[string]any{"iat": clock.Unix(), "exp": clock.Unix() + 600})
	if _, err := v.Verify(t.Context(), token); !errors.Is(err, ErrUnauthenticated) || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("Verify = %v", err)
	}
	i.setDown(false)
	clock = clock.Add(refreshEvery)
	token = i.sign("skey_one", nil, map[string]any{"iat": clock.Unix(), "exp": clock.Unix() + 600})
	if _, err := v.Verify(t.Context(), token); err != nil {
		t.Fatalf("after ts-auth returns: %v", err)
	}
}

// A key set URL that redirects is refused rather than followed, so keys
// never come from a host the signed jwks_urls did not name.
func TestVerifierRefusesKeySetRedirects(t *testing.T) {
	i := newIssuer(t)
	redirect := httptest.NewServer(http.RedirectHandler(i.server.URL, http.StatusFound))
	defer redirect.Close()
	v := NewVerifier(testIssuer, testAudience, []string{redirect.URL})
	if _, err := v.Verify(t.Context(), i.sign("skey_one", nil, nil)); !errors.Is(err, ErrUnauthenticated) ||
		!strings.Contains(err.Error(), "302") {
		t.Fatalf("Verify = %v", err)
	}
}

// A key is looked for on every replica: a reachable replica that has not
// caught up with a new key neither hides it nor, at the next refresh,
// drops it.
func TestVerifierFindsANewKeyOnALaterReplica(t *testing.T) {
	lagging, current := newIssuer(t), newIssuer(t)
	current.mu.Lock()
	current.keys["skey_one"] = lagging.keys["skey_one"]
	current.mu.Unlock()
	current.addKey("skey_two")
	v := lagging.verifier(lagging.server.URL)
	v.jwksURLs = []string{lagging.server.URL, current.server.URL}
	clock := time.Now()
	v.now = func() time.Time { return clock }
	if _, err := v.Verify(t.Context(), current.sign("skey_two", nil, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(t.Context(), lagging.sign("skey_one", nil, nil)); err != nil {
		t.Fatalf("key both replicas publish: %v", err)
	}
	clock = clock.Add(keysFresh + time.Second)
	for range 2 {
		if _, err := v.Verify(t.Context(), current.sign("skey_two", nil, nil)); err != nil {
			t.Fatalf("new key after a refresh: %v", err)
		}
	}
}
