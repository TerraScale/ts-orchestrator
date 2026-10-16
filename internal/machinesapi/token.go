package machinesapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const (
	maxTokenBytes = 8 << 10
	maxJWKSBytes  = 64 << 10
	clockSkew     = time.Minute
	// keysFresh is how long fetched keys are used without a refresh;
	// refreshEvery bounds the refreshes that tokens with unknown key IDs
	// trigger, so forged key IDs cannot make the API hammer ts-auth.
	keysFresh    = 10 * time.Minute
	refreshEvery = 30 * time.Second
	fetchTimeout = 5 * time.Second
	// maxKeyAge outlasts every token ts-auth signed (they live one hour)
	// before the set was last fetched. Older keys are not used, so a key
	// ts-auth withdrew is not trusted forever while refreshes fail.
	maxKeyAge = keysFresh + time.Hour
)

// ErrUnauthenticated is every token rejection. The reason stays in the
// wrapped error for logs; clients only learn that the token was refused.
var ErrUnauthenticated = errors.New("access token rejected")

// Principal is who a verified access token speaks for: a user's ULID, or a
// service client's ID for a client-credentials token.
type Principal struct {
	Subject  string
	ClientID string
	Scopes   []string
}

// HasScope reports whether the token was granted scope.
func (p Principal) HasScope(scope string) bool { return slices.Contains(p.Scopes, scope) }

// Verifier checks ts-auth OAuth access tokens: RFC 9068 at+jwt signed with
// ES256 by a key of the issuer's published key set.
type Verifier struct {
	issuer   string
	audience string
	jwksURLs []string
	client   *http.Client
	now      func() time.Time

	// fetching serializes key set fetches; mu guards the fields below.
	fetching  sync.Mutex
	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetched   time.Time
	attempted time.Time
}

// NewVerifier verifies tokens of issuer for audience with the key set at
// the first of jwksURLs that answers. They are separate from the issuer
// because controllers reach ts-auth on the cell's private network, not
// through the public origin.
func NewVerifier(issuer, audience string, jwksURLs []string) *Verifier {
	// A redirect is refused, not followed: it could lead to a host the
	// signed jwks_urls never named, whose keys would then be trusted.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Verifier{issuer: issuer, audience: audience, jwksURLs: jwksURLs, client: client, now: time.Now}
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	Expiry    *int64   `json:"exp"`
	NotBefore *int64   `json:"nbf"`
	IssuedAt  *int64   `json:"iat"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope"`
}

// audience is the aud claim: ts-auth sends a string for one configured
// audience and an array for several.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var one string
	if json.Unmarshal(data, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = many
	return nil
}

// Verify checks a compact JWS access token and returns its principal.
func (v *Verifier) Verify(ctx context.Context, token string) (Principal, error) {
	principal, err := v.verify(ctx, token)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	return principal, nil
}

func (v *Verifier) verify(ctx context.Context, token string) (Principal, error) {
	if len(token) > maxTokenBytes {
		return Principal{}, errors.New("token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Principal{}, errors.New("token is not a compact JWS")
	}
	var header jwtHeader
	if err := decodeSegment(parts[0], &header); err != nil {
		return Principal{}, fmt.Errorf("header: %w", err)
	}
	// RFC 9068 section 4: only a token typed as an access token, so an ID
	// token of the same issuer (typ JWT) is never accepted. ts-auth signs
	// with ES256 alone; no other algorithm, none included, is tried.
	if typ := strings.ToLower(header.Typ); typ != "at+jwt" && typ != "application/at+jwt" {
		return Principal{}, fmt.Errorf("typ %q is not at+jwt", header.Typ)
	}
	if header.Alg != "ES256" {
		return Principal{}, fmt.Errorf("alg %q is not ES256", header.Alg)
	}
	if header.Kid == "" {
		return Principal{}, errors.New("header has no kid")
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return Principal{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return Principal{}, errors.New("signature is not a base64url ES256 signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return Principal{}, fmt.Errorf("signature does not verify with key %q", header.Kid)
	}
	var claims jwtClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return Principal{}, fmt.Errorf("claims: %w", err)
	}
	now := v.now()
	switch {
	case claims.Issuer != v.issuer:
		return Principal{}, fmt.Errorf("issuer %q is not trusted", claims.Issuer)
	case !slices.Contains(claims.Audience, v.audience):
		return Principal{}, errors.New("token is not for this audience")
	case claims.Expiry == nil || !now.Before(time.Unix(*claims.Expiry, 0).Add(clockSkew)):
		return Principal{}, errors.New("token expired or has no exp")
	case claims.NotBefore != nil && now.Add(clockSkew).Before(time.Unix(*claims.NotBefore, 0)):
		return Principal{}, errors.New("token is not valid yet")
	case claims.IssuedAt != nil && now.Add(clockSkew).Before(time.Unix(*claims.IssuedAt, 0)):
		return Principal{}, errors.New("token was issued in the future")
	case !entityid.Valid(claims.Subject) || !entityid.Valid(claims.ClientID):
		return Principal{}, errors.New("token subject and client ID must be canonical ULIDs")
	}
	return Principal{Subject: claims.Subject, ClientID: claims.ClientID, Scopes: strings.Fields(claims.Scope)}, nil
}

func decodeSegment(segment string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return errors.New("segment is not base64url")
	}
	return json.Unmarshal(data, into)
}

// key returns the key for kid. The key set is refetched when it is stale,
// so a key ts-auth withdrew stops verifying, and when it does not know kid,
// so a new key verifies; at most once per refreshEvery. A failed refresh
// keeps the keys already fetched for up to maxKeyAge, so a short ts-auth
// outage does not lock out holders of valid tokens. Only a request for an
// unknown key waits for a fetch in flight.
func (v *Verifier) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	key, age := v.cached(kid)
	if key != nil && age <= keysFresh {
		return key, nil
	}
	if key == nil {
		v.fetching.Lock()
	} else if !v.fetching.TryLock() {
		return usable(key, age, kid)
	}
	defer v.fetching.Unlock()
	key, age = v.cached(kid)
	v.mu.Lock()
	now := v.now()
	due := now.Sub(v.attempted) >= refreshEvery && (key == nil || age > keysFresh)
	if due {
		v.attempted = now
	}
	v.mu.Unlock()
	if due {
		keys, err := v.fetch(ctx, kid)
		switch {
		case err == nil:
			v.mu.Lock()
			v.keys, v.fetched = keys, now
			v.mu.Unlock()
			key, age = keys[kid], 0
		case key == nil:
			return nil, fmt.Errorf("fetch signing keys: %w", err)
		}
	}
	return usable(key, age, kid)
}

func usable(key *ecdsa.PublicKey, age time.Duration, kid string) (*ecdsa.PublicKey, error) {
	switch {
	case key == nil:
		return nil, fmt.Errorf("unknown signing key %q", kid)
	case age > maxKeyAge:
		return nil, errors.New("the signing keys are too old to trust: ts-auth's key set has been unreachable")
	}
	return key, nil
}

// cached returns the key for kid and the age of the set it came from.
func (v *Verifier) cached(kid string) (*ecdsa.PublicKey, time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.keys[kid], v.now().Sub(v.fetched)
}

// jwk is one key of the issuer's key set.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// fetch returns the first key set, in jwksURLs order, that holds kid, so
// a replica that has not caught up with a new key neither hides nor drops
// it; failing that, the first usable set. ts-auth's replicas share one key
// ring and never retire a key, so lag only ever hides a new key; a key
// ts-auth withdraws goes once no replica publishes it.
func (v *Verifier) fetch(ctx context.Context, kid string) (map[string]*ecdsa.PublicKey, error) {
	var first map[string]*ecdsa.PublicKey
	var errs []error
	for _, url := range v.jwksURLs {
		keys, err := v.fetchURL(ctx, url)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
			continue
		}
		if keys[kid] != nil {
			return keys, nil
		}
		if first == nil {
			first = keys
		}
	}
	if first != nil {
		return first, nil
	}
	return nil, errors.Join(errs...)
}

func (v *Verifier) fetchURL(ctx context.Context, url string) (map[string]*ecdsa.PublicKey, error) {
	// The fetch outlives the request that triggered it: a client that hangs
	// up must not cancel it and use up the refresh slot for everyone else.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("key set returned %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxJWKSBytes {
		return nil, errors.New("key set is too large")
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("decode key set: %w", err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, key := range set.Keys {
		// A key this verifier cannot use is skipped, not fatal: the set may
		// publish more than ES256 signing keys.
		if key.Kty != "EC" || key.Crv != "P-256" || key.Kid == "" || key.Use != "" && key.Use != "sig" ||
			key.Alg != "" && key.Alg != "ES256" {
			continue
		}
		x, errX := base64.RawURLEncoding.DecodeString(key.X)
		y, errY := base64.RawURLEncoding.DecodeString(key.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			continue
		}
		public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			continue
		}
		keys[key.Kid] = public
	}
	if len(keys) == 0 {
		return nil, errors.New("key set has no usable ES256 key")
	}
	return keys, nil
}
