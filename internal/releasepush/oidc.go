// Package releasepush lets CI push GitHub-OIDC-signed releases to a running
// ts-orch over its embedded NATS (TLS :4222). CI holds no secret: its GitHub
// Actions OIDC token is both the NATS credential and the release signature.
package releasepush

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	githubIssuer = "https://token.actions.githubusercontent.com"
	githubJWKS   = githubIssuer + "/.well-known/jwks"
	// Audience is the OIDC audience CI requests and ts-orch accepts.
	Audience  = "ts-orch"
	owner     = "TerraScale"
	mainRef   = "refs/heads/main"
	clockSkew = time.Minute
	// An unknown kid refetches the JWKS at most this often, so unauthenticated
	// clients cannot turn connects into GitHub requests.
	refetchEvery = 30 * time.Second
	maxTokenSize = 16 << 10
)

// Claims are the GitHub Actions OIDC claims ts-orch acts on.
type Claims struct {
	Issuer          string   `json:"iss"`
	Audience        audience `json:"aud"`
	Expires         int64    `json:"exp"`
	NotBefore       int64    `json:"nbf"`
	Repository      string   `json:"repository"`
	RepositoryOwner string   `json:"repository_owner"`
	Ref             string   `json:"ref"`
	SHA             string   `json:"sha"`
	RunID           string   `json:"run_id"`
}

// audience accepts the JWT "aud" string or array form.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var one string
	if json.Unmarshal(data, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Verifier checks GitHub Actions OIDC tokens against GitHub's JWKS.
type Verifier struct {
	JWKSURL string
	Client  *http.Client
	Now     func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// NewVerifier verifies against GitHub's published keys.
func NewVerifier() *Verifier {
	return &Verifier{JWKSURL: githubJWKS, Client: &http.Client{Timeout: 10 * time.Second}, Now: time.Now}
}

// Verify returns the claims of a valid main-branch TerraScale token for ts-orch.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	if len(token) > maxTokenSize {
		return Claims{}, errors.New("token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("token is not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil || header.Alg != "RS256" || header.Kid == "" {
		return Claims{}, errors.New("token header must be RS256 with a kid")
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return Claims{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, errors.New("token signature is not base64url")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return Claims{}, errors.New("token signature is invalid")
	}
	var claims Claims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return Claims{}, errors.New("token claims are invalid")
	}
	now := v.Now()
	switch {
	case claims.Issuer != githubIssuer:
		return Claims{}, errors.New("token issuer is not GitHub Actions")
	case len(claims.Audience) != 1 || claims.Audience[0] != Audience:
		return Claims{}, errors.New("token audience is not " + Audience)
	case claims.Expires == 0 || !now.Before(time.Unix(claims.Expires, 0).Add(clockSkew)):
		return Claims{}, errors.New("token expired")
	case claims.NotBefore != 0 && now.Add(clockSkew).Before(time.Unix(claims.NotBefore, 0)):
		return Claims{}, errors.New("token not yet valid")
	case claims.RepositoryOwner != owner || !strings.HasPrefix(claims.Repository, owner+"/"):
		return Claims{}, errors.New("token is not from a " + owner + " repository")
	case claims.Ref != mainRef:
		return Claims{}, errors.New("token is not from " + mainRef)
	}
	return claims, nil
}

func decodeSegment(segment string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if key := v.keys[kid]; key != nil {
		return key, nil
	}
	if !v.fetched.IsZero() && v.Now().Sub(v.fetched) < refetchEvery {
		return nil, fmt.Errorf("unknown token key %q", kid)
	}
	keys, err := v.fetch(ctx)
	v.fetched = v.Now()
	if err != nil {
		return nil, fmt.Errorf("fetch GitHub JWKS: %w", err)
	}
	v.keys = keys
	if key := keys[kid]; key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("unknown token key %q", kid)
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := v.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", response.Status)
	}
	var set struct {
		Keys []struct{ Kty, Kid, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if k.Kty != "RSA" || k.Kid == "" || errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if key.N.BitLen() >= 2048 {
			keys[k.Kid] = key
		}
	}
	return keys, nil
}
