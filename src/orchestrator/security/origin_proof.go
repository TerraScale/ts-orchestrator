package security

// This file is the Go side of the ts-proxy Snippet's origin-proof contract.
// Keep it dependency-free and byte-for-byte boring: the Snippet signs
// `v1.<UPPER_METHOD>.<canonical-path-query>.<bucket>` and sends
// `v1.<bucket>.<hex>` to the member. No key value is returned by a verify
// operation, and key IDs are the only durable/public identity.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const OriginProofVersion = "v1"

var (
	ErrOriginProofMalformed = errors.New("origin proof malformed")
	ErrOriginProofExpired   = errors.New("origin proof expired")
	ErrOriginProofMismatch  = errors.New("origin proof mismatch")
)

// OriginProofKey is a key-ring entry. ID is safe for state, logs, and
// receipts; Secret is borrowed transient material and must be wiped by the
// caller after the operation.
type OriginProofKey struct {
	ID     string
	Secret []byte
}

// OriginProofBucket returns the ten-minute bucket used by ts-proxy.
func OriginProofBucket(now time.Time) int64 {
	return now.Unix() / int64(CapabilityBucket/time.Second)
}

// OriginProofBody constructs the exact HMAC input shared with ts-proxy.
func OriginProofBody(method, canonicalPathQuery string, bucket int64) (string, error) {
	if bucket < 0 || strings.TrimSpace(method) == "" || !validCanonicalPathQuery(canonicalPathQuery) {
		return "", ErrOriginProofMalformed
	}
	method = strings.ToUpper(method)
	if strings.ContainsAny(method, "\r\n \t") {
		return "", ErrOriginProofMalformed
	}
	return fmt.Sprintf("%s.%s.%s.%d", OriginProofVersion, method, canonicalPathQuery, bucket), nil
}

// MintOriginProof emits the v1.<bucket>.<hex> header value.
func MintOriginProof(secret []byte, method, canonicalPathQuery string, bucket int64) (string, error) {
	if len(secret) == 0 {
		return "", ErrOriginProofMalformed
	}
	body, err := OriginProofBody(method, canonicalPathQuery, bucket)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(body))
	return fmt.Sprintf("%s.%d.%s", OriginProofVersion, bucket, hex.EncodeToString(mac.Sum(nil))), nil
}

// MintOriginProofAt is the safer production helper: callers cannot
// accidentally derive a daily rotation bucket instead of the ten-minute
// origin-proof bucket.
func MintOriginProofAt(secret []byte, method, canonicalPathQuery string, now time.Time) (string, error) {
	return MintOriginProof(secret, method, canonicalPathQuery, OriginProofBucket(now))
}

// MintOriginProofForRequest is a convenience seam for HTTP adapters. It
// signs only URL.EscapedPath plus RawQuery, never a host or fragment.
func MintOriginProofForRequest(secret []byte, method string, requestURL *url.URL, now time.Time) (string, error) {
	if requestURL == nil {
		return "", ErrOriginProofMalformed
	}
	return MintOriginProofAt(secret, method, CanonicalPathQuery(requestURL), now)
}

// CanonicalPathQuery returns the exact path/query bytes bound by ts-proxy.
func CanonicalPathQuery(requestURL *url.URL) string {
	if requestURL == nil {
		return ""
	}
	path := requestURL.EscapedPath()
	if path == "" {
		path = "/"
	}
	return path + func() string {
		if requestURL.RawQuery == "" {
			return ""
		}
		return "?" + requestURL.RawQuery
	}()
}

// VerifyOriginProof accepts the current and immediately previous ten-minute
// bucket. Keys are attempted in order (current first), allowing a key
// rotation to overlap without making old long polls fail.
func VerifyOriginProof(keys [][]byte, raw, method, canonicalPathQuery string, now time.Time) error {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 || parts[0] != OriginProofVersion {
		return ErrOriginProofMalformed
	}
	bucket, err := parseOriginProofInt(parts[1])
	if err != nil {
		return ErrOriginProofMalformed
	}
	signature, err := hex.DecodeString(parts[2])
	if err != nil || len(signature) != sha256.Size || parts[2] != strings.ToLower(parts[2]) {
		return ErrOriginProofMalformed
	}
	current := OriginProofBucket(now)
	if bucket != current && bucket != current-1 {
		return ErrOriginProofExpired
	}
	body, err := OriginProofBody(method, canonicalPathQuery, bucket)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(body))
		if hmac.Equal(mac.Sum(nil), signature) {
			return nil
		}
	}
	return ErrOriginProofMismatch
}

// VerifyOriginProofKeyRing is the identifier-bearing counterpart used by
// restart-safe coordinators. It intentionally returns no matching key or
// secret, only success/failure.
func VerifyOriginProofKeyRing(ring []OriginProofKey, raw, method, canonicalPathQuery string, now time.Time) error {
	keys := make([][]byte, 0, len(ring))
	for _, key := range ring {
		keys = append(keys, key.Secret)
	}
	return VerifyOriginProof(keys, raw, method, canonicalPathQuery, now)
}

func validCanonicalPathQuery(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\r\n") {
		return false
	}
	// A canonical path-query is not allowed to contain a fragment or an
	// absolute URL. URL parsing catches malformed escapes while preserving the
	// exact RawQuery spelling used by the cache key.
	u, err := url.ParseRequestURI(value)
	return err == nil && u.Path != "" && u.Fragment == "" && u.Host == "" && u.Scheme == ""
}

func parseOriginProofInt(raw string) (int64, error) {
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, ErrOriginProofMalformed
	}
	return strconv.ParseInt(raw, 10, 64)
}
