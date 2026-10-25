package edge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/oklog/ulid/v2"
)

const requestIDHeader = "X-Request-ID"
const requestProofHeader = "X-TerraScale-Request-Proof"

// Transport trailers arrive while reading the body; scrub them again at EOF.
type identityResponseBody struct {
	io.ReadCloser
	response *http.Response
}

func (b identityResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.response.Trailer.Del(requestProofHeader)
	b.response.Trailer.Del(requestIDHeader)
	return n, err
}

// SetRequestProofSecret refreshes the existing Vault-delivered TerraBase peer
// credential. An unavailable or revoked credential clears proof trust.
func (e *Edge) SetRequestProofSecret(value string) error {
	if value == "" {
		e.requestProofSecret.Store(nil)
		return nil
	}
	if _, err := hex.DecodeString(value); err != nil || len(value) != 64 {
		e.requestProofSecret.Store(nil)
		return errors.New("edge request proof needs a 64-character hexadecimal peer credential")
	}
	key := []byte(value) // Exact UTF-8 credential characters, not decoded hex.
	e.requestProofSecret.Store(&key)
	return nil
}

func (e *Edge) validRequestProof(value string, proofs []string) bool {
	if len(proofs) != 1 || len(proofs[0]) != 64 {
		return false
	}
	want := e.requestProof(value)
	return want != "" && hmac.Equal([]byte(want), []byte(proofs[0]))
}

func (e *Edge) requestProof(value string) string {
	key := e.requestProofSecret.Load()
	if key == nil {
		return ""
	}
	mac := hmac.New(sha256.New, *key)
	mac.Write([]byte("terrascale.request-id.v1\n" + value))
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

// identify accepts only canonical ULIDs from mesh mTLS or a first-party proof.
// Proofs authenticate correlation only; they never grant resource access.
func (e *Edge) identify(w http.ResponseWriter, r *http.Request) {
	value := r.Header.Get(requestIDHeader)
	id, err := ulid.ParseStrict(value)
	if len(r.Header.Values(requestIDHeader)) != 1 || err != nil || id.String() != value ||
		(!fromPeer(r) && !e.validRequestProof(value, r.Header.Values(requestProofHeader))) {
		value = ulid.Make().String()
	}
	r.Header.Del(requestProofHeader)
	r.Header.Set(requestIDHeader, value)
	w.Header().Set(requestIDHeader, value)
}
