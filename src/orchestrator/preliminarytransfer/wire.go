package preliminarytransfer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// MaximumBytes bounds the entire signed wire document, including its signature.
const MaximumBytes = 1 << 20

type signedDocument struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

// Digest returns the lower-case SHA-256 digest of the exact supplied bytes.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func publicKey(public []byte) (*ecdsa.PublicKey, string, error) {
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 || len(block.Headers) != 0 || !bytes.Equal(public, pem.EncodeToMemory(block)) {
		return nil, "", errors.New("preliminarytransfer: canonical public key PEM required")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", errors.New("preliminarytransfer: invalid public key")
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, "", errors.New("preliminarytransfer: P256 public key required")
	}
	return key, Digest(block.Bytes), nil
}

// PublicKeyID validates canonical P256 public-key PEM and hashes its DER bytes.
func PublicKeyID(public []byte) (string, error) {
	_, id, err := publicKey(public)
	return id, err
}

func canonicalDecode(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > MaximumBytes {
		return errors.New("preliminarytransfer: document exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("preliminarytransfer: malformed document")
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("preliminarytransfer: noncanonical document")
	}
	return nil
}

func signDocument(s *security.CommandSignatureSigner, domain string, value any) ([]byte, error) {
	if s == nil || domain == "" {
		return nil, errors.New("preliminarytransfer: signer and signature domain required")
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaximumBytes {
		return nil, errors.New("preliminarytransfer: invalid or oversized payload")
	}
	sig, err := s.SignCanonicalMaterial(append([]byte(domain), raw...))
	if err != nil {
		return nil, err
	}
	signed, err := json.Marshal(signedDocument{Payload: raw, Signature: sig.Bytes()})
	if err != nil || len(signed) > MaximumBytes {
		return nil, errors.New("preliminarytransfer: signed document exceeds bound")
	}
	return signed, nil
}

func verifyDocument(public, signed []byte, domain string, out any) (string, error) {
	fail := errors.New("preliminarytransfer: signature or document refused")
	key, owner, err := publicKey(public)
	if err != nil || domain == "" {
		return "", fail
	}
	var doc signedDocument
	if canonicalDecode(signed, &doc) != nil {
		return "", fail
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(doc.Signature)
	if !ok {
		return "", fail
	}
	id, _, sig, ok := security.DecodeCommandSignature(signature)
	hash := sha256.Sum256(append([]byte(domain), doc.Payload...))
	if !ok || id != owner || !ecdsa.VerifyASN1(key, hash[:], sig) || canonicalDecode(doc.Payload, out) != nil {
		return "", fail
	}
	return owner, nil
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s
}

func validSHA256(s string) bool {
	return strings.HasPrefix(s, "sha256:") && validDigest(strings.TrimPrefix(s, "sha256:"))
}

func validToken(s string) bool {
	_, err := hostmanifest.RequireToken(s, "identity", "preliminarytransfer: invalid identity")
	return err == nil
}

func finite(issued, expires time.Time) bool {
	return !issued.IsZero() && expires.After(issued) && expires.Sub(issued) <= 24*time.Hour
}

func validObjectKey(key string) bool {
	if len(key) == 0 || len(key) > 1024 {
		return false
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, r := range segment {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
				return false
			}
		}
	}
	return true
}
