package managedmaterial

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const maxCustomerPlaintextBytes = 16 << 10

// CustomerMaterial is the owner-only plaintext of a prepared customer
// envelope. Callers must write it only to an owner-only destination.
type CustomerMaterial struct {
	Version    uint64 `json:"version"`
	Token      string `json:"token"`
	HTTPSCAPEM string `json:"https_ca_pem"`
}

// OpenCustomerEnvelope uses the same recipient grant, AAD, and KDF as the
// producer. The caller must first authenticate the signed preparation reply
// against an independently pinned controller key and the requested spec.
func OpenCustomerEnvelope(spec InitialSpec, envelope CustomerEnvelope,
	recipient *ecdh.PrivateKey,
) (CustomerMaterial, error) {
	if recipient == nil || recipient.Curve() != ecdh.X25519() ||
		!bytes.Equal(recipient.PublicKey().Bytes(), spec.Recipient.PublicKey) ||
		envelope.Version != 2 || !lowerHexDigest(envelope.VerifierSHA256) ||
		!lowerHexDigest(envelope.HTTPSCASHA256) ||
		len(envelope.Ciphertext) > base64.RawURLEncoding.EncodedLen(maxCustomerPlaintextBytes+16) {
		return CustomerMaterial{}, errors.New("customer envelope recipient or fields are invalid")
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(envelope.EphemeralPublicKey)
	if err != nil || len(publicBytes) != 32 {
		return CustomerMaterial{}, errors.New("customer envelope ephemeral key is invalid")
	}
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return CustomerMaterial{}, errors.New("customer envelope ephemeral key is invalid")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != 12 {
		return CustomerMaterial{}, errors.New("customer envelope nonce is invalid")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > maxCustomerPlaintextBytes+16 {
		return CustomerMaterial{}, errors.New("customer envelope ciphertext is invalid")
	}
	shared, err := recipient.ECDH(public)
	if err != nil {
		return CustomerMaterial{}, errors.New("customer envelope key agreement failed")
	}
	defer clear(shared)
	associated := customerEnvelopeAAD(spec, envelope.TokenID, envelope.VerifierSHA256, envelope.HTTPSCASHA256)
	key, err := hkdf.Key(sha256.New, shared, associated, "TB-CUSTOMER-TOKEN-V2", 32)
	if err != nil {
		return CustomerMaterial{}, errors.New("customer envelope key derivation failed")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return CustomerMaterial{}, errors.New("customer envelope cipher is invalid")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return CustomerMaterial{}, errors.New("customer envelope cipher is invalid")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, associated)
	if err != nil {
		return CustomerMaterial{}, errors.New("customer envelope authentication failed")
	}
	defer clear(plaintext)
	var material CustomerMaterial
	if err := protocol.DecodeStrict(plaintext, &material, maxCustomerPlaintextBytes); err != nil ||
		material.Version != 1 || material.Token == "" || material.HTTPSCAPEM == "" {
		return CustomerMaterial{}, errors.New("customer envelope plaintext is invalid")
	}
	parts := strings.Split(material.Token, ".")
	if len(parts) != 3 || parts[0] != "tbk1" || parts[1] != envelope.TokenID {
		return CustomerMaterial{}, errors.New("customer token binding is invalid")
	}
	id, idErr := base64.RawURLEncoding.DecodeString(parts[1])
	secret, secretErr := base64.RawURLEncoding.DecodeString(parts[2])
	defer clear(secret)
	if idErr != nil || secretErr != nil || len(id) != 16 || len(secret) != 32 ||
		base64.RawURLEncoding.EncodeToString(id) != parts[1] ||
		base64.RawURLEncoding.EncodeToString(secret) != parts[2] {
		return CustomerMaterial{}, errors.New("customer token binding is invalid")
	}
	verifier := sha256.New()
	verifier.Write([]byte("TB-APIKEY-V1\x00"))
	verifier.Write(id)
	verifier.Write(secret)
	if hex.EncodeToString(verifier.Sum(nil)) != envelope.VerifierSHA256 {
		return CustomerMaterial{}, errors.New("customer token verifier differs from envelope")
	}
	caDigest := sha256.Sum256([]byte(material.HTTPSCAPEM))
	if hex.EncodeToString(caDigest[:]) != envelope.HTTPSCASHA256 {
		return CustomerMaterial{}, errors.New("customer HTTPS CA differs from envelope")
	}
	return material, nil
}
