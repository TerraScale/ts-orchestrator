package security

// Production command identity and signature verification.  The protocol owns
// the canonical command bytes; this package owns the algorithm, trust set, and
// the small detached-signature envelope used by control runtimes.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

const (
	// CommandSignatureAlgorithm is deliberately a single pinned algorithm.  A
	// new algorithm requires a new envelope version and an explicit review.
	CommandSignatureAlgorithm = "ecdsa-p256-sha256"
	maximumCommandTrustKeys   = 4
	maximumCommandKeyBytes    = 32 * 1024
	maximumCommandKeyIDBytes  = 64
	maximumCommandSigBytes    = 128
	commandSignatureVersion   = 1
	commandSignatureAlgorithm = 1
	commandSignatureHeader    = 4 + 1 + 1 + sha256.Size + 2
)

var commandSignatureMagic = [4]byte{'T', 'S', 'C', 'S'}

// CommandSignatureTrustKey is public-only configuration for one rotating
// command signer. PublicKeySPKI is copied when the verifier is constructed.
// Empty validity endpoints mean that the key has no additional time bound.
type CommandSignatureTrustKey struct {
	KeyID         string
	Algorithm     string
	PublicKeySPKI []byte
	NotBefore     time.Time
	NotAfter      time.Time
	RevokedAt     *time.Time
}

// CommandTrustKey is a readable compatibility alias for configuration code.
type CommandTrustKey = CommandSignatureTrustKey

// CommandSignatureVerifierConfig is bounded, owner-supplied verifier
// configuration. The verifier retains public keys only.
type CommandSignatureVerifierConfig struct {
	TrustedKeys []CommandSignatureTrustKey
}

// CommandSignatureVerifier verifies the protocol's versioned ECDSA signature
// envelope against a fixed, rotating public-key trust set.
type CommandSignatureVerifier struct {
	keys map[string]*commandTrustedKey
}

type commandTrustedKey struct {
	publicKey  *ecdsa.PublicKey
	notBefore  time.Time
	notAfter   time.Time
	revokedAt  *time.Time
}

// NewCommandSignatureVerifier validates and freezes a bounded public trust
// configuration. Key IDs are pinned to the lowercase SHA-256 SPKI fingerprint.
func NewCommandSignatureVerifier(config CommandSignatureVerifierConfig) (*CommandSignatureVerifier, error) {
	if len(config.TrustedKeys) < 1 || len(config.TrustedKeys) > maximumCommandTrustKeys {
		return nil, errors.New("the command trust set must contain one to four public keys")
	}
	keys := make(map[string]*commandTrustedKey, len(config.TrustedKeys))
	for _, configured := range config.TrustedKeys {
		key, keyID, err := parseCommandPublicKey(configured.PublicKeySPKI)
		if err != nil {
			return nil, errors.New("a command trust key is not a NIST P-256 public key")
		}
		if configured.Algorithm != CommandSignatureAlgorithm {
			return nil, errors.New("a command trust key uses an unsupported signature algorithm")
		}
		if configured.KeyID == "" {
			configured.KeyID = keyID
		}
		if err := validateCommandKeyID(configured.KeyID); err != nil || configured.KeyID != keyID {
			return nil, errors.New("a command trust key has an invalid key ID")
		}
		if !configured.NotBefore.IsZero() && !configured.NotAfter.IsZero() &&
			!configured.NotAfter.After(configured.NotBefore) {
			return nil, errors.New("a command trust key has an invalid validity window")
		}
		if configured.RevokedAt != nil {
			revoked := configured.RevokedAt.UTC()
			configured.RevokedAt = &revoked
		}
		if _, exists := keys[configured.KeyID]; exists {
			return nil, errors.New("the command trust set contains a duplicate key")
		}
		keys[configured.KeyID] = &commandTrustedKey{
			publicKey: key, notBefore: configured.NotBefore, notAfter: configured.NotAfter,
			revokedAt: configured.RevokedAt,
		}
	}
	return &CommandSignatureVerifier{keys: keys}, nil
}

// NewCommandSignatureVerifierFromKeys is a convenient explicit slice seam for
// future control-runtime composition.
func NewCommandSignatureVerifierFromKeys(keys []CommandSignatureTrustKey) (*CommandSignatureVerifier, error) {
	return NewCommandSignatureVerifier(CommandSignatureVerifierConfig{TrustedKeys: keys})
}

// LoadCommandSignatureVerifierPEM loads one to four public SubjectPublicKeyInfo
// PEM files. Private PEM blocks are rejected before parsing as public keys.
func LoadCommandSignatureVerifierPEM(paths []string) (*CommandSignatureVerifier, error) {
	if len(paths) < 1 || len(paths) > maximumCommandTrustKeys {
		return nil, errors.New("the command trust set must contain one to four public keys")
	}
	keys := make([]CommandSignatureTrustKey, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		data, err := readBoundedPublicPEM(path)
		if err != nil {
			return nil, err
		}
		_, id, err := parseCommandPublicKey(data)
		if err != nil {
			return nil, errors.New("a command trust key is not a NIST P-256 public key")
		}
		if _, exists := seen[id]; exists {
			return nil, errors.New("the command trust set contains a duplicate key")
		}
		seen[id] = struct{}{}
		keys = append(keys, CommandSignatureTrustKey{KeyID: id, Algorithm: CommandSignatureAlgorithm, PublicKeySPKI: data})
	}
	return NewCommandSignatureVerifierFromKeys(keys)
}

// NewEcdsaCommandSignatureVerifier and LoadEcdsaCommandSignatureVerifierPEM
// preserve the descriptive name used by the deleted implementation.
func NewEcdsaCommandSignatureVerifier(config CommandSignatureVerifierConfig) (*CommandSignatureVerifier, error) {
	return NewCommandSignatureVerifier(config)
}

func LoadEcdsaCommandSignatureVerifierPEM(paths []string) (*CommandSignatureVerifier, error) {
	return LoadCommandSignatureVerifierPEM(paths)
}

// Verify implements protocol.ICommandSignatureVerifier. Envelope validity
// timestamps are checked by protocol.CommandEnvelopeValidator; use VerifyAt
// when a caller also wants configured trust-key validity checked here.
func (v *CommandSignatureVerifier) Verify(material protocol.CommandSignedMaterial, signature protocol.OpaqueSignature) protocol.VerificationOutcome {
	if v == nil {
		return protocol.VerificationOutcomeInvalid
	}
	digest, err := protocol.CommandSignedMaterialCodec.Hash(&material)
	if err != nil {
		return protocol.VerificationOutcomeInvalid
	}
	keyID, value, ok := decodeCommandSignature(signature.Bytes())
	if !ok {
		return protocol.VerificationOutcomeInvalid
	}
	key := v.keys[hex.EncodeToString(keyID[:])]
	if key == nil || !verifyCommandSignature(key.publicKey, digest[:], value) {
		return protocol.VerificationOutcomeInvalid
	}
	return protocol.VerificationOutcomeValid
}

// VerifyAt additionally enforces not-before, not-after, and revocation on the
// selected trust key. It never renders key or signed-material bytes.
func (v *CommandSignatureVerifier) VerifyAt(material protocol.CommandSignedMaterial, signature protocol.OpaqueSignature, now time.Time) protocol.VerificationOutcome {
	if v == nil {
		return protocol.VerificationOutcomeInvalid
	}
	keyID, value, ok := decodeCommandSignature(signature.Bytes())
	if !ok {
		return protocol.VerificationOutcomeInvalid
	}
	key := v.keys[hex.EncodeToString(keyID[:])]
	if key == nil || !commandKeyValidAt(key, now) {
		return protocol.VerificationOutcomeInvalid
	}
	digest, err := protocol.CommandSignedMaterialCodec.Hash(&material)
	if err != nil || !verifyCommandSignature(key.publicKey, digest[:], value) {
		return protocol.VerificationOutcomeInvalid
	}
	return protocol.VerificationOutcomeValid
}

func (v *CommandSignatureVerifier) String() string {
	if v == nil {
		return "<nil>"
	}
	return "<command-signature-verifier>"
}

// CommandSignatureIdentity returns the stable, redacted-by-construction
// identity string carried by higher-level runtime diagnostics.
func CommandSignatureIdentity(keyID string) string {
	if validateCommandKeyID(keyID) != nil {
		return "<invalid-command-key>"
	}
	return CommandSignatureAlgorithm + "-" + keyID
}

func commandKeyValidAt(key *commandTrustedKey, now time.Time) bool {
	now = now.UTC()
	if !key.notBefore.IsZero() && now.Before(key.notBefore) {
		return false
	}
	if !key.notAfter.IsZero() && !now.Before(key.notAfter) {
		return false
	}
	return key.revokedAt == nil || now.Before(*key.revokedAt)
}

func verifyCommandSignature(key *ecdsa.PublicKey, digest, signature []byte) (valid bool) {
	if key == nil || len(digest) != sha256.Size || len(signature) < 1 || len(signature) > maximumCommandSigBytes {
		return false
	}
	// VerifyASN1 performs strict public-key and DER signature handling in the
	// standard library; no application comparison or secret-dependent branch is
	// introduced here.
	return ecdsa.VerifyASN1(key, digest, signature)
}

func decodeCommandSignature(value []byte) (keyID [sha256.Size]byte, signature []byte, ok bool) {
	if len(value) < commandSignatureHeader || len(value) > commandSignatureHeader+maximumCommandSigBytes {
		return keyID, nil, false
	}
	if value[0] != commandSignatureMagic[0] || value[1] != commandSignatureMagic[1] ||
		value[2] != commandSignatureMagic[2] || value[3] != commandSignatureMagic[3] ||
		value[4] != commandSignatureVersion || value[5] != commandSignatureAlgorithm {
		return keyID, nil, false
	}
	copy(keyID[:], value[6:6+sha256.Size])
	length := int(binary.BigEndian.Uint16(value[38:40]))
	if length < 1 || length > maximumCommandSigBytes || len(value) != commandSignatureHeader+length {
		return keyID, nil, false
	}
	return keyID, value[commandSignatureHeader:], true
}

func encodeCommandSignature(keyID [sha256.Size]byte, signature []byte) (protocol.OpaqueSignature, error) {
	if len(signature) < 1 || len(signature) > maximumCommandSigBytes {
		return protocol.OpaqueSignature{}, errors.New("the command signature envelope is invalid")
	}
	encoded := make([]byte, commandSignatureHeader+len(signature))
	copy(encoded, commandSignatureMagic[:])
	encoded[4] = commandSignatureVersion
	encoded[5] = commandSignatureAlgorithm
	copy(encoded[6:6+sha256.Size], keyID[:])
	binary.BigEndian.PutUint16(encoded[38:40], uint16(len(signature)))
	copy(encoded[commandSignatureHeader:], signature)
	result, ok := protocol.OpaqueSignatureTryCopyFrom(encoded)
	if !ok {
		return protocol.OpaqueSignature{}, errors.New("the command signature envelope is empty")
	}
	return result, nil
}

func parseCommandPublicKey(spki []byte) (*ecdsa.PublicKey, string, error) {
	if len(spki) < 1 || len(spki) > maximumCommandKeyBytes {
		return nil, "", errors.New("invalid public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, "", err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, "", errors.New("not p256")
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !equalBytes(canonical, spki) {
		return nil, "", errors.New("non-canonical public key")
	}
	digest := sha256.Sum256(canonical)
	return key, hex.EncodeToString(digest[:]), nil
}

func validateCommandKeyID(value string) error {
	if len(value) != sha256.Size*2 || len(value) > maximumCommandKeyIDBytes {
		return errors.New("invalid key ID")
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return errors.New("invalid key ID")
		}
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var mismatch byte
	for i := range a {
		mismatch |= a[i] ^ b[i]
	}
	return mismatch == 0
}

// CommandSignatureSigner is the private-key counterpart used by a future
// control runtime. Private material is accepted only from a bounded,
// owner-private Linux PEM credential.
type CommandSignatureSigner struct {
	key  *ecdsa.PrivateKey
	id   [sha256.Size]byte
	sync sync.Mutex
}

// LoadCommandSignatureSignerPEM loads a PKCS#8 or SEC1 P-256 private key.
func LoadCommandSignatureSignerPEM(path string) (*CommandSignatureSigner, error) {
	data, err := readBoundedPrivatePEM(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 || !strings.Contains(block.Type, "PRIVATE KEY") {
		return nil, errors.New("the command signing credential is not a P-256 private key")
	}
	var parsed any
	if block.Type == "PRIVATE KEY" {
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() || key.D == nil || key.D.Sign() <= 0 {
		return nil, errors.New("the command signing credential is not a P-256 private key")
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, errors.New("the command signing credential is not a P-256 private key")
	}
	id := sha256.Sum256(spki)
	return &CommandSignatureSigner{key: key, id: id}, nil
}

// NewCommandSignatureSignerFromKey is intended for controlled test or KMS
// adapters; callers must supply a P-256 private key.
func NewCommandSignatureSignerFromKey(key *ecdsa.PrivateKey) (*CommandSignatureSigner, error) {
	if key == nil || key.Curve != elliptic.P256() || key.D == nil {
		return nil, errors.New("the command signing key must be a P-256 private key")
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, errors.New("the command signing key must be a P-256 private key")
	}
	return &CommandSignatureSigner{key: key, id: sha256.Sum256(spki)}, nil
}

// Sign authenticates canonical command material and returns the versioned
// detached signature envelope.
func (s *CommandSignatureSigner) Sign(material protocol.CommandSignedMaterial) (protocol.OpaqueSignature, error) {
	if s == nil || s.key == nil {
		return protocol.OpaqueSignature{}, errors.New("the command signer is unavailable")
	}
	digest, err := protocol.CommandSignedMaterialCodec.Hash(&material)
	if err != nil {
		return protocol.OpaqueSignature{}, err
	}
	s.sync.Lock()
	value, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	s.sync.Unlock()
	if err != nil {
		return protocol.OpaqueSignature{}, errors.New("the command signature could not be produced")
	}
	return encodeCommandSignature(s.id, value)
}

func (s *CommandSignatureSigner) Identity() string {
	if s == nil {
		return "<nil>"
	}
	return CommandSignatureIdentity(hex.EncodeToString(s.id[:]))
}

func (s *CommandSignatureSigner) PublicKeyID() string {
	if s == nil {
		return ""
	}
	return hex.EncodeToString(s.id[:])
}

func (s *CommandSignatureSigner) String() string {
	if s == nil {
		return "<nil>"
	}
	return "<command-signature-signer>"
}

func (s *CommandSignatureSigner) Close() error {
	if s != nil {
		s.sync.Lock()
		s.key = nil
		s.sync.Unlock()
	}
	return nil
}

func (s *CommandSignatureSigner) Dispose() error { return s.Close() }

func readBoundedPublicPEM(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("the command trust key path is required")
	}
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumCommandKeyBytes {
		return nil, errors.New("a command trust key must be a bounded existing public PEM file")
	}
	value, err := os.ReadFile(clean)
	if err != nil {
		return nil, errors.New("a command trust key must be a bounded existing public PEM file")
	}
	block, rest := pem.Decode(value)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("a command trust key must contain public key material only")
	}
	return append([]byte(nil), block.Bytes...), nil
}

func readBoundedPrivatePEM(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("the command signing credential path is required")
	}
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumCommandKeyBytes {
		return nil, errors.New("the command signing credential must be a bounded existing PEM file")
	}
	if runtimeIsLinux() {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			return nil, errors.New("the command signing credential must be private to the owner")
		}
	}
	return os.ReadFile(clean)
}

// Kept as a variable to make platform-specific tests and future non-Linux
// credential providers straightforward without weakening the Linux boundary.
var runtimeIsLinux = func() bool { return runtime.GOOS == "linux" }

// Compile-time assertion documents the integration seam expected by protocol.
var _ protocol.ICommandSignatureVerifier = (*CommandSignatureVerifier)(nil)
