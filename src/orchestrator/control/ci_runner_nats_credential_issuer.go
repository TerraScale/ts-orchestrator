package control

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nkeys"
)

// CiRunnerNatsIdentityConfiguration mirrors the C# sealed class.
type CiRunnerNatsIdentityConfiguration struct {
	SigningKeyFile   string
	AccountPublicKey *string
}

// CiRunnerNatsIdentityConfigurationResolve mirrors the C# Resolve. A nil
// result means no identity was supplied.
func CiRunnerNatsIdentityConfigurationResolve(
	signingKeyFile string,
	accountPublicKey string,
) (*CiRunnerNatsIdentityConfiguration, error) {
	if strings.TrimSpace(signingKeyFile) == "" {
		if strings.TrimSpace(accountPublicKey) != "" {
			return nil, errors.New(
				"A CI runner NATS issuer account requires its account signing credential. (Parameter 'accountPublicKey')")
		}

		return nil, nil
	}

	path, err := filepath.Abs(strings.TrimSpace(signingKeyFile))
	if err != nil {
		return nil, err
	}

	var accountKey *string
	if strings.TrimSpace(accountPublicKey) != "" {
		trimmed := strings.TrimSpace(accountPublicKey)
		accountKey = &trimmed
	}

	return &CiRunnerNatsIdentityConfiguration{SigningKeyFile: path, AccountPublicKey: accountKey}, nil
}

// Open mirrors the C# Open.
func (c *CiRunnerNatsIdentityConfiguration) Open() (*NatsAccountJwtSigner, error) {
	if c == nil {
		return nil, errors.New("The CI runner NATS identity is unavailable.")
	}
	return NatsAccountJwtSignerOpen(c.SigningKeyFile, c.AccountPublicKey)
}

// INatsAccountJwtSigner mirrors the C# interface.
type INatsAccountJwtSigner interface {
	IssuerPublicKey() string
	AccountPublicKey() string
	SignAsync(ctx context.Context, material []byte) ([]byte, error)
}

// NatsAccountJwtSigner mirrors the C# class: an account or account-signing
// NKey retained from a private systemd credential.
type NatsAccountJwtSigner struct {
	mu               chan struct{}
	seed             []byte
	issuerPublicKey  string
	accountPublicKey string
}

// NatsAccountJwtSignerOpen mirrors the C# Open.
func NatsAccountJwtSignerOpen(path string, accountPublicKey *string) (*NatsAccountJwtSigner, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("The NATS account signing credential path is required. (Parameter 'path')")
	}

	fullPath, err := NatsCredentialFile.Resolve(path, "path")
	if err != nil {
		return nil, errors.New(
			"The NATS account signing credential must be a bounded owner-private NKey file. (Parameter 'path')")
	}

	seed, err := nkeySeed(fullPath)
	if err != nil {
		return nil, errors.New("The NATS account signing credential is empty. (Parameter 'path')")
	}

	pair, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return nil, errors.New("The NATS account signing credential is invalid. (Parameter 'path')")
	}

	issuer, err := pair.PublicKey()
	if err != nil {
		return nil, errors.New("The NATS account signing credential is invalid. (Parameter 'path')")
	}

	if err := natsRequireAccountPublicKey(issuer, "The NATS signing seed must be an account NKey."); err != nil {
		return nil, errors.New("The NATS account signing credential is invalid. (Parameter 'path')")
	}

	account := issuer
	if accountPublicKey != nil && strings.TrimSpace(*accountPublicKey) != "" {
		account = strings.TrimSpace(*accountPublicKey)
	}

	if err := natsRequireAccountPublicKey(account, "The NATS issuer account must be an account public NKey."); err != nil {
		return nil, errors.New("The NATS account signing credential is invalid. (Parameter 'path')")
	}

	return &NatsAccountJwtSigner{
		mu:               make(chan struct{}, 1),
		seed:             []byte(seed),
		issuerPublicKey:  issuer,
		accountPublicKey: account,
	}, nil
}

// IssuerPublicKey mirrors the C# property.
func (s *NatsAccountJwtSigner) IssuerPublicKey() string { return s.issuerPublicKey }

// AccountPublicKey mirrors the C# property.
func (s *NatsAccountJwtSigner) AccountPublicKey() string { return s.accountPublicKey }

// SignAsync mirrors the C# SignAsync.
func (s *NatsAccountJwtSigner) SignAsync(ctx context.Context, material []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("The NATS account signing credential is unavailable.")
	}
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.mu == nil {
		return nil, errors.New("The NATS account signing credential is unavailable.")
	}

	select {
	case s.mu <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s.mu }()

	pair, err := nkeys.FromSeed(s.seed)
	if err != nil {
		return nil, err
	}
	defer pair.Wipe()

	return pair.Sign(material)
}

// Dispose mirrors the C# Dispose.
func (s *NatsAccountJwtSigner) Dispose() {
	if s == nil {
		return
	}
	if s.mu == nil {
		for index := range s.seed {
			s.seed[index] = 0
		}
		s.seed = nil
		return
	}
	// Hold the same guard as SignAsync while clearing the seed. This keeps
	// disposal from racing either seed parsing or signing with the derived key.
	s.mu <- struct{}{}
	defer func() { <-s.mu }()
	for index := range s.seed {
		s.seed[index] = 0
	}
	s.seed = nil
}

func natsRequireAccountPublicKey(value, message string) error {
	if len(value) == 0 || len(value) > natsAccountPublicKeyMaximumCharacters {
		return errors.New(message)
	}
	decoded, err := nkeys.Decode(nkeys.PrefixByteAccount, []byte(value))
	if err != nil {
		return errors.New(message)
	}

	// nkeys.Decode strips the one-byte type prefix; account public keys
	// therefore decode to exactly the 32-byte payload.
	if len(decoded) != 32 {
		return errors.New(message)
	}

	return nil
}

// CiRunnerNatsCredentialLease mirrors the C# class: a disposable user JWT and
// nonce-signing seed. Its string form never contains either.
type CiRunnerNatsCredentialLease struct {
	mu        sync.Mutex
	PublicKey string
	Jwt       string
	seed      []byte
	LeaseId   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// NewCiRunnerNatsCredentialLease mirrors the C# constructor.
func NewCiRunnerNatsCredentialLease(
	publicKey string,
	jwt string,
	seed string,
	leaseId string,
	issuedAt time.Time,
	expiresAt time.Time,
) *CiRunnerNatsCredentialLease {
	return &CiRunnerNatsCredentialLease{
		PublicKey: publicKey,
		Jwt:       jwt,
		seed:      []byte(seed),
		LeaseId:   leaseId,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}
}

// WriteCredentialsFile mirrors the C# WriteCredentialsFile: an owner-private
// credentials file in the exact NATS.Net format.
func (l *CiRunnerNatsCredentialLease) WriteCredentialsFile(path string) (string, error) {
	if l == nil {
		return "", os.ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seed == nil {
		return "", os.ErrClosed
	}

	fullPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	parent := filepath.Dir(fullPath)
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return "", errors.New("The CI runner credential directory must be owner-private. (Parameter 'path')")
	}

	parentMode, err := messagingUnixFileMode(parent)
	if err != nil || parentMode != 0o700 {
		return "", errors.New("The CI runner credential directory must be owner-private. (Parameter 'path')")
	}

	created := false
	defer func() {
		if created {
			_ = os.Remove(fullPath)
		}
	}()

	document := strings.Join([]string{
		"-----BEGIN NATS USER JWT-----",
		l.Jwt,
		"------END NATS USER JWT------",
		"",
		"-----BEGIN USER NKEY SEED-----",
		string(l.seed),
		"------END USER NKEY SEED------",
		"",
	}, "\n")

	file, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}

	created = true
	if _, err := file.WriteString(document); err != nil {
		file.Close()
		return "", err
	}

	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}

	if err := file.Close(); err != nil {
		return "", err
	}

	return fullPath, nil
}

// Dispose mirrors the C# Dispose.
func (l *CiRunnerNatsCredentialLease) Dispose() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for index := range l.seed {
		l.seed[index] = 0
	}

	l.seed = nil
}

// String mirrors the redacted C# ToString.
func (l *CiRunnerNatsCredentialLease) String() string {
	return fmt.Sprintf("CI runner NATS credential %s for %s, expires %s",
		l.LeaseId, l.PublicKey, l.ExpiresAt.Format(time.RFC3339))
}

// CiRunnerNatsCredentialIssuer lifetimes mirror the C# constants.
const (
	CiRunnerNatsCredentialIssuerMaximumLifetime      = 75 * time.Minute
	CiRunnerNatsCredentialIssuerMinimumLifetime      = time.Minute
	CiRunnerNatsCredentialIssuerMaximumPayloadBytes  = 128 * 1024
	CiRunnerNatsCredentialIssuerMaximumSubscriptions = 32
	natsAccountPublicKeyMaximumCharacters            = 128
)

// CiRunnerNatsCredentialIssuer mirrors the C# class: issues a short-lived NATS
// user only after its exact consumer was reconciled.
type CiRunnerNatsCredentialIssuer struct {
	topology *GlobalNatsTopology
	signer   INatsAccountJwtSigner
}

// NewCiRunnerNatsCredentialIssuer mirrors the C# constructor.
func NewCiRunnerNatsCredentialIssuer(
	topology *GlobalNatsTopology,
	signer INatsAccountJwtSigner,
) (*CiRunnerNatsCredentialIssuer, error) {
	if topology == nil {
		return nil, errors.New("(Parameter 'topology')")
	}

	if signer == nil {
		return nil, errors.New("(Parameter 'signer')")
	}

	return &CiRunnerNatsCredentialIssuer{topology: topology, signer: signer}, nil
}

// IssueAsync mirrors the C# IssueAsync.
func (i *CiRunnerNatsCredentialIssuer) IssueAsync(
	ctx context.Context,
	registration CiRunnerConsumerRegistration,
	runner string,
	now time.Time,
	lifetime time.Duration,
) (*CiRunnerNatsCredentialLease, error) {
	if i == nil || i.topology == nil || i.signer == nil {
		return nil, errors.New("The CI runner NATS credential issuer is unavailable.")
	}
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if lifetime < CiRunnerNatsCredentialIssuerMinimumLifetime ||
		lifetime > CiRunnerNatsCredentialIssuerMaximumLifetime ||
		lifetime%time.Second != 0 {
		return nil, errors.New(
			"Specified argument was out of the range of valid values. (Parameter 'lifetime')")
	}

	expected, err := i.topology.CiJobConsumer(registration.Zone, runner)
	if err != nil {
		return nil, err
	}

	if expected.Name == "" {
		return nil, errors.New("The CI runner consumer must have a name.")
	}

	if expected.FilterSubject == "" {
		return nil, errors.New("The CI runner consumer must have a filter subject.")
	}

	if registration.Consumer != expected.Name || registration.Subject != expected.FilterSubject {
		return nil, errors.New(
			"A matching reconciled CI runner consumer is required before identity issuance.")
	}

	issuedSeconds := now.Unix()
	if issuedSeconds <= 0 {
		return nil, errors.New("Specified argument was out of the range of valid values. (Parameter 'now')")
	}

	expiresSeconds := issuedSeconds + int64(lifetime/time.Second)
	issuedAt := time.Unix(issuedSeconds, 0).UTC()
	expiresAt := time.Unix(expiresSeconds, 0).UTC()

	seedPair, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}

	seed, err := seedPair.Seed()
	if err != nil {
		return nil, err
	}

	publicKey, err := seedPair.PublicKey()
	if err != nil {
		return nil, err
	}

	plan, err := CiRunnerNatsPermissions.Create(i.topology, registration.Zone, runner)
	if err != nil {
		return nil, err
	}

	token, err := NatsUserJwtCodecEncodeAsync(ctx, i.signer, publicKey, expectedName(expected.Name),
		plan, issuedSeconds, expiresSeconds)
	if err != nil {
		return nil, err
	}

	return NewCiRunnerNatsCredentialLease(
		publicKey,
		token.Jwt,
		string(seed),
		token.Id,
		issuedAt,
		expiresAt), nil
}

func expectedName(name string) string { return name }

// NatsUserJwtCodecToken mirrors the C# (string Jwt, string Id) tuple.
type NatsUserJwtCodecToken struct {
	Jwt string
	Id  string
}

const natsUserJwtBase32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// NatsUserJwtCodec mirrors the C# static class.
var NatsUserJwtCodec natsUserJwtCodecStatic

type natsUserJwtCodecStatic struct{}

// NatsUserJwtCodecEncodeAsync mirrors the C# EncodeAsync.
func NatsUserJwtCodecEncodeAsync(
	ctx context.Context,
	signer INatsAccountJwtSigner,
	userPublicKey string,
	name string,
	permissions *CiRunnerNatsPermissionPlan,
	issuedAt int64,
	expiresAt int64,
) (*NatsUserJwtCodecToken, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if signer == nil {
		return nil, errors.New("(Parameter 'signer')")
	}
	if permissions == nil {
		return nil, errors.New("(Parameter 'permissions')")
	}
	if issuedAt <= 0 || expiresAt <= issuedAt {
		return nil, errors.New("The NATS user JWT lifetime is invalid.")
	}
	claims := map[string]interface{}{
		"exp":  expiresAt,
		"iat":  issuedAt,
		"iss":  signer.IssuerPublicKey(),
		"name": name,
		"sub":  userPublicKey,
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	idHash := sha256.Sum256(claimsBytes)
	id := natsUserJwtBase32(idHash[:])

	header, err := json.Marshal(map[string]string{"typ": "JWT", "alg": "ed25519-nkey"})
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"exp":  expiresAt,
		"jti":  id,
		"iat":  issuedAt,
		"iss":  signer.IssuerPublicKey(),
		"name": name,
		"sub":  userPublicKey,
		"nats": map[string]interface{}{
			"pub":                      map[string]interface{}{"allow": permissions.Publish},
			"sub":                      map[string]interface{}{"allow": permissions.Subscribe},
			"subs":                     CiRunnerNatsCredentialIssuerMaximumSubscriptions,
			"data":                     -1,
			"payload":                  CiRunnerNatsCredentialIssuerMaximumPayloadBytes,
			"allowed_connection_types": []string{"STANDARD"},
			"type":                     "user",
			"version":                  2,
		},
	}

	if signer.IssuerPublicKey() != signer.AccountPublicKey() {
		payload["nats"].(map[string]interface{})["issuer_account"] = signer.AccountPublicKey()
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature, err := signer.SignAsync(ctx, []byte(signingInput))
	if err != nil {
		return nil, err
	}

	if len(signature) != 64 {
		return nil, errors.New("A NATS account NKey signature must contain 64 bytes.")
	}

	return &NatsUserJwtCodecToken{
		Jwt: signingInput + "." + base64.RawURLEncoding.EncodeToString(signature),
		Id:  id,
	}, nil
}

// natsUserJwtBase32 mirrors the C# Base32 helper (RFC 4648, no padding).
func natsUserJwtBase32(value []byte) string {
	var encoded strings.Builder
	buffer := 0
	bits := 0
	for _, current := range value {
		buffer = buffer<<8 | int(current)
		bits += 8
		for bits >= 5 {
			bits -= 5
			encoded.WriteByte(natsUserJwtBase32Alphabet[(buffer>>bits)&31])
		}
	}

	if bits > 0 {
		encoded.WriteByte(natsUserJwtBase32Alphabet[(buffer<<(5-bits))&31])
	}

	return encoded.String()
}
