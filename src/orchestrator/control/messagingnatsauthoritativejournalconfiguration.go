// Port of src/TerraScale.Orchestrator/Messaging/NatsAuthoritativeJournalConfiguration.cs.
package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nats-io/nkeys"
)

// NatsAuthoritativeJournalConfiguration mirrors the C# record: the separate
// credentials and trust root required to host the private authoritative
// journal writer.
type NatsAuthoritativeJournalConfiguration struct {
	NKeyFile                    string
	Tls                         *NatsTlsFiles
	AuthorityPublicKey          []byte
	ReplySigningKeyFile         string
	ReplySigningPublicKey       []byte
	EligibleControllerIdentities map[string]struct{}
}

// NatsAuthoritativeJournalConfigurationResolve mirrors the C# Resolve. A nil
// result with a nil error means nothing was supplied.
func NatsAuthoritativeJournalConfigurationResolve(
	nkeyFile string,
	caFile string,
	certificateFile string,
	keyFile string,
	authorityPublicKeyFile string,
	replySigningKeyFile string,
	eligibleControllerIdentities string,
) (*NatsAuthoritativeJournalConfiguration, error) {
	values := []string{nkeyFile, caFile, certificateFile, keyFile,
		authorityPublicKeyFile, replySigningKeyFile, eligibleControllerIdentities}
	supplied := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			supplied++
		}
	}

	if supplied == 0 {
		return nil, nil
	}

	if supplied != len(values) {
		return nil, errors.New(
			"TS_ORCH_JOURNAL requires NKey, mTLS, authority public-key, reply signing-key, and eligible " +
				"controller identities together.")
	}

	resolvedNkey, err := NatsCredentialFile.Resolve(nkeyFile, "TS_ORCH_JOURNAL_NATS_NKEY_FILE")
	if err != nil {
		return nil, err
	}

	if resolvedNkey == "" {
		return nil, errors.New("TS_ORCH_JOURNAL_NATS_NKEY_FILE is missing.")
	}

	tls, err := NatsTlsFilesResolve(caFile, certificateFile, keyFile, "TS_ORCH_JOURNAL_NATS_TLS")
	if err != nil {
		return nil, err
	}

	if tls == nil {
		return nil, errors.New("TS_ORCH_JOURNAL_NATS_TLS credentials are missing.")
	}

	path, err := filepath.Abs(authorityPublicKeyFile)
	if err != nil {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE must identify a bounded authority public key file.")
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() < 1 || info.Size() > 8192 {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE must identify a bounded authority public key file.")
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.")
	}

	if !strings.Contains(string(pemBytes), "-----BEGIN PUBLIC KEY-----") {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.")
	}

	authority, err := natsJournalPemPublicKey(pemBytes)
	if err != nil {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.")
	}

	if authority.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.")
	}

	publicKey, err := x509.MarshalPKIXPublicKey(authority)
	if err != nil || len(publicKey) == 0 {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.")
	}

	replyPath, err := natsJournalResolveReplySigningKey(replySigningKeyFile)
	if err != nil {
		return nil, err
	}

	replyPem, err := os.ReadFile(replyPath)
	if err != nil {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.")
	}

	replyKey, err := natsJournalPemPrivateKey(replyPem)
	if err != nil {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.")
	}

	if replyKey.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New("Reply signing key must be a distinct NIST P-256 key.")
	}

	replyPublicKey, err := x509.MarshalPKIXPublicKey(&replyKey.PublicKey)
	if err != nil {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE is not a valid ECDSA public key.")
	}

	if bytes.Equal(replyPublicKey, publicKey) {
		return nil, errors.New("Reply signing key must be a distinct NIST P-256 key.")
	}

	if tls.HasSubjectPublicKeyInfo(publicKey) || tls.HasSubjectPublicKeyInfo(replyPublicKey) {
		return nil, errors.New("Authority keys must be distinct from the journal writer TLS identity.")
	}

	controllers, err := natsJournalParseControllerIdentities(eligibleControllerIdentities)
	if err != nil {
		return nil, err
	}

	writerPublicKey, err := NatsCredentialFile.PublicKey(resolvedNkey)
	if err != nil {
		return nil, err
	}

	if _, contains := controllers[writerPublicKey]; contains {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_CONTROLLER_NKEYS must not contain the journal writer NKey public identity.")
	}

	return &NatsAuthoritativeJournalConfiguration{
		NKeyFile:                     resolvedNkey,
		Tls:                          tls,
		AuthorityPublicKey:           publicKey,
		ReplySigningKeyFile:          replyPath,
		ReplySigningPublicKey:        replyPublicKey,
		EligibleControllerIdentities: controllers,
	}, nil
}

func natsJournalPemPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return publicKey, nil
}

func natsJournalPemPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if keyEC, errEC := x509.ParseECPrivateKey(block.Bytes); errEC == nil {
			return keyEC, nil
		}

		return nil, err
	}

	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}

	return privateKey, nil
}

func natsJournalParseControllerIdentities(value string) (map[string]struct{}, error) {
	identities := map[string]struct{}{}
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			identities[trimmed] = struct{}{}
		}
	}

	if len(identities) == 0 {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_CONTROLLER_NKEYS must contain at least one NKey public identity.")
	}

	keys := make([]string, 0, len(identities))
	for identity := range identities {
		keys = append(keys, identity)
	}

	sort.Strings(keys)

	for _, identity := range keys {
		if !strings.HasPrefix(identity, "U") {
			return nil, errors.New(
				"TS_ORCH_JOURNAL_CONTROLLER_NKEYS contains an invalid user NKey public identity.")
		}

		if _, err := nkeys.Decode([]byte(identity)); err != nil {
			return nil, errors.New(
				"TS_ORCH_JOURNAL_CONTROLLER_NKEYS contains an invalid user NKey public identity.")
		}
	}

	return identities, nil
}

func natsJournalResolveReplySigningKey(value string) (string, error) {
	path, err := filepath.Abs(value)
	if err != nil {
		return "", errors.New(
			"TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must identify a bounded owner-private key file.")
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() < 1 || info.Size() > 8192 {
		return "", errors.New(
			"TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must identify a bounded owner-private key file.")
	}

	mode, err := messagingUnixFileMode(path)
	if err != nil || mode&(messagingGroupAny|messagingOtherAny) != 0 {
		return "", errors.New(
			"TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must identify a bounded owner-private key file.")
	}

	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "-----BEGIN PRIVATE KEY-----") {
		return "", errors.New("TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must contain a private key.")
	}

	return path, nil
}
