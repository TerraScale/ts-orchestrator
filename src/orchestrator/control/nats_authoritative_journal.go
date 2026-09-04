package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

// NatsAuthoritativeJournalConfiguration carries the separate credentials and
// trust root required to host the private authoritative journal writer.
type NatsAuthoritativeJournalConfiguration struct {
	NKeyFile                     string
	Tls                          *NatsTlsFiles
	AuthorityPublicKey           []byte
	ReplySigningKeyFile          string
	ReplySigningPublicKey        []byte
	EligibleControllerIdentities map[string]struct{}
}

// NatsAuthoritativeJournalConfigurationResolve resolves the configuration. A
// nil result with a nil error means nothing was supplied.
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

	_, pemBytes, err := natsJournalReadFile(authorityPublicKeyFile, 8192, true)
	if err != nil {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE must identify a bounded owner-private regular file.")
	}
	defer clear(pemBytes)

	if !bytes.Contains(pemBytes, []byte("-----BEGIN PUBLIC KEY-----")) {
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

	replyPath, replyPem, err := natsJournalResolveReplySigningKeyData(replySigningKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(replyPem)

	replyKey, err := natsJournalPemPrivateKey(replyPem)
	if err != nil {
		return nil, errors.New(
			"TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must contain a private key.")
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

		if _, err := nkeys.Decode(nkeys.PrefixByteUser, []byte(identity)); err != nil {
			return nil, errors.New(
				"TS_ORCH_JOURNAL_CONTROLLER_NKEYS contains an invalid user NKey public identity.")
		}
	}

	return identities, nil
}

func natsJournalResolveReplySigningKey(value string) (string, error) {
	path, _, err := natsJournalResolveReplySigningKeyData(value)
	return path, err
}

func natsJournalResolveReplySigningKeyData(value string) (string, []byte, error) {
	path, data, err := natsJournalReadFile(value, 8192, true)
	if err != nil {
		return "", nil, errors.New(
			"TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must identify a bounded owner-private regular file.")
	}

	if !bytes.Contains(data, []byte("-----BEGIN PRIVATE KEY-----")) {
		clear(data)
		return "", nil, errors.New("TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE must contain a private key.")
	}

	return path, data, nil
}

// natsJournalReadFile resolves and reads one bounded owner-private regular
// file without following symlinks. The final descriptor is checked against
// the initial lstat identity before any bytes are read, so replacement races
// cannot redirect parsing to an unvalidated file. Errors intentionally contain
// no file contents.
func natsJournalReadFile(value string, maximum int64, requirePrivate bool) (string, []byte, error) {
	path, err := filepath.Abs(value)
	if err != nil || strings.TrimSpace(value) == "" {
		return "", nil, errors.New("invalid credential file path")
	}
	path = filepath.Clean(path)

	initial, err := os.Lstat(path)
	if err != nil || initial.Mode()&os.ModeSymlink != 0 || !initial.Mode().IsRegular() ||
		initial.Size() < 1 || initial.Size() > maximum {
		return "", nil, errors.New("invalid credential file")
	}
	if requirePrivate && uint32(initial.Mode().Perm())&(messagingGroupAny|messagingOtherAny) != 0 {
		return "", nil, errors.New("credential file is not owner-private")
	}

	file, err := natsJournalOpenNoFollow(path)
	if err != nil {
		return "", nil, errors.New("unable to open credential file")
	}
	defer file.Close()

	current, err := file.Stat()
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		current.Size() < 1 || current.Size() > maximum ||
		!natsJournalSameFileIdentity(initial, current) {
		return "", nil, errors.New("credential file changed while opening")
	}
	if requirePrivate && uint32(current.Mode().Perm())&(messagingGroupAny|messagingOtherAny) != 0 {
		return "", nil, errors.New("credential file is not owner-private")
	}

	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) < 1 || int64(len(data)) > maximum {
		clear(data)
		return "", nil, errors.New("unable to read credential file")
	}

	return path, data, nil
}

func natsJournalSameFileIdentity(first, second os.FileInfo) bool {
	firstStat, firstOK := first.Sys().(*syscall.Stat_t)
	secondStat, secondOK := second.Sys().(*syscall.Stat_t)
	return firstOK && secondOK && firstStat.Dev == secondStat.Dev && firstStat.Ino == secondStat.Ino
}

// natsJournalOpenNoFollow walks the already-cleaned absolute path one
// component at a time with O_NOFOLLOW. This protects the component check from
// a parent-directory symlink replacement between lstat and open.
func natsJournalOpenNoFollow(path string) (*os.File, error) {
	root, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}

	fd := root
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			unix.Close(fd)
			return nil, errors.New("invalid journal identity file path")
		}

		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < len(components)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, component, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}

	return os.NewFile(uintptr(fd), path), nil
}
