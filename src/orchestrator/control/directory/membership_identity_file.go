package directory

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
)

const maximumMembershipIdentityFileBytes = 64 << 10

// RegionalRuntimeMembershipIdentityLoadFile opens an explicit owner-private
// PKCS8 PEM P-256 key. Missing or invalid files never generate an identity.
// The caller owns the returned identity and must Dispose it after membership.
func RegionalRuntimeMembershipIdentityLoadFile(path string) (*RegionalRuntimeMembershipIdentity, error) {
	data, err := readMembershipConfigurationFile(path, true)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return parseMembershipIdentityPEM(data)
}

// RegionalRuntimeMembershipPublicKeyFromPEM derives the exact identity pin
// carried by ORCH_RUNTIME: canonical base64 PKIX P-256 plus its key identifier.
// Credential issuers call this before boot, without observing runtime records.
func RegionalRuntimeMembershipPublicKeyFromPEM(data []byte) (keyID, publicKey string, err error) {
	identity, err := parseMembershipIdentityPEM(data)
	if err != nil {
		return "", "", err
	}
	defer identity.Dispose()
	return identity.KeyId, identity.PublicKey, nil
}

func parseMembershipIdentityPEM(data []byte) (*RegionalRuntimeMembershipIdentity, error) {
	invalid := errors.New("membership identity requires one unencrypted PKCS8 PEM P-256 private key")
	if len(data) == 0 || len(data) > maximumMembershipIdentityFileBytes || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, invalid
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, invalid
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, invalid
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, invalid
	}
	x, y := elliptic.P256().ScalarBaseMult(key.D.Bytes())
	if key.X == nil || key.Y == nil || key.X.Cmp(x) != 0 || key.Y.Cmp(y) != 0 {
		key.D.SetInt64(0)
		return nil, invalid
	}
	return newRegionalRuntimeMembershipIdentity(key)
}

// RegionalRuntimeMembershipPinsLoadFile reads an explicit immutable pin map.
// Keys are controller instance IDs; values are canonical base64 PKIX P-256.
func RegionalRuntimeMembershipPinsLoadFile(path string) (map[string]string, error) {
	data, err := readMembershipConfigurationFile(path, false)
	if err != nil {
		return nil, err
	}
	return parseMembershipPins(data)
}

func parseMembershipPins(data []byte) (map[string]string, error) {
	invalid := errors.New("membership pins require one bounded JSON object with unique controller instances and canonical PKIX P-256 public keys")
	if len(data) == 0 || len(data) > maximumMembershipIdentityFileBytes {
		return nil, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, invalid
	}
	pins := map[string]string{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, invalid
		}
		instance, ok := token.(string)
		if !ok || !shared.MessagingCellTokenIsValid(instance) || len(instance) > 128 {
			return nil, invalid
		}
		if _, exists := pins[instance]; exists || len(pins) >= 128 {
			return nil, invalid
		}
		var public string
		if err := decoder.Decode(&public); err != nil || !validMembershipPublicKey(public) {
			return nil, invalid
		}
		pins[instance] = public
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, invalid
	}
	if _, err = decoder.Token(); err != io.EOF || len(pins) == 0 {
		return nil, invalid
	}
	return pins, nil
}

func validMembershipPublicKey(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(der) != value {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) {
		return false
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	return err == nil && bytes.Equal(canonical, der)
}

func readMembershipConfigurationFile(path string, private bool) ([]byte, error) {
	invalid := errors.New("membership configuration requires a bounded canonical regular file with trusted ownership and permissions")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return nil, invalid
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, invalid
		}
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, invalid
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximumMembershipIdentityFileBytes || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, invalid
	}
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if before.Mode().Perm()&mask != 0 || !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) || owner.Nlink != 1 {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumMembershipIdentityFileBytes+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(data)) != before.Size() {
		clear(data)
		return nil, invalid
	}
	return data, nil
}
