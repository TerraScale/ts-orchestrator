package transitiongrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
)

// CandidateSyncConfig admits a local preliminary download and verification
// worker. The owner-signed transfer scope separately selects exact objects.
// It does not authorize store promotion, election, or TerraBase membership.
type CandidateSyncConfig struct {
	AuthorityReaderSHA256 string             `json:"authorityReaderSha256"`
	RequestFile           string             `json:"requestFile"`
	StagingDir            string             `json:"stagingDir"`
	ReceiptDir            string             `json:"receiptDir"`
	ReceiptPrivateKeyFile string             `json:"receiptPrivateKeyFile"`
	ReceiptPublicKeyPEM   string             `json:"receiptPublicKeyPem"`
	MaxSnapshotBytes      int64              `json:"maxSnapshotBytes"`
	MaxTotalBytes         int64              `json:"maxTotalBytes"`
	MaxRestoreBytes       int64              `json:"maxRestoreBytes"`
	Identity              ociinstance.Config `json:"identity"`
}

func (s CandidateSyncConfig) Validate(storeDir string) error {
	bad := errors.New("transitiongrant: invalid isolated candidate sync configuration")
	if !digest(s.AuthorityReaderSHA256) || s.MaxSnapshotBytes < 1024 || s.MaxSnapshotBytes > 1<<30 || s.MaxTotalBytes < s.MaxSnapshotBytes || s.MaxTotalBytes > 256<<30 || s.MaxRestoreBytes < s.MaxSnapshotBytes || s.MaxRestoreBytes > 256<<30 {
		return bad
	}
	paths := []string{s.RequestFile, s.StagingDir, s.ReceiptDir, s.ReceiptPrivateKeyFile, storeDir}
	if s.Identity.Qualification != nil {
		paths = append(paths, s.Identity.Qualification.ClientPrivateKeyFile)
	}
	for i, path := range paths {
		if !hostmanifest.SafeAbsolutePath(path) || path == "/" {
			return bad
		}
		for _, prior := range paths[:i] {
			if hostmanifest.PathsOverlap(path, prior) {
				return bad
			}
		}
	}
	if err := ociinstance.ValidateConfig(s.Identity); err != nil {
		return bad
	}
	block, rest := pem.Decode([]byte(s.ReceiptPublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 || len(block.Headers) != 0 || !bytes.Equal(pem.EncodeToMemory(block), []byte(s.ReceiptPublicKeyPEM)) {
		return bad
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return bad
	}
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return bad
	}
	return nil
}

func (s CandidateSyncConfig) validateComponent(dataVolume string) error {
	prefix := strings.TrimSuffix(dataVolume, "/") + "/"
	privatePaths := []string{s.RequestFile, s.ReceiptPrivateKeyFile}
	if s.Identity.Qualification != nil {
		privatePaths = append(privatePaths, s.Identity.Qualification.ClientPrivateKeyFile)
	}
	for _, path := range privatePaths {
		if hostmanifest.PathsOverlap(dataVolume, path) {
			return errors.New("transitiongrant: candidate sync protected file overlaps writable data volume")
		}
	}
	if !strings.HasPrefix(s.StagingDir, prefix) || !strings.HasPrefix(s.ReceiptDir, prefix) {
		return errors.New("transitiongrant: candidate sync storage escapes dedicated data volume")
	}
	return nil
}

// Equal compares immutable configuration values, including optional nested
// declarations decoded into independently allocated objects.
func (c Config) Equal(other Config) bool {
	left, err := json.Marshal(c)
	if err != nil {
		return false
	}
	right, err := json.Marshal(other)
	return err == nil && bytes.Equal(left, right)
}
