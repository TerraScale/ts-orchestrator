// Package vmcandidateseed binds separately stored candidate credentials to the
// original owner-signed preparation and bootstrap grants before image staging.
package vmcandidateseed

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
)

const Directory = "/etc/terrascale/candidate"
const ReceiptKeyPath = Directory + "/receipt.key"
const QualificationKeyPath = Directory + "/qualification.key"
const GrantPath = Directory + "/grant.json"
const OwnerPath = Directory + "/owner.pem"

// Declaration references independently provisioned reader credentials on the
// runner. Reader contains the exact guest configuration to be owner-pinned.
type Declaration struct {
	Reader                      nodeauthority.ReaderConfig `json:"reader"`
	ReaderNKeyFile              string                     `json:"readerNkeyFile"`
	ReaderCAFile                string                     `json:"readerCaFile"`
	ReaderCertificateFile       string                     `json:"readerCertificateFile"`
	ReaderPrivateKeyFile        string                     `json:"readerPrivateKeyFile"`
	QualificationPrivateKeyFile string                     `json:"qualificationPrivateKeyFile,omitempty"`
}

// PrivateArtifact stays in a protected per-host directory, never the public bundle.
type PrivateArtifact struct {
	PlanSHA256 string                     `json:"planSha256"`
	Config     transitiongrant.Config     `json:"config"`
	Reader     nodeauthority.ReaderConfig `json:"reader"`
	Files      map[string][]byte          `json:"files"`
}
type Material struct {
	PrivateArtifact
	PublicKeyPEM     []byte
	BootstrapGrant   []byte
	PreparationGrant []byte
}

func (p PrivateArtifact) Clear() {
	for _, b := range p.Files {
		clear(b)
	}
}
func IsServiceFile(path string) bool {
	return path == ReceiptKeyPath || path == QualificationKeyPath || path == GrantPath || path == OwnerPath
}
func hash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func (p PrivateArtifact) Validate() error {
	bad := errors.New("vmcandidateseed: candidate private material differs from pinned configuration")
	c, r := p.Config, p.Reader
	pin, err := hex.DecodeString(p.PlanSHA256)
	if err != nil || len(pin) != 32 || hex.EncodeToString(pin) != p.PlanSHA256 {
		return bad
	}
	if c.Validate() != nil || c.Sync == nil || r.Validate() != nil || c.GrantFile != GrantPath || c.GrantPublicKeyFile != OwnerPath || c.Sync.ReceiptPrivateKeyFile != ReceiptKeyPath {
		return bad
	}
	raw, _ := json.Marshal(r)
	if hash(raw) != c.Sync.AuthorityReaderSHA256 || r.NKeySeedFile != vmcontrolseed.AuthorityNKeyPath || r.CAFile != vmcontrolseed.AuthorityCAPath || r.CertificateFile != vmcontrolseed.AuthorityCertificatePath || r.KeyFile != vmcontrolseed.AuthorityPrivateKeyPath {
		return bad
	}
	if hash(p.Files[r.CAFile]) != r.CASHA256 || hash(p.Files[r.CertificateFile]) != r.CertificateSHA256 {
		return bad
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(p.Files[r.CAFile]) {
		return bad
	}
	if _, err := tls.X509KeyPair(p.Files[r.CertificateFile], p.Files[r.KeyFile]); err != nil {
		return bad
	}
	pair, err := nkeys.FromSeed(p.Files[r.NKeySeedFile])
	if err != nil {
		return bad
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil || public != r.PublicNKey {
		return bad
	}
	key, err := receiptKey(p.Files[ReceiptKeyPath])
	if err != nil {
		return bad
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), []byte(c.Sync.ReceiptPublicKeyPEM)) {
		return bad
	}
	expected := map[string]bool{ReceiptKeyPath: true, r.NKeySeedFile: true, r.CAFile: true, r.CertificateFile: true, r.KeyFile: true}
	if q := c.Sync.Identity.Qualification; q != nil {
		if q.ClientPrivateKeyFile != QualificationKeyPath {
			return bad
		}
		if _, err := tls.X509KeyPair([]byte(q.ClientCertificatePEM), p.Files[QualificationKeyPath]); err != nil {
			return bad
		}
		expected[QualificationKeyPath] = true
	}
	if len(expected) != len(p.Files) {
		return bad
	}
	for path, raw := range p.Files {
		if !expected[path] || len(raw) == 0 || len(raw) > 64<<10 {
			return bad
		}
	}
	return nil
}
func receiptKey(raw []byte) (*ecdsa.PrivateKey, error) {
	bad := errors.New("vmcandidateseed: invalid private receipt identity")
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.Equal(pem.EncodeToMemory(block), raw) {
		return nil, bad
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, bad
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, bad
	}
	return key, nil
}
func (m Material) Validate() error {
	if err := m.PrivateArtifact.Validate(); err != nil {
		return err
	}
	peer, err := bootstrap.PlanControlCandidatePeer(m.Config, m.PublicKeyPEM, m.BootstrapGrant)
	if err != nil {
		return err
	}
	grant, err := transitiongrant.VerifyGrant(m.PublicKeyPEM, m.PreparationGrant)
	if err != nil {
		return err
	}
	return grant.CheckCandidate(time.Now().UTC(), m.Config, peer.BootstrapGrantSHA256, peer.PreparedManifestSHA256)
}
func (m Material) ValidateManifest(raw []byte) error {
	if err := m.Validate(); err != nil {
		return err
	}
	manifest, err := hostmanifest.ParseHostManifest(raw)
	if err != nil {
		return err
	}
	peer, err := bootstrap.PlanControlCandidatePeer(m.Config, m.PublicKeyPEM, m.BootstrapGrant)
	if err != nil {
		return err
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil || digest != peer.PreparedManifestSHA256 {
		return errors.New("vmcandidateseed: image manifest differs from original admission")
	}
	return nil
}
