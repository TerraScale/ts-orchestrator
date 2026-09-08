package vmcontrolseed

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

// NodeAuthorityReaderSHA256Setting binds root-owned ts-node reader material to
// the finite ordinary host manifest without adding secrets to the orchestrator
// inventory. The orchestrator never needs access to this reader's private key.
const NodeAuthorityReaderSHA256Setting = "TS_ORCH_NODE_AUTHORITY_READER_SHA256"

type AuthorityMaterial struct {
	HostID string
	Reader nodeauthority.ReaderConfig
	Files  map[string][]byte
}

func (m *AuthorityMaterial) Clear() {
	if m != nil {
		for _, raw := range m.Files {
			clear(raw)
		}
	}
}
func (m *AuthorityMaterial) Clone() *AuthorityMaterial {
	if m == nil {
		return nil
	}
	out := *m
	out.Files = map[string][]byte{}
	for path, raw := range m.Files {
		out.Files[path] = bytes.Clone(raw)
	}
	return &out
}
func (m *AuthorityMaterial) Validate() error {
	bad := errors.New("vmcontrolseed: independent ordinary node authority material invalid")
	if m == nil || !identifierPattern.MatchString(m.HostID) || m.Reader.Validate() != nil || len(m.Files) != 4 {
		return bad
	}
	reader := m.Reader
	if reader.NKeySeedFile != AuthorityNKeyPath || reader.CAFile != AuthorityCAPath || reader.CertificateFile != AuthorityCertificatePath || reader.KeyFile != AuthorityPrivateKeyPath {
		return bad
	}
	for path, raw := range m.Files {
		if !IsAuthorityFilePath(path) || len(raw) == 0 || len(raw) > 64<<10 {
			return bad
		}
	}
	if digest(m.Files[reader.CAFile]) != reader.CASHA256 || digest(m.Files[reader.CertificateFile]) != reader.CertificateSHA256 {
		return bad
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(m.Files[reader.CAFile]) {
		return bad
	}
	if _, err := tls.X509KeyPair(m.Files[reader.CertificateFile], m.Files[reader.KeyFile]); err != nil {
		return bad
	}
	pair, err := nkeys.FromSeed(m.Files[reader.NKeySeedFile])
	if err != nil {
		return bad
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || public != reader.PublicNKey {
		return bad
	}
	return nil
}
func (m *AuthorityMaterial) ReaderSHA256() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(m.Reader)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}
func (m *AuthorityMaterial) ValidateManifest(hostID string, manifest hostmanifest.HostManifest) error {
	bad := errors.New("vmcontrolseed: ordinary node authority differs from finite signed host manifest")
	if m == nil || m.HostID != hostID {
		return bad
	}
	pin, err := m.ReaderSHA256()
	if err != nil {
		return err
	}
	if _, err := hostmanifest.CanonicalHostManifestJSON(manifest); err != nil {
		return err
	}
	found := false
	for _, component := range manifest.Components {
		if component.Name != "orchestrator" {
			continue
		}
		if found || component.Arguments != RunArguments {
			return bad
		}
		found = true
		var settings map[string]string
		if json.Unmarshal([]byte(component.Configuration), &settings) != nil || settings[NodeAuthorityReaderSHA256Setting] != pin || settings["TS_ORCH_INSTANCE"] != hostID {
			return bad
		}
	}
	if !found {
		return bad
	}
	return nil
}
