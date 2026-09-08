package vmqualbootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// Material is public initial admission; the issuer's private key never leaves
// the runner. It contains no regional lease, global lease, or runtime epoch.
type Material struct{ PublicKeyPEM, SignedGrant []byte }

type Issuer struct {
	mu         sync.Mutex
	signer     *security.CommandSignatureSigner
	public     []byte
	issued     time.Time
	grants     map[string]Material
	persistent *persistentIssuer
}

func NewIssuer() (*Issuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		_ = signer.Close()
		return nil, err
	}
	return &Issuer{signer: signer, public: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), issued: time.Now().UTC().Add(-time.Minute), grants: map[string]Material{}}, nil
}

func (i *Issuer) Grant(host string, manifest hostmanifest.HostManifest) (Material, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.signer == nil {
		return Material{}, errors.New("vmqual: bootstrap grant issuer is closed")
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil {
		return Material{}, err
	}
	if material, ok := i.grants[host]; ok {
		grant, err := hostagent.VerifyBootstrapGrant(host, material.PublicKeyPEM, material.SignedGrant)
		if err != nil {
			return Material{}, err
		}
		previous, err := hostmanifest.CanonicalHostManifestJSON(grant.Manifest)
		if err != nil || !bytes.Equal(previous, canonical) {
			return Material{}, errors.New("vmqual: initial grant cannot change its admitted manifest")
		}
		return cloneMaterial(material), nil
	}
	if len(i.grants) >= 256 {
		return Material{}, errors.New("vmqual: initial grant host bound exceeded")
	}
	create := func() (Material, error) {
		hash := sha256.Sum256(append(append(append([]byte(nil), i.public...), []byte(host)...), canonical...))
		grant := hostagent.BootstrapGrant{Version: 1, GrantID: "vmq-initial-" + hex.EncodeToString(hash[:16]), NodeID: host, Manifest: manifest, IssuedAt: i.issued, ExpiresAt: i.issued.Add(24 * time.Hour)}
		signed, err := hostagent.SignBootstrapGrant(i.signer, grant)
		if err != nil {
			return Material{}, err
		}
		return Material{PublicKeyPEM: append([]byte(nil), i.public...), SignedGrant: signed}, nil
	}
	var material Material
	if i.persistent != nil {
		material, err = i.persistent.loadGrant(host, manifest, i.public, create)
	} else {
		material, err = create()
	}
	if err != nil {
		return Material{}, err
	}
	i.grants[host] = material
	return cloneMaterial(material), nil
}

func (i *Issuer) Sign(host, subject string, command json.RawMessage) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.signer == nil {
		return nil, errors.New("vmqual: bootstrap grant issuer is closed")
	}
	material, ok := i.grants[host]
	if !ok {
		return nil, errors.New("vmqual: host has no seeded initial grant")
	}
	issued := time.Now().UTC().Add(-time.Second)
	return hostagent.SignBootstrapCommand(i.signer, material.SignedGrant, subject, command, issued, issued.Add(30*time.Second))
}
func (i *Issuer) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.signer != nil {
		_ = i.signer.Close()
		i.signer = nil
	}
	i.grants = nil
	i.public = nil
	if i.persistent != nil {
		err := i.persistent.close()
		i.persistent = nil
		return err
	}
	return nil
}
func cloneMaterial(m Material) Material {
	return Material{PublicKeyPEM: append([]byte(nil), m.PublicKeyPEM...), SignedGrant: append([]byte(nil), m.SignedGrant...)}
}

// AdmittedGrant returns only a grant already issued by this run. It never signs
// or renews admission while a candidate asks for its source identity.
func (i *Issuer) AdmittedGrant(host string) (Material, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	material, ok := i.grants[host]
	if i.signer == nil || !ok {
		return Material{}, errors.New("vmqual: initial source grant has not been issued")
	}
	return cloneMaterial(material), nil
}
