package vmqualbootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/qualificationstate"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

var errPersistentIssuer = errors.New("vmqualbootstrap: protected immutable issuer state required")

type persistentIssuer struct{ store *qualificationstate.Store }
type persistentIssuerDocument struct {
	Version    int       `json:"version"`
	RunID      string    `json:"runId"`
	IssuedAt   time.Time `json:"issuedAt"`
	PrivatePEM []byte    `json:"privatePem"`
}

// NewPersistentIssuer retains the owner identity and each original signed grant
// before returning it to image staging. Retry never renews a grant or replaces
// a source hash already bound into candidate admission.
func NewPersistentIssuer(directory, runID string) (_ *Issuer, err error) {
	if len(runID) != 32 {
		return nil, errPersistentIssuer
	}
	if raw, decodeErr := hex.DecodeString(runID); decodeErr != nil || hex.EncodeToString(raw) != runID {
		return nil, errPersistentIssuer
	}
	store, err := qualificationstate.Open(directory)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			store.Close()
		}
	}()
	validate := func(raw []byte) error {
		var document persistentIssuerDocument
		if json.Unmarshal(raw, &document, json.RejectUnknownMembers(true)) != nil {
			return errPersistentIssuer
		}
		defer clear(document.PrivatePEM)
		now := time.Now().UTC()
		if document.Version != 1 || document.RunID != runID || document.IssuedAt.IsZero() || now.Before(document.IssuedAt) || !now.Before(document.IssuedAt.Add(24*time.Hour)) {
			return errPersistentIssuer
		}
		signer, err := security.ParseCommandSignatureSignerPEM(document.PrivatePEM)
		if err != nil {
			return errPersistentIssuer
		}
		return signer.Close()
	}
	raw, err := store.LoadOrCreate("initial-issuer.json", 64<<10, func() ([]byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		defer key.D.SetInt64(0)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		defer clear(der)
		document := persistentIssuerDocument{Version: 1, RunID: runID, IssuedAt: time.Now().UTC().Add(-time.Minute), PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}
		defer clear(document.PrivatePEM)
		return json.Marshal(document)
	}, validate)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var document persistentIssuerDocument
	if json.Unmarshal(raw, &document, json.RejectUnknownMembers(true)) != nil {
		return nil, errPersistentIssuer
	}
	defer clear(document.PrivatePEM)
	now := time.Now().UTC()
	if document.Version != 1 || document.RunID != runID || document.IssuedAt.IsZero() || now.Before(document.IssuedAt) || !now.Before(document.IssuedAt.Add(24*time.Hour)) {
		return nil, errPersistentIssuer
	}
	signer, err := security.ParseCommandSignatureSignerPEM(document.PrivatePEM)
	if err != nil {
		return nil, errPersistentIssuer
	}
	block, _ := pem.Decode(document.PrivatePEM)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		signer.Close()
		return nil, errPersistentIssuer
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		signer.Close()
		return nil, errPersistentIssuer
	}
	defer key.D.SetInt64(0)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		signer.Close()
		return nil, err
	}
	retained = true
	return &Issuer{signer: signer, public: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), issued: document.IssuedAt, grants: map[string]Material{}, persistent: &persistentIssuer{store: store}}, nil
}

func (p *persistentIssuer) saveGrant(host string, manifest hostmanifest.HostManifest, material Material) (Material, error) {
	return p.loadGrant(host, manifest, material.PublicKeyPEM, func() (Material, error) { return material, nil })
}
func (p *persistentIssuer) loadGrant(host string, manifest hostmanifest.HostManifest, public []byte, create func() (Material, error)) (Material, error) {
	if _, err := hostagent.NewNodeId(host); err != nil || strings.ContainsAny(host, "/\\") || host == "." || host == ".." {
		return Material{}, errPersistentIssuer
	}
	var admitted Material
	validate := func(raw []byte) error {
		if json.Unmarshal(raw, &admitted, json.RejectUnknownMembers(true)) != nil || !bytes.Equal(admitted.PublicKeyPEM, public) {
			return errPersistentIssuer
		}
		verified, err := hostagent.VerifyBootstrapGrant(host, admitted.PublicKeyPEM, admitted.SignedGrant)
		if err != nil {
			return err
		}
		expected, err := hostmanifest.CanonicalHostManifestJSON(manifest)
		if err != nil {
			return err
		}
		actual, err := hostmanifest.CanonicalHostManifestJSON(verified.Manifest)
		if err != nil || !bytes.Equal(expected, actual) {
			return errPersistentIssuer
		}
		return nil
	}
	raw, err := p.store.LoadOrCreate("grant-"+host+".json", 2<<20, func() ([]byte, error) {
		material, err := create()
		if err != nil {
			return nil, err
		}
		return json.Marshal(material)
	}, validate)
	if err != nil {
		return Material{}, err
	}
	defer clear(raw)
	return cloneMaterial(admitted), nil
}
func (p *persistentIssuer) close() error {
	if p == nil {
		return nil
	}
	return p.store.Close()
}
