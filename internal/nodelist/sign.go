package nodelist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"path/filepath"
)

func Sign(state string, message []byte) (spki, signature []byte, err error) {
	if err := checkDirectory(filepath.Join(state, "node")); err != nil {
		return nil, nil, err
	}
	wire, err := identityFile(filepath.Join(state, "node", "tls.key"))
	if err != nil {
		return nil, nil, err
	}
	defer clear(wire)
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, nil, errors.New("invalid node TLS key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, errors.New("invalid node TLS key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, errors.New("node TLS key must be P-256")
	}
	spki, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(message)
	signature, err = ecdsa.SignASN1(rand.Reader, key, digest[:])
	return spki, signature, err
}

func (l List) Verify(name, region string, spki, message, signature []byte) error {
	pin := sha256.Sum256(spki)
	for _, node := range l.Nodes {
		if node.Name != name {
			continue
		}
		if node.Region != region || node.TLSSPKISHA256 != hex.EncodeToString(pin[:]) {
			return errors.New("signer identity differs from the node list")
		}
		parsed, err := x509.ParsePKIXPublicKey(spki)
		key, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || key.Curve != elliptic.P256() {
			return errors.New("signer key must be P-256")
		}
		digest := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return errors.New("invalid node signature")
		}
		return nil
	}
	return errors.New("signer is not in the node list")
}
