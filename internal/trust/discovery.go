package trust

import (
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
)

// The reviewed TS-470 production public genesis is shared with image inputs.
// Root rotation verifies from this genesis; downloaded objects cannot add roots.
//
//go:embed bootstrap-root-002.pem
var discoveryGenesisPEM []byte

func DiscoveryGenesis() (Keyring, error) {
	block, rest := pem.Decode(discoveryGenesisPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return nil, errors.New("embedded discovery genesis public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("embedded discovery genesis is not Ed25519")
	}
	return ParseKeyring(key)
}
