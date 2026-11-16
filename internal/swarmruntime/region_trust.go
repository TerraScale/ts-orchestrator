package swarmruntime

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	jsonv1 "encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
)

func NodeCertificates(state string) string { return filepath.Join(SwarmDir(state), "certificates") }

func RegionManagersFile(state string) string { return filepath.Join(SwarmDir(state), "state.json") }

func RegionManagers(state string) []string {
	wire, err := os.ReadFile(RegionManagersFile(state))
	var peers []api.Peer
	if err != nil || jsonv1.Unmarshal(wire, &peers) != nil {
		return nil
	}
	managers := []string{}
	for _, peer := range peers {
		if peer.NodeID != "" {
			managers = append(managers, peer.NodeID)
		}
	}
	return managers
}

func HoldsManagerCertificate(state string) bool {
	_, _, certificates, err := loadNodeKey(NodeCertificates(state))
	return err == nil && slices.Equal(certificates[0].Subject.OrganizationalUnit, []string{ca.ManagerRole})
}

func SignRegional(state string, message []byte) ([][]byte, []byte, error) {
	key, chain, _, err := loadNodeKey(NodeCertificates(state))
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(message)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	return chain, signature, err
}

func VerifyRegionalManager(state string, chain [][]byte, message, signature []byte) (string, error) {
	dir := NodeCertificates(state)
	_, _, own, err := loadNodeKey(dir)
	if err != nil {
		return "", err
	}
	leaf, err := verifyRegionalChain(dir, chain)
	if err != nil {
		return "", err
	}
	id := leaf.Subject.CommonName
	if id == "" || !slices.Equal(leaf.Subject.Organization, own[0].Subject.Organization) || !slices.Equal(leaf.Subject.OrganizationalUnit, []string{ca.ManagerRole}) {
		return "", errors.New("publisher certificate is not a manager certificate of this region")
	}
	if !slices.Contains(RegionManagers(state), id) {
		return "", errors.New("publisher is not a current manager of this region")
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	digest := sha256.Sum256(message)
	if !ok || !ecdsa.VerifyASN1(key, digest[:], signature) {
		return "", errors.New("invalid publisher signature")
	}
	return id, nil
}
