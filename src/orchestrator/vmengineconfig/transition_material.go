package vmengineconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

const transitionTrustRoot = "/etc/terrascale/terrabase/transition"
const exportCursorKeyPath = "/etc/terrascale/terrabase/transition/export-cursor.key"

const receiptSignerPath = "/etc/terrascale/terrabase/transition/receipt-signer.key"

type TransitionPublicKey struct {
	KeyID         string `json:"keyId"`
	PublicKeyFile string `json:"publicKeyFile"`
}
type TransitionTrust struct {
	ExportCursorKeyFile   string                `json:"exportCursorKeyFile,omitempty"`
	Authority             []TransitionPublicKey `json:"authority"`
	Genesis               []TransitionPublicKey `json:"genesis"`
	Members               []TransitionPublicKey `json:"members"`
	ReceiptKeyID          string                `json:"receiptKeyId,omitempty"`
	ReceiptPrivateKeyFile string                `json:"receiptPrivateKeyFile,omitempty"`
}

func transitionPinPath(role, id string) string {
	digest := sha256.Sum256([]byte(id))
	return transitionTrustRoot + "/" + role + "-" + hex.EncodeToString(digest[:]) + ".pub"
}
func IsTransitionTrustPath(path string) bool {
	name, ok := strings.CutPrefix(path, transitionTrustRoot+"/")
	if !ok {
		return false
	}
	for _, role := range []string{"authority", "genesis", "member"} {
		digest, ok := strings.CutPrefix(name, role+"-")
		if !ok {
			continue
		}
		digest, ok = strings.CutSuffix(digest, ".pub")
		if !ok {
			return false
		}
		raw, err := hex.DecodeString(digest)
		return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == digest
	}
	return false
}
func validateTransitionTrust(trust *TransitionTrust) error {
	if trust == nil {
		return nil
	}
	if (trust.ReceiptKeyID == "") != (trust.ReceiptPrivateKeyFile == "") {
		return errors.New("vmengineconfig: receipt signer identity and key file must be paired")
	}
	if len(trust.Authority) == 0 || len(trust.Genesis) == 0 || len(trust.Authority) > 32 || len(trust.Genesis) > 32 || len(trust.Members) > 40 {
		return errors.New("vmengineconfig: bounded explicit transition signing pins required")
	}
	for _, group := range [][]TransitionPublicKey{trust.Authority, trust.Genesis, trust.Members} {
		seen := map[string]bool{}
		for _, pin := range group {
			if pin.KeyID == "" || len(pin.KeyID) > 256 || strings.ContainsAny(pin.KeyID, "\r\n\t ") || seen[pin.KeyID] {
				return errors.New("vmengineconfig: invalid transition key identity")
			}
			seen[pin.KeyID] = true
		}
	}
	return nil
}
func renderTransitionTrust(out *strings.Builder, trust *TransitionTrust) {
	if trust == nil {
		return
	}
	for _, group := range []struct {
		role, field string
		pins        []TransitionPublicKey
	}{{"authority", "authority_keys", trust.Authority}, {"genesis", "genesis_keys", trust.Genesis}, {"member", "member_keys", trust.Members}} {
		pins := slices.Clone(group.pins)
		slices.SortFunc(pins, func(a, b TransitionPublicKey) int { return strings.Compare(a.KeyID, b.KeyID) })
		for _, pin := range pins {
			fmt.Fprintf(out, "\n[[control.transition.%s]]\nkey_id = %q\npublic_key_file = %q\n", group.field, pin.KeyID, transitionPinPath(group.role, pin.KeyID))
		}
	}
}
func prepareTransitionTrust(m *Material, trust *TransitionTrust) error {
	if err := validateTransitionTrust(trust); err != nil {
		return err
	}
	if trust == nil {
		return nil
	}
	m.transitionFiles = map[string][]byte{}
	if trust.ExportCursorKeyFile != "" {
		raw, err := initialgrant.ReadMaterialFile(trust.ExportCursorKeyFile, 32, true)
		if err != nil || len(raw) != 32 || bytes.Equal(raw, make([]byte, 32)) {
			return errors.New("vmengineconfig: export cursor key unavailable")
		}
		m.transitionFiles[exportCursorKeyPath] = raw
	}
	if trust.ReceiptKeyID != "" {
		raw, err := initialgrant.ReadMaterialFile(trust.ReceiptPrivateKeyFile, 16<<10, true)
		if err != nil || len(raw) == 0 {
			return errors.New("vmengineconfig: receipt signer private key is unavailable")
		}
		m.transitionFiles[receiptSignerPath] = raw
	}
	for _, group := range []struct {
		role string
		pins []TransitionPublicKey
	}{{"authority", trust.Authority}, {"genesis", trust.Genesis}, {"member", trust.Members}} {
		for _, pin := range group.pins {
			raw, err := initialgrant.ReadMaterialFile(pin.PublicKeyFile, ed25519.PublicKeySize, false)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return errors.New("vmengineconfig: exact raw Ed25519 transition public key required")
			}
			m.transitionFiles[transitionPinPath(group.role, pin.KeyID)] = raw
		}
	}
	return nil
}
func (m *Material) TransitionFiles() map[string][]byte {
	result := make(map[string][]byte, len(m.transitionFiles))
	for key, value := range m.transitionFiles {
		result[key] = bytes.Clone(value)
	}
	return result
}
func (m *Material) TransitionPaths() []string { return slices.Sorted(maps.Keys(m.transitionFiles)) }
