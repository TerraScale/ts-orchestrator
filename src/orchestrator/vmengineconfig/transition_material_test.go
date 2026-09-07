package vmengineconfig_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/internal/testengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func TestTransitionTrustCopiesOnlyPinnedPublicKeys(t *testing.T) {
	bindings := []vmengineconfig.Binding{{NodeID: "gru-one", Region: "GRU", Address: "10.77.0.10"}, {NodeID: "gru-two", Region: "GRU", Address: "10.77.0.11"}}
	artifact := strings.Repeat("a", 64)
	declaration, path := testengineconfig.Declaration(t, bindings, artifact, "1.0.0")
	keyDir := t.TempDir()
	key := func(name string) vmengineconfig.TransitionPublicKey {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		clear(private)
		path := filepath.Join(keyDir, name+".pub")
		if err := os.WriteFile(path, public, 0600); err != nil {
			t.Fatal(err)
		}
		return vmengineconfig.TransitionPublicKey{KeyID: name, PublicKeyFile: path}
	}
	declaration.TransitionTrust = &vmengineconfig.TransitionTrust{Authority: []vmengineconfig.TransitionPublicKey{key("authority")}, Genesis: []vmengineconfig.TransitionPublicKey{key("genesis")}, Members: []vmengineconfig.TransitionPublicKey{key("member")}}
	data, _ := json.Marshal(declaration)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	materials, err := vmengineconfig.Load(path, artifact, "1.0.0", bindings)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, material := range materials {
			material.Clear()
		}
	}()
	for _, material := range materials {
		if len(material.TransitionFiles()) != 3 {
			t.Fatal("transition key material missing")
		}
		for path, data := range material.TransitionFiles() {
			if !vmengineconfig.IsTransitionTrustPath(path) || len(data) != 32 {
				t.Fatal("unbound transition public key material")
			}
		}
	}
	declaration.TransitionTrust.Genesis = nil
	data, _ = json.Marshal(declaration)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := vmengineconfig.Load(path, artifact, "1.0.0", bindings); err == nil {
		t.Fatal("implicit genesis trust accepted")
	}
	if vmengineconfig.IsTransitionTrustPath("/etc/terrascale/terrabase/transition/member-../../secret.pub") {
		t.Fatal("trust file path escaped")
	}
}

func TestReceiptSignerStagesCanonicalPrivateMaterial(t *testing.T) {
	bindings := []vmengineconfig.Binding{{NodeID: "gru-one", Region: "GRU", Address: "10.77.0.10"}, {NodeID: "gru-two", Region: "GRU", Address: "10.77.0.11"}}
	artifact := strings.Repeat("a", 64)
	declaration, path := testengineconfig.Declaration(t, bindings, artifact, "1.0.0")
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	key := []byte("qualification-receipt-private-key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "pin.pub")
	if err := os.WriteFile(pubPath, make([]byte, ed25519.PublicKeySize), 0600); err != nil {
		t.Fatal(err)
	}
	declaration.TransitionTrust = &vmengineconfig.TransitionTrust{Authority: []vmengineconfig.TransitionPublicKey{{KeyID: "authority", PublicKeyFile: pubPath}}, Genesis: []vmengineconfig.TransitionPublicKey{{KeyID: "genesis", PublicKeyFile: pubPath}}, ReceiptKeyID: "qualification-receipt", ReceiptPrivateKeyFile: keyPath}
	data, _ := json.Marshal(declaration)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	materials, err := vmengineconfig.Load(path, artifact, "1.0.0", bindings)
	if err != nil {
		t.Fatal(err)
	}
	var material *vmengineconfig.Material
	for _, candidate := range materials {
		material = candidate
		break
	}
	defer material.Clear()
	files := material.TransitionFiles()
	got, ok := files["/etc/terrascale/terrabase/transition/receipt-signer.key"]
	if !ok || string(got) != string(key) {
		t.Fatalf("receipt material = %q, want staged key", got)
	}
}
