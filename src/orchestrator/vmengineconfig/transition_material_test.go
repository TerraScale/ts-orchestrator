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
